//! Compiled policy structures for efficient evaluation.

use std::collections::HashMap;
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;

use crate::Policy;
use crate::error::PolicyError;
use crate::field::LogFieldSelector;
use crate::proto::tero::policy::v1::{
    LogField, LogMatcher, LogSampleKey, log_matcher, log_sample_key,
};
use crate::registry::PolicyStats;

use super::keep::CompiledKeep;
use super::match_key::MatchKey;
use super::transform::CompiledTransform;

/// Reference from a pattern match back to its policy.
#[derive(Debug, Clone)]
pub struct PolicyMatchRef {
    /// Index into CompiledMatchers::policies.
    pub policy_index: usize,
}

/// A compiled policy ready for evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Policy ID.
    pub id: String,
    /// Number of matchers that must match for this policy to apply.
    pub required_match_count: usize,
    /// The keep action for this policy.
    pub keep: CompiledKeep,
    /// The transform to apply when this policy matches (if any).
    pub transform: Option<CompiledTransform>,
    /// Statistics for this policy.
    pub stats: Arc<PolicyStats>,
    /// Whether this policy is enabled.
    pub enabled: bool,
    /// Optional sample key for consistent hash-based sampling.
    /// When set with percentage-based sampling, logs with the same sample key
    /// value will consistently be either kept or dropped together.
    pub sample_key: Option<LogFieldSelector>,
}

/// Existence check that can't be handled by Vectorscan.
#[derive(Debug, Clone)]
pub struct ExistenceCheck {
    /// Index into CompiledMatchers::policies.
    pub policy_index: usize,
    /// The field to check.
    pub field: LogFieldSelector,
    /// Whether the field should exist.
    pub should_exist: bool,
    /// Whether this is a negated matcher.
    pub is_negated: bool,
}

/// Pattern info for building Vectorscan databases.
#[derive(Debug)]
pub struct PatternInfo {
    /// The regex pattern.
    pub pattern: String,
    /// Index into the policies vector.
    pub policy_index: usize,
    /// Whether the pattern should be matched case-insensitively.
    pub case_insensitive: bool,
}

/// A compiled Vectorscan database with scratch space.
pub struct VectorscanDatabase {
    db: *mut vectorscan_rs_sys::hs_database_t,
    scratch: *mut vectorscan_rs_sys::hs_scratch_t,
}

// Safety: The database and scratch pointers are thread-safe for reads.
// Each thread should have its own scratch space for scanning, but we
// clone scratch for each scan operation.
unsafe impl Send for VectorscanDatabase {}
unsafe impl Sync for VectorscanDatabase {}

impl VectorscanDatabase {
    /// Compile patterns into a Vectorscan database.
    ///
    /// # Arguments
    /// * `patterns` - The regex patterns to compile.
    /// * `ids` - The pattern IDs (must match patterns length).
    /// * `flags` - The Vectorscan flags for each pattern (must match patterns length).
    fn compile(patterns: &[String], ids: &[u32], flags: &[u32]) -> Result<Self, PolicyError> {
        assert_eq!(patterns.len(), ids.len());
        assert_eq!(patterns.len(), flags.len());

        if patterns.is_empty() {
            return Err(PolicyError::CompileError {
                reason: "no patterns to compile".to_string(),
            });
        }

        // Convert patterns to C strings
        let c_patterns: Vec<CString> = patterns
            .iter()
            .map(|p| {
                CString::new(p.as_str()).map_err(|e| PolicyError::CompileError {
                    reason: format!("invalid pattern string: {}", e),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let pattern_ptrs: Vec<*const std::ffi::c_char> =
            c_patterns.iter().map(|s| s.as_ptr()).collect();

        let mut db: *mut vectorscan_rs_sys::hs_database_t = ptr::null_mut();
        let mut compile_error: *mut vectorscan_rs_sys::hs_compile_error_t = ptr::null_mut();

        // Compile the database
        let result = unsafe {
            vectorscan_rs_sys::hs_compile_multi(
                pattern_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                patterns.len() as u32,
                vectorscan_rs_sys::HS_MODE_BLOCK,
                ptr::null(),
                &mut db,
                &mut compile_error,
            )
        };

        if result != vectorscan_rs_sys::HS_SUCCESS as i32 {
            let error_msg = if !compile_error.is_null() {
                let msg = unsafe {
                    let msg_ptr = (*compile_error).message;
                    if msg_ptr.is_null() {
                        "unknown error".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(msg_ptr)
                            .to_string_lossy()
                            .into_owned()
                    }
                };
                unsafe {
                    vectorscan_rs_sys::hs_free_compile_error(compile_error);
                }
                msg
            } else {
                format!("compile failed with code {}", result)
            };

            return Err(PolicyError::CompileError {
                reason: format!("failed to compile Vectorscan database: {}", error_msg),
            });
        }

        // Allocate scratch space
        let mut scratch: *mut vectorscan_rs_sys::hs_scratch_t = ptr::null_mut();
        let result = unsafe { vectorscan_rs_sys::hs_alloc_scratch(db, &mut scratch) };

        if result != vectorscan_rs_sys::HS_SUCCESS as i32 {
            unsafe {
                vectorscan_rs_sys::hs_free_database(db);
            }
            return Err(PolicyError::CompileError {
                reason: format!("failed to allocate scratch space: code {}", result),
            });
        }

        Ok(VectorscanDatabase { db, scratch })
    }

    /// Scan data and call the callback for each match.
    /// Returns the pattern IDs that matched.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<u32>, PolicyError> {
        let matches = std::cell::RefCell::new(Vec::new());

        // Clone scratch for this scan (required for thread safety)
        let mut scan_scratch: *mut vectorscan_rs_sys::hs_scratch_t = ptr::null_mut();
        let result =
            unsafe { vectorscan_rs_sys::hs_clone_scratch(self.scratch, &mut scan_scratch) };

        if result != vectorscan_rs_sys::HS_SUCCESS as i32 {
            return Err(PolicyError::CompileError {
                reason: format!("failed to clone scratch space: code {}", result),
            });
        }

        // Callback that collects pattern IDs
        unsafe extern "C" fn on_match(
            id: std::ffi::c_uint,
            _from: std::ffi::c_ulonglong,
            _to: std::ffi::c_ulonglong,
            _flags: std::ffi::c_uint,
            context: *mut std::ffi::c_void,
        ) -> std::ffi::c_int {
            // Safety: context is a valid pointer to RefCell<Vec<u32>> passed from scan()
            unsafe {
                let matches = &*(context as *const std::cell::RefCell<Vec<u32>>);
                matches.borrow_mut().push(id);
            }
            0 // Continue scanning
        }

        let result = unsafe {
            vectorscan_rs_sys::hs_scan(
                self.db,
                data.as_ptr() as *const std::ffi::c_char,
                data.len() as u32,
                0,
                scan_scratch,
                Some(on_match),
                &matches as *const _ as *mut std::ffi::c_void,
            )
        };

        unsafe {
            vectorscan_rs_sys::hs_free_scratch(scan_scratch);
        }

        if result != vectorscan_rs_sys::HS_SUCCESS as i32
            && result != vectorscan_rs_sys::HS_SCAN_TERMINATED
        {
            return Err(PolicyError::CompileError {
                reason: format!("scan failed with code {}", result),
            });
        }

        Ok(matches.into_inner())
    }
}

impl Drop for VectorscanDatabase {
    fn drop(&mut self) {
        unsafe {
            if !self.scratch.is_null() {
                vectorscan_rs_sys::hs_free_scratch(self.scratch);
            }
            if !self.db.is_null() {
                vectorscan_rs_sys::hs_free_database(self.db);
            }
        }
    }
}

/// A compiled Vectorscan database with its pattern index.
pub struct CompiledDatabase {
    /// The Vectorscan database.
    pub database: VectorscanDatabase,
    /// Maps pattern_id to policy reference.
    pub pattern_index: Vec<PolicyMatchRef>,
}

impl std::fmt::Debug for CompiledDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledDatabase")
            .field("pattern_count", &self.pattern_index.len())
            .finish()
    }
}

/// Compiled matchers ready for evaluation.
#[derive(Debug)]
pub struct CompiledMatchers {
    /// Hyperscan databases keyed by (field, negated).
    pub databases: HashMap<MatchKey, CompiledDatabase>,
    /// Existence checks that can't be compiled to Hyperscan.
    pub existence_checks: Vec<ExistenceCheck>,
    /// Compiled policies indexed by position.
    pub policies: Vec<CompiledPolicy>,
}

impl CompiledMatchers {
    /// Build compiled matchers from a list of policies.
    pub fn build(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let groups = PatternGroups::build(policies)?;
        groups.compile()
    }
}

/// Grouped patterns ready for Hyperscan compilation.
#[derive(Debug, Default)]
pub struct PatternGroups {
    /// Patterns grouped by match key.
    pub groups: HashMap<MatchKey, Vec<PatternInfo>>,
    /// Existence checks that can't be compiled to Hyperscan.
    pub existence_checks: Vec<ExistenceCheck>,
    /// Compiled policies.
    pub policies: Vec<CompiledPolicy>,
}

impl PatternGroups {
    /// Build pattern groups from a list of policies.
    pub fn build(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let mut result = PatternGroups::default();

        for (policy_index, (policy, stats)) in policies.enumerate() {
            let log_target = match policy.log_target() {
                Some(t) => t,
                None => continue, // Skip non-log policies
            };

            // Count only non-negated matchers for required_match_count
            // Negated matchers only disqualify, they don't add to the match count
            let required_match_count = log_target.r#match.iter().filter(|m| !m.negate).count();

            // Compile transform if present
            let transform = log_target
                .transform
                .as_ref()
                .map(CompiledTransform::from_proto)
                .filter(|t| !t.is_empty());

            // Extract sample key if present
            let sample_key = log_target.sample_key.as_ref().and_then(extract_sample_key);

            // Add compiled policy
            result.policies.push(CompiledPolicy {
                id: policy.id().to_string(),
                required_match_count,
                keep: CompiledKeep::parse(&log_target.keep)?,
                transform,
                stats,
                enabled: policy.enabled(),
                sample_key,
            });

            // Process each matcher
            for matcher in &log_target.r#match {
                let field = extract_field(matcher)?;
                let is_negated = matcher.negate;

                let case_insensitive = matcher.case_insensitive;

                match &matcher.r#match {
                    Some(log_matcher::Match::Exact(s)) => {
                        // Convert exact match to anchored regex
                        let pattern = format!("^{}$", regex_escape(s));
                        let key = MatchKey::new(field, is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern,
                            policy_index,
                            case_insensitive,
                        });
                    }
                    Some(log_matcher::Match::Regex(pattern)) => {
                        let key = MatchKey::new(field.clone(), is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern: pattern.clone(),
                            policy_index,
                            case_insensitive,
                        });
                    }
                    Some(log_matcher::Match::Exists(should_exist)) => {
                        result.existence_checks.push(ExistenceCheck {
                            policy_index,
                            field,
                            should_exist: *should_exist,
                            is_negated,
                        });
                    }
                    Some(log_matcher::Match::StartsWith(s)) => {
                        // Convert starts_with to anchored prefix regex
                        let pattern = format!("^{}", regex_escape(s));
                        let key = MatchKey::new(field, is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern,
                            policy_index,
                            case_insensitive,
                        });
                    }
                    Some(log_matcher::Match::EndsWith(s)) => {
                        // Convert ends_with to anchored suffix regex
                        let pattern = format!("{}$", regex_escape(s));
                        let key = MatchKey::new(field, is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern,
                            policy_index,
                            case_insensitive,
                        });
                    }
                    Some(log_matcher::Match::Contains(s)) => {
                        // Contains is just an unanchored literal search
                        let pattern = regex_escape(s);
                        let key = MatchKey::new(field, is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern,
                            policy_index,
                            case_insensitive,
                        });
                    }
                    None => {
                        // No match type specified, skip
                    }
                }
            }
        }

        Ok(result)
    }

    /// Compile pattern groups into Vectorscan databases.
    pub fn compile(self) -> Result<CompiledMatchers, PolicyError> {
        let mut databases = HashMap::new();

        for (key, patterns) in self.groups {
            if patterns.is_empty() {
                continue;
            }

            let mut pattern_strings = Vec::with_capacity(patterns.len());
            let mut pattern_ids = Vec::with_capacity(patterns.len());
            let mut pattern_flags = Vec::with_capacity(patterns.len());
            let mut pattern_index = Vec::with_capacity(patterns.len());

            for (pattern_id, info) in patterns.into_iter().enumerate() {
                pattern_strings.push(info.pattern);
                pattern_ids.push(pattern_id as u32);
                // Apply HS_FLAG_CASELESS for case-insensitive patterns
                let flags = if info.case_insensitive {
                    vectorscan_rs_sys::HS_FLAG_CASELESS
                } else {
                    0
                };
                pattern_flags.push(flags);
                pattern_index.push(PolicyMatchRef {
                    policy_index: info.policy_index,
                });
            }

            let database =
                VectorscanDatabase::compile(&pattern_strings, &pattern_ids, &pattern_flags)?;

            databases.insert(
                key,
                CompiledDatabase {
                    database,
                    pattern_index,
                },
            );
        }

        Ok(CompiledMatchers {
            databases,
            existence_checks: self.existence_checks,
            policies: self.policies,
        })
    }
}

/// Extract the field selector from a log matcher.
fn extract_field(matcher: &LogMatcher) -> Result<LogFieldSelector, PolicyError> {
    match &matcher.field {
        Some(log_matcher::Field::LogField(f)) => {
            let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
            Ok(LogFieldSelector::Simple(field))
        }
        Some(log_matcher::Field::LogAttribute(path)) => {
            Ok(LogFieldSelector::from_log_attribute(path))
        }
        Some(log_matcher::Field::ResourceAttribute(path)) => {
            Ok(LogFieldSelector::from_resource_attribute(path))
        }
        Some(log_matcher::Field::ScopeAttribute(path)) => {
            Ok(LogFieldSelector::from_scope_attribute(path))
        }
        None => Err(PolicyError::FieldError {
            reason: "matcher has no field specified".to_string(),
        }),
    }
}

/// Extract the field selector from a sample key.
fn extract_sample_key(sample_key: &LogSampleKey) -> Option<LogFieldSelector> {
    match &sample_key.field {
        Some(log_sample_key::Field::LogField(f)) => {
            let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
            Some(LogFieldSelector::Simple(field))
        }
        Some(log_sample_key::Field::LogAttribute(path)) => {
            Some(LogFieldSelector::from_log_attribute(path))
        }
        Some(log_sample_key::Field::ResourceAttribute(path)) => {
            Some(LogFieldSelector::from_resource_attribute(path))
        }
        Some(log_sample_key::Field::ScopeAttribute(path)) => {
            Some(LogFieldSelector::from_scope_attribute(path))
        }
        None => None,
    }
}

/// Escape special regex characters in a string.
fn regex_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' => {
                result.push('\\');
                result.push(c);
            }
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::{
        LogAdd, LogRedact, LogTarget, LogTransform, Policy as ProtoPolicy, log_add, log_redact,
    };

    fn make_policy_with_matcher(
        id: &str,
        field: log_matcher::Field,
        match_type: log_matcher::Match,
        negate: bool,
        keep: &str,
    ) -> Policy {
        let matcher = LogMatcher {
            field: Some(field),
            r#match: Some(match_type),
            negate,
            case_insensitive: false,
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: keep.to_string(),
            transform: None,
            sample_key: None,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        Policy::new(proto)
    }

    fn attr_path(key: &str) -> crate::proto::tero::policy::v1::AttributePath {
        crate::proto::tero::policy::v1::AttributePath {
            path: vec![key.to_string()],
        }
    }

    #[test]
    fn build_pattern_groups_regex() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Regex("error.*".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        assert_eq!(groups.policies.len(), 1);
        assert_eq!(groups.policies[0].id, "test");
        assert_eq!(groups.groups.len(), 1);

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern, "error.*");
    }

    #[test]
    fn build_pattern_groups_exact() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            log_matcher::Match::Exact("ERROR".to_string()),
            false,
            "all",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::SeverityText), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert_eq!(patterns[0].pattern, "^ERROR$");
    }

    #[test]
    fn build_pattern_groups_negated() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Regex("debug".to_string()),
            true, // negated
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        // Negated patterns get their own key
        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), true);
        assert!(groups.groups.contains_key(&key));
    }

    #[test]
    fn build_pattern_groups_existence() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogAttribute(attr_path("trace_id")),
            log_matcher::Match::Exists(true),
            false,
            "all",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        // Existence checks go to separate list
        assert!(groups.groups.is_empty());
        assert_eq!(groups.existence_checks.len(), 1);
        assert!(groups.existence_checks[0].should_exist);
    }

    #[test]
    fn regex_escape_special_chars() {
        assert_eq!(regex_escape("hello.world"), "hello\\.world");
        assert_eq!(regex_escape("test*"), "test\\*");
        assert_eq!(regex_escape("a+b"), "a\\+b");
        assert_eq!(regex_escape("(test)"), "\\(test\\)");
        assert_eq!(regex_escape("plain"), "plain");
    }

    #[test]
    fn compile_pattern_groups() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Regex("error".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        assert_eq!(compiled.policies.len(), 1);
        assert_eq!(compiled.databases.len(), 1);

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();
        assert_eq!(db.pattern_index.len(), 1);
        assert_eq!(db.pattern_index[0].policy_index, 0);
    }

    #[test]
    fn compile_policy_without_transform() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Regex("error".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        assert!(compiled.policies[0].transform.is_none());
    }

    #[test]
    fn compile_policy_with_transform() {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Regex("error".to_string())),
            negate: false,
            case_insensitive: false,
        };

        let transform = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path("password"))),
                replacement: "[REDACTED]".to_string(),
            }],
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("processed"))),
                value: "true".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "all".to_string(),
            transform: Some(transform),
            sample_key: None,
        };

        let proto = ProtoPolicy {
            id: "test".to_string(),
            name: "test".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        let policy = Policy::new(proto);
        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let transform = compiled.policies[0].transform.as_ref().unwrap();
        assert_eq!(transform.ops.len(), 2); // redact + add
    }

    #[test]
    fn compile_policy_with_empty_transform() {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Regex("error".to_string())),
            negate: false,
            case_insensitive: false,
        };

        // Empty transform (no operations)
        let transform = LogTransform::default();

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "all".to_string(),
            transform: Some(transform),
            sample_key: None,
        };

        let proto = ProtoPolicy {
            id: "test".to_string(),
            name: "test".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        let policy = Policy::new(proto);
        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        // Empty transforms are filtered out (set to None)
        assert!(compiled.policies[0].transform.is_none());
    }

    // ==================== New Matcher Type Tests ====================

    #[test]
    fn build_pattern_groups_starts_with() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::StartsWith("ERROR:".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        // StartsWith should produce anchored prefix pattern
        assert_eq!(patterns[0].pattern, "^ERROR:");
    }

    #[test]
    fn build_pattern_groups_ends_with() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::EndsWith(".json".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        // EndsWith should produce anchored suffix pattern
        assert_eq!(patterns[0].pattern, "\\.json$");
    }

    #[test]
    fn build_pattern_groups_contains() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Contains("error".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        // Contains should produce unanchored escaped pattern
        assert_eq!(patterns[0].pattern, "error");
    }

    #[test]
    fn build_pattern_groups_contains_special_chars() {
        let policy = make_policy_with_matcher(
            "test",
            log_matcher::Field::LogField(LogField::Body.into()),
            log_matcher::Match::Contains("file.txt".to_string()),
            false,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        // Contains should escape special regex characters
        assert_eq!(patterns[0].pattern, "file\\.txt");
    }

    // ==================== Case-Insensitive Tests ====================

    fn make_policy_with_case_insensitive(
        id: &str,
        match_type: log_matcher::Match,
        case_insensitive: bool,
    ) -> Policy {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(match_type),
            negate: false,
            case_insensitive,
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "none".to_string(),
            transform: None,
            sample_key: None,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        Policy::new(proto)
    }

    #[test]
    fn build_pattern_groups_case_insensitive_flag() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Exact("ERROR".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert!(patterns[0].case_insensitive);
    }

    #[test]
    fn build_pattern_groups_case_sensitive_flag() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Exact("ERROR".to_string()),
            false,
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert!(!patterns[0].case_insensitive);
    }

    #[test]
    fn compile_case_insensitive_patterns() {
        // This test verifies that case-insensitive patterns compile successfully
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Regex("error".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        // If compilation succeeded, the case-insensitive flag was applied correctly
        assert_eq!(compiled.policies.len(), 1);
        assert_eq!(compiled.databases.len(), 1);
    }

    #[test]
    fn case_insensitive_exact_match_compiles() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Exact("Error".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        // Test that it matches case-insensitively
        let matches = db.database.scan(b"error").unwrap();
        assert!(!matches.is_empty(), "Should match 'error' (lowercase)");

        let matches = db.database.scan(b"ERROR").unwrap();
        assert!(!matches.is_empty(), "Should match 'ERROR' (uppercase)");

        let matches = db.database.scan(b"Error").unwrap();
        assert!(!matches.is_empty(), "Should match 'Error' (mixed case)");

        let matches = db.database.scan(b"warning").unwrap();
        assert!(matches.is_empty(), "Should not match 'warning'");
    }

    #[test]
    fn case_sensitive_exact_match_compiles() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Exact("Error".to_string()),
            false, // case-sensitive
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        // Test that it matches case-sensitively only
        let matches = db.database.scan(b"Error").unwrap();
        assert!(!matches.is_empty(), "Should match 'Error' (exact case)");

        let matches = db.database.scan(b"error").unwrap();
        assert!(matches.is_empty(), "Should NOT match 'error' (wrong case)");

        let matches = db.database.scan(b"ERROR").unwrap();
        assert!(matches.is_empty(), "Should NOT match 'ERROR' (wrong case)");
    }

    #[test]
    fn case_insensitive_contains_match() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Contains("error".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        let matches = db.database.scan(b"This is an ERROR message").unwrap();
        assert!(!matches.is_empty(), "Should match ERROR in message");

        let matches = db.database.scan(b"This is an Error message").unwrap();
        assert!(!matches.is_empty(), "Should match Error in message");
    }

    #[test]
    fn case_insensitive_starts_with_match() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::StartsWith("error".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        let matches = db.database.scan(b"ERROR: something went wrong").unwrap();
        assert!(!matches.is_empty(), "Should match ERROR at start");

        let matches = db.database.scan(b"Error: something went wrong").unwrap();
        assert!(!matches.is_empty(), "Should match Error at start");

        let matches = db.database.scan(b"Something ERROR happened").unwrap();
        assert!(matches.is_empty(), "Should NOT match ERROR in middle");
    }

    #[test]
    fn case_insensitive_ends_with_match() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::EndsWith(".json".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        let matches = db.database.scan(b"config.JSON").unwrap();
        assert!(!matches.is_empty(), "Should match .JSON at end");

        let matches = db.database.scan(b"config.Json").unwrap();
        assert!(!matches.is_empty(), "Should match .Json at end");

        let matches = db.database.scan(b"config.json.bak").unwrap();
        assert!(matches.is_empty(), "Should NOT match .json in middle");
    }
}
