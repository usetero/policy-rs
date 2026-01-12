//! Compiled policy structures for efficient evaluation.

use std::collections::HashMap;
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;

use crate::Policy;
use crate::error::PolicyError;
use crate::field::LogFieldSelector;
use crate::proto::tero::policy::v1::{LogField, LogMatcher, log_matcher};
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
    fn compile(patterns: &[String], ids: &[u32]) -> Result<Self, PolicyError> {
        assert_eq!(patterns.len(), ids.len());

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

        // All patterns use default flags (0)
        let flags: Vec<u32> = vec![0; patterns.len()];

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

            // Add compiled policy
            result.policies.push(CompiledPolicy {
                id: policy.id().to_string(),
                required_match_count,
                keep: CompiledKeep::parse(&log_target.keep)?,
                transform,
                stats,
                enabled: policy.enabled(),
            });

            // Process each matcher
            for matcher in &log_target.r#match {
                let field = extract_field(matcher)?;
                let is_negated = matcher.negate;

                match &matcher.r#match {
                    Some(log_matcher::Match::Exact(s)) => {
                        // Convert exact match to anchored regex
                        let pattern = format!("^{}$", regex_escape(s));
                        let key = MatchKey::new(field, is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern,
                            policy_index,
                        });
                    }
                    Some(log_matcher::Match::Regex(pattern)) => {
                        let key = MatchKey::new(field.clone(), is_negated);

                        result.groups.entry(key).or_default().push(PatternInfo {
                            pattern: pattern.clone(),
                            policy_index,
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
            let mut pattern_index = Vec::with_capacity(patterns.len());

            for (pattern_id, info) in patterns.into_iter().enumerate() {
                pattern_strings.push(info.pattern);
                pattern_ids.push(pattern_id as u32);
                pattern_index.push(PolicyMatchRef {
                    policy_index: info.policy_index,
                });
            }

            let database = VectorscanDatabase::compile(&pattern_strings, &pattern_ids)?;

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
        Some(log_matcher::Field::LogAttribute(key)) => {
            Ok(LogFieldSelector::LogAttribute(key.clone()))
        }
        Some(log_matcher::Field::ResourceAttribute(key)) => {
            Ok(LogFieldSelector::ResourceAttribute(key.clone()))
        }
        Some(log_matcher::Field::ScopeAttribute(key)) => {
            Ok(LogFieldSelector::ScopeAttribute(key.clone()))
        }
        None => Err(PolicyError::FieldError {
            reason: "matcher has no field specified".to_string(),
        }),
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
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: keep.to_string(),
            transform: None,
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
            log_matcher::Field::LogAttribute("trace_id".to_string()),
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
        };

        let transform = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute("password".to_string())),
                replacement: "[REDACTED]".to_string(),
            }],
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute("processed".to_string())),
                value: "true".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "all".to_string(),
            transform: Some(transform),
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
        };

        // Empty transform (no operations)
        let transform = LogTransform::default();

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "all".to_string(),
            transform: Some(transform),
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
}
