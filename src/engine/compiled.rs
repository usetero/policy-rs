//! Compiled policy structures for efficient evaluation.

use std::collections::HashMap;
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;

use crate::Policy;
use crate::error::PolicyError;
use crate::field::{LogFieldSelector, MetricFieldSelector, TraceFieldSelector};
use crate::proto::tero::policy::v1::{
    AggregationTemporality, LogField, LogMatcher, LogSampleKey, MetricField, MetricMatcher,
    MetricType, NumericValue, SamplingMode, SpanKind, SpanStatusCode, TraceField, TraceMatcher,
    TraceSamplingConfig, Value, log_matcher, log_sample_key, metric_matcher, numeric_value,
    trace_matcher, value,
};
use crate::registry::PolicyStats;

use super::keep::CompiledKeep;
use super::match_key::MatchKey;
use super::signal::{LogSignal, MetricSignal, Signal, TraceSignal};
use super::transform::CompiledTransform;

/// Reference from a pattern match back to its policy.
#[derive(Debug, Clone)]
pub struct PolicyMatchRef {
    /// Index into CompiledMatchers::policies.
    pub policy_index: usize,
}

/// The compiled sampling mode for trace evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSamplingMode {
    /// Hash trace ID with seed for deterministic sampling.
    HashSeed,
    /// Adjust threshold relative to incoming probability (tracestate `th`).
    Proportional,
    /// Equalize sampling across sources with different incoming probabilities.
    Equalizing,
}

/// Compiled trace sampling configuration.
///
/// Stores precomputed values from `TraceSamplingConfig` for efficient
/// evaluation using the OTel consistent probability sampling algorithm.
#[derive(Debug, Clone)]
pub struct CompiledTraceSampling {
    /// Precomputed 56-bit rejection threshold.
    pub threshold: u64,
    /// Original probability (0.0-1.0) for result reporting.
    pub probability: f64,
    /// Number of hex digits for threshold encoding (1-14, default 4).
    pub precision: u32,
    /// If true, reject spans when randomness extraction fails.
    pub fail_closed: bool,
    /// Sampling mode.
    pub mode: CompiledSamplingMode,
    /// Hash seed for HASH_SEED mode (combined with trace ID for deterministic sampling).
    pub hash_seed: u32,
}

/// A compiled policy ready for evaluation.
#[derive(Debug)]
pub struct CompiledPolicy<S: Signal> {
    /// Policy ID.
    pub id: String,
    /// Number of matchers that must match for this policy to apply.
    pub required_match_count: usize,
    /// The keep action for this policy.
    pub keep: CompiledKeep,
    /// The transform to apply when this policy matches (if any).
    pub transform: Option<CompiledTransform<S>>,
    /// Statistics for this policy.
    pub stats: Arc<PolicyStats>,
    /// Whether this policy is enabled.
    pub enabled: bool,
    /// Optional sample key for consistent hash-based sampling.
    pub sample_key: Option<S::FieldSelector>,
    /// Trace sampling configuration (only set for trace policies).
    pub trace_sampling: Option<CompiledTraceSampling>,
}

/// Existence check that can't be handled by Vectorscan.
#[derive(Debug, Clone)]
pub struct ExistenceCheck<S: Signal> {
    /// Index into CompiledMatchers::policies.
    pub policy_index: usize,
    /// The field to check.
    pub field: S::FieldSelector,
    /// Whether the field should exist.
    pub should_exist: bool,
    /// Whether this is a negated matcher.
    pub is_negated: bool,
}

/// A compiled non-string typed value for the `equals` matcher.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledValue {
    Bool(bool),
    Int(i64),
    Double(f64),
    /// Raw bytes — `hex_value` is decoded to bytes at compile time.
    Bytes(Vec<u8>),
}

/// A compiled numeric value for `gt`/`gte`/`lt`/`lte` matchers.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledNumericValue {
    Int(i64),
    Double(f64),
}

/// A compiled typed matcher (equals / numeric comparison).
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledTypedMatcher {
    Equals(CompiledValue),
    Gt(CompiledNumericValue),
    Gte(CompiledNumericValue),
    Lt(CompiledNumericValue),
    Lte(CompiledNumericValue),
}

impl CompiledTypedMatcher {
    /// Evaluate this typed matcher against a typed field value.
    ///
    /// Returns `true` when the matcher fires (before applying `negate`).
    pub fn evaluate(&self, field_value: Option<TypedValue<'_>>) -> bool {
        let Some(fv) = field_value else {
            return false;
        };
        match self {
            CompiledTypedMatcher::Equals(expected) => match (expected, &fv) {
                (CompiledValue::Bool(e), TypedValue::Bool(a)) => e == a,
                // Numeric domain: int == int, double == double, cross-type promoted to double
                (CompiledValue::Int(e), TypedValue::Int(a)) => e == a,
                (CompiledValue::Double(e), TypedValue::Double(a)) => e == a,
                (CompiledValue::Int(e), TypedValue::Double(a)) => (*e as f64) == *a,
                (CompiledValue::Double(e), TypedValue::Int(a)) => *e == (*a as f64),
                (CompiledValue::Bytes(e), TypedValue::Bytes(a)) => e.as_slice() == *a,
                _ => false,
            },
            CompiledTypedMatcher::Gt(threshold) => compare_numeric(fv, threshold, |a, t| a > t),
            CompiledTypedMatcher::Gte(threshold) => compare_numeric(fv, threshold, |a, t| a >= t),
            CompiledTypedMatcher::Lt(threshold) => compare_numeric(fv, threshold, |a, t| a < t),
            CompiledTypedMatcher::Lte(threshold) => compare_numeric(fv, threshold, |a, t| a <= t),
        }
    }
}

/// Perform a numeric comparison between a field value and a compiled threshold.
fn compare_numeric<F: Fn(f64, f64) -> bool>(
    fv: TypedValue<'_>,
    threshold: &CompiledNumericValue,
    cmp: F,
) -> bool {
    let field_f64 = match fv {
        TypedValue::Int(i) => i as f64,
        TypedValue::Double(d) => d,
        _ => return false,
    };
    let threshold_f64 = match threshold {
        CompiledNumericValue::Int(i) => *i as f64,
        CompiledNumericValue::Double(d) => *d,
    };
    cmp(field_f64, threshold_f64)
}

/// Typed check for non-string matchers (equals, gt, gte, lt, lte).
#[derive(Debug, Clone)]
pub struct TypedCheck<S: Signal> {
    /// Index into CompiledMatchers::policies.
    pub policy_index: usize,
    /// The field to read.
    pub field: S::FieldSelector,
    /// The compiled matcher.
    pub matcher: CompiledTypedMatcher,
    /// Whether this is a negated matcher.
    pub is_negated: bool,
}

/// A typed field value returned by `Matchable::get_typed_value`.
#[derive(Debug, Clone)]
pub enum TypedValue<'a> {
    String(std::borrow::Cow<'a, str>),
    Bool(bool),
    Int(i64),
    Double(f64),
    Bytes(&'a [u8]),
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
    fn compile(patterns: &[String], ids: &[u32], flags: &[u32]) -> Result<Self, PolicyError> {
        assert_eq!(patterns.len(), ids.len());
        assert_eq!(patterns.len(), flags.len());

        if patterns.is_empty() {
            return Err(PolicyError::CompileError {
                reason: "no patterns to compile".to_string(),
            });
        }

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

    /// Scan data and return the pattern IDs that matched.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<u32>, PolicyError> {
        let matches = std::cell::RefCell::new(Vec::new());

        let mut scan_scratch: *mut vectorscan_rs_sys::hs_scratch_t = ptr::null_mut();
        let result =
            unsafe { vectorscan_rs_sys::hs_clone_scratch(self.scratch, &mut scan_scratch) };

        if result != vectorscan_rs_sys::HS_SUCCESS as i32 {
            return Err(PolicyError::CompileError {
                reason: format!("failed to clone scratch space: code {}", result),
            });
        }

        unsafe extern "C" fn on_match(
            id: std::ffi::c_uint,
            _from: std::ffi::c_ulonglong,
            _to: std::ffi::c_ulonglong,
            _flags: std::ffi::c_uint,
            context: *mut std::ffi::c_void,
        ) -> std::ffi::c_int {
            unsafe {
                let matches = &*(context as *const std::cell::RefCell<Vec<u32>>);
                matches.borrow_mut().push(id);
            }
            0
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
pub struct CompiledMatchers<S: Signal> {
    /// Hyperscan databases keyed by (field, negated).
    pub databases: HashMap<MatchKey<S>, CompiledDatabase>,
    /// Existence checks that can't be compiled to Hyperscan.
    pub existence_checks: Vec<ExistenceCheck<S>>,
    /// Typed matchers (equals, gt, gte, lt, lte) evaluated directly.
    pub typed_checks: Vec<TypedCheck<S>>,
    /// Compiled policies indexed by position.
    pub policies: Vec<CompiledPolicy<S>>,
}

impl CompiledMatchers<LogSignal> {
    /// Build compiled matchers from a list of log policies.
    pub fn build(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let groups = PatternGroups::<LogSignal>::build_from_log_policies(policies)?;
        groups.compile()
    }
}

impl CompiledMatchers<MetricSignal> {
    /// Build compiled matchers from a list of metric policies.
    pub fn build(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let groups = PatternGroups::<MetricSignal>::build_from_metric_policies(policies)?;
        groups.compile()
    }
}

impl CompiledMatchers<TraceSignal> {
    /// Build compiled matchers from a list of trace policies.
    pub fn build(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let groups = PatternGroups::<TraceSignal>::build_from_trace_policies(policies)?;
        groups.compile()
    }
}

/// Grouped patterns ready for Hyperscan compilation.
#[derive(Debug)]
pub struct PatternGroups<S: Signal> {
    /// Patterns grouped by match key.
    pub groups: HashMap<MatchKey<S>, Vec<PatternInfo>>,
    /// Existence checks that can't be compiled to Hyperscan.
    pub existence_checks: Vec<ExistenceCheck<S>>,
    /// Typed matchers (equals, gt, gte, lt, lte).
    pub typed_checks: Vec<TypedCheck<S>>,
    /// Compiled policies.
    pub policies: Vec<CompiledPolicy<S>>,
}

impl<S: Signal> Default for PatternGroups<S> {
    fn default() -> Self {
        Self {
            groups: HashMap::new(),
            existence_checks: Vec::new(),
            typed_checks: Vec::new(),
            policies: Vec::new(),
        }
    }
}

impl PatternGroups<LogSignal> {
    /// Build pattern groups from a list of log policies.
    pub fn build_from_log_policies(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let mut result = PatternGroups::default();

        for (policy_index, (policy, stats)) in policies.enumerate() {
            let log_target = match policy.log_target() {
                Some(t) => t,
                None => continue,
            };

            if log_target.r#match.is_empty() {
                return Err(PolicyError::InvalidPolicy {
                    policy_id: policy.id().to_string(),
                    reason: "log target must have at least one matcher".to_string(),
                });
            }

            let required_match_count = log_target.r#match.iter().filter(|m| !m.negate).count();

            let transform = log_target
                .transform
                .as_ref()
                .map(|t| CompiledTransform::from_proto(t, policy.id()))
                .transpose()?
                .filter(|t| !t.is_empty());

            let sample_key = log_target
                .sample_key
                .as_ref()
                .and_then(extract_log_sample_key);

            result.policies.push(CompiledPolicy {
                id: policy.id().to_string(),
                required_match_count,
                keep: CompiledKeep::parse(&log_target.keep)?,
                transform,
                stats,
                enabled: policy.enabled(),
                sample_key,
                trace_sampling: None,
            });

            for matcher in &log_target.r#match {
                let field = extract_log_field(matcher)?;
                let is_negated = matcher.negate;
                let case_insensitive = matcher.case_insensitive;

                process_match_type(
                    matcher.r#match.as_ref(),
                    field,
                    is_negated,
                    case_insensitive,
                    policy_index,
                    &mut result.groups,
                    &mut result.existence_checks,
                    &mut result.typed_checks,
                );
            }
        }

        Ok(result)
    }
}

impl PatternGroups<MetricSignal> {
    /// Build pattern groups from a list of metric policies.
    pub fn build_from_metric_policies(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let mut result = PatternGroups::default();

        for (policy_index, (policy, stats)) in policies.enumerate() {
            let metric_target = match policy.metric_target() {
                Some(t) => t,
                None => continue,
            };

            if metric_target.r#match.is_empty() {
                return Err(PolicyError::InvalidPolicy {
                    policy_id: policy.id().to_string(),
                    reason: "metric target must have at least one matcher".to_string(),
                });
            }

            let required_match_count = metric_target.r#match.iter().filter(|m| !m.negate).count();

            let keep = if metric_target.keep {
                CompiledKeep::All
            } else {
                CompiledKeep::None
            };

            result.policies.push(CompiledPolicy {
                id: policy.id().to_string(),
                required_match_count,
                keep,
                transform: None,
                stats,
                enabled: policy.enabled(),
                sample_key: None,
                trace_sampling: None,
            });

            for matcher in &metric_target.r#match {
                let is_negated = matcher.negate;
                let case_insensitive = matcher.case_insensitive;

                let extraction = extract_metric_field(matcher)?;

                // Use synthesized match for enum fields, otherwise use the matcher's match.
                let match_type = extraction
                    .synthesized_match
                    .as_ref()
                    .or(matcher.r#match.as_ref());

                process_match_type(
                    match_type,
                    extraction.field,
                    is_negated,
                    case_insensitive,
                    policy_index,
                    &mut result.groups,
                    &mut result.existence_checks,
                    &mut result.typed_checks,
                );
            }
        }

        Ok(result)
    }
}

impl PatternGroups<TraceSignal> {
    /// Build pattern groups from a list of trace policies.
    pub fn build_from_trace_policies(
        policies: impl Iterator<Item = (Policy, Arc<PolicyStats>)>,
    ) -> Result<Self, PolicyError> {
        let mut result = PatternGroups::default();

        for (policy_index, (policy, stats)) in policies.enumerate() {
            let trace_target = match policy.trace_target() {
                Some(t) => t,
                None => continue,
            };

            if trace_target.r#match.is_empty() {
                return Err(PolicyError::InvalidPolicy {
                    policy_id: policy.id().to_string(),
                    reason: "trace target must have at least one matcher".to_string(),
                });
            }

            let required_match_count = trace_target.r#match.iter().filter(|m| !m.negate).count();

            let keep = compile_trace_keep(trace_target.keep.as_ref());
            let trace_sampling = compile_trace_sampling(trace_target.keep.as_ref());

            result.policies.push(CompiledPolicy {
                id: policy.id().to_string(),
                required_match_count,
                keep,
                transform: None,
                stats,
                enabled: policy.enabled(),
                sample_key: None,
                trace_sampling: Some(trace_sampling),
            });

            for matcher in &trace_target.r#match {
                let is_negated = matcher.negate;
                let case_insensitive = matcher.case_insensitive;

                let extraction = extract_trace_field(matcher)?;

                let match_type = extraction
                    .synthesized_match
                    .as_ref()
                    .or(matcher.r#match.as_ref());

                process_match_type(
                    match_type,
                    extraction.field,
                    is_negated,
                    case_insensitive,
                    policy_index,
                    &mut result.groups,
                    &mut result.existence_checks,
                    &mut result.typed_checks,
                );
            }
        }

        Ok(result)
    }
}

impl<S: Signal> PatternGroups<S> {
    /// Compile pattern groups into Vectorscan databases.
    pub fn compile(self) -> Result<CompiledMatchers<S>, PolicyError> {
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
                let mut flags = vectorscan_rs_sys::HS_FLAG_SINGLEMATCH;
                if info.case_insensitive {
                    flags |= vectorscan_rs_sys::HS_FLAG_CASELESS;
                }
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
            typed_checks: self.typed_checks,
            policies: self.policies,
        })
    }
}

// =============================================================================
// Shared match type processing
// =============================================================================

/// Process a match type and add the pattern, existence check, or typed check.
///
/// This is shared across log, metric, and trace matchers since the match oneof
/// is structurally identical across signal types.
#[allow(clippy::too_many_arguments)]
fn process_match_type<S: Signal, M>(
    match_type: Option<&M>,
    field: S::FieldSelector,
    is_negated: bool,
    case_insensitive: bool,
    policy_index: usize,
    groups: &mut HashMap<MatchKey<S>, Vec<PatternInfo>>,
    existence_checks: &mut Vec<ExistenceCheck<S>>,
    typed_checks: &mut Vec<TypedCheck<S>>,
) where
    M: MatchTypeAccessor,
{
    let Some(m) = match_type else { return };

    match m.as_match_variant() {
        MatchVariant::Exact(s) => {
            let pattern = format!("^{}$", regex_escape(s));
            let key = MatchKey::new(field, is_negated);
            groups.entry(key).or_default().push(PatternInfo {
                pattern,
                policy_index,
                case_insensitive,
            });
        }
        MatchVariant::Regex(pattern) => {
            let key = MatchKey::new(field, is_negated);
            groups.entry(key).or_default().push(PatternInfo {
                pattern: pattern.to_string(),
                policy_index,
                case_insensitive,
            });
        }
        MatchVariant::Exists(should_exist) => {
            existence_checks.push(ExistenceCheck {
                policy_index,
                field,
                should_exist,
                is_negated,
            });
        }
        MatchVariant::StartsWith(s) => {
            let pattern = format!("^{}", regex_escape(s));
            let key = MatchKey::new(field, is_negated);
            groups.entry(key).or_default().push(PatternInfo {
                pattern,
                policy_index,
                case_insensitive,
            });
        }
        MatchVariant::EndsWith(s) => {
            let pattern = format!("{}$", regex_escape(s));
            let key = MatchKey::new(field, is_negated);
            groups.entry(key).or_default().push(PatternInfo {
                pattern,
                policy_index,
                case_insensitive,
            });
        }
        MatchVariant::Contains(s) => {
            let pattern = regex_escape(s);
            let key = MatchKey::new(field, is_negated);
            groups.entry(key).or_default().push(PatternInfo {
                pattern,
                policy_index,
                case_insensitive,
            });
        }
        MatchVariant::Typed(matcher) => {
            typed_checks.push(TypedCheck {
                policy_index,
                field,
                matcher,
                is_negated,
            });
        }
    }
}

/// Unified view of match variants across signal-specific match oneofs.
enum MatchVariant<'a> {
    Exact(&'a str),
    Regex(&'a str),
    Exists(bool),
    StartsWith(&'a str),
    EndsWith(&'a str),
    Contains(&'a str),
    /// Typed matcher (equals/gt/gte/lt/lte) — bypasses Vectorscan.
    Typed(CompiledTypedMatcher),
}

/// Trait for converting signal-specific match oneofs to MatchVariant.
trait MatchTypeAccessor {
    fn as_match_variant(&self) -> MatchVariant<'_>;
}

/// Compile a proto `Value` to a `CompiledValue`, returning `None` on error.
fn compile_value(v: &Value) -> Option<CompiledValue> {
    match &v.value {
        Some(value::Value::BoolValue(b)) => Some(CompiledValue::Bool(*b)),
        Some(value::Value::IntValue(i)) => Some(CompiledValue::Int(*i)),
        Some(value::Value::DoubleValue(d)) => Some(CompiledValue::Double(*d)),
        Some(value::Value::BytesValue(b)) => Some(CompiledValue::Bytes(b.clone())),
        Some(value::Value::HexValue(h)) => {
            // Decode hex string to bytes at compile time.
            hex_decode(h).map(CompiledValue::Bytes)
        }
        None => None,
    }
}

/// Compile a proto `NumericValue` to a `CompiledNumericValue`.
fn compile_numeric(v: &NumericValue) -> Option<CompiledNumericValue> {
    match &v.value {
        Some(numeric_value::Value::IntValue(i)) => Some(CompiledNumericValue::Int(*i)),
        Some(numeric_value::Value::DoubleValue(d)) => Some(CompiledNumericValue::Double(*d)),
        None => None,
    }
}

/// Decode a lowercase-hex string to bytes. Returns `None` on invalid input.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

impl MatchTypeAccessor for log_matcher::Match {
    fn as_match_variant(&self) -> MatchVariant<'_> {
        match self {
            log_matcher::Match::Exact(s) => MatchVariant::Exact(s),
            log_matcher::Match::Regex(s) => MatchVariant::Regex(s),
            log_matcher::Match::Exists(b) => MatchVariant::Exists(*b),
            log_matcher::Match::StartsWith(s) => MatchVariant::StartsWith(s),
            log_matcher::Match::EndsWith(s) => MatchVariant::EndsWith(s),
            log_matcher::Match::Contains(s) => MatchVariant::Contains(s),
            log_matcher::Match::Equals(v) => compile_value(v)
                .map(|cv| MatchVariant::Typed(CompiledTypedMatcher::Equals(cv)))
                .unwrap_or(MatchVariant::Exists(false)), // invalid value → never match
            log_matcher::Match::Gt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            log_matcher::Match::Gte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            log_matcher::Match::Lt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            log_matcher::Match::Lte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
        }
    }
}

impl MatchTypeAccessor for metric_matcher::Match {
    fn as_match_variant(&self) -> MatchVariant<'_> {
        match self {
            metric_matcher::Match::Exact(s) => MatchVariant::Exact(s),
            metric_matcher::Match::Regex(s) => MatchVariant::Regex(s),
            metric_matcher::Match::Exists(b) => MatchVariant::Exists(*b),
            metric_matcher::Match::StartsWith(s) => MatchVariant::StartsWith(s),
            metric_matcher::Match::EndsWith(s) => MatchVariant::EndsWith(s),
            metric_matcher::Match::Contains(s) => MatchVariant::Contains(s),
            metric_matcher::Match::Equals(v) => compile_value(v)
                .map(|cv| MatchVariant::Typed(CompiledTypedMatcher::Equals(cv)))
                .unwrap_or(MatchVariant::Exists(false)),
            metric_matcher::Match::Gt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            metric_matcher::Match::Gte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            metric_matcher::Match::Lt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            metric_matcher::Match::Lte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
        }
    }
}

impl MatchTypeAccessor for trace_matcher::Match {
    fn as_match_variant(&self) -> MatchVariant<'_> {
        match self {
            trace_matcher::Match::Exact(s) => MatchVariant::Exact(s),
            trace_matcher::Match::Regex(s) => MatchVariant::Regex(s),
            trace_matcher::Match::Exists(b) => MatchVariant::Exists(*b),
            trace_matcher::Match::StartsWith(s) => MatchVariant::StartsWith(s),
            trace_matcher::Match::EndsWith(s) => MatchVariant::EndsWith(s),
            trace_matcher::Match::Contains(s) => MatchVariant::Contains(s),
            trace_matcher::Match::Equals(v) => compile_value(v)
                .map(|cv| MatchVariant::Typed(CompiledTypedMatcher::Equals(cv)))
                .unwrap_or(MatchVariant::Exists(false)),
            trace_matcher::Match::Gt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            trace_matcher::Match::Gte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Gte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            trace_matcher::Match::Lt(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lt(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
            trace_matcher::Match::Lte(v) => compile_numeric(v)
                .map(|cn| MatchVariant::Typed(CompiledTypedMatcher::Lte(cn)))
                .unwrap_or(MatchVariant::Exists(false)),
        }
    }
}

// =============================================================================
// Log-specific field extraction
// =============================================================================

/// Extract the field selector from a log matcher.
fn extract_log_field(matcher: &LogMatcher) -> Result<LogFieldSelector, PolicyError> {
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

/// Extract the field selector from a log sample key.
fn extract_log_sample_key(sample_key: &LogSampleKey) -> Option<LogFieldSelector> {
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

// =============================================================================
// Metric-specific field extraction
// =============================================================================

/// Extracted metric field info.
///
/// For enum fields (metric_type, aggregation_temporality), the field itself
/// carries the enum value. We extract a unit field selector (`Type` or
/// `Temporality`) and synthesize an exact-match pattern on the enum's
/// string name. This lets all metric_type matchers share a single Vectorscan
/// database key.
struct MetricFieldExtraction {
    field: MetricFieldSelector,
    /// If set, overrides the matcher's match oneof with a synthesized exact match.
    synthesized_match: Option<metric_matcher::Match>,
}

fn extract_metric_field(matcher: &MetricMatcher) -> Result<MetricFieldExtraction, PolicyError> {
    match &matcher.field {
        Some(metric_matcher::Field::MetricField(f)) => {
            let field = MetricField::try_from(*f).unwrap_or(MetricField::Unspecified);
            Ok(MetricFieldExtraction {
                field: MetricFieldSelector::Simple(field),
                synthesized_match: None,
            })
        }
        Some(metric_matcher::Field::DatapointAttribute(path)) => Ok(MetricFieldExtraction {
            field: MetricFieldSelector::from_datapoint_attribute(path),
            synthesized_match: None,
        }),
        Some(metric_matcher::Field::ResourceAttribute(path)) => Ok(MetricFieldExtraction {
            field: MetricFieldSelector::from_resource_attribute(path),
            synthesized_match: None,
        }),
        Some(metric_matcher::Field::ScopeAttribute(path)) => Ok(MetricFieldExtraction {
            field: MetricFieldSelector::from_scope_attribute(path),
            synthesized_match: None,
        }),
        Some(metric_matcher::Field::MetricType(t)) => {
            let metric_type = MetricType::try_from(*t).unwrap_or(MetricType::Unspecified);
            Ok(MetricFieldExtraction {
                field: MetricFieldSelector::Type,
                synthesized_match: Some(metric_matcher::Match::Exact(
                    metric_type.as_str_name().to_string(),
                )),
            })
        }
        Some(metric_matcher::Field::AggregationTemporality(t)) => {
            let temporality =
                AggregationTemporality::try_from(*t).unwrap_or(AggregationTemporality::Unspecified);
            Ok(MetricFieldExtraction {
                field: MetricFieldSelector::Temporality,
                synthesized_match: Some(metric_matcher::Match::Exact(
                    temporality.as_str_name().to_string(),
                )),
            })
        }
        None => Err(PolicyError::FieldError {
            reason: "matcher has no field specified".to_string(),
        }),
    }
}

// =============================================================================
// Trace-specific field extraction and compilation
// =============================================================================

/// Extracted trace field info.
///
/// For enum fields (span_kind, span_status) and string-value fields
/// (event_name, link_trace_id), the extraction produces a unit field selector
/// and a synthesized exact-match pattern on the value's string representation.
struct TraceFieldExtraction {
    field: TraceFieldSelector,
    synthesized_match: Option<trace_matcher::Match>,
}

fn extract_trace_field(matcher: &TraceMatcher) -> Result<TraceFieldExtraction, PolicyError> {
    match &matcher.field {
        Some(trace_matcher::Field::TraceField(f)) => {
            let field = TraceField::try_from(*f).unwrap_or(TraceField::Unspecified);
            Ok(TraceFieldExtraction {
                field: TraceFieldSelector::Simple(field),
                synthesized_match: None,
            })
        }
        Some(trace_matcher::Field::SpanAttribute(path)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::from_span_attribute(path),
            synthesized_match: None,
        }),
        Some(trace_matcher::Field::ResourceAttribute(path)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::from_resource_attribute(path),
            synthesized_match: None,
        }),
        Some(trace_matcher::Field::ScopeAttribute(path)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::from_scope_attribute(path),
            synthesized_match: None,
        }),
        Some(trace_matcher::Field::SpanKind(k)) => {
            let kind = SpanKind::try_from(*k).unwrap_or(SpanKind::Unspecified);
            Ok(TraceFieldExtraction {
                field: TraceFieldSelector::SpanKind,
                synthesized_match: Some(trace_matcher::Match::Exact(
                    kind.as_str_name().to_string(),
                )),
            })
        }
        Some(trace_matcher::Field::SpanStatus(s)) => {
            let status = SpanStatusCode::try_from(*s).unwrap_or(SpanStatusCode::Unspecified);
            Ok(TraceFieldExtraction {
                field: TraceFieldSelector::SpanStatus,
                synthesized_match: Some(trace_matcher::Match::Exact(
                    status.as_str_name().to_string(),
                )),
            })
        }
        Some(trace_matcher::Field::EventName(name)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::EventName,
            synthesized_match: Some(trace_matcher::Match::Exact(name.clone())),
        }),
        Some(trace_matcher::Field::EventAttribute(path)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::from_event_attribute(path),
            synthesized_match: None,
        }),
        Some(trace_matcher::Field::LinkTraceId(id)) => Ok(TraceFieldExtraction {
            field: TraceFieldSelector::LinkTraceId,
            synthesized_match: Some(trace_matcher::Match::Exact(id.clone())),
        }),
        None => Err(PolicyError::FieldError {
            reason: "matcher has no field specified".to_string(),
        }),
    }
}

/// Compile trace keep from sampling config.
///
/// Maps `TraceSamplingConfig` percentage to a `CompiledKeep` variant for the
/// standard keep/drop evaluation path.
fn compile_trace_keep(config: Option<&TraceSamplingConfig>) -> CompiledKeep {
    match config {
        None => CompiledKeep::All,
        Some(c) if c.percentage >= 100.0 => CompiledKeep::All,
        Some(c) if c.percentage <= 0.0 => CompiledKeep::None,
        Some(c) => CompiledKeep::Percentage(c.percentage as f64 / 100.0),
    }
}

/// Compile trace sampling metadata from sampling config.
///
/// Produces a `CompiledTraceSampling` with precomputed 56-bit rejection
/// threshold and encoding parameters for tracestate propagation.
fn compile_trace_sampling(config: Option<&TraceSamplingConfig>) -> CompiledTraceSampling {
    match config {
        None => CompiledTraceSampling {
            threshold: 0,
            probability: 1.0,
            precision: 4,
            fail_closed: true,
            mode: CompiledSamplingMode::HashSeed,
            hash_seed: 0,
        },
        Some(c) => {
            let probability = (c.percentage as f64 / 100.0).clamp(0.0, 1.0);
            let precision = c.sampling_precision.unwrap_or(4).clamp(1, 14);
            let mode = match c.mode.and_then(|m| SamplingMode::try_from(m).ok()) {
                Some(SamplingMode::Proportional) => CompiledSamplingMode::Proportional,
                Some(SamplingMode::Equalizing) => CompiledSamplingMode::Equalizing,
                // HashSeed, Unspecified, or None all default to HashSeed
                _ => CompiledSamplingMode::HashSeed,
            };
            CompiledTraceSampling {
                threshold: super::rejection_threshold(probability),
                probability,
                precision,
                fail_closed: c.fail_closed.unwrap_or(true),
                mode,
                hash_seed: c.hash_seed.unwrap_or(0),
            }
        }
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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

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
            true,
            "none",
        );

        let stats = Arc::new(PolicyStats::default());
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

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
                regex: None,
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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

        let transform = compiled.policies[0].transform.as_ref().unwrap();
        assert_eq!(transform.ops.len(), 2);
    }

    #[test]
    fn compile_policy_with_empty_transform() {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Regex("error".to_string())),
            negate: false,
            case_insensitive: false,
        };

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

        assert!(compiled.policies[0].transform.is_none());
    }

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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert_eq!(patterns[0].pattern, "file\\.txt");
    }

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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

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
        let groups = PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let patterns = groups.groups.get(&key).unwrap();
        assert!(!patterns[0].case_insensitive);
    }

    #[test]
    fn compile_case_insensitive_patterns() {
        let policy = make_policy_with_case_insensitive(
            "test",
            log_matcher::Match::Regex("error".to_string()),
            true,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

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
            false,
        );

        let stats = Arc::new(PolicyStats::default());
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

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
        let compiled = CompiledMatchers::<LogSignal>::build([(policy, stats)].into_iter()).unwrap();

        let key = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let db = compiled.databases.get(&key).unwrap();

        let matches = db.database.scan(b"config.JSON").unwrap();
        assert!(!matches.is_empty(), "Should match .JSON at end");

        let matches = db.database.scan(b"config.Json").unwrap();
        assert!(!matches.is_empty(), "Should match .Json at end");

        let matches = db.database.scan(b"config.json.bak").unwrap();
        assert!(matches.is_empty(), "Should NOT match .json in middle");
    }

    #[test]
    fn build_from_log_policies_empty_match_list_rejected() {
        let log_target = LogTarget {
            r#match: Vec::new(),
            keep: "all".to_string(),
            transform: None,
            sample_key: None,
        };
        let proto = ProtoPolicy {
            id: "no-matchers".to_string(),
            name: "no-matchers".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };
        let policy = Policy::new(proto);
        let stats = Arc::new(PolicyStats::default());
        let err =
            PatternGroups::build_from_log_policies([(policy, stats)].into_iter()).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidPolicy { ref policy_id, .. } if policy_id == "no-matchers"
        ));
    }

    #[test]
    fn build_from_metric_policies_empty_match_list_rejected() {
        use crate::proto::tero::policy::v1::MetricTarget;
        let metric_target = MetricTarget {
            r#match: Vec::new(),
            keep: true,
        };
        let proto = ProtoPolicy {
            id: "metric-no-matchers".to_string(),
            name: "metric-no-matchers".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Metric(
                metric_target,
            )),
            ..Default::default()
        };
        let policy = Policy::new(proto);
        let stats = Arc::new(PolicyStats::default());
        let err =
            PatternGroups::build_from_metric_policies([(policy, stats)].into_iter()).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidPolicy { ref policy_id, .. } if policy_id == "metric-no-matchers"
        ));
    }

    #[test]
    fn build_from_trace_policies_empty_match_list_rejected() {
        use crate::proto::tero::policy::v1::TraceTarget;
        let trace_target = TraceTarget {
            r#match: Vec::new(),
            keep: None,
        };
        let proto = ProtoPolicy {
            id: "trace-no-matchers".to_string(),
            name: "trace-no-matchers".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Trace(
                trace_target,
            )),
            ..Default::default()
        };
        let policy = Policy::new(proto);
        let stats = Arc::new(PolicyStats::default());
        let err =
            PatternGroups::build_from_trace_policies([(policy, stats)].into_iter()).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidPolicy { ref policy_id, .. } if policy_id == "trace-no-matchers"
        ));
    }
}
