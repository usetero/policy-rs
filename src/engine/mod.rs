//! Policy evaluation engine using Vectorscan for high-performance matching.

mod compiled;
mod keep;
mod match_key;
mod matchable;
mod rate_limiter;
pub mod signal;
mod transform;
mod transformable;

pub use compiled::{CompiledDatabase, CompiledMatchers, CompiledPolicy, ExistenceCheck};
pub use keep::CompiledKeep;
pub use match_key::MatchKey;
pub use matchable::Matchable;
pub use rate_limiter::RateLimiters;
pub use signal::{LogSignal, MetricSignal, Signal};
pub use transform::{CompiledTransform, TransformOp};
pub use transformable::Transformable;

use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::error::PolicyError;
use crate::registry::PolicySnapshot;

/// Result of evaluating a log record against policies.
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluateResult {
    /// No policies matched - pass through unchanged.
    NoMatch,
    /// Matched policy says keep all.
    Keep {
        policy_id: String,
        /// Whether transforms were applied to the log.
        transformed: bool,
    },
    /// Matched policy says drop all.
    Drop { policy_id: String },
    /// Matched policy says sample at percentage.
    Sample {
        policy_id: String,
        percentage: f64,
        keep: bool,
        /// Whether transforms were applied to the log (only if keep=true).
        transformed: bool,
    },
    /// Matched policy says rate limit.
    RateLimit {
        policy_id: String,
        allowed: bool,
        /// Whether transforms were applied to the log (only if allowed=true).
        transformed: bool,
    },
}

/// Policy evaluation engine.
///
/// The engine evaluates log records against policies using pre-compiled
/// Hyperscan databases from the policy snapshot.
pub struct PolicyEngine {
    /// Rate limiters for policies with rate limits.
    rate_limiters: RateLimiters,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self {
            rate_limiters: RateLimiters::new(),
        }
    }

    /// Evaluate a telemetry record against the policies in a snapshot.
    ///
    /// This scans the record's fields using the pre-compiled Hyperscan databases
    /// in the snapshot and returns the appropriate action. The signal type is
    /// inferred from the `Matchable` implementation's associated `Signal` type.
    ///
    /// # Arguments
    /// * `snapshot` - The policy snapshot to evaluate against
    /// * `log` - The telemetry record to evaluate
    ///
    /// # Returns
    /// The evaluation result indicating what should happen to the record.
    pub async fn evaluate<T: Matchable>(
        &self,
        snapshot: &PolicySnapshot,
        log: &T,
    ) -> Result<EvaluateResult, PolicyError> {
        let Some(compiled) = T::Signal::compiled_matchers(snapshot) else {
            return Ok(EvaluateResult::NoMatch);
        };

        let policy_count = compiled.policies.len();
        if policy_count == 0 {
            return Ok(EvaluateResult::NoMatch);
        }

        // Track match counts and disqualified policies
        let mut match_counts: Vec<usize> = vec![0; policy_count];
        let mut disqualified: Vec<bool> = vec![false; policy_count];

        // Scan each Vectorscan database
        for (key, db) in &compiled.databases {
            // Get field value from log
            let Some(value) = log.get_field(&key.field) else {
                // Field missing - positive matchers don't match, nothing to do
                continue;
            };

            // Scan for matches
            let matches = db.database.scan(value.as_bytes())?;

            for pattern_id in matches {
                if let Some(pattern_ref) = db.pattern_index.get(pattern_id as usize) {
                    if key.negated {
                        // Negated matcher matched = policy is disqualified
                        disqualified[pattern_ref.policy_index] = true;
                    } else {
                        // Positive match
                        match_counts[pattern_ref.policy_index] += 1;
                    }
                }
            }
        }

        // Handle existence checks
        for check in &compiled.existence_checks {
            if disqualified[check.policy_index] {
                continue;
            }

            let exists = log.get_field(&check.field).is_some();
            let matches = exists == check.should_exist;

            if check.is_negated {
                // Negated existence check: disqualify if the condition IS met
                // (e.g., "NOT exists:true" disqualifies if field exists)
                if matches {
                    disqualified[check.policy_index] = true;
                }
                // Don't increment match_counts for negated checks - they only disqualify
            } else if matches {
                match_counts[check.policy_index] += 1;
            }
        }

        // Find matching policies
        let mut matching: Vec<usize> = Vec::new();
        for (idx, policy) in compiled.policies.iter().enumerate() {
            if !policy.enabled {
                continue;
            }
            if disqualified[idx] {
                policy.stats.record_miss();
                continue;
            }
            if match_counts[idx] == policy.required_match_count {
                policy.stats.record_hit();
                matching.push(idx);
            } else {
                policy.stats.record_miss();
            }
        }

        if matching.is_empty() {
            return Ok(EvaluateResult::NoMatch);
        }

        // Select most restrictive policy
        matching.sort_by(|a, b| {
            compiled.policies[*b]
                .keep
                .restrictiveness()
                .cmp(&compiled.policies[*a].keep.restrictiveness())
        });

        let winner = &compiled.policies[matching[0]];

        // Extract sample key value if configured
        let sample_key_value = winner
            .sample_key
            .as_ref()
            .and_then(|key| log.get_field(key));

        Ok(self.apply_keep(&winner.id, &winner.keep, false, sample_key_value.as_deref()))
    }

    /// Evaluate a telemetry record and apply transforms from all matching policies.
    ///
    /// This is similar to `evaluate`, but also applies transforms to the record
    /// when it is kept (not dropped). Transforms are applied from ALL
    /// matching policies, not just the winning policy.
    ///
    /// # Arguments
    /// * `snapshot` - The policy snapshot to evaluate against
    /// * `log` - The telemetry record to evaluate and potentially transform
    ///
    /// # Returns
    /// The evaluation result with the `transformed` flag set if transforms were applied.
    pub async fn evaluate_and_transform<T: Matchable + Transformable>(
        &self,
        snapshot: &PolicySnapshot,
        log: &mut T,
    ) -> Result<EvaluateResult, PolicyError> {
        let Some(compiled) = T::Signal::compiled_matchers(snapshot) else {
            return Ok(EvaluateResult::NoMatch);
        };

        let policy_count = compiled.policies.len();
        if policy_count == 0 {
            return Ok(EvaluateResult::NoMatch);
        }

        // Track match counts and disqualified policies
        let mut match_counts: Vec<usize> = vec![0; policy_count];
        let mut disqualified: Vec<bool> = vec![false; policy_count];

        // Scan each Vectorscan database
        for (key, db) in &compiled.databases {
            // Get field value from log
            let Some(value) = log.get_field(&key.field) else {
                continue;
            };

            // Scan for matches
            let matches = db.database.scan(value.as_bytes())?;

            for pattern_id in matches {
                if let Some(pattern_ref) = db.pattern_index.get(pattern_id as usize) {
                    if key.negated {
                        disqualified[pattern_ref.policy_index] = true;
                    } else {
                        match_counts[pattern_ref.policy_index] += 1;
                    }
                }
            }
        }

        // Handle existence checks
        for check in &compiled.existence_checks {
            if disqualified[check.policy_index] {
                continue;
            }

            let exists = log.get_field(&check.field).is_some();
            let matches = exists == check.should_exist;

            if check.is_negated {
                if matches {
                    disqualified[check.policy_index] = true;
                }
            } else if matches {
                match_counts[check.policy_index] += 1;
            }
        }

        // Find matching policies
        let mut matching: Vec<usize> = Vec::new();
        for (idx, policy) in compiled.policies.iter().enumerate() {
            if !policy.enabled {
                continue;
            }
            if disqualified[idx] {
                policy.stats.record_miss();
                continue;
            }
            if match_counts[idx] == policy.required_match_count {
                policy.stats.record_hit();
                matching.push(idx);
            } else {
                policy.stats.record_miss();
            }
        }

        if matching.is_empty() {
            return Ok(EvaluateResult::NoMatch);
        }

        // Select most restrictive policy
        matching.sort_by(|a, b| {
            compiled.policies[*b]
                .keep
                .restrictiveness()
                .cmp(&compiled.policies[*a].keep.restrictiveness())
        });

        let winner_idx = matching[0];
        let winner = &compiled.policies[winner_idx];

        // Extract sample key value if configured (for consistent sampling)
        let sample_key_value = winner
            .sample_key
            .as_ref()
            .and_then(|key| log.get_field(key));

        // Determine if the log will be kept
        let will_keep = match &winner.keep {
            CompiledKeep::None => false,
            CompiledKeep::All => true,
            CompiledKeep::Percentage(p) => should_keep_percentage(*p, sample_key_value.as_deref()),
            CompiledKeep::RatePerSecond(limit) => {
                self.rate_limiters
                    .check(&winner.id, *limit, Duration::from_secs(1))
            }
            CompiledKeep::RatePerMinute(limit) => {
                self.rate_limiters
                    .check(&winner.id, *limit, Duration::from_secs(60))
            }
        };

        // Only apply transforms if the log is being kept
        let transformed = if will_keep {
            let mut ops_applied = 0;
            // Apply transforms from ALL matching policies, recording stats
            for &idx in &matching {
                let policy = &compiled.policies[idx];
                if let Some(transform) = &policy.transform {
                    ops_applied += transform.apply_with_stats(log, Some(&policy.stats));
                }
            }
            ops_applied > 0
        } else {
            false
        };

        // Return the result based on the keep action
        match &winner.keep {
            CompiledKeep::None => Ok(EvaluateResult::Drop {
                policy_id: winner.id.clone(),
            }),
            CompiledKeep::All => Ok(EvaluateResult::Keep {
                policy_id: winner.id.clone(),
                transformed,
            }),
            CompiledKeep::Percentage(p) => Ok(EvaluateResult::Sample {
                policy_id: winner.id.clone(),
                percentage: *p * 100.0,
                keep: will_keep,
                transformed,
            }),
            CompiledKeep::RatePerSecond(_) | CompiledKeep::RatePerMinute(_) => {
                Ok(EvaluateResult::RateLimit {
                    policy_id: winner.id.clone(),
                    allowed: will_keep,
                    transformed,
                })
            }
        }
    }

    /// Apply the keep action and return the evaluation result.
    ///
    /// # Arguments
    /// * `policy_id` - The ID of the winning policy
    /// * `keep` - The keep action to apply
    /// * `transformed` - Whether transforms were applied
    /// * `sample_key_value` - Optional sample key value for consistent sampling
    fn apply_keep(
        &self,
        policy_id: &str,
        keep: &CompiledKeep,
        transformed: bool,
        sample_key_value: Option<&str>,
    ) -> EvaluateResult {
        match keep {
            CompiledKeep::None => EvaluateResult::Drop {
                policy_id: policy_id.to_string(),
            },
            CompiledKeep::All => EvaluateResult::Keep {
                policy_id: policy_id.to_string(),
                transformed,
            },
            CompiledKeep::Percentage(p) => {
                let keep = should_keep_percentage(*p, sample_key_value);
                EvaluateResult::Sample {
                    policy_id: policy_id.to_string(),
                    percentage: *p * 100.0,
                    keep,
                    // Only report transformed if we're keeping the log
                    transformed: keep && transformed,
                }
            }
            CompiledKeep::RatePerSecond(limit) => {
                let allowed = self
                    .rate_limiters
                    .check(policy_id, *limit, Duration::from_secs(1));
                EvaluateResult::RateLimit {
                    policy_id: policy_id.to_string(),
                    allowed,
                    // Only report transformed if we're allowing the log
                    transformed: allowed && transformed,
                }
            }
            CompiledKeep::RatePerMinute(limit) => {
                let allowed = self
                    .rate_limiters
                    .check(policy_id, *limit, Duration::from_secs(60));
                EvaluateResult::RateLimit {
                    policy_id: policy_id.to_string(),
                    allowed,
                    // Only report transformed if we're allowing the log
                    transformed: allowed && transformed,
                }
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum threshold value: 2^56.
const MAX_THRESHOLD: u64 = 1 << 56;

/// Mask for extracting 56-bit randomness from a 64-bit hash.
const RANDOMNESS_MASK: u64 = MAX_THRESHOLD - 1;

/// Hash a sample key value to produce a deterministic 56-bit randomness value.
///
/// Uses consistent probability sampling per the OpenTelemetry specification.
/// The same key value always produces the same 56-bit randomness value,
/// enabling consistent sampling decisions across multiple records with the
/// same key. Higher sampling probabilities are strict supersets of lower ones:
/// if a record is kept at 10%, it will also be kept at 50%.
fn hash_sample_key(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() & RANDOMNESS_MASK
}

/// Convert a sampling probability (0.0–1.0) to a 56-bit rejection threshold.
///
/// The threshold T = (1 - probability) * 2^56. A record is kept when its
/// randomness value R >= T. This means T=0 keeps everything (100%) and
/// T=2^56 keeps nothing (0%).
fn rejection_threshold(probability: f64) -> u64 {
    if probability >= 1.0 {
        return 0;
    }
    if probability <= 0.0 {
        return MAX_THRESHOLD;
    }
    ((1.0 - probability) * MAX_THRESHOLD as f64) as u64
}

/// Determine if a record should be kept based on percentage sampling.
///
/// Uses consistent probability sampling per the OpenTelemetry specification:
/// computes a 56-bit rejection threshold from the probability and compares
/// against a 56-bit randomness value derived from the sample key hash.
///
/// If a sample key value is provided, uses hash-based consistent sampling.
/// Otherwise, uses random sampling with a 56-bit random value.
fn should_keep_percentage(percentage: f64, sample_key_value: Option<&str>) -> bool {
    let threshold = rejection_threshold(percentage);
    let randomness = match sample_key_value {
        Some(key) => hash_sample_key(key),
        None => rand::random::<u64>() & RANDOMNESS_MASK,
    };
    randomness >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;
    use crate::engine::signal::LogSignal;
    use crate::field::LogFieldSelector;
    use crate::proto::tero::policy::v1::Policy as ProtoPolicy;
    use crate::proto::tero::policy::v1::{
        LogAdd, LogField, LogMatcher, LogRedact, LogRemove, LogTarget, LogTransform, log_add,
        log_matcher, log_redact, log_remove,
    };
    use crate::registry::PolicyRegistry;
    use std::borrow::Cow;
    use std::collections::HashMap;

    /// Test log record implementation.
    struct TestLog {
        body: Option<String>,
        severity_text: Option<String>,
        log_attributes: HashMap<String, String>,
        resource_attributes: HashMap<String, String>,
    }

    impl TestLog {
        fn new() -> Self {
            Self {
                body: None,
                severity_text: None,
                log_attributes: HashMap::new(),
                resource_attributes: HashMap::new(),
            }
        }

        fn with_body(mut self, body: &str) -> Self {
            self.body = Some(body.to_string());
            self
        }

        fn with_severity(mut self, severity: &str) -> Self {
            self.severity_text = Some(severity.to_string());
            self
        }

        fn with_log_attr(mut self, key: &str, value: &str) -> Self {
            self.log_attributes
                .insert(key.to_string(), value.to_string());
            self
        }

        fn with_resource_attr(mut self, key: &str, value: &str) -> Self {
            self.resource_attributes
                .insert(key.to_string(), value.to_string());
            self
        }
    }

    impl Matchable for TestLog {
        type Signal = LogSignal;

        fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.as_deref().map(Cow::Borrowed),
                    LogField::SeverityText => self.severity_text.as_deref().map(Cow::Borrowed),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(path) => path
                    .first()
                    .and_then(|key| self.log_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                LogFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                LogFieldSelector::ScopeAttribute(_) => None,
            }
        }
    }

    impl Transformable for TestLog {
        fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.take().is_some(),
                    LogField::SeverityText => self.severity_text.take().is_some(),
                    _ => false,
                },
                LogFieldSelector::LogAttribute(path) => path
                    .first()
                    .and_then(|key| self.log_attributes.remove(key))
                    .is_some(),
                LogFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.remove(key))
                    .is_some(),
                LogFieldSelector::ScopeAttribute(_) => false,
            }
        }

        fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => {
                        if self.body.is_some() {
                            self.body = Some(replacement.to_string());
                            true
                        } else {
                            false
                        }
                    }
                    LogField::SeverityText => {
                        if self.severity_text.is_some() {
                            self.severity_text = Some(replacement.to_string());
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                },
                LogFieldSelector::LogAttribute(path) => {
                    let Some(key) = path.first() else {
                        return false;
                    };
                    if self.log_attributes.contains_key(key) {
                        self.log_attributes
                            .insert(key.clone(), replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                LogFieldSelector::ResourceAttribute(path) => {
                    let Some(key) = path.first() else {
                        return false;
                    };
                    if self.resource_attributes.contains_key(key) {
                        self.resource_attributes
                            .insert(key.clone(), replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                LogFieldSelector::ScopeAttribute(_) => false,
            }
        }

        fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
            if !upsert && self.log_attributes.contains_key(to) {
                return false;
            }
            let value = match from {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.take(),
                    LogField::SeverityText => self.severity_text.take(),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(path) => {
                    path.first().and_then(|key| self.log_attributes.remove(key))
                }
                LogFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.remove(key)),
                LogFieldSelector::ScopeAttribute(_) => None,
            };
            if let Some(v) = value {
                self.log_attributes.insert(to.to_string(), v);
                true
            } else {
                false
            }
        }

        fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => {
                        if !upsert && self.body.is_some() {
                            return false;
                        }
                        self.body = Some(value.to_string());
                        true
                    }
                    LogField::SeverityText => {
                        if !upsert && self.severity_text.is_some() {
                            return false;
                        }
                        self.severity_text = Some(value.to_string());
                        true
                    }
                    _ => false,
                },
                LogFieldSelector::LogAttribute(path) => {
                    let Some(key) = path.first() else {
                        return false;
                    };
                    if !upsert && self.log_attributes.contains_key(key) {
                        return false;
                    }
                    self.log_attributes.insert(key.clone(), value.to_string());
                    true
                }
                LogFieldSelector::ResourceAttribute(path) => {
                    let Some(key) = path.first() else {
                        return false;
                    };
                    if !upsert && self.resource_attributes.contains_key(key) {
                        return false;
                    }
                    self.resource_attributes
                        .insert(key.clone(), value.to_string());
                    true
                }
                LogFieldSelector::ScopeAttribute(_) => false,
            }
        }
    }

    fn make_policy(id: &str, matchers: Vec<LogMatcher>, keep: &str, enabled: bool) -> Policy {
        make_policy_with_transform(id, matchers, keep, enabled, None)
    }

    fn make_policy_with_transform(
        id: &str,
        matchers: Vec<LogMatcher>,
        keep: &str,
        enabled: bool,
        transform: Option<LogTransform>,
    ) -> Policy {
        let log_target = LogTarget {
            r#match: matchers,
            keep: keep.to_string(),
            transform,
            sample_key: None,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled,
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

    fn body_regex_matcher(pattern: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn body_exact_matcher(value: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Exact(value.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn severity_exact_matcher(value: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::SeverityText.into())),
            r#match: Some(log_matcher::Match::Exact(value.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn log_attr_exists_matcher(key: &str, should_exist: bool, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogAttribute(attr_path(key))),
            r#match: Some(log_matcher::Match::Exists(should_exist)),
            negate,
            case_insensitive: false,
        }
    }

    fn log_attr_regex_matcher(key: &str, pattern: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogAttribute(attr_path(key))),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    #[test]
    fn evaluate_result_variants() {
        let no_match = EvaluateResult::NoMatch;
        let keep = EvaluateResult::Keep {
            policy_id: "test".to_string(),
            transformed: false,
        };
        let drop = EvaluateResult::Drop {
            policy_id: "test".to_string(),
        };

        assert_eq!(no_match, EvaluateResult::NoMatch);
        assert_ne!(keep, drop);
    }

    #[test]
    fn engine_default() {
        let _engine = PolicyEngine::default();
    }

    #[tokio::test]
    async fn evaluate_no_policies_returns_no_match() {
        let registry = PolicyRegistry::new();
        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("test message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_no_matching_policy_returns_no_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Policy matches "error" but log has "info"
        let policy = make_policy(
            "drop-errors",
            vec![body_regex_matcher("error", false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("info message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_matching_policy_keep_all() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "keep-errors",
            vec![body_regex_matcher("error", false)],
            "all",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("error occurred");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "keep-errors".to_string(),
                transformed: false,
            }
        );
    }

    #[tokio::test]
    async fn evaluate_matching_policy_keep_none() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "drop-debug",
            vec![body_regex_matcher("debug", false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("debug message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-debug".to_string()
            }
        );
    }

    #[tokio::test]
    async fn evaluate_matching_policy_sample_percentage() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "sample-info",
            vec![body_regex_matcher("info", false)],
            "50%",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("info message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        match result {
            EvaluateResult::Sample {
                policy_id,
                percentage,
                ..
            } => {
                assert_eq!(policy_id, "sample-info");
                assert!((percentage - 50.0).abs() < 0.01);
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn evaluate_matching_policy_rate_limit_per_second() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "rate-limit",
            vec![body_regex_matcher("message", false)],
            "100/s",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("any message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        match result {
            EvaluateResult::RateLimit {
                policy_id, allowed, ..
            } => {
                assert_eq!(policy_id, "rate-limit");
                assert!(allowed); // First request should be allowed
            }
            _ => panic!("expected RateLimit result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn evaluate_matching_policy_rate_limit_per_minute() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "rate-limit-min",
            vec![body_regex_matcher("message", false)],
            "1000/m",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("any message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        match result {
            EvaluateResult::RateLimit {
                policy_id, allowed, ..
            } => {
                assert_eq!(policy_id, "rate-limit-min");
                assert!(allowed);
            }
            _ => panic!("expected RateLimit result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn evaluate_negated_matcher_disqualifies_policy() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Policy: drop if body matches "error" BUT NOT if it contains "ignore"
        let policy = make_policy(
            "drop-errors-except-ignore",
            vec![
                body_regex_matcher("error", false),
                body_regex_matcher("ignore", true), // negated
            ],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log with "error" but also "ignore" - policy should NOT match
        let log = TestLog::new().with_body("error: please ignore this");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);

        // Log with just "error" - policy should match
        let log2 = TestLog::new().with_body("error occurred");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(
            result2,
            EvaluateResult::Drop {
                policy_id: "drop-errors-except-ignore".to_string()
            }
        );
    }

    #[tokio::test]
    async fn evaluate_existence_check_field_exists() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "keep-with-trace",
            vec![log_attr_exists_matcher("trace_id", true, false)],
            "all",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log with trace_id attribute
        let log = TestLog::new().with_log_attr("trace_id", "abc123");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "keep-with-trace".to_string(),
                transformed: false,
            }
        );

        // Log without trace_id attribute
        let log2 = TestLog::new().with_body("no trace");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_existence_check_field_not_exists() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "drop-without-trace",
            vec![log_attr_exists_matcher("trace_id", false, false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log without trace_id - should match
        let log = TestLog::new().with_body("no trace");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-without-trace".to_string()
            }
        );

        // Log with trace_id - should not match
        let log2 = TestLog::new().with_log_attr("trace_id", "abc123");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_existence_check_negated() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Negated existence: "exists: true" with negate means match if field does NOT exist
        let policy = make_policy(
            "negated-exists",
            vec![log_attr_exists_matcher("debug_flag", true, true)], // negated
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log without debug_flag - negated "exists: true" matches
        let log = TestLog::new().with_body("test");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "negated-exists".to_string()
            }
        );

        // Log with debug_flag - negated "exists: true" does not match (disqualified)
        let log2 = TestLog::new().with_log_attr("debug_flag", "true");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_most_restrictive_policy_wins() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Two policies match the same log, but with different keep values
        let policy_all = make_policy(
            "keep-all",
            vec![body_regex_matcher("message", false)],
            "all",
            true,
        );
        let policy_none = make_policy(
            "drop-all",
            vec![body_regex_matcher("message", false)],
            "none",
            true,
        );
        handle.update(vec![policy_all, policy_none]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("test message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        // "none" is more restrictive than "all", so drop-all should win
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-all".to_string()
            }
        );
    }

    #[tokio::test]
    async fn evaluate_percentage_more_restrictive_than_all() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy_all = make_policy(
            "keep-all",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
        );
        let policy_pct = make_policy(
            "sample-10",
            vec![body_regex_matcher("test", false)],
            "10%",
            true,
        );
        handle.update(vec![policy_all, policy_pct]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("test");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        // 10% sampling is more restrictive than all
        match result {
            EvaluateResult::Sample { policy_id, .. } => {
                assert_eq!(policy_id, "sample-10");
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn evaluate_disabled_policy_skipped() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "disabled-policy",
            vec![body_regex_matcher("test", false)],
            "none",
            false, // disabled
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let log = TestLog::new().with_body("test message");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_multiple_matchers_all_must_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Policy requires both body AND severity to match
        let policy = make_policy(
            "multi-matcher",
            vec![
                body_regex_matcher("error", false),
                severity_exact_matcher("ERROR", false),
            ],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Only body matches - no match
        let log1 = TestLog::new()
            .with_body("error occurred")
            .with_severity("INFO");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(result1, EvaluateResult::NoMatch);

        // Only severity matches - no match
        let log2 = TestLog::new()
            .with_body("info message")
            .with_severity("ERROR");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Both match - should match
        let log3 = TestLog::new()
            .with_body("error occurred")
            .with_severity("ERROR");
        let result3 = engine.evaluate(&snapshot, &log3).await.unwrap();
        assert_eq!(
            result3,
            EvaluateResult::Drop {
                policy_id: "multi-matcher".to_string()
            }
        );
    }

    #[tokio::test]
    async fn evaluate_exact_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "exact-match",
            vec![body_exact_matcher("exact message", false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Exact match
        let log1 = TestLog::new().with_body("exact message");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "exact-match".to_string()
            }
        );

        // Partial match - should not match
        let log2 = TestLog::new().with_body("exact message with more");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Substring - should not match
        let log3 = TestLog::new().with_body("the exact message");
        let result3 = engine.evaluate(&snapshot, &log3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_log_attribute_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "attr-match",
            vec![log_attr_regex_matcher("service", "nginx", false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching attribute
        let log1 = TestLog::new().with_log_attr("service", "nginx-proxy");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "attr-match".to_string()
            }
        );

        // Non-matching attribute
        let log2 = TestLog::new().with_log_attr("service", "apache");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Missing attribute
        let log3 = TestLog::new().with_body("no service attr");
        let result3 = engine.evaluate(&snapshot, &log3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn evaluate_stats_recorded() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "stats-test",
            vec![body_regex_matcher("error", false)],
            "all",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching log - should record hit
        let log1 = TestLog::new().with_body("error occurred");
        engine.evaluate(&snapshot, &log1).await.unwrap();

        // Non-matching log - should record miss
        let log2 = TestLog::new().with_body("info message");
        engine.evaluate(&snapshot, &log2).await.unwrap();

        // Check stats
        let entry = snapshot.get("stats-test").unwrap();
        assert_eq!(entry.stats.hits(), 1);
        assert_eq!(entry.stats.misses(), 1);
    }

    #[tokio::test]
    async fn evaluate_missing_field_does_not_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "body-required",
            vec![body_regex_matcher("anything", false)],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log without body field
        let log = TestLog::new().with_severity("ERROR");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    fn resource_attr_regex_matcher(key: &str, pattern: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::ResourceAttribute(attr_path(key))),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    #[tokio::test]
    async fn evaluate_resource_attribute_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "resource-attr-match",
            vec![resource_attr_regex_matcher(
                "service.name",
                "my-service",
                false,
            )],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching resource attribute
        let log1 = TestLog::new()
            .with_body("test")
            .with_resource_attr("service.name", "my-service-prod");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "resource-attr-match".to_string()
            }
        );

        // Non-matching resource attribute
        let log2 = TestLog::new()
            .with_body("test")
            .with_resource_attr("service.name", "other-service");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Missing resource attribute
        let log3 = TestLog::new().with_body("test");
        let result3 = engine.evaluate(&snapshot, &log3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    // Transform tests

    #[tokio::test]
    async fn evaluate_and_transform_no_transform() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Policy with no transform
        let policy = make_policy(
            "keep-all",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("test message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "keep-all".to_string(),
                transformed: false,
            }
        );
        // Body should be unchanged
        assert_eq!(log.body, Some("test message".to_string()));
    }

    #[tokio::test]
    async fn evaluate_and_transform_redact_attribute() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path("password"))),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "redact-password",
            vec![body_regex_matcher("login", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new()
            .with_body("login attempt")
            .with_log_attr("password", "secret123");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "redact-password".to_string(),
                transformed: true,
            }
        );
        // Password should be redacted
        assert_eq!(
            log.log_attributes.get("password"),
            Some(&"[REDACTED]".to_string())
        );
    }

    #[tokio::test]
    async fn evaluate_and_transform_remove_field() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogAttribute(attr_path("debug_info"))),
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "remove-debug",
            vec![body_regex_matcher("message", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new()
            .with_body("test message")
            .with_log_attr("debug_info", "internal data")
            .with_log_attr("user_id", "12345");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "remove-debug".to_string(),
                transformed: true,
            }
        );
        // debug_info should be removed, user_id preserved
        assert!(!log.log_attributes.contains_key("debug_info"));
        assert_eq!(
            log.log_attributes.get("user_id"),
            Some(&"12345".to_string())
        );
    }

    #[tokio::test]
    async fn evaluate_and_transform_add_field() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("processed_by"))),
                value: "policy-engine".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "add-tag",
            vec![body_regex_matcher("event", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("event occurred");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "add-tag".to_string(),
                transformed: true,
            }
        );
        // Field should be added
        assert_eq!(
            log.log_attributes.get("processed_by"),
            Some(&"policy-engine".to_string())
        );
    }

    #[tokio::test]
    async fn evaluate_and_transform_no_transform_on_drop() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("should_not_exist"))),
                value: "value".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        // Policy that drops logs (transform should NOT be applied)
        let policy = make_policy_with_transform(
            "drop-debug",
            vec![body_regex_matcher("debug", false)],
            "none",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("debug message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-debug".to_string(),
            }
        );
        // Field should NOT be added since log is dropped
        assert!(!log.log_attributes.contains_key("should_not_exist"));
    }

    #[tokio::test]
    async fn evaluate_and_transform_multiple_policies_all_transforms_applied() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Two policies match the same log, both have transforms
        let transform1 = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("tag1"))),
                value: "from-policy1".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let transform2 = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("tag2"))),
                value: "from-policy2".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let policy1 = make_policy_with_transform(
            "policy1",
            vec![body_regex_matcher("message", false)],
            "all",
            true,
            Some(transform1),
        );
        let policy2 = make_policy_with_transform(
            "policy2",
            vec![body_regex_matcher("message", false)],
            "all",
            true,
            Some(transform2),
        );
        handle.update(vec![policy1, policy2]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("test message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        // One policy wins, but both transforms are applied
        match result {
            EvaluateResult::Keep { transformed, .. } => {
                assert!(transformed);
            }
            _ => panic!("expected Keep result"),
        }
        // BOTH transforms should be applied
        assert_eq!(
            log.log_attributes.get("tag1"),
            Some(&"from-policy1".to_string())
        );
        assert_eq!(
            log.log_attributes.get("tag2"),
            Some(&"from-policy2".to_string())
        );
    }

    #[tokio::test]
    async fn evaluate_and_transform_nonexistent_field_not_transformed() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path("nonexistent"))),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "redact-nonexistent",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("test message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        // Transform attempted but failed (field doesn't exist), so transformed=false
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "redact-nonexistent".to_string(),
                transformed: false,
            }
        );
    }

    #[tokio::test]
    async fn evaluate_and_transform_records_stats_on_success() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogAttribute(attr_path("temp"))),
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path("secret"))),
                replacement: "[REDACTED]".to_string(),
            }],
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("processed"))),
                value: "true".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "stats-test",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new()
            .with_body("test message")
            .with_log_attr("temp", "temporary")
            .with_log_attr("secret", "password123");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert!(matches!(
            result,
            EvaluateResult::Keep {
                transformed: true,
                ..
            }
        ));

        // Check stats were recorded
        let entry = snapshot.get("stats-test").unwrap();
        assert_eq!(entry.stats.remove.hits(), 1);
        assert_eq!(entry.stats.remove.misses(), 0);
        assert_eq!(entry.stats.redact.hits(), 1);
        assert_eq!(entry.stats.redact.misses(), 0);
        assert_eq!(entry.stats.add.hits(), 1);
        assert_eq!(entry.stats.add.misses(), 0);
    }

    #[tokio::test]
    async fn evaluate_and_transform_records_stats_on_miss() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogAttribute(attr_path("nonexistent"))),
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path(
                    "also_nonexistent",
                ))),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "stats-miss-test",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("test message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        // No transforms succeeded
        assert!(matches!(
            result,
            EvaluateResult::Keep {
                transformed: false,
                ..
            }
        ));

        // Check miss stats were recorded
        let entry = snapshot.get("stats-miss-test").unwrap();
        assert_eq!(entry.stats.remove.hits(), 0);
        assert_eq!(entry.stats.remove.misses(), 1);
        assert_eq!(entry.stats.redact.hits(), 0);
        assert_eq!(entry.stats.redact.misses(), 1);
    }

    #[tokio::test]
    async fn evaluate_and_transform_no_stats_on_drop() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("tag"))),
                value: "value".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "stats-drop-test",
            vec![body_regex_matcher("test", false)],
            "none", // Drop policy
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut log = TestLog::new().with_body("test message");

        let result = engine
            .evaluate_and_transform(&snapshot, &mut log)
            .await
            .unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));

        // Transform was NOT applied, so no stats should be recorded
        let entry = snapshot.get("stats-drop-test").unwrap();
        assert_eq!(entry.stats.add.hits(), 0);
        assert_eq!(entry.stats.add.misses(), 0);
    }

    #[tokio::test]
    async fn evaluate_and_transform_stats_accumulate() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let transform = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(attr_path("count"))),
                value: "1".to_string(),
                upsert: true, // Use upsert so it always succeeds
            }],
            ..Default::default()
        };

        let policy = make_policy_with_transform(
            "stats-accumulate-test",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
            Some(transform),
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Run evaluation multiple times
        for _ in 0..5 {
            let mut log = TestLog::new().with_body("test message");
            engine
                .evaluate_and_transform(&snapshot, &mut log)
                .await
                .unwrap();
        }

        // Check stats accumulated
        let entry = snapshot.get("stats-accumulate-test").unwrap();
        assert_eq!(entry.stats.add.hits(), 5);
        assert_eq!(entry.stats.add.misses(), 0);

        // Test reset
        let snapshot_data = entry.stats.reset_all();
        assert_eq!(snapshot_data.add.0, 5); // hits
        assert_eq!(snapshot_data.add.1, 0); // misses

        // Stats should be reset
        assert_eq!(entry.stats.add.hits(), 0);
    }

    // ==================== Sample Key Tests ====================

    #[test]
    fn hash_sample_key_is_deterministic() {
        // Same key always produces same hash
        let hash1 = hash_sample_key("request-123");
        let hash2 = hash_sample_key("request-123");
        assert_eq!(hash1, hash2);

        // Different keys produce different hashes
        let hash3 = hash_sample_key("request-456");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn hash_sample_key_produces_56_bit_values() {
        let test_keys = [
            "request-1",
            "request-2",
            "user-abc",
            "trace-xyz",
            "",
            "a",
            "very-long-key-with-lots-of-characters-1234567890",
        ];

        for key in test_keys {
            let hash = hash_sample_key(key);
            assert!(
                hash < MAX_THRESHOLD,
                "Hash for '{}' should be < 2^56, got {}",
                key,
                hash
            );
        }
    }

    #[test]
    fn rejection_threshold_edge_cases() {
        // 100% probability → threshold 0 (keep everything)
        assert_eq!(rejection_threshold(1.0), 0);

        // 0% probability → threshold 2^56 (keep nothing)
        assert_eq!(rejection_threshold(0.0), MAX_THRESHOLD);

        // 50% probability → threshold ~2^55
        let t50 = rejection_threshold(0.5);
        let expected = MAX_THRESHOLD / 2;
        assert_eq!(t50, expected);

        // Over 100% clamped to 0
        assert_eq!(rejection_threshold(1.5), 0);

        // Below 0% clamped to MAX_THRESHOLD
        assert_eq!(rejection_threshold(-0.1), MAX_THRESHOLD);
    }

    #[test]
    fn should_keep_percentage_with_sample_key_is_consistent() {
        // With a sample key, the decision should be consistent
        let key = "request-123";

        // Call multiple times with the same key and percentage
        let decisions: Vec<bool> = (0..10)
            .map(|_| should_keep_percentage(0.5, Some(key)))
            .collect();

        // All decisions should be the same
        let first = decisions[0];
        assert!(
            decisions.iter().all(|&d| d == first),
            "Sample key decisions should be consistent"
        );
    }

    #[test]
    fn should_keep_percentage_different_keys_different_decisions() {
        // With many different keys at 50%, roughly half should be kept
        let keys: Vec<String> = (0..1000).map(|i| format!("request-{}", i)).collect();

        let kept_count = keys
            .iter()
            .filter(|k| should_keep_percentage(0.5, Some(k)))
            .count();

        // With 1000 samples at 50%, we expect ~500 kept
        // Allow for some variance (400-600 is reasonable)
        assert!(
            kept_count > 400 && kept_count < 600,
            "Expected ~50% kept, got {} out of 1000",
            kept_count
        );
    }

    #[test]
    fn should_keep_percentage_respects_threshold() {
        // At 0%, no keys should be kept
        let keys: Vec<String> = (0..100).map(|i| format!("key-{}", i)).collect();
        let kept_at_0 = keys
            .iter()
            .filter(|k| should_keep_percentage(0.0, Some(k)))
            .count();
        assert_eq!(kept_at_0, 0, "At 0%, nothing should be kept");

        // At 100%, all keys should be kept
        let kept_at_100 = keys
            .iter()
            .filter(|k| should_keep_percentage(1.0, Some(k)))
            .count();
        assert_eq!(kept_at_100, 100, "At 100%, everything should be kept");
    }

    #[test]
    fn should_keep_percentage_without_key_uses_random() {
        // Without a sample key, decisions vary (random)
        // We can't test randomness directly, but we can verify it works
        // Just verify it returns without panicking
        let _decision = should_keep_percentage(0.5, None);
    }

    #[test]
    fn consistent_sampling_superset_property() {
        // Core property of consistent probability sampling:
        // if a key is kept at probability P, it must also be kept at any P' > P.
        let keys: Vec<String> = (0..500).map(|i| format!("key-{}", i)).collect();
        let probabilities = [0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99];

        for key in &keys {
            let mut was_kept = false;
            for &p in &probabilities {
                let kept = should_keep_percentage(p, Some(key));
                if was_kept {
                    assert!(
                        kept,
                        "Key '{}' was kept at lower probability but dropped at {}",
                        key, p
                    );
                }
                if kept {
                    was_kept = true;
                }
            }
        }
    }

    #[tokio::test]
    async fn evaluate_with_sample_key_is_consistent() {
        use crate::proto::tero::policy::v1::{LogSampleKey, log_sample_key};

        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Create a policy with 50% sampling and a sample key
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Contains("test".to_string())),
            negate: false,
            case_insensitive: false,
        };

        let sample_key = LogSampleKey {
            field: Some(log_sample_key::Field::LogAttribute(
                crate::proto::tero::policy::v1::AttributePath {
                    path: vec!["request_id".to_string()],
                },
            )),
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "50%".to_string(),
            transform: None,
            sample_key: Some(sample_key),
        };

        let proto = ProtoPolicy {
            id: "sample-key-test".to_string(),
            name: "sample-key-test".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        handle.update(vec![Policy::new(proto)]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Evaluate the same log multiple times - should get consistent results
        let log = TestLog::new()
            .with_body("test")
            .with_log_attr("request_id", "req-12345");

        let mut results = Vec::new();
        for _ in 0..5 {
            let result = engine.evaluate(&snapshot, &log).await.unwrap();
            if let EvaluateResult::Sample { keep, .. } = result {
                results.push(keep);
            }
        }

        // All results should be the same (consistent sampling)
        assert_eq!(results.len(), 5);
        let first = results[0];
        assert!(
            results.iter().all(|&r| r == first),
            "Sample key should produce consistent results"
        );
    }

    #[tokio::test]
    async fn evaluate_without_sample_key_field_falls_back_to_random() {
        use crate::proto::tero::policy::v1::{LogSampleKey, log_sample_key};

        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Create a policy with sample key pointing to a field that doesn't exist
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Contains("test".to_string())),
            negate: false,
            case_insensitive: false,
        };

        let sample_key = LogSampleKey {
            field: Some(log_sample_key::Field::LogAttribute(
                crate::proto::tero::policy::v1::AttributePath {
                    path: vec!["nonexistent_field".to_string()],
                },
            )),
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: "50%".to_string(),
            transform: None,
            sample_key: Some(sample_key),
        };

        let proto = ProtoPolicy {
            id: "missing-key-test".to_string(),
            name: "missing-key-test".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        handle.update(vec![Policy::new(proto)]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log without the sample key field - should fall back to random sampling
        let log = TestLog::new().with_body("test");

        // Just verify it doesn't panic and returns a valid result
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert!(matches!(result, EvaluateResult::Sample { .. }));
    }

    // ==================== Metric-specific tests ====================

    use crate::engine::signal::MetricSignal;
    use crate::field::MetricFieldSelector;
    use crate::proto::tero::policy::v1::{
        AggregationTemporality, MetricField, MetricMatcher, MetricTarget, MetricType,
        metric_matcher,
    };

    /// Test metric record implementation.
    struct TestMetric {
        name: Option<String>,
        description: Option<String>,
        unit: Option<String>,
        metric_type: Option<MetricType>,
        aggregation_temporality: Option<AggregationTemporality>,
        datapoint_attributes: HashMap<String, String>,
        resource_attributes: HashMap<String, String>,
        scope_name: Option<String>,
    }

    impl TestMetric {
        fn new() -> Self {
            Self {
                name: None,
                description: None,
                unit: None,
                metric_type: None,
                aggregation_temporality: None,
                datapoint_attributes: HashMap::new(),
                resource_attributes: HashMap::new(),
                scope_name: None,
            }
        }

        fn with_name(mut self, name: &str) -> Self {
            self.name = Some(name.to_string());
            self
        }

        fn with_description(mut self, desc: &str) -> Self {
            self.description = Some(desc.to_string());
            self
        }

        fn with_unit(mut self, unit: &str) -> Self {
            self.unit = Some(unit.to_string());
            self
        }

        fn with_type(mut self, t: MetricType) -> Self {
            self.metric_type = Some(t);
            self
        }

        fn with_temporality(mut self, t: AggregationTemporality) -> Self {
            self.aggregation_temporality = Some(t);
            self
        }

        fn with_datapoint_attr(mut self, key: &str, value: &str) -> Self {
            self.datapoint_attributes
                .insert(key.to_string(), value.to_string());
            self
        }

        fn with_resource_attr(mut self, key: &str, value: &str) -> Self {
            self.resource_attributes
                .insert(key.to_string(), value.to_string());
            self
        }

        fn with_scope_name(mut self, name: &str) -> Self {
            self.scope_name = Some(name.to_string());
            self
        }
    }

    impl Matchable for TestMetric {
        type Signal = MetricSignal;

        fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                MetricFieldSelector::Simple(metric_field) => match metric_field {
                    MetricField::Name => self.name.as_deref().map(Cow::Borrowed),
                    MetricField::Description => self.description.as_deref().map(Cow::Borrowed),
                    MetricField::Unit => self.unit.as_deref().map(Cow::Borrowed),
                    MetricField::ScopeName => self.scope_name.as_deref().map(Cow::Borrowed),
                    _ => None,
                },
                MetricFieldSelector::DatapointAttribute(path) => path
                    .first()
                    .and_then(|key| self.datapoint_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                MetricFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                MetricFieldSelector::ScopeAttribute(_) => None,
                MetricFieldSelector::Type => self
                    .metric_type
                    .as_ref()
                    .map(|t| Cow::Borrowed(t.as_str_name())),
                MetricFieldSelector::Temporality => self
                    .aggregation_temporality
                    .as_ref()
                    .map(|t| Cow::Borrowed(t.as_str_name())),
            }
        }
    }

    fn make_metric_policy(
        id: &str,
        matchers: Vec<MetricMatcher>,
        keep: bool,
        enabled: bool,
    ) -> Policy {
        let metric_target = MetricTarget {
            r#match: matchers,
            keep,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Metric(
                metric_target,
            )),
            ..Default::default()
        };

        Policy::new(proto)
    }

    fn metric_name_regex_matcher(pattern: &str, negate: bool) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(MetricField::Name.into())),
            r#match: Some(metric_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn metric_name_exact_matcher(value: &str, negate: bool) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(MetricField::Name.into())),
            r#match: Some(metric_matcher::Match::Exact(value.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn metric_datapoint_attr_regex_matcher(
        key: &str,
        pattern: &str,
        negate: bool,
    ) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::DatapointAttribute(attr_path(key))),
            r#match: Some(metric_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn metric_type_matcher(t: MetricType) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricType(t.into())),
            r#match: None, // Synthesized by extract_metric_field
            negate: false,
            case_insensitive: false,
        }
    }

    fn metric_temporality_matcher(t: AggregationTemporality) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::AggregationTemporality(t.into())),
            r#match: None,
            negate: false,
            case_insensitive: false,
        }
    }

    #[tokio::test]
    async fn metric_evaluate_no_policies_returns_no_match() {
        let registry = PolicyRegistry::new();
        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("cpu.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_keep_true() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "keep-cpu",
            vec![metric_name_regex_matcher("cpu", false)],
            true,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("cpu.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "keep-cpu".to_string(),
                transformed: false,
            }
        );
    }

    #[tokio::test]
    async fn metric_evaluate_keep_false_drops() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-cpu",
            vec![metric_name_regex_matcher("cpu", false)],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("cpu.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-cpu".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn metric_evaluate_no_match_returns_no_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-cpu",
            vec![metric_name_regex_matcher("cpu", false)],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("memory.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_exact_name_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "exact-cpu",
            vec![metric_name_exact_matcher("cpu.usage", false)],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Exact match
        let metric1 = TestMetric::new().with_name("cpu.usage");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "exact-cpu".to_string(),
            }
        );

        // Not exact — should not match
        let metric2 = TestMetric::new().with_name("cpu.usage.total");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_datapoint_attribute() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-by-attr",
            vec![metric_datapoint_attr_regex_matcher(
                "host", "prod-.*", false,
            )],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_datapoint_attr("host", "prod-web-1");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-by-attr".to_string(),
            }
        );

        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_datapoint_attr("host", "dev-web-1");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_resource_attribute() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-by-service",
            vec![MetricMatcher {
                field: Some(metric_matcher::Field::ResourceAttribute(attr_path(
                    "service.name",
                ))),
                r#match: Some(metric_matcher::Match::Exact("my-service".to_string())),
                negate: false,
                case_insensitive: false,
            }],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let metric = TestMetric::new()
            .with_name("cpu.usage")
            .with_resource_attr("service.name", "my-service");
        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-by-service".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn metric_evaluate_metric_type_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-gauges",
            vec![metric_type_matcher(MetricType::Gauge)],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Gauge metric — should match
        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_type(MetricType::Gauge);
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-gauges".to_string(),
            }
        );

        // Sum metric — should not match
        let metric2 = TestMetric::new()
            .with_name("requests.total")
            .with_type(MetricType::Sum);
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_aggregation_temporality_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-delta",
            vec![metric_temporality_matcher(AggregationTemporality::Delta)],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Delta metric — should match
        let metric1 = TestMetric::new()
            .with_name("requests.total")
            .with_temporality(AggregationTemporality::Delta);
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-delta".to_string(),
            }
        );

        // Cumulative metric — should not match
        let metric2 = TestMetric::new()
            .with_name("requests.total")
            .with_temporality(AggregationTemporality::Cumulative);
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_multiple_matchers_all_must_match() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-gauge-cpu",
            vec![
                metric_name_regex_matcher("cpu", false),
                metric_type_matcher(MetricType::Gauge),
            ],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Both match
        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_type(MetricType::Gauge);
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-gauge-cpu".to_string(),
            }
        );

        // Only name matches
        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_type(MetricType::Sum);
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Only type matches
        let metric3 = TestMetric::new()
            .with_name("memory.usage")
            .with_type(MetricType::Gauge);
        let result3 = engine.evaluate(&snapshot, &metric3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_most_restrictive_wins() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy_keep = make_metric_policy(
            "keep-cpu",
            vec![metric_name_regex_matcher("cpu", false)],
            true,
            true,
        );
        let policy_drop = make_metric_policy(
            "drop-cpu",
            vec![metric_name_regex_matcher("cpu", false)],
            false,
            true,
        );
        handle.update(vec![policy_keep, policy_drop]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("cpu.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-cpu".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn metric_evaluate_disabled_policy_skipped() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "disabled-metric",
            vec![metric_name_regex_matcher("cpu", false)],
            false,
            false, // disabled
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let metric = TestMetric::new().with_name("cpu.usage");

        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn mixed_log_and_metric_policies_signal_isolation() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // A log policy and a metric policy — each should only match its own signal
        let log_policy = make_policy(
            "drop-log-errors",
            vec![body_regex_matcher("error", false)],
            "none",
            true,
        );
        let metric_policy = make_metric_policy(
            "drop-cpu-metrics",
            vec![metric_name_regex_matcher("cpu", false)],
            false,
            true,
        );
        handle.update(vec![log_policy, metric_policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log with "error" — should match log policy
        let log = TestLog::new().with_body("error occurred");
        let log_result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            log_result,
            EvaluateResult::Drop {
                policy_id: "drop-log-errors".to_string(),
            }
        );

        // Metric with "cpu" — should match metric policy
        let metric = TestMetric::new().with_name("cpu.usage");
        let metric_result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert_eq!(
            metric_result,
            EvaluateResult::Drop {
                policy_id: "drop-cpu-metrics".to_string(),
            }
        );

        // Log without "error" — no match
        let log2 = TestLog::new().with_body("info message");
        let log_result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(log_result2, EvaluateResult::NoMatch);

        // Metric without "cpu" — no match
        let metric2 = TestMetric::new().with_name("memory.usage");
        let metric_result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(metric_result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_negated_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Drop metrics named "cpu" unless they have a "debug" datapoint attribute
        let policy = make_metric_policy(
            "drop-cpu-no-debug",
            vec![
                metric_name_regex_matcher("cpu", false),
                metric_datapoint_attr_regex_matcher("debug", "true", true), // negated
            ],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // CPU metric without debug — should match (drop)
        let metric1 = TestMetric::new().with_name("cpu.usage");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-cpu-no-debug".to_string(),
            }
        );

        // CPU metric with debug=true — negated matcher disqualifies
        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_datapoint_attr("debug", "true");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_description_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-by-desc",
            vec![MetricMatcher {
                field: Some(metric_matcher::Field::MetricField(
                    MetricField::Description.into(),
                )),
                r#match: Some(metric_matcher::Match::Regex("internal".to_string())),
                negate: false,
                case_insensitive: false,
            }],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let metric1 = TestMetric::new()
            .with_name("gc.pause")
            .with_description("internal gc pause time");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-by-desc".to_string(),
            }
        );

        let metric2 = TestMetric::new()
            .with_name("gc.pause")
            .with_description("garbage collection pause");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_unit_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-by-unit",
            vec![MetricMatcher {
                field: Some(metric_matcher::Field::MetricField(MetricField::Unit.into())),
                r#match: Some(metric_matcher::Match::Exact("ms".to_string())),
                negate: false,
                case_insensitive: false,
            }],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let metric1 = TestMetric::new()
            .with_name("request.duration")
            .with_unit("ms");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-by-unit".to_string(),
            }
        );

        let metric2 = TestMetric::new()
            .with_name("request.duration")
            .with_unit("s");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_scope_name_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-by-scope",
            vec![MetricMatcher {
                field: Some(metric_matcher::Field::MetricField(
                    MetricField::ScopeName.into(),
                )),
                r#match: Some(metric_matcher::Match::Regex("otel-debug".to_string())),
                negate: false,
                case_insensitive: false,
            }],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_name("otel-debug-sdk");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-by-scope".to_string(),
            }
        );

        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_name("otel-prod-sdk");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }
}
