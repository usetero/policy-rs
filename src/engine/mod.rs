//! Policy evaluation engine using Vectorscan for high-performance matching.

mod compiled;
mod keep;
mod match_key;
mod matchable;
mod rate_limiter;
mod transform;
mod transformable;

pub use compiled::{CompiledDatabase, CompiledMatchers, CompiledPolicy, ExistenceCheck};
pub use keep::CompiledKeep;
pub use match_key::MatchKey;
pub use matchable::Matchable;
pub use rate_limiter::RateLimiters;
pub use transform::{CompiledTransform, TransformOp};
pub use transformable::Transformable;

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

    /// Evaluate a log record against the policies in a snapshot.
    ///
    /// This scans the log fields using the pre-compiled Hyperscan databases
    /// in the snapshot and returns the appropriate action for the log.
    ///
    /// # Arguments
    /// * `snapshot` - The policy snapshot to evaluate against
    /// * `log` - The log record to evaluate
    ///
    /// # Returns
    /// The evaluation result indicating what should happen to the log.
    pub async fn evaluate<T: Matchable>(
        &self,
        snapshot: &PolicySnapshot,
        log: &T,
    ) -> Result<EvaluateResult, PolicyError> {
        let Some(compiled) = snapshot.compiled_matchers() else {
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
        Ok(self.apply_keep(&winner.id, &winner.keep, false))
    }

    /// Evaluate a log record and apply transforms from all matching policies.
    ///
    /// This is similar to `evaluate`, but also applies transforms to the log
    /// when the log is kept (not dropped). Transforms are applied from ALL
    /// matching policies, not just the winning policy.
    ///
    /// # Arguments
    /// * `snapshot` - The policy snapshot to evaluate against
    /// * `log` - The log record to evaluate and potentially transform
    ///
    /// # Returns
    /// The evaluation result with the `transformed` flag set if transforms were applied.
    pub async fn evaluate_and_transform<T: Matchable + Transformable>(
        &self,
        snapshot: &PolicySnapshot,
        log: &mut T,
    ) -> Result<EvaluateResult, PolicyError> {
        let Some(compiled) = snapshot.compiled_matchers() else {
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

        // Determine if the log will be kept
        let will_keep = match &winner.keep {
            CompiledKeep::None => false,
            CompiledKeep::All => true,
            CompiledKeep::Percentage(p) => rand::random::<f64>() < *p,
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
    fn apply_keep(
        &self,
        policy_id: &str,
        keep: &CompiledKeep,
        transformed: bool,
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
                let keep = rand::random::<f64>() < *p;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;
    use crate::field::LogFieldSelector;
    use crate::proto::tero::policy::v1::Policy as ProtoPolicy;
    use crate::proto::tero::policy::v1::{
        LogAdd, LogField, LogMatcher, LogRedact, LogRemove, LogTarget, LogTransform, log_add,
        log_matcher, log_redact, log_remove,
    };
    use crate::registry::PolicyRegistry;
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
        fn get_field(&self, field: &LogFieldSelector) -> Option<&str> {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.as_deref(),
                    LogField::SeverityText => self.severity_text.as_deref(),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(key) => {
                    self.log_attributes.get(key).map(|s| s.as_str())
                }
                LogFieldSelector::ResourceAttribute(key) => {
                    self.resource_attributes.get(key).map(|s| s.as_str())
                }
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
                LogFieldSelector::LogAttribute(key) => self.log_attributes.remove(key).is_some(),
                LogFieldSelector::ResourceAttribute(key) => {
                    self.resource_attributes.remove(key).is_some()
                }
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
                LogFieldSelector::LogAttribute(key) => {
                    if self.log_attributes.contains_key(key) {
                        self.log_attributes
                            .insert(key.clone(), replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                LogFieldSelector::ResourceAttribute(key) => {
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
                LogFieldSelector::LogAttribute(key) => self.log_attributes.remove(key),
                LogFieldSelector::ResourceAttribute(key) => self.resource_attributes.remove(key),
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
                LogFieldSelector::LogAttribute(key) => {
                    if !upsert && self.log_attributes.contains_key(key) {
                        return false;
                    }
                    self.log_attributes.insert(key.clone(), value.to_string());
                    true
                }
                LogFieldSelector::ResourceAttribute(key) => {
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

    fn body_regex_matcher(pattern: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
        }
    }

    fn body_exact_matcher(value: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body.into())),
            r#match: Some(log_matcher::Match::Exact(value.to_string())),
            negate,
        }
    }

    fn severity_exact_matcher(value: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::SeverityText.into())),
            r#match: Some(log_matcher::Match::Exact(value.to_string())),
            negate,
        }
    }

    fn log_attr_exists_matcher(key: &str, should_exist: bool, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogAttribute(key.to_string())),
            r#match: Some(log_matcher::Match::Exists(should_exist)),
            negate,
        }
    }

    fn log_attr_regex_matcher(key: &str, pattern: &str, negate: bool) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogAttribute(key.to_string())),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
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
            field: Some(log_matcher::Field::ResourceAttribute(key.to_string())),
            r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
            negate,
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
                field: Some(log_redact::Field::LogAttribute("password".to_string())),
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
                field: Some(log_remove::Field::LogAttribute("debug_info".to_string())),
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
                field: Some(log_add::Field::LogAttribute("processed_by".to_string())),
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
                field: Some(log_add::Field::LogAttribute("should_not_exist".to_string())),
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
                field: Some(log_add::Field::LogAttribute("tag1".to_string())),
                value: "from-policy1".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };

        let transform2 = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute("tag2".to_string())),
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
                field: Some(log_redact::Field::LogAttribute("nonexistent".to_string())),
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
                field: Some(log_remove::Field::LogAttribute("temp".to_string())),
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute("secret".to_string())),
                replacement: "[REDACTED]".to_string(),
            }],
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute("processed".to_string())),
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
                field: Some(log_remove::Field::LogAttribute("nonexistent".to_string())),
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(
                    "also_nonexistent".to_string(),
                )),
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
                field: Some(log_add::Field::LogAttribute("tag".to_string())),
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
                field: Some(log_add::Field::LogAttribute("count".to_string())),
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
}
