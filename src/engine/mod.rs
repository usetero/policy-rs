//! Policy evaluation engine using Hyperscan for high-performance matching.

mod compiled;
mod keep;
mod match_key;
mod matchable;
mod rate_limiter;

pub use compiled::{CompiledDatabase, CompiledMatchers, CompiledPolicy, ExistenceCheck};
pub use keep::CompiledKeep;
pub use match_key::MatchKey;
pub use matchable::Matchable;
pub use rate_limiter::RateLimiters;

use std::time::Duration;

use crate::error::PolicyError;
use crate::registry::PolicySnapshot;

/// Result of evaluating a log record against policies.
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluateResult {
    /// No policies matched - pass through unchanged.
    NoMatch,
    /// Matched policy says keep all.
    Keep { policy_id: String },
    /// Matched policy says drop all.
    Drop { policy_id: String },
    /// Matched policy says sample at percentage.
    Sample {
        policy_id: String,
        percentage: f64,
        keep: bool,
    },
    /// Matched policy says rate limit.
    RateLimit { policy_id: String, allowed: bool },
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

        // Scan each Hyperscan database
        for (key, db) in &compiled.databases {
            // Get field value from log
            let Some(value) = log.get_field(&key.field) else {
                // Field missing - positive matchers don't match, nothing to do
                continue;
            };

            // Copy value to owned string for async scan (hyperscan requires 'static)
            let value_owned = value.to_string();

            // Scan for matches
            let matches = db.scanner.scan_bytes(value_owned).await.map_err(|e| {
                PolicyError::CompileError {
                    reason: format!("scan error: {}", e),
                }
            })?;

            for m in matches {
                if let Some(pattern_ref) = db.pattern_index.get(m.pattern_id as usize) {
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
        Ok(self.apply_keep(&winner.id, &winner.keep))
    }

    /// Apply the keep action and return the evaluation result.
    fn apply_keep(&self, policy_id: &str, keep: &CompiledKeep) -> EvaluateResult {
        match keep {
            CompiledKeep::None => EvaluateResult::Drop {
                policy_id: policy_id.to_string(),
            },
            CompiledKeep::All => EvaluateResult::Keep {
                policy_id: policy_id.to_string(),
            },
            CompiledKeep::Percentage(p) => {
                let keep = rand::random::<f64>() < *p;
                EvaluateResult::Sample {
                    policy_id: policy_id.to_string(),
                    percentage: *p * 100.0,
                    keep,
                }
            }
            CompiledKeep::RatePerSecond(limit) => {
                let allowed = self
                    .rate_limiters
                    .check(policy_id, *limit, Duration::from_secs(1));
                EvaluateResult::RateLimit {
                    policy_id: policy_id.to_string(),
                    allowed,
                }
            }
            CompiledKeep::RatePerMinute(limit) => {
                let allowed = self
                    .rate_limiters
                    .check(policy_id, *limit, Duration::from_secs(60));
                EvaluateResult::RateLimit {
                    policy_id: policy_id.to_string(),
                    allowed,
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
    use crate::proto::tero::policy::v1::{LogField, LogMatcher, LogTarget, log_matcher};
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

    fn make_policy(id: &str, matchers: Vec<LogMatcher>, keep: &str, enabled: bool) -> Policy {
        let log_target = LogTarget {
            r#match: matchers,
            keep: keep.to_string(),
            transform: None,
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
                policy_id: "keep-errors".to_string()
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
                keep: _,
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
            EvaluateResult::RateLimit { policy_id, allowed } => {
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
            EvaluateResult::RateLimit { policy_id, allowed } => {
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
                policy_id: "keep-with-trace".to_string()
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
}
