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
                // Negated existence: matches if field existence != should_exist
                if matches {
                    // The condition was met, but it's negated, so disqualify
                    disqualified[check.policy_index] = true;
                } else {
                    // The condition was not met, negated makes it a match
                    match_counts[check.policy_index] += 1;
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
        // Engine created successfully
    }
}
