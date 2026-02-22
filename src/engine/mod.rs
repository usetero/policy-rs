//! Policy evaluation engine using Vectorscan for high-performance matching.

mod compiled;
mod keep;
mod match_key;
mod matchable;
mod rate_limiter;
pub(crate) mod sampling;
pub mod signal;
mod transform;
mod transformable;

pub use compiled::{
    CompiledDatabase, CompiledMatchers, CompiledPolicy, CompiledSamplingMode,
    CompiledTraceSampling, ExistenceCheck,
};
pub use keep::CompiledKeep;
pub use match_key::MatchKey;
pub use matchable::Matchable;
pub use rate_limiter::RateLimiters;
pub use signal::{LogSignal, MetricSignal, Signal, TraceSignal};
pub use transform::{CompiledTransform, TransformOp};
pub use transformable::Transformable;

use std::time::Duration;

use crate::error::PolicyError;
use crate::field::TraceFieldSelector;
use crate::proto::tero::policy::v1::TraceField;
use crate::registry::PolicySnapshot;

use self::sampling::{
    encode_threshold, extract_hash_seed_randomness, extract_incoming_threshold,
    extract_trace_randomness, parse_tracestate_rv, parse_tracestate_th, rejection_threshold,
    should_sample_log, threshold_to_probability,
};

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

        let Some(matching) = find_matching_policies(compiled, log)? else {
            return Ok(EvaluateResult::NoMatch);
        };

        let winner = &compiled.policies[matching[0]];

        // Extract sample key value if configured
        let sample_key_value = winner
            .sample_key
            .as_ref()
            .and_then(|key| log.get_field(key));

        let result = self.apply_keep(&winner.id, &winner.keep, false, sample_key_value.as_deref());
        let will_keep = matches!(
            &result,
            EvaluateResult::Keep { .. }
                | EvaluateResult::Sample { keep: true, .. }
                | EvaluateResult::RateLimit { allowed: true, .. }
        );
        record_match_stats(compiled, &matching, will_keep);
        Ok(result)
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

        let Some(matching) = find_matching_policies(compiled, log)? else {
            return Ok(EvaluateResult::NoMatch);
        };

        let winner = &compiled.policies[matching[0]];

        // Extract sample key value if configured (for consistent sampling)
        let sample_key_value = winner
            .sample_key
            .as_ref()
            .and_then(|key| log.get_field(key));

        // Determine if the log will be kept
        let will_keep = match &winner.keep {
            CompiledKeep::None => false,
            CompiledKeep::All => true,
            CompiledKeep::Percentage(p) => should_sample_log(*p, sample_key_value.as_deref()),
            CompiledKeep::RatePerSecond(limit) => {
                self.rate_limiters
                    .check(&winner.id, *limit, Duration::from_secs(1))
            }
            CompiledKeep::RatePerMinute(limit) => {
                self.rate_limiters
                    .check(&winner.id, *limit, Duration::from_secs(60))
            }
        };

        // Record match hit/miss stats based on outcome
        record_match_stats(compiled, &matching, will_keep);

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
                let keep = should_sample_log(*p, sample_key_value);
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

    /// Evaluate a trace span against policies, applying consistent probability sampling.
    ///
    /// This method handles the full OTel consistent probability sampling flow:
    /// 1. Standard matching (same as `evaluate`)
    /// 2. Extract 56-bit randomness from tracestate `rv` sub-key or TraceID
    /// 3. Compare randomness against the winning policy's rejection threshold
    /// 4. If sampled, write the `th` value back to the span via `Transformable::add_field`
    ///
    /// The `th` value is written to `TraceFieldSelector::SamplingThreshold`, which the
    /// user's `Transformable` implementation should handle by updating the tracestate.
    pub async fn evaluate_trace<T: Matchable<Signal = TraceSignal> + Transformable>(
        &self,
        snapshot: &PolicySnapshot,
        span: &mut T,
    ) -> Result<EvaluateResult, PolicyError> {
        let Some(compiled) = TraceSignal::compiled_matchers(snapshot) else {
            return Ok(EvaluateResult::NoMatch);
        };

        let Some(matching) = find_matching_policies(compiled, span)? else {
            return Ok(EvaluateResult::NoMatch);
        };

        let winner = &compiled.policies[matching[0]];

        // For trace policies, use consistent probability sampling with tracestate
        let trace_sampling = match &winner.trace_sampling {
            Some(ts) => ts,
            None => {
                // No sampling config — treat as keep all
                record_match_stats(compiled, &matching, true);
                return Ok(EvaluateResult::Keep {
                    policy_id: winner.id.clone(),
                    transformed: false,
                });
            }
        };

        // Short-circuit for 100% and 0%
        match &winner.keep {
            CompiledKeep::None => {
                record_match_stats(compiled, &matching, false);
                return Ok(EvaluateResult::Drop {
                    policy_id: winner.id.clone(),
                });
            }
            CompiledKeep::All => {
                // 100% sampling — write th=0 and keep
                span.add_field(
                    &TraceFieldSelector::SamplingThreshold,
                    &encode_threshold(0, trace_sampling.precision),
                    true,
                );
                record_match_stats(compiled, &matching, true);
                return Ok(EvaluateResult::Keep {
                    policy_id: winner.id.clone(),
                    transformed: true,
                });
            }
            _ => {}
        }

        // Consistency check: if both rv and th are present in tracestate,
        // verify rv >= th. If inconsistent, keep the span but erase threshold.
        // Per OTel spec: "Sampling stages should check for consistency when it
        // is a simple test, and they should erase the threshold when it is
        // apparently inconsistent."
        if let Some(tracestate) =
            span.get_field(&TraceFieldSelector::Simple(TraceField::TraceState))
        {
            if let (Some(rv), Some(th)) =
                (parse_tracestate_rv(&tracestate), parse_tracestate_th(&tracestate))
            {
                if rv < th {
                    record_match_stats(compiled, &matching, true);
                    return Ok(EvaluateResult::Keep {
                        policy_id: winner.id.clone(),
                        transformed: false,
                    });
                }
            }
        }

        // Mode-specific sampling decision
        match trace_sampling.mode {
            CompiledSamplingMode::HashSeed => {
                let randomness =
                    extract_hash_seed_randomness(span, trace_sampling.hash_seed);

                match randomness {
                    Some(r) => {
                        let keep = r >= trace_sampling.threshold;
                        if keep {
                            span.add_field(
                                &TraceFieldSelector::SamplingThreshold,
                                &encode_threshold(
                                    trace_sampling.threshold,
                                    trace_sampling.precision,
                                ),
                                true,
                            );
                        }
                        record_match_stats(compiled, &matching, keep);
                        Ok(EvaluateResult::Sample {
                            policy_id: winner.id.clone(),
                            percentage: trace_sampling.probability * 100.0,
                            keep,
                            transformed: keep,
                        })
                    }
                    None => fail_or_open(trace_sampling, compiled, &matching, &winner.id),
                }
            }
            CompiledSamplingMode::Proportional => {
                // Proportional downstream sampler per OTel spec:
                //   T_o = ProbabilityToThreshold(p * ThresholdToProbability(T_s))
                //   If R >= T_o → selected with outbound threshold T_o
                //   Otherwise → not sampled
                //
                // Where p is the configured probability and T_s is the incoming
                // threshold. When no incoming threshold exists, T_s = 0 (100%
                // incoming probability), so T_o = rejection_threshold(p * 1.0)
                // = our precomputed target threshold.
                let incoming_th = extract_incoming_threshold(span);
                let randomness = extract_trace_randomness(span);

                match randomness {
                    Some(r) => {
                        // Compute the product threshold T_o
                        let inc_prob = incoming_th
                            .map(threshold_to_probability)
                            .unwrap_or(1.0);
                        let product_prob =
                            (trace_sampling.probability * inc_prob).clamp(0.0, 1.0);
                        let t_o = rejection_threshold(product_prob);

                        let keep = r >= t_o;
                        if keep {
                            span.add_field(
                                &TraceFieldSelector::SamplingThreshold,
                                &encode_threshold(t_o, trace_sampling.precision),
                                true,
                            );
                        }
                        record_match_stats(compiled, &matching, keep);
                        Ok(EvaluateResult::Sample {
                            policy_id: winner.id.clone(),
                            percentage: trace_sampling.probability * 100.0,
                            keep,
                            transformed: keep,
                        })
                    }
                    None => fail_or_open(trace_sampling, compiled, &matching, &winner.id),
                }
            }
            CompiledSamplingMode::Equalizing => {
                // Equalizing mode preferentially keeps spans that have been
                // sampled at lower rates (higher thresholds). If the incoming
                // threshold is at least as restrictive as ours, the span is
                // already rare — keep it. Otherwise apply our threshold directly.
                let incoming_th = extract_incoming_threshold(span);
                let randomness = extract_trace_randomness(span);

                match randomness {
                    Some(r) => {
                        let (keep, effective_th) = match incoming_th {
                            Some(inc_th) if inc_th >= trace_sampling.threshold => {
                                // Already sampled at or below our target rate — keep
                                // and preserve the incoming threshold.
                                (true, inc_th)
                            }
                            _ => {
                                // Not previously sampled or sampled at a higher rate
                                // than our target. Apply our target threshold directly
                                // to equalize all sources to the same rate.
                                (r >= trace_sampling.threshold, trace_sampling.threshold)
                            }
                        };

                        if keep {
                            span.add_field(
                                &TraceFieldSelector::SamplingThreshold,
                                &encode_threshold(effective_th, trace_sampling.precision),
                                true,
                            );
                        }
                        record_match_stats(compiled, &matching, keep);
                        Ok(EvaluateResult::Sample {
                            policy_id: winner.id.clone(),
                            percentage: trace_sampling.probability * 100.0,
                            keep,
                            transformed: keep,
                        })
                    }
                    None => fail_or_open(trace_sampling, compiled, &matching, &winner.id),
                }
            }
        }
    }
}

/// Handle the case where no randomness is available for trace sampling.
///
/// Respects the `fail_closed` setting: if true, drops the span; if false, keeps it.
fn fail_or_open(
    trace_sampling: &CompiledTraceSampling,
    compiled: &CompiledMatchers<TraceSignal>,
    matching: &[usize],
    policy_id: &str,
) -> Result<EvaluateResult, PolicyError> {
    let will_keep = !trace_sampling.fail_closed;
    record_match_stats(compiled, matching, will_keep);
    if trace_sampling.fail_closed {
        Ok(EvaluateResult::Drop {
            policy_id: policy_id.to_string(),
        })
    } else {
        Ok(EvaluateResult::Keep {
            policy_id: policy_id.to_string(),
            transformed: false,
        })
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Find matching policies by scanning Vectorscan databases and checking existence.
///
/// Returns the matching policy indices sorted by restrictiveness (most restrictive first),
/// or `None` if no policies match. Does NOT record match stats — callers must call
/// `record_match_stats` after determining the keep outcome.
/// NOTE: Later we will need to iterate over all the policies for transforms on keep decisions.
fn find_matching_policies<S: Signal>(
    compiled: &CompiledMatchers<S>,
    record: &impl Matchable<Signal = S>,
) -> Result<Option<Vec<usize>>, PolicyError> {
    let policy_count = compiled.policies.len();
    if policy_count == 0 {
        return Ok(None);
    }

    // Track match counts and disqualified policies
    let mut match_counts: Vec<usize> = vec![0; policy_count];
    let mut disqualified: Vec<bool> = vec![false; policy_count];

    // Scan each Vectorscan database
    for (key, db) in &compiled.databases {
        let Some(value) = record.get_field(&key.field) else {
            continue;
        };

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

        let exists = record.get_field(&check.field).is_some();
        let field_matches = exists == check.should_exist;

        if check.is_negated {
            if field_matches {
                disqualified[check.policy_index] = true;
            }
        } else if field_matches {
            match_counts[check.policy_index] += 1;
        }
    }

    // Find matching policies (stats are recorded later, after the keep decision)
    let mut matching: Vec<usize> = Vec::new();
    for (idx, policy) in compiled.policies.iter().enumerate() {
        if !policy.enabled {
            continue;
        }
        if disqualified[idx] {
            continue;
        }
        if match_counts[idx] == policy.required_match_count {
            matching.push(idx);
        }
    }

    if matching.is_empty() {
        return Ok(None);
    }

    // Sort by restrictiveness (most restrictive first)
    matching.sort_by(|a, b| {
        compiled.policies[*b]
            .keep
            .restrictiveness()
            .cmp(&compiled.policies[*a].keep.restrictiveness())
    });

    Ok(Some(matching))
}

/// Record match hit/miss stats based on the final keep outcome.
///
/// Per spec:
/// - If kept: all matching policies record a hit.
/// - If dropped: the winner (matching[0], most restrictive) records a hit;
///   all other matching policies record a miss.
/// - Non-matching policies: no counter change.
fn record_match_stats<S: Signal>(
    compiled: &CompiledMatchers<S>,
    matching: &[usize],
    will_keep: bool,
) {
    if will_keep {
        for &idx in matching {
            compiled.policies[idx].stats.record_hit();
        }
    } else {
        compiled.policies[matching[0]].stats.record_hit();
        for &idx in &matching[1..] {
            compiled.policies[idx].stats.record_miss();
        }
    }
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
        resource_schema_url: Option<String>,
        scope_schema_url: Option<String>,
    }

    impl TestLog {
        fn new() -> Self {
            Self {
                body: None,
                severity_text: None,
                log_attributes: HashMap::new(),
                resource_attributes: HashMap::new(),
                resource_schema_url: None,
                scope_schema_url: None,
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

        fn with_resource_schema_url(mut self, url: &str) -> Self {
            self.resource_schema_url = Some(url.to_string());
            self
        }

        fn with_scope_schema_url(mut self, url: &str) -> Self {
            self.scope_schema_url = Some(url.to_string());
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
                    LogField::ResourceSchemaUrl => {
                        self.resource_schema_url.as_deref().map(Cow::Borrowed)
                    }
                    LogField::ScopeSchemaUrl => self.scope_schema_url.as_deref().map(Cow::Borrowed),
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

    fn log_resource_schema_url_matcher(url: &str) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(
                LogField::ResourceSchemaUrl.into(),
            )),
            r#match: Some(log_matcher::Match::Exact(url.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn log_scope_schema_url_matcher(url: &str) -> LogMatcher {
        LogMatcher {
            field: Some(log_matcher::Field::LogField(
                LogField::ScopeSchemaUrl.into(),
            )),
            r#match: Some(log_matcher::Match::Exact(url.to_string())),
            negate: false,
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
    async fn evaluate_rate_limit_enforces_limit() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "rate-3-per-sec",
            vec![body_regex_matcher("message", false)],
            "3/s",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Send 10 logs — first 3 should be allowed, remaining 7 should be rejected
        let mut allowed_count = 0;
        let mut rejected_count = 0;
        for _ in 0..10 {
            let log = TestLog::new().with_body("any message");
            let result = engine.evaluate(&snapshot, &log).await.unwrap();
            match result {
                EvaluateResult::RateLimit { allowed: true, .. } => allowed_count += 1,
                EvaluateResult::RateLimit { allowed: false, .. } => rejected_count += 1,
                other => panic!("expected RateLimit result, got {:?}", other),
            }
        }
        assert_eq!(allowed_count, 3);
        assert_eq!(rejected_count, 7);
    }

    #[tokio::test]
    async fn evaluate_and_transform_rate_limit_enforces_limit() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "rate-3-per-sec",
            vec![body_regex_matcher("message", false)],
            "3/s",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut allowed_count = 0;
        let mut rejected_count = 0;
        for _ in 0..10 {
            let mut log = TestLog::new().with_body("any message");
            let result = engine
                .evaluate_and_transform(&snapshot, &mut log)
                .await
                .unwrap();
            match result {
                EvaluateResult::RateLimit { allowed: true, .. } => allowed_count += 1,
                EvaluateResult::RateLimit { allowed: false, .. } => rejected_count += 1,
                other => panic!("expected RateLimit result, got {:?}", other),
            }
        }
        assert_eq!(allowed_count, 3);
        assert_eq!(rejected_count, 7);
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

        // Non-matching log - per spec, no counter change (matchers didn't fire)
        let log2 = TestLog::new().with_body("info message");
        engine.evaluate(&snapshot, &log2).await.unwrap();

        // Check stats: 1 hit from the match, 0 misses (non-match = no counter change)
        let entry = snapshot.get("stats-test").unwrap();
        assert_eq!(entry.stats.hits(), 1);
        assert_eq!(entry.stats.misses(), 0);
    }

    #[tokio::test]
    async fn evaluate_stats_drop_overrides_keep() {
        // Spec example: keep-all policy matched but drop-all wins → keep-all gets miss
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy_keep = make_policy(
            "keep-info",
            vec![body_regex_matcher("health", false)],
            "all",
            true,
        );
        let policy_drop = make_policy(
            "drop-health",
            vec![body_regex_matcher("health", false)],
            "none",
            true,
        );
        handle.update(vec![policy_keep, policy_drop]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Both policies match, but drop-health wins (more restrictive)
        let log = TestLog::new().with_body("health check ok");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-health".to_string()
            }
        );

        // drop-health: hit (winner, outcome matches its intent)
        let drop_entry = snapshot.get("drop-health").unwrap();
        assert_eq!(drop_entry.stats.hits(), 1);
        assert_eq!(drop_entry.stats.misses(), 0);

        // keep-info: miss (matched but overridden)
        let keep_entry = snapshot.get("keep-info").unwrap();
        assert_eq!(keep_entry.stats.hits(), 0);
        assert_eq!(keep_entry.stats.misses(), 1);
    }

    #[tokio::test]
    async fn evaluate_stats_all_kept() {
        // When record is kept, all matching policies get a hit
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy1 = make_policy(
            "keep-a",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
        );
        let policy2 = make_policy(
            "keep-b",
            vec![body_regex_matcher("test", false)],
            "all",
            true,
        );
        handle.update(vec![policy1, policy2]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let log = TestLog::new().with_body("test message");
        engine.evaluate(&snapshot, &log).await.unwrap();

        let entry_a = snapshot.get("keep-a").unwrap();
        assert_eq!(entry_a.stats.hits(), 1);
        assert_eq!(entry_a.stats.misses(), 0);

        let entry_b = snapshot.get("keep-b").unwrap();
        assert_eq!(entry_b.stats.hits(), 1);
        assert_eq!(entry_b.stats.misses(), 0);
    }

    #[tokio::test]
    async fn evaluate_stats_non_matching_unchanged() {
        // Non-matching policies should have no counter change
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let matching_policy = make_policy(
            "matches",
            vec![body_regex_matcher("error", false)],
            "all",
            true,
        );
        let non_matching_policy = make_policy(
            "no-match",
            vec![body_regex_matcher("warning", false)],
            "none",
            true,
        );
        handle.update(vec![matching_policy, non_matching_policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let log = TestLog::new().with_body("error occurred");
        engine.evaluate(&snapshot, &log).await.unwrap();

        // matches: hit
        let entry = snapshot.get("matches").unwrap();
        assert_eq!(entry.stats.hits(), 1);
        assert_eq!(entry.stats.misses(), 0);

        // no-match: neither counter changes
        let entry = snapshot.get("no-match").unwrap();
        assert_eq!(entry.stats.hits(), 0);
        assert_eq!(entry.stats.misses(), 0);
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
    async fn evaluate_without_sample_key_field_falls_back_to_keep() {
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

        // Log without the sample key field - per OTel spec, falls back to keep
        let log = TestLog::new().with_body("test");

        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        // Missing sample key value → always keep (per Go conformance)
        assert!(matches!(result, EvaluateResult::Sample { keep: true, .. }));
    }

    #[tokio::test]
    async fn log_evaluate_resource_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "drop-old-schema",
            vec![log_resource_schema_url_matcher("https://old-schema/1.0")],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching schema URL — should drop
        let log1 = TestLog::new()
            .with_body("test")
            .with_resource_schema_url("https://old-schema/1.0");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-old-schema".to_string(),
            }
        );

        // Different schema URL — should not match
        let log2 = TestLog::new()
            .with_body("test")
            .with_resource_schema_url("https://new-schema/2.0");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn log_evaluate_scope_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_policy(
            "drop-old-scope-schema",
            vec![log_scope_schema_url_matcher("https://old-scope/1.0")],
            "none",
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching scope schema URL — should drop
        let log1 = TestLog::new()
            .with_body("test")
            .with_scope_schema_url("https://old-scope/1.0");
        let result1 = engine.evaluate(&snapshot, &log1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-old-scope-schema".to_string(),
            }
        );

        // Different scope schema URL — should not match
        let log2 = TestLog::new()
            .with_body("test")
            .with_scope_schema_url("https://new-scope/2.0");
        let result2 = engine.evaluate(&snapshot, &log2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
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
        scope_version: Option<String>,
        resource_schema_url: Option<String>,
        scope_schema_url: Option<String>,
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
                scope_version: None,
                resource_schema_url: None,
                scope_schema_url: None,
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

        fn with_scope_version(mut self, version: &str) -> Self {
            self.scope_version = Some(version.to_string());
            self
        }

        fn with_resource_schema_url(mut self, url: &str) -> Self {
            self.resource_schema_url = Some(url.to_string());
            self
        }

        fn with_scope_schema_url(mut self, url: &str) -> Self {
            self.scope_schema_url = Some(url.to_string());
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
                    MetricField::ScopeVersion => self.scope_version.as_deref().map(Cow::Borrowed),
                    MetricField::ResourceSchemaUrl => {
                        self.resource_schema_url.as_deref().map(Cow::Borrowed)
                    }
                    MetricField::ScopeSchemaUrl => {
                        self.scope_schema_url.as_deref().map(Cow::Borrowed)
                    }
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

    fn metric_scope_version_exact_matcher(version: &str) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(
                MetricField::ScopeVersion.into(),
            )),
            r#match: Some(metric_matcher::Match::Exact(version.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn metric_resource_schema_url_matcher(url: &str) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(
                MetricField::ResourceSchemaUrl.into(),
            )),
            r#match: Some(metric_matcher::Match::Exact(url.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn metric_scope_schema_url_matcher(url: &str) -> MetricMatcher {
        MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(
                MetricField::ScopeSchemaUrl.into(),
            )),
            r#match: Some(metric_matcher::Match::Exact(url.to_string())),
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
    async fn metric_evaluate_scope_version() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-old-version",
            vec![metric_scope_version_exact_matcher("0.1.0")],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching scope version — should drop
        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_version("0.1.0");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-old-version".to_string(),
            }
        );

        // Different version — should not match
        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_version("1.0.0");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_resource_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-old-schema",
            vec![metric_resource_schema_url_matcher("https://old-schema/1.0")],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching schema URL — should drop
        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_resource_schema_url("https://old-schema/1.0");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-old-schema".to_string(),
            }
        );

        // Different schema URL — should not match
        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_resource_schema_url("https://new-schema/2.0");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn metric_evaluate_scope_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_metric_policy(
            "drop-old-scope-schema",
            vec![metric_scope_schema_url_matcher("https://old-scope/1.0")],
            false,
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching scope schema URL — should drop
        let metric1 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_schema_url("https://old-scope/1.0");
        let result1 = engine.evaluate(&snapshot, &metric1).await.unwrap();
        assert_eq!(
            result1,
            EvaluateResult::Drop {
                policy_id: "drop-old-scope-schema".to_string(),
            }
        );

        // Different scope schema URL — should not match
        let metric2 = TestMetric::new()
            .with_name("cpu.usage")
            .with_scope_schema_url("https://new-scope/2.0");
        let result2 = engine.evaluate(&snapshot, &metric2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
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

    // ==================== Trace Tests ====================

    use crate::engine::signal::TraceSignal;
    use crate::field::TraceFieldSelector;
    use crate::engine::sampling::MAX_THRESHOLD;
    use crate::proto::tero::policy::v1::{
        SamplingMode, SpanKind, SpanStatusCode, TraceField, TraceMatcher, TraceSamplingConfig,
        TraceTarget, trace_matcher,
    };

    /// Test span implementation for trace evaluation tests.
    struct TestSpan {
        name: Option<String>,
        trace_id: Option<String>,
        tracestate: Option<String>,
        span_kind: Option<SpanKind>,
        span_status: Option<SpanStatusCode>,
        span_attributes: HashMap<String, String>,
        resource_attributes: HashMap<String, String>,
        scope_name: Option<String>,
        scope_version: Option<String>,
        resource_schema_url: Option<String>,
        scope_schema_url: Option<String>,
        event_name: Option<String>,
        /// Written by the engine via `add_field` for `SamplingThreshold`.
        th_value: Option<String>,
    }

    impl TestSpan {
        fn new() -> Self {
            Self {
                name: None,
                trace_id: None,
                tracestate: None,
                span_kind: None,
                span_status: None,
                span_attributes: HashMap::new(),
                resource_attributes: HashMap::new(),
                scope_name: None,
                scope_version: None,
                resource_schema_url: None,
                scope_schema_url: None,
                event_name: None,
                th_value: None,
            }
        }

        fn with_name(mut self, name: &str) -> Self {
            self.name = Some(name.to_string());
            self
        }

        fn with_trace_id(mut self, trace_id: &str) -> Self {
            self.trace_id = Some(trace_id.to_string());
            self
        }

        fn with_tracestate(mut self, tracestate: &str) -> Self {
            self.tracestate = Some(tracestate.to_string());
            self
        }

        fn with_span_kind(mut self, kind: SpanKind) -> Self {
            self.span_kind = Some(kind);
            self
        }

        fn with_span_status(mut self, status: SpanStatusCode) -> Self {
            self.span_status = Some(status);
            self
        }

        fn with_span_attr(mut self, key: &str, value: &str) -> Self {
            self.span_attributes
                .insert(key.to_string(), value.to_string());
            self
        }

        #[allow(dead_code)]
        fn with_resource_attr(mut self, key: &str, value: &str) -> Self {
            self.resource_attributes
                .insert(key.to_string(), value.to_string());
            self
        }

        fn with_scope_name(mut self, name: &str) -> Self {
            self.scope_name = Some(name.to_string());
            self
        }

        fn with_scope_version(mut self, version: &str) -> Self {
            self.scope_version = Some(version.to_string());
            self
        }

        fn with_resource_schema_url(mut self, url: &str) -> Self {
            self.resource_schema_url = Some(url.to_string());
            self
        }

        fn with_scope_schema_url(mut self, url: &str) -> Self {
            self.scope_schema_url = Some(url.to_string());
            self
        }

        fn with_event_name(mut self, name: &str) -> Self {
            self.event_name = Some(name.to_string());
            self
        }
    }

    impl Matchable for TestSpan {
        type Signal = TraceSignal;

        fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                TraceFieldSelector::Simple(trace_field) => match trace_field {
                    TraceField::Name => self.name.as_deref().map(Cow::Borrowed),
                    TraceField::TraceId => self.trace_id.as_deref().map(Cow::Borrowed),
                    TraceField::TraceState => self.tracestate.as_deref().map(Cow::Borrowed),
                    TraceField::ScopeName => self.scope_name.as_deref().map(Cow::Borrowed),
                    TraceField::ScopeVersion => self.scope_version.as_deref().map(Cow::Borrowed),
                    TraceField::ResourceSchemaUrl => {
                        self.resource_schema_url.as_deref().map(Cow::Borrowed)
                    }
                    TraceField::ScopeSchemaUrl => {
                        self.scope_schema_url.as_deref().map(Cow::Borrowed)
                    }
                    _ => None,
                },
                TraceFieldSelector::SpanKind => self
                    .span_kind
                    .map(|k| Cow::Owned(k.as_str_name().to_string())),
                TraceFieldSelector::SpanStatus => self
                    .span_status
                    .map(|s| Cow::Owned(s.as_str_name().to_string())),
                TraceFieldSelector::EventName => self.event_name.as_deref().map(Cow::Borrowed),
                TraceFieldSelector::SpanAttribute(path) => path
                    .first()
                    .and_then(|key| self.span_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                TraceFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                _ => None,
            }
        }
    }

    impl Transformable for TestSpan {
        fn remove_field(&mut self, _field: &TraceFieldSelector) -> bool {
            false
        }

        fn redact_field(&mut self, _field: &TraceFieldSelector, _replacement: &str) -> bool {
            false
        }

        fn rename_field(&mut self, _from: &TraceFieldSelector, _to: &str, _upsert: bool) -> bool {
            false
        }

        fn add_field(&mut self, field: &TraceFieldSelector, value: &str, _upsert: bool) -> bool {
            if matches!(field, TraceFieldSelector::SamplingThreshold) {
                self.th_value = Some(value.to_string());
                true
            } else {
                false
            }
        }
    }

    fn make_trace_policy(
        id: &str,
        matchers: Vec<TraceMatcher>,
        sampling: Option<TraceSamplingConfig>,
        enabled: bool,
    ) -> Policy {
        let trace_target = TraceTarget {
            r#match: matchers,
            keep: sampling,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Trace(
                trace_target,
            )),
            ..Default::default()
        };

        Policy::new(proto)
    }

    fn trace_name_regex_matcher(pattern: &str, negate: bool) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::TraceField(TraceField::Name.into())),
            r#match: Some(trace_matcher::Match::Regex(pattern.to_string())),
            negate,
            case_insensitive: false,
        }
    }

    fn trace_span_kind_matcher(kind: SpanKind) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::SpanKind(kind.into())),
            r#match: None,
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_span_status_matcher(status: SpanStatusCode) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::SpanStatus(status.into())),
            r#match: None,
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_span_attr_regex_matcher(key: &str, pattern: &str) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::SpanAttribute(
                crate::proto::tero::policy::v1::AttributePath {
                    path: vec![key.to_string()],
                },
            )),
            r#match: Some(trace_matcher::Match::Regex(pattern.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_event_name_matcher(name: &str) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::EventName(name.to_string())),
            r#match: None, // Synthesized by extract_trace_field
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_scope_name_matcher(name: &str) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::TraceField(
                TraceField::ScopeName.into(),
            )),
            r#match: Some(trace_matcher::Match::Exact(name.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_resource_schema_url_matcher(url: &str) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::TraceField(
                TraceField::ResourceSchemaUrl.into(),
            )),
            r#match: Some(trace_matcher::Match::Exact(url.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn trace_scope_schema_url_matcher(url: &str) -> TraceMatcher {
        TraceMatcher {
            field: Some(trace_matcher::Field::TraceField(
                TraceField::ScopeSchemaUrl.into(),
            )),
            r#match: Some(trace_matcher::Match::Exact(url.to_string())),
            negate: false,
            case_insensitive: false,
        }
    }

    fn sampling_config(percentage: f32) -> TraceSamplingConfig {
        TraceSamplingConfig {
            percentage,
            mode: None,
            sampling_precision: Some(4),
            hash_seed: None,
            fail_closed: Some(true),
        }
    }

    // Helper: create a trace_id whose last 14 hex chars produce a known randomness
    fn trace_id_with_randomness(randomness: u64) -> String {
        // Pad to 32 hex chars total, last 14 carry the randomness
        format!("{:018x}{:014x}", 0u64, randomness)
    }

    #[tokio::test]
    async fn trace_evaluate_no_policies_returns_no_match() {
        let registry = PolicyRegistry::new();
        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut span = TestSpan::new().with_name("GET /api/users");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_sampled_100_percent() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "keep-all",
            vec![trace_name_regex_matcher("GET.*", false)],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut span = TestSpan::new()
            .with_name("GET /api/users")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "keep-all".to_string(),
                transformed: true,
            }
        );
        // th="0" should be written (100% = threshold 0)
        assert_eq!(span.th_value, Some("0".to_string()));
    }

    #[tokio::test]
    async fn trace_evaluate_not_sampled_0_percent() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-all",
            vec![trace_name_regex_matcher("GET.*", false)],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut span = TestSpan::new()
            .with_name("GET /api/users")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "drop-all".to_string(),
            }
        );
        // No th should be written
        assert_eq!(span.th_value, None);
    }

    #[tokio::test]
    async fn trace_evaluate_partial_sampling_with_traceid() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "sample-50",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(50.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Use a known randomness value via trace_id
        let threshold = rejection_threshold(0.5);
        // Randomness above threshold → kept
        let high_randomness = threshold + 1;
        let mut span_keep = TestSpan::new()
            .with_name("test-span")
            .with_trace_id(&trace_id_with_randomness(high_randomness));

        let result = engine
            .evaluate_trace(&snapshot, &mut span_keep)
            .await
            .unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep, "High randomness should be kept");
                assert!(
                    span_keep.th_value.is_some(),
                    "th should be written when kept"
                );
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }

        // Randomness below threshold → dropped
        let low_randomness = threshold.saturating_sub(1);
        let mut span_drop = TestSpan::new()
            .with_name("test-span")
            .with_trace_id(&trace_id_with_randomness(low_randomness));

        let result = engine
            .evaluate_trace(&snapshot, &mut span_drop)
            .await
            .unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(!keep, "Low randomness should be dropped");
                assert!(
                    span_drop.th_value.is_none(),
                    "th should not be written when dropped"
                );
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn trace_evaluate_span_kind_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "server-spans",
            vec![trace_span_kind_matcher(SpanKind::Server)],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching span kind
        let mut span1 = TestSpan::new()
            .with_name("handle-request")
            .with_span_kind(SpanKind::Server)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Keep { .. }));

        // Non-matching span kind
        let mut span2 = TestSpan::new()
            .with_name("call-service")
            .with_span_kind(SpanKind::Client)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_span_status_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "error-spans",
            vec![trace_span_status_matcher(SpanStatusCode::Error)],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span1 = TestSpan::new()
            .with_name("failing-op")
            .with_span_status(SpanStatusCode::Error)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Keep { .. }));

        let mut span2 = TestSpan::new()
            .with_name("ok-op")
            .with_span_status(SpanStatusCode::Ok)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_span_attribute() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "http-spans",
            vec![trace_span_attr_regex_matcher("http.method", "GET|POST")],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span1 = TestSpan::new()
            .with_name("request")
            .with_span_attr("http.method", "GET")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));

        let mut span2 = TestSpan::new()
            .with_name("request")
            .with_span_attr("http.method", "DELETE")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_writes_th_to_tracestate() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // 50% sampling with precision 4
        let policy = make_trace_policy(
            "sample-50",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(50.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Use a high randomness trace ID that will be kept at 50%
        let threshold = rejection_threshold(0.5);
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1000));

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep);
                // th should be a non-empty hex string
                let th = span.th_value.as_ref().unwrap();
                assert!(!th.is_empty());
                // Should not have trailing zeros
                assert!(!th.ends_with('0') || th == "0");
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn trace_evaluate_uses_tracestate_rv_over_traceid() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "sample-50",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(50.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);
        // TraceID randomness would be dropped (low), but tracestate rv is high (kept)
        let high_rv = threshold + 1000;
        let rv_hex = format!("{:014x}", high_rv);
        let tracestate = format!("ot=rv:{}", rv_hex);

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(0)) // low randomness (would be dropped)
            .with_tracestate(&tracestate);

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep, "Should use tracestate rv (high) over trace_id (low)");
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn trace_evaluate_multiple_matchers_and_logic() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Requires both name AND span_kind to match
        let policy = make_trace_policy(
            "server-gets",
            vec![
                trace_name_regex_matcher("GET.*", false),
                trace_span_kind_matcher(SpanKind::Server),
            ],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Both match
        let mut span1 = TestSpan::new()
            .with_name("GET /users")
            .with_span_kind(SpanKind::Server)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Keep { .. }));

        // Only name matches
        let mut span2 = TestSpan::new()
            .with_name("GET /users")
            .with_span_kind(SpanKind::Client)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Only span kind matches
        let mut span3 = TestSpan::new()
            .with_name("POST /users")
            .with_span_kind(SpanKind::Server)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result3 = engine.evaluate_trace(&snapshot, &mut span3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_most_restrictive_wins() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Two policies match, one at 100% and one at 10%
        let policy_100 = make_trace_policy(
            "keep-all",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(100.0)),
            true,
        );
        let policy_10 = make_trace_policy(
            "sample-10",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(10.0)),
            true,
        );
        handle.update(vec![policy_100, policy_10]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        // 10% is more restrictive than 100%
        match result {
            EvaluateResult::Sample {
                policy_id,
                percentage,
                ..
            } => {
                assert_eq!(policy_id, "sample-10");
                assert!((percentage - 10.0).abs() < 0.01);
            }
            _ => panic!("expected Sample result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn trace_evaluate_negated_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Match all spans EXCEPT those with name containing "health"
        let policy = make_trace_policy(
            "skip-health",
            vec![
                trace_name_regex_matcher(".+", false),
                trace_name_regex_matcher("health", true), // negated
            ],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Non-health span matches
        let mut span1 = TestSpan::new()
            .with_name("GET /api/users")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Keep { .. }));

        // Health span is disqualified
        let mut span2 = TestSpan::new()
            .with_name("GET /health")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_fail_closed_no_randomness() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let mut config = sampling_config(50.0);
        config.fail_closed = Some(true);

        let policy = make_trace_policy(
            "fail-closed",
            vec![trace_name_regex_matcher(".+", false)],
            Some(config),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Span with no trace_id and no tracestate — no randomness available
        let mut span = TestSpan::new().with_name("test");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Drop {
                policy_id: "fail-closed".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn trace_evaluate_fail_open_no_randomness() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let mut config = sampling_config(50.0);
        config.fail_closed = Some(false);

        let policy = make_trace_policy(
            "fail-open",
            vec![trace_name_regex_matcher(".+", false)],
            Some(config),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Span with no trace_id and no tracestate
        let mut span = TestSpan::new().with_name("test");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert_eq!(
            result,
            EvaluateResult::Keep {
                policy_id: "fail-open".to_string(),
                transformed: false,
            }
        );
    }

    #[tokio::test]
    async fn mixed_log_metric_trace_signal_isolation() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Register one policy of each signal type
        let log_policy = make_policy(
            "log-policy",
            vec![body_regex_matcher("error", false)],
            "none",
            true,
        );

        let metric_policy = {
            let matcher = MetricMatcher {
                field: Some(metric_matcher::Field::MetricField(MetricField::Name.into())),
                r#match: Some(metric_matcher::Match::Regex("cpu.*".to_string())),
                negate: false,
                case_insensitive: false,
            };
            let metric_target = crate::proto::tero::policy::v1::MetricTarget {
                r#match: vec![matcher],
                keep: false,
            };
            let proto = ProtoPolicy {
                id: "metric-policy".to_string(),
                name: "metric-policy".to_string(),
                enabled: true,
                target: Some(crate::proto::tero::policy::v1::policy::Target::Metric(
                    metric_target,
                )),
                ..Default::default()
            };
            Policy::new(proto)
        };

        let trace_policy = make_trace_policy(
            "trace-policy",
            vec![trace_name_regex_matcher("GET.*", false)],
            Some(sampling_config(100.0)),
            true,
        );

        handle.update(vec![log_policy, metric_policy, trace_policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log evaluation — only log policy should match
        let log = TestLog::new().with_body("error occurred");
        let result = engine.evaluate(&snapshot, &log).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));

        // Metric evaluation — only metric policy should match
        let metric = TestMetric::new().with_name("cpu.usage");
        let result = engine.evaluate(&snapshot, &metric).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));

        // Trace evaluation — only trace policy should match
        let mut span = TestSpan::new()
            .with_name("GET /api")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));

        // Cross-signal isolation: trace span should NOT match log/metric policies
        let mut span2 = TestSpan::new().with_name("error"); // matches log pattern but this is a trace
        let result = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result, EvaluateResult::NoMatch); // "error" doesn't match "GET.*"
    }

    #[tokio::test]
    async fn trace_evaluate_event_name_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-exception-events",
            vec![trace_event_name_matcher("exception")],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Span with exception event — should match and drop
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_event_name("exception")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Drop { .. }));

        // Span with different event — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_event_name("db_query")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Span with no event — should not match
        let mut span3 = TestSpan::new()
            .with_name("GET /api")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result3 = engine.evaluate_trace(&snapshot, &mut span3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_scope_name_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-debug-sdk",
            vec![trace_scope_name_matcher("otel-debug-sdk")],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching scope name — should drop
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_name("otel-debug-sdk")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Drop { .. }));

        // Different scope name — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_name("otel-prod-sdk")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_scope_version_matcher() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-old-version",
            vec![TraceMatcher {
                field: Some(trace_matcher::Field::TraceField(
                    TraceField::ScopeVersion.into(),
                )),
                r#match: Some(trace_matcher::Match::Exact("0.1.0".to_string())),
                negate: false,
                case_insensitive: false,
            }],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching version — should drop
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_version("0.1.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Drop { .. }));

        // Different version — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_version("1.0.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_resource_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-old-schema",
            vec![trace_resource_schema_url_matcher("https://old-schema/1.0")],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching schema URL — should drop
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_resource_schema_url("https://old-schema/1.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Drop { .. }));

        // Different schema URL — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_resource_schema_url("https://new-schema/2.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_scope_schema_url() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-old-scope-schema",
            vec![trace_scope_schema_url_matcher("https://old-scope/1.0")],
            Some(sampling_config(0.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Matching scope schema URL — should drop
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_schema_url("https://old-scope/1.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Drop { .. }));

        // Different scope schema URL — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_scope_schema_url("https://new-scope/2.0")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);
    }

    #[tokio::test]
    async fn trace_evaluate_span_status_unspecified() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "match-unset-status",
            vec![trace_span_status_matcher(SpanStatusCode::Unspecified)],
            Some(sampling_config(100.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Span with Unspecified status — should match
        let mut span1 = TestSpan::new()
            .with_name("GET /api")
            .with_span_status(SpanStatusCode::Unspecified)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result1 = engine.evaluate_trace(&snapshot, &mut span1).await.unwrap();
        assert!(matches!(result1, EvaluateResult::Keep { .. }));

        // Span with Ok status — should not match
        let mut span2 = TestSpan::new()
            .with_name("GET /api")
            .with_span_status(SpanStatusCode::Ok)
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result2 = engine.evaluate_trace(&snapshot, &mut span2).await.unwrap();
        assert_eq!(result2, EvaluateResult::NoMatch);

        // Span with no status set — should not match (field doesn't exist)
        let mut span3 = TestSpan::new()
            .with_name("GET /api")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result3 = engine.evaluate_trace(&snapshot, &mut span3).await.unwrap();
        assert_eq!(result3, EvaluateResult::NoMatch);
    }

    // ==================== Sampling Mode Tests ====================

    // Generate a trace ID whose last 14 hex chars are spread across the full
    // 56-bit range. Uses a multiplier to distribute i values evenly.
    fn distributed_trace_id(i: u64) -> String {
        // Golden ratio constant scaled to 56-bit range for even distribution
        let randomness = i.wrapping_mul(0x9E3779B97F4A7) & (MAX_THRESHOLD - 1);
        trace_id_with_randomness(randomness)
    }

    fn sampling_config_with_mode(percentage: f32, mode: SamplingMode) -> TraceSamplingConfig {
        TraceSamplingConfig {
            percentage,
            mode: Some(mode as i32),
            sampling_precision: Some(4),
            hash_seed: None,
            fail_closed: Some(true),
        }
    }

    fn sampling_config_with_seed(percentage: f32, hash_seed: u32) -> TraceSamplingConfig {
        TraceSamplingConfig {
            percentage,
            mode: Some(SamplingMode::HashSeed as i32),
            sampling_precision: Some(4),
            hash_seed: Some(hash_seed),
            fail_closed: Some(true),
        }
    }

    // ==================== HashSeed Mode Tests ====================

    #[tokio::test]
    async fn hash_seed_mode_default_seed_matches_basic_behavior() {
        // With seed=0 (default), hash_seed mode should behave identically
        // to the original implementation (trace ID randomness directly).
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "hash-seed-default",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::HashSeed)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);

        // High randomness → kept
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(keep),
            _ => panic!("expected Sample, got {:?}", result),
        }

        // Low randomness → dropped
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold - 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(!keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn hash_seed_mode_nonzero_seed_changes_decisions() {
        // A non-zero seed should produce different keep/drop decisions
        // compared to seed=0 for the same trace IDs.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "hash-seed-42",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(50.0, 42)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Run many trace IDs and verify ~50% are kept
        let mut kept = 0;
        let total = 500;
        for i in 0..total {
            let trace_id = distributed_trace_id(i);
            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id(&trace_id);
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            if let EvaluateResult::Sample { keep: true, .. } = result {
                kept += 1;
            }
        }
        assert!(
            kept > 200 && kept < 300,
            "Expected ~50% kept with seed 42, got {}/{}",
            kept,
            total,
        );
    }

    #[tokio::test]
    async fn hash_seed_mode_different_seeds_different_sets() {
        // Two different seeds at the same percentage should keep different
        // subsets of trace IDs (with high probability).
        let trace_ids: Vec<String> = (0..500u64).map(distributed_trace_id).collect();
        let engine = PolicyEngine::new();

        let mut results_seed1 = Vec::new();
        let mut results_seed2 = Vec::new();

        for seed in [1u32, 1000] {
            let registry = PolicyRegistry::new();
            let handle = registry.register_provider();
            let policy = make_trace_policy(
                "test",
                vec![trace_name_regex_matcher(".+", false)],
                Some(sampling_config_with_seed(50.0, seed)),
                true,
            );
            handle.update(vec![policy]);
            let snapshot = registry.snapshot();

            for tid in &trace_ids {
                let mut span = TestSpan::new().with_name("test").with_trace_id(tid);
                let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
                let kept = matches!(result, EvaluateResult::Sample { keep: true, .. });
                if seed == 1 {
                    results_seed1.push(kept);
                } else {
                    results_seed2.push(kept);
                }
            }
        }

        // Count differences — with independent hash functions, ~50% of spans
        // should differ in keep/drop between two seeds at 50% sampling rate.
        let differences: usize = results_seed1
            .iter()
            .zip(results_seed2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differences > 50,
            "Expected different seeds to produce different decisions, only {} differences out of {}",
            differences,
            trace_ids.len(),
        );
    }

    #[tokio::test]
    async fn hash_seed_mode_deterministic() {
        // Same seed + same trace ID should always produce the same decision.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "deterministic",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(50.0, 99)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();
        let trace_id = "0af7651916cd43dd8448eb211c80319c";

        let mut first_result = None;
        for _ in 0..10 {
            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id(trace_id);
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            let kept = matches!(result, EvaluateResult::Sample { keep: true, .. });
            if let Some(first) = first_result {
                assert_eq!(kept, first, "Decisions must be consistent for same input");
            } else {
                first_result = Some(kept);
            }
        }
    }

    #[tokio::test]
    async fn hash_seed_mode_100_percent() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "keep-all",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(100.0, 42)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));
        assert_eq!(span.th_value, Some("0".to_string()));
    }

    #[tokio::test]
    async fn hash_seed_mode_0_percent() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "drop-all",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(0.0, 42)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    #[tokio::test]
    async fn hash_seed_mode_seed_zero_uses_tracestate_rv() {
        // With seed=0, the rv sub-key from tracestate should be preferred.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "seed-0-rv",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(50.0, 0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);
        let high_rv = threshold + 1000;

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(0)) // low (would drop)
            .with_tracestate(&format!("ot=rv:{:014x}", high_rv));

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep, "Seed 0 should use tracestate rv (high) over trace_id (low)");
            }
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn hash_seed_mode_nonzero_seed_ignores_tracestate_rv() {
        // With non-zero seed, the rv sub-key should be ignored.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "seed-42-no-rv",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(50.0, 42)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Run many trace IDs with a tracestate rv that would always keep (high value)
        // and verify that some are still dropped (seed doesn't use rv)
        let high_rv = MAX_THRESHOLD - 1;
        let mut dropped = 0;
        for i in 0..200u64 {
            let trace_id = distributed_trace_id(i);
            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id(&trace_id)
                .with_tracestate(&format!("ot=rv:{:014x}", high_rv));
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            if let EvaluateResult::Sample { keep: false, .. } = result {
                dropped += 1;
            }
        }
        assert!(
            dropped > 50,
            "Non-zero seed should ignore rv and drop ~50%, but only dropped {}/200",
            dropped,
        );
    }

    #[tokio::test]
    async fn hash_seed_mode_fail_closed_no_trace_id() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "fail-closed-seed",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_seed(50.0, 42)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new().with_name("test"); // no trace_id
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    // ==================== Proportional Mode Tests ====================

    #[tokio::test]
    async fn proportional_mode_no_incoming_th_applies_target() {
        // Without an incoming th in tracestate, proportional mode should
        // apply the target threshold directly (same as hash_seed mode).
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-no-th",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);

        // High randomness → kept
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep);
                assert!(span.th_value.is_some());
            }
            _ => panic!("expected Sample, got {:?}", result),
        }

        // Low randomness → dropped
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold - 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(!keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn proportional_mode_multiplies_incoming_probability() {
        // Per OTel spec: T_o = ProbabilityToThreshold(p * ThresholdToProbability(T_s))
        // With p=0.5 and incoming at 10% (T_s for 10%), the product probability
        // is 0.5 * 0.1 = 0.05, so T_o = rejection_threshold(0.05).
        // Only spans with R >= T_o are kept.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-multiply",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: 10% sampling
        let incoming_th = rejection_threshold(0.1);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        // Product probability = 0.5 * 0.1 = 0.05
        let t_o = rejection_threshold(0.05);

        // High randomness above T_o → kept
        let mut span_keep = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(t_o + 1))
            .with_tracestate(&tracestate);
        let result = engine
            .evaluate_trace(&snapshot, &mut span_keep)
            .await
            .unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep);
                // Written th should encode T_o
                let expected_th = super::sampling::encode_threshold(t_o, 4);
                assert_eq!(span_keep.th_value.as_ref().unwrap(), &expected_th);
            }
            _ => panic!("expected Sample, got {:?}", result),
        }

        // Low randomness below T_o → dropped
        let mut span_drop = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(t_o.saturating_sub(1)))
            .with_tracestate(&tracestate);
        let result = engine
            .evaluate_trace(&snapshot, &mut span_drop)
            .await
            .unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(!keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn proportional_mode_reduces_by_configured_factor() {
        // Per OTel spec: T_o = ProbabilityToThreshold(p * ThresholdToProbability(T_s))
        // With p=0.1 (10%) and incoming at 50%: product = 0.1 * 0.5 = 0.05
        // So ~5% of spans should be kept.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-reduce",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(10.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: 50% sampling
        let incoming_th = rejection_threshold(0.5);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        let mut kept = 0;
        let total = 2000;
        for i in 0..total {
            let trace_id = distributed_trace_id(i);
            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id(&trace_id)
                .with_tracestate(&tracestate);
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            if let EvaluateResult::Sample { keep: true, .. } = result {
                kept += 1;
            }
        }
        // 5% of 2000 = 100
        assert!(
            kept > 50 && kept < 150,
            "Expected ~5% kept (10% * 50% incoming), got {}/{}",
            kept,
            total,
        );
    }

    #[tokio::test]
    async fn proportional_mode_100_percent_short_circuits() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-100",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(100.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));
        assert_eq!(span.th_value, Some("0".to_string()));
    }

    #[tokio::test]
    async fn proportional_mode_0_percent_short_circuits() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-0",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(0.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    #[tokio::test]
    async fn proportional_mode_incoming_th_zero_keeps_all_at_target() {
        // Incoming th=0 means incoming probability is 100%.
        // Proportional should then apply the target threshold directly.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-incoming-100",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // th=0 means 100% incoming
        let tracestate = "ot=th:0";
        let threshold = rejection_threshold(0.5);

        // High randomness → kept
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1))
            .with_tracestate(tracestate);
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn proportional_mode_fail_closed_no_randomness() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-fail-closed",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new().with_name("test"); // no trace_id
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    #[tokio::test]
    async fn proportional_mode_fail_open_no_randomness() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let mut config = sampling_config_with_mode(50.0, SamplingMode::Proportional);
        config.fail_closed = Some(false);

        let policy = make_trace_policy(
            "proportional-fail-open",
            vec![trace_name_regex_matcher(".+", false)],
            Some(config),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new().with_name("test"); // no trace_id
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));
    }

    #[tokio::test]
    async fn proportional_mode_writes_target_th_when_adjusting() {
        // When proportional mode adjusts (incoming is less restrictive),
        // the written th should be the target threshold.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "proportional-th-write",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(10.0, SamplingMode::Proportional)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: th=0 (100% probability, less restrictive than 10%)
        let target_th = rejection_threshold(0.1);

        // Use high randomness to ensure span is kept
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(MAX_THRESHOLD - 1))
            .with_tracestate("ot=th:0");

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep: true, .. } => {
                let written_th = span.th_value.as_ref().unwrap();
                let expected_th = super::sampling::encode_threshold(target_th, 4);
                assert_eq!(written_th, &expected_th);
            }
            _ => panic!("expected Sample(keep=true), got {:?}", result),
        }
    }

    // ==================== Equalizing Mode Tests ====================

    #[tokio::test]
    async fn equalizing_mode_no_incoming_th_applies_target() {
        // Without incoming th, equalizing should apply the target threshold directly.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "equalizing-no-th",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);

        // High randomness → kept
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(keep),
            _ => panic!("expected Sample, got {:?}", result),
        }

        // Low randomness → dropped
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold - 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(!keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn equalizing_mode_incoming_th_more_restrictive_keeps() {
        // If incoming th >= target th (span already rare enough), keep it.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Target: 50%
        let policy = make_trace_policy(
            "equalizing-keep-rare",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: 10% (more restrictive)
        let incoming_th = rejection_threshold(0.1);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        // Even with low randomness that would normally fail the 50% threshold
        let target_th = rejection_threshold(0.5);
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(target_th - 1))
            .with_tracestate(&tracestate);

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => {
                assert!(keep, "Equalizing should keep spans already sampled below target");
            }
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn equalizing_mode_incoming_th_less_restrictive_applies_target() {
        // If incoming th < target th (span sampled at higher rate), apply target directly.
        // This is different from proportional which adjusts.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Target: 10%
        let policy = make_trace_policy(
            "equalizing-hard-cut",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(10.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: 50% (less restrictive than 10%)
        let incoming_th = rejection_threshold(0.5);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        // Run many spans and verify ~10% are kept (equalizing applies target directly)
        let mut kept = 0;
        let total = 1000;
        for i in 0..total {
            let trace_id = distributed_trace_id(i);
            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id(&trace_id)
                .with_tracestate(&tracestate);
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            if let EvaluateResult::Sample { keep: true, .. } = result {
                kept += 1;
            }
        }
        // 10% of 1000 = 100
        assert!(
            kept > 60 && kept < 140,
            "Expected ~10% kept with equalizing, got {}/{}",
            kept,
            total,
        );
    }

    #[tokio::test]
    async fn equalizing_mode_100_percent_short_circuits() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "equalizing-100",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(100.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Keep { .. }));
        assert_eq!(span.th_value, Some("0".to_string()));
    }

    #[tokio::test]
    async fn equalizing_mode_0_percent_short_circuits() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "equalizing-0",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(0.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id("0af7651916cd43dd8448eb211c80319c");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    #[tokio::test]
    async fn equalizing_mode_fail_closed_no_randomness() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "equalizing-fail-closed",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let mut span = TestSpan::new().with_name("test");
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        assert!(matches!(result, EvaluateResult::Drop { .. }));
    }

    #[tokio::test]
    async fn equalizing_mode_preserves_incoming_th_when_keeping_rare() {
        // When keeping a rare span, the written th should be the incoming th (not target).
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "equalizing-preserve-th",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Equalizing)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Incoming: 10% → th is high (more restrictive)
        let incoming_th = rejection_threshold(0.1);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(1)) // any randomness, rare spans always kept
            .with_tracestate(&tracestate);

        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep: true, .. } => {
                // The written th should be the incoming th (preserving it)
                let written_th = span.th_value.as_ref().unwrap();
                let expected_th = super::sampling::encode_threshold(incoming_th, 4);
                assert_eq!(written_th, &expected_th);
            }
            _ => panic!("expected Sample(keep=true), got {:?}", result),
        }
    }

    // ==================== Cross-Mode Comparison Tests ====================

    #[tokio::test]
    async fn proportional_vs_equalizing_with_incoming_th() {
        // Key difference per OTel spec:
        // - Proportional multiplies incoming probability by p:
        //   T_o = ProbabilityToThreshold(p * ThresholdToProbability(T_s))
        // - Equalizing applies target threshold directly when incoming is
        //   less restrictive.
        //
        // With p=0.1 and incoming=50%:
        // - Proportional: 0.1 * 0.5 = 0.05 → ~5% kept
        // - Equalizing: applies target 10% threshold directly → ~10% kept
        let engine = PolicyEngine::new();

        let incoming_th = rejection_threshold(0.5);
        let tracestate = format!("ot=th:{}", super::sampling::encode_threshold(incoming_th, 14));

        let mut proportional_kept = 0;
        let mut equalizing_kept = 0;
        let total = 2000;

        for mode in [SamplingMode::Proportional, SamplingMode::Equalizing] {
            let registry = PolicyRegistry::new();
            let handle = registry.register_provider();
            let policy = make_trace_policy(
                "test",
                vec![trace_name_regex_matcher(".+", false)],
                Some(sampling_config_with_mode(10.0, mode)),
                true,
            );
            handle.update(vec![policy]);
            let snapshot = registry.snapshot();

            let mut kept = 0;
            for i in 0..total {
                let trace_id = distributed_trace_id(i);
                let mut span = TestSpan::new()
                    .with_name("test")
                    .with_trace_id(&trace_id)
                    .with_tracestate(&tracestate);
                let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
                if let EvaluateResult::Sample { keep: true, .. } = result {
                    kept += 1;
                }
            }
            match mode {
                SamplingMode::Proportional => proportional_kept = kept,
                SamplingMode::Equalizing => equalizing_kept = kept,
                _ => {}
            }
        }

        // Proportional: p * incoming = 0.1 * 0.5 = 5% → ~100 of 2000
        assert!(
            proportional_kept > 50 && proportional_kept < 150,
            "Proportional expected ~5% (100), got {}/{}",
            proportional_kept,
            total,
        );

        // Equalizing: applies target directly → 10% → ~200 of 2000
        assert!(
            equalizing_kept > 120 && equalizing_kept < 280,
            "Equalizing expected ~10% (200), got {}/{}",
            equalizing_kept,
            total,
        );

        // Equalizing should keep more than proportional (10% > 5%)
        assert!(
            equalizing_kept > proportional_kept,
            "Equalizing ({}) should keep more than proportional ({})",
            equalizing_kept,
            proportional_kept,
        );
    }

    #[tokio::test]
    async fn all_modes_agree_on_no_incoming_th() {
        // Without incoming th, all three modes should produce the same
        // keep/drop decisions (all use target threshold against trace ID randomness).
        let engine = PolicyEngine::new();
        let trace_ids: Vec<String> = (0..100u64).map(distributed_trace_id).collect();

        let mut results_by_mode: Vec<Vec<bool>> = Vec::new();

        for mode in [SamplingMode::HashSeed, SamplingMode::Proportional, SamplingMode::Equalizing] {
            let registry = PolicyRegistry::new();
            let handle = registry.register_provider();
            let mut config = sampling_config_with_mode(30.0, mode);
            config.hash_seed = Some(0); // Ensure hash_seed=0 for fair comparison
            let policy = make_trace_policy(
                "test",
                vec![trace_name_regex_matcher(".+", false)],
                Some(config),
                true,
            );
            handle.update(vec![policy]);
            let snapshot = registry.snapshot();

            let mut results = Vec::new();
            for tid in &trace_ids {
                let mut span = TestSpan::new().with_name("test").with_trace_id(tid);
                let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
                let kept = matches!(
                    result,
                    EvaluateResult::Sample { keep: true, .. } | EvaluateResult::Keep { .. }
                );
                results.push(kept);
            }
            results_by_mode.push(results);
        }

        // All modes should agree
        assert_eq!(results_by_mode[0], results_by_mode[1], "HashSeed and Proportional should agree without incoming th");
        assert_eq!(results_by_mode[0], results_by_mode[2], "HashSeed and Equalizing should agree without incoming th");
    }

    #[tokio::test]
    async fn all_modes_agree_on_100_and_0_percent() {
        // All modes should short-circuit on 100% and 0%.
        for mode in [SamplingMode::HashSeed, SamplingMode::Proportional, SamplingMode::Equalizing] {
            let engine = PolicyEngine::new();

            // 100%
            let registry = PolicyRegistry::new();
            let handle = registry.register_provider();
            let policy = make_trace_policy(
                "keep-all",
                vec![trace_name_regex_matcher(".+", false)],
                Some(sampling_config_with_mode(100.0, mode)),
                true,
            );
            handle.update(vec![policy]);
            let snapshot = registry.snapshot();

            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id("0af7651916cd43dd8448eb211c80319c");
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            assert!(
                matches!(result, EvaluateResult::Keep { .. }),
                "Mode {:?} should keep at 100%",
                mode,
            );

            // 0%
            let registry = PolicyRegistry::new();
            let handle = registry.register_provider();
            let policy = make_trace_policy(
                "drop-all",
                vec![trace_name_regex_matcher(".+", false)],
                Some(sampling_config_with_mode(0.0, mode)),
                true,
            );
            handle.update(vec![policy]);
            let snapshot = registry.snapshot();

            let mut span = TestSpan::new()
                .with_name("test")
                .with_trace_id("0af7651916cd43dd8448eb211c80319c");
            let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
            assert!(
                matches!(result, EvaluateResult::Drop { .. }),
                "Mode {:?} should drop at 0%",
                mode,
            );
        }
    }

    #[tokio::test]
    async fn unspecified_mode_defaults_to_hash_seed() {
        // SamplingMode::Unspecified should behave like HashSeed.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policy = make_trace_policy(
            "unspecified-mode",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config_with_mode(50.0, SamplingMode::Unspecified)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn mode_none_defaults_to_hash_seed() {
        // When mode is None (not set), should behave like HashSeed.
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Use sampling_config() which sets mode: None
        let policy = make_trace_policy(
            "no-mode",
            vec![trace_name_regex_matcher(".+", false)],
            Some(sampling_config(50.0)),
            true,
        );
        handle.update(vec![policy]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        let threshold = rejection_threshold(0.5);
        let mut span = TestSpan::new()
            .with_name("test")
            .with_trace_id(&trace_id_with_randomness(threshold + 1));
        let result = engine.evaluate_trace(&snapshot, &mut span).await.unwrap();
        match &result {
            EvaluateResult::Sample { keep, .. } => assert!(keep),
            _ => panic!("expected Sample, got {:?}", result),
        }
    }
}
