//! Consistent probability sampling for policy evaluation.
//!
//! Implements the OpenTelemetry consistent probability sampling algorithm
//! for logs (hash-based and trace-ID-based) and traces (tracestate/TraceID-based).
//!
//! Log sampling has two modes depending on the sample key:
//! - **trace_id sample key**: uses OTel algorithm directly (last 14 hex chars of trace ID)
//!   for consistent keep/drop decisions across logs and traces.
//! - **other sample keys**: hashes the value with FNV-1a to produce 56-bit randomness,
//!   then applies the OTel threshold comparison.
//! - **no sample key / empty value**: falls back to keep (no sampling).

use std::hash::Hasher;

use crate::field::TraceFieldSelector;
use crate::proto::tero::policy::v1::TraceField;

use super::matchable::Matchable;
use super::signal::TraceSignal;

/// Maximum threshold value: 2^56.
pub(crate) const MAX_THRESHOLD: u64 = 1 << 56;

/// Mask for extracting 56-bit randomness from a 64-bit hash.
pub(crate) const RANDOMNESS_MASK: u64 = MAX_THRESHOLD - 1;

/// Hash arbitrary input with FNV-1a to produce a deterministic 56-bit randomness value.
///
/// Uses FNV-1a (matching the Go implementation's `fnv.New64a()`) to ensure
/// cross-language conformance. The same input always produces the same value.
fn fnv_hash(value: &str) -> u64 {
    let mut hasher = fnv::FnvHasher::default();
    hasher.write(value.as_bytes());
    hasher.finish() & RANDOMNESS_MASK
}

/// Convert a sampling probability (0.0–1.0) to a 56-bit rejection threshold.
///
/// The threshold T = (1 - probability) * 2^56. A record is kept when its
/// randomness value R >= T. This means T=0 keeps everything (100%) and
/// T=2^56 keeps nothing (0%).
pub(crate) fn rejection_threshold(probability: f64) -> u64 {
    if probability >= 1.0 {
        return 0;
    }
    if probability <= 0.0 {
        return MAX_THRESHOLD;
    }
    ((1.0 - probability) * MAX_THRESHOLD as f64) as u64
}

/// Determine if a log record should be kept based on percentage sampling.
///
/// Implements the same algorithm as policy-go's `shouldSampleLog`:
/// - If no sample key value is available, falls back to **keep** (not random).
/// - Tries to parse the value as a hex trace ID (last 14 hex chars → 56-bit
///   randomness). If the value parses successfully, uses the OTel consistent
///   probability sampling algorithm directly.
/// - If parsing fails, hashes the value with FNV-1a to produce 56-bit
///   randomness, then applies the OTel threshold comparison.
pub(crate) fn should_sample_log(percentage: f64, sample_key_value: Option<&str>) -> bool {
    // No sample key value → can't do consistent sampling → keep
    let value = match sample_key_value {
        Some(v) if !v.is_empty() => v,
        _ => return true,
    };

    let threshold = rejection_threshold(percentage);

    // Try to extract randomness directly from the value as a hex trace ID.
    // If it parses, use the OTel algorithm; otherwise hash with FNV-1a.
    let randomness = parse_trace_id_randomness(value).unwrap_or_else(|| fnv_hash(value));
    randomness >= threshold
}

/// Encode a 56-bit rejection threshold as a hex string for the tracestate `th` sub-key.
///
/// Per the OTel spec, the threshold is encoded as 1-14 hex digits with trailing
/// zeros removed. A threshold of 0 encodes as "0".
pub(crate) fn encode_threshold(threshold: u64, precision: u32) -> String {
    if threshold == 0 {
        return "0".to_string();
    }
    let hex = format!("{:014x}", threshold);
    let truncated = &hex[..precision as usize];
    truncated.trim_end_matches('0').to_string()
}

/// Extract 56-bit randomness from a trace span for consistent probability sampling.
///
/// Tries two sources in order:
/// 1. The `rv` sub-key from the OTel tracestate entry
/// 2. The least-significant 56 bits of the TraceID
pub(crate) fn extract_trace_randomness<T: Matchable<Signal = TraceSignal>>(
    span: &T,
) -> Option<u64> {
    // Try tracestate rv first
    if let Some(tracestate) = span.get_field(&TraceFieldSelector::Simple(TraceField::TraceState))
        && let Some(rv) = parse_tracestate_rv(&tracestate)
    {
        return Some(rv);
    }
    // Fall back to TraceID least-significant 56 bits
    if let Some(trace_id) = span.get_field(&TraceFieldSelector::Simple(TraceField::TraceId)) {
        return parse_trace_id_randomness(&trace_id);
    }
    None
}

/// Parse the `rv` (randomness value) from an OTel tracestate entry.
///
/// The tracestate format is `key1=value1,key2=value2,...` where the OTel
/// entry has key `ot` and value contains semicolon-separated sub-keys like
/// `rv:XXXXXXXXXXXX`. The rv value is up to 14 hex digits representing
/// a 56-bit randomness value.
pub(crate) fn parse_tracestate_rv(tracestate: &str) -> Option<u64> {
    // Find the "ot" vendor entry
    for entry in tracestate.split(',') {
        let entry = entry.trim();
        if let Some(value) = entry.strip_prefix("ot=") {
            // Parse semicolon-separated sub-keys
            for sub_key in value.split(';') {
                if let Some(rv_hex) = sub_key.strip_prefix("rv:") {
                    // Parse hex value, left-aligned to 14 digits
                    let padded = format!("{:0<14}", rv_hex);
                    return u64::from_str_radix(&padded, 16)
                        .ok()
                        .map(|v| v & RANDOMNESS_MASK);
                }
            }
        }
    }
    None
}

/// Parse 56-bit randomness from a TraceID string.
///
/// The TraceID is a 32-character hex string. We take the last 14 hex
/// characters (least-significant 56 bits) as the randomness value.
pub(crate) fn parse_trace_id_randomness(trace_id: &str) -> Option<u64> {
    if trace_id.len() < 14 {
        return None;
    }
    let suffix = &trace_id[trace_id.len() - 14..];
    u64::from_str_radix(suffix, 16)
        .ok()
        .map(|v| v & RANDOMNESS_MASK)
}

/// Parse the `th` (threshold) value from an OTel tracestate entry.
///
/// The `th` sub-key encodes the rejection threshold as 1-14 hex digits
/// (right-padded with zeros to 14 digits). This represents the incoming
/// sampling threshold from upstream collectors.
pub(crate) fn parse_tracestate_th(tracestate: &str) -> Option<u64> {
    for entry in tracestate.split(',') {
        let entry = entry.trim();
        if let Some(value) = entry.strip_prefix("ot=") {
            for sub_key in value.split(';') {
                if let Some(th_hex) = sub_key.strip_prefix("th:") {
                    // Right-pad to 14 hex digits (same encoding as rv)
                    let padded = format!("{:0<14}", th_hex);
                    return u64::from_str_radix(&padded, 16)
                        .ok()
                        .map(|v| v & RANDOMNESS_MASK);
                }
            }
        }
    }
    None
}

/// Convert a 56-bit rejection threshold back to a probability (0.0–1.0).
///
/// Inverse of `rejection_threshold`: probability = 1.0 - (threshold / 2^56).
pub(crate) fn threshold_to_probability(threshold: u64) -> f64 {
    if threshold == 0 {
        return 1.0;
    }
    if threshold >= MAX_THRESHOLD {
        return 0.0;
    }
    1.0 - (threshold as f64 / MAX_THRESHOLD as f64)
}

/// Compute 56-bit randomness from a trace ID combined with a hash seed.
///
/// When `hash_seed` is 0, this is equivalent to `parse_trace_id_randomness`
/// (uses the least-significant 56 bits directly). When non-zero, the trace ID
/// bytes are hashed together with the seed using FNV-1a to produce deterministic
/// but seed-specific randomness.
pub(crate) fn hash_seed_randomness(trace_id: &str, hash_seed: u32) -> Option<u64> {
    if hash_seed == 0 {
        return parse_trace_id_randomness(trace_id);
    }
    if trace_id.len() < 14 {
        return None;
    }
    let mut hasher = fnv::FnvHasher::default();
    hasher.write(trace_id.as_bytes());
    hasher.write_u32(hash_seed);
    Some(hasher.finish() & RANDOMNESS_MASK)
}

/// Extract randomness for hash_seed mode.
///
/// Tries two sources in order:
/// 1. The `rv` sub-key from the OTel tracestate entry (if hash_seed is 0)
/// 2. The TraceID hashed with the seed
///
/// When hash_seed is non-zero, the `rv` sub-key is ignored because the seed
/// produces different randomness than the original trace ID randomness.
pub(crate) fn extract_hash_seed_randomness<T: Matchable<Signal = TraceSignal>>(
    span: &T,
    hash_seed: u32,
) -> Option<u64> {
    if hash_seed == 0 {
        // Seed 0 is compatible with standard OTel randomness
        return extract_trace_randomness(span);
    }
    // Non-zero seed: hash the trace ID with the seed
    let trace_id = span.get_field(&TraceFieldSelector::Simple(TraceField::TraceId))?;
    hash_seed_randomness(&trace_id, hash_seed)
}

/// Extract the incoming threshold from tracestate for proportional/equalizing modes.
///
/// Returns the `th` sub-key from the OTel tracestate, or `None` if not present.
pub(crate) fn extract_incoming_threshold<T: Matchable<Signal = TraceSignal>>(
    span: &T,
) -> Option<u64> {
    let tracestate = span.get_field(&TraceFieldSelector::Simple(TraceField::TraceState))?;
    parse_tracestate_th(&tracestate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_hash_is_deterministic() {
        // Same key always produces same hash
        let hash1 = fnv_hash("request-123");
        let hash2 = fnv_hash("request-123");
        assert_eq!(hash1, hash2);

        // Different keys produce different hashes
        let hash3 = fnv_hash("request-456");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn fnv_hash_produces_56_bit_values() {
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
            let hash = fnv_hash(key);
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

    // ==================== should_sample_log tests ====================

    #[test]
    fn sample_log_no_value_returns_keep() {
        // No sample key value → fall back to keep (for non-boundary percentages)
        assert!(should_sample_log(0.5, None));
        assert!(should_sample_log(0.5, Some("")));
        assert!(should_sample_log(0.01, None));
    }

    #[test]
    fn sample_log_with_hash_key_is_consistent() {
        let key = "request-123";
        let decisions: Vec<bool> = (0..10).map(|_| should_sample_log(0.5, Some(key))).collect();

        let first = decisions[0];
        assert!(
            decisions.iter().all(|&d| d == first),
            "Hash-based sample key decisions should be consistent"
        );
    }

    #[test]
    fn sample_log_with_trace_id_key_is_consistent() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let decisions: Vec<bool> = (0..10)
            .map(|_| should_sample_log(0.5, Some(trace_id)))
            .collect();

        let first = decisions[0];
        assert!(
            decisions.iter().all(|&d| d == first),
            "Trace ID sample key decisions should be consistent"
        );
    }

    #[test]
    fn sample_log_hash_key_different_keys_different_decisions() {
        let keys: Vec<String> = (0..1000).map(|i| format!("request-{}", i)).collect();
        let kept_count = keys
            .iter()
            .filter(|k| should_sample_log(0.5, Some(k)))
            .count();

        assert!(
            kept_count > 400 && kept_count < 600,
            "Expected ~50% kept, got {} out of 1000",
            kept_count
        );
    }

    #[test]
    fn sample_log_respects_threshold() {
        let keys: Vec<String> = (0..100).map(|i| format!("key-{}", i)).collect();

        // At 0%, no keys should be kept
        let kept_at_0 = keys
            .iter()
            .filter(|k| should_sample_log(0.0, Some(k)))
            .count();
        assert_eq!(kept_at_0, 0, "At 0%, nothing should be kept");

        // At 100%, all keys should be kept
        let kept_at_100 = keys
            .iter()
            .filter(|k| should_sample_log(1.0, Some(k)))
            .count();
        assert_eq!(kept_at_100, 100, "At 100%, everything should be kept");
    }

    #[test]
    fn sample_log_trace_id_key_uses_otel_algorithm() {
        // A trace ID whose last 14 hex chars parse to a known value
        // "8448eb211c80319c" → last 14 chars = "eb211c80319c" ... no, let's use a full one.
        // trace_id = "00000000000000000000000000000001"
        // last 14 chars = "00000000000001" → randomness = 1
        // At 50%, threshold = 2^55 = 36028797018963968
        // 1 < threshold → drop
        let trace_id = "00000000000000000000000000000001";
        assert!(!should_sample_log(0.5, Some(trace_id)));

        // trace_id with high randomness → kept
        // "ffffffffffffff" → randomness = 0x00ffffffffffffff & MASK
        let trace_id_high = "000000000000000000ffffffffffffff";
        assert!(should_sample_log(0.5, Some(trace_id_high)));
    }

    #[test]
    fn sample_log_trace_id_matches_direct_threshold_comparison() {
        // Verify the trace_id path uses parse_trace_id_randomness + threshold comparison
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let randomness = parse_trace_id_randomness(trace_id).unwrap();
        let threshold = rejection_threshold(0.5);
        let expected = randomness >= threshold;
        assert_eq!(should_sample_log(0.5, Some(trace_id)), expected);
    }

    #[test]
    fn consistent_sampling_superset_property() {
        // Core property: if a key is kept at probability P, it must also be kept at P' > P.
        let keys: Vec<String> = (0..500).map(|i| format!("key-{}", i)).collect();
        let probabilities = [0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99];

        for key in &keys {
            let mut was_kept = false;
            for &p in &probabilities {
                let kept = should_sample_log(p, Some(key));
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

    // ==================== Trace-specific tests ====================

    #[test]
    fn encode_threshold_values() {
        // Threshold 0 → "0"
        assert_eq!(encode_threshold(0, 4), "0");

        // Non-zero threshold with trailing zeros stripped
        assert_eq!(encode_threshold(0x00800000000000, 4), "008");

        // Full precision, trailing zeros stripped (leading zeros preserved)
        assert_eq!(encode_threshold(0x00abcdef000000, 14), "00abcdef");

        // Precision truncation (leading zeros from 14-hex encoding preserved)
        assert_eq!(encode_threshold(0x00abcdef123456, 4), "00ab");

        // Value with significant digits starting at precision boundary
        assert_eq!(encode_threshold(0xabcd0000000000, 4), "abcd");
    }

    #[test]
    fn parse_tracestate_rv_values() {
        assert_eq!(
            parse_tracestate_rv("ot=rv:abcdef12345678"),
            Some(0xabcdef12345678)
        );

        assert_eq!(
            parse_tracestate_rv("ot=th:5;rv:abcdef12345678"),
            Some(0xabcdef12345678)
        );

        assert_eq!(
            parse_tracestate_rv("vendor1=foo,ot=rv:abcdef12345678,vendor2=bar"),
            Some(0xabcdef12345678)
        );

        // Short rv (left-padded with zeros on right)
        assert_eq!(parse_tracestate_rv("ot=rv:abc"), Some(0xabc00000000000));

        assert_eq!(parse_tracestate_rv("vendor1=foo"), None);
        assert_eq!(parse_tracestate_rv("ot=th:5"), None);
    }

    #[test]
    fn parse_trace_id_randomness_values() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let result = parse_trace_id_randomness(trace_id);
        assert!(result.is_some());
        let expected = u64::from_str_radix("48eb211c80319c", 16).unwrap() & RANDOMNESS_MASK;
        assert_eq!(result.unwrap(), expected);

        assert_eq!(parse_trace_id_randomness("abc"), None);
    }

    // ==================== parse_tracestate_th tests ====================

    #[test]
    fn parse_tracestate_th_basic() {
        assert_eq!(
            parse_tracestate_th("ot=th:8"),
            Some(0x80000000000000)
        );
    }

    #[test]
    fn parse_tracestate_th_full_precision() {
        assert_eq!(
            parse_tracestate_th("ot=th:abcdef12345678"),
            Some(0xabcdef12345678)
        );
    }

    #[test]
    fn parse_tracestate_th_with_other_subkeys() {
        assert_eq!(
            parse_tracestate_th("ot=rv:abc;th:8"),
            Some(0x80000000000000)
        );
    }

    #[test]
    fn parse_tracestate_th_with_other_vendors() {
        assert_eq!(
            parse_tracestate_th("vendor1=foo,ot=th:4,vendor2=bar"),
            Some(0x40000000000000)
        );
    }

    #[test]
    fn parse_tracestate_th_zero() {
        assert_eq!(
            parse_tracestate_th("ot=th:0"),
            Some(0)
        );
    }

    #[test]
    fn parse_tracestate_th_missing() {
        assert_eq!(parse_tracestate_th("ot=rv:abc"), None);
        assert_eq!(parse_tracestate_th("vendor1=foo"), None);
        assert_eq!(parse_tracestate_th(""), None);
    }

    #[test]
    fn parse_tracestate_th_roundtrip_with_encode() {
        // Encode a threshold then parse it back
        let threshold = rejection_threshold(0.5); // 50% → threshold at ~2^55
        let encoded = encode_threshold(threshold, 14);
        let tracestate = format!("ot=th:{}", encoded);
        let parsed = parse_tracestate_th(&tracestate).unwrap();
        // Due to right-padding, the parsed value should match the original
        assert_eq!(parsed, threshold);
    }

    // ==================== threshold_to_probability tests ====================

    #[test]
    fn threshold_to_probability_edge_cases() {
        assert_eq!(threshold_to_probability(0), 1.0);
        assert_eq!(threshold_to_probability(MAX_THRESHOLD), 0.0);
    }

    #[test]
    fn threshold_to_probability_roundtrip() {
        let probabilities = [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99];
        for p in probabilities {
            let th = rejection_threshold(p);
            let p_back = threshold_to_probability(th);
            assert!(
                (p - p_back).abs() < 1e-10,
                "Roundtrip failed for {}: got {}",
                p,
                p_back
            );
        }
    }

    // ==================== hash_seed_randomness tests ====================

    #[test]
    fn hash_seed_zero_matches_parse_trace_id() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let seeded = hash_seed_randomness(trace_id, 0);
        let direct = parse_trace_id_randomness(trace_id);
        assert_eq!(seeded, direct);
    }

    #[test]
    fn hash_seed_nonzero_differs_from_direct() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let seeded = hash_seed_randomness(trace_id, 42).unwrap();
        let direct = parse_trace_id_randomness(trace_id).unwrap();
        assert_ne!(seeded, direct, "Non-zero seed should produce different randomness");
    }

    #[test]
    fn hash_seed_deterministic() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let r1 = hash_seed_randomness(trace_id, 42);
        let r2 = hash_seed_randomness(trace_id, 42);
        assert_eq!(r1, r2, "Same trace_id + seed should always produce same result");
    }

    #[test]
    fn hash_seed_different_seeds_different_randomness() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let r1 = hash_seed_randomness(trace_id, 1).unwrap();
        let r2 = hash_seed_randomness(trace_id, 2).unwrap();
        assert_ne!(r1, r2, "Different seeds should produce different randomness");
    }

    #[test]
    fn hash_seed_produces_56_bit_values() {
        for seed in [1, 42, 100, 1000, u32::MAX] {
            let r = hash_seed_randomness("0af7651916cd43dd8448eb211c80319c", seed).unwrap();
            assert!(r < MAX_THRESHOLD, "Hash seed {} produced out-of-range value {}", seed, r);
        }
    }

    #[test]
    fn hash_seed_short_trace_id_returns_none() {
        assert_eq!(hash_seed_randomness("abc", 42), None);
    }

    #[test]
    fn hash_seed_same_trace_id_different_seeds_distribution() {
        // Verify that different seeds produce well-distributed randomness
        // by checking that a reasonable fraction fall above/below the midpoint
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let midpoint = MAX_THRESHOLD / 2;
        let total = 1000u32;
        let above = (0..total)
            .filter(|&seed| hash_seed_randomness(trace_id, seed).unwrap() >= midpoint)
            .count();
        assert!(
            above > 350 && above < 650,
            "Expected ~50% above midpoint, got {}/{}", above, total
        );
    }

    #[test]
    fn hash_seed_consistent_sampling_across_trace_ids() {
        // With a given seed and 50% threshold, verify ~50% of trace IDs are kept
        let threshold = rejection_threshold(0.5);
        let kept = (0..1000u64)
            .map(|i| format!("{:032x}", i))
            .filter(|tid| {
                hash_seed_randomness(tid, 42).unwrap() >= threshold
            })
            .count();
        assert!(
            kept > 400 && kept < 600,
            "Expected ~50% kept with seed 42, got {}/1000", kept
        );
    }

    #[test]
    fn hash_seed_superset_property() {
        // Core OTel property: if kept at probability P, must also be kept at P' > P
        let trace_ids: Vec<String> = (0..200u64).map(|i| format!("{:032x}", i)).collect();
        let probabilities = [0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99];
        let seed = 42;

        for tid in &trace_ids {
            let r = hash_seed_randomness(tid, seed).unwrap();
            let mut was_kept = false;
            for &p in &probabilities {
                let th = rejection_threshold(p);
                let kept = r >= th;
                if was_kept {
                    assert!(
                        kept,
                        "Trace ID '{}' with seed {} was kept at lower probability but dropped at {}",
                        tid, seed, p
                    );
                }
                if kept {
                    was_kept = true;
                }
            }
        }
    }
}
