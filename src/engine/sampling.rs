//! Consistent probability sampling for policy evaluation.
//!
//! Implements the OpenTelemetry consistent probability sampling algorithm
//! for logs (hash-based) and traces (tracestate/TraceID-based).

use std::hash::{Hash, Hasher};

use crate::field::TraceFieldSelector;
use crate::proto::tero::policy::v1::TraceField;

use super::matchable::Matchable;
use super::signal::TraceSignal;

/// Maximum threshold value: 2^56.
pub(crate) const MAX_THRESHOLD: u64 = 1 << 56;

/// Mask for extracting 56-bit randomness from a 64-bit hash.
pub(crate) const RANDOMNESS_MASK: u64 = MAX_THRESHOLD - 1;

/// Hash a sample key value to produce a deterministic 56-bit randomness value.
///
/// Uses consistent probability sampling per the OpenTelemetry specification.
/// The same key value always produces the same 56-bit randomness value,
/// enabling consistent sampling decisions across multiple records with the
/// same key. Higher sampling probabilities are strict supersets of lower ones:
/// if a record is kept at 10%, it will also be kept at 50%.
pub(crate) fn hash_sample_key(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
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

/// Determine if a record should be kept based on percentage sampling.
///
/// Uses consistent probability sampling per the OpenTelemetry specification:
/// computes a 56-bit rejection threshold from the probability and compares
/// against a 56-bit randomness value derived from the sample key hash.
///
/// If a sample key value is provided, uses hash-based consistent sampling.
/// Otherwise, uses random sampling with a 56-bit random value.
pub(crate) fn should_keep_percentage(percentage: f64, sample_key_value: Option<&str>) -> bool {
    let threshold = rejection_threshold(percentage);
    let randomness = match sample_key_value {
        Some(key) => hash_sample_key(key),
        None => rand::random::<u64>() & RANDOMNESS_MASK,
    };
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn encode_threshold_values() {
        // Threshold 0 → "0"
        assert_eq!(encode_threshold(0, 4), "0");

        // Non-zero threshold with trailing zeros stripped
        // 0x00800000000000 → "00800000000000", precision 4 → "0080", trim → "008"
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
        // Standard OTel tracestate with rv
        assert_eq!(
            parse_tracestate_rv("ot=rv:abcdef12345678"),
            Some(0xabcdef12345678)
        );

        // rv with other sub-keys
        assert_eq!(
            parse_tracestate_rv("ot=th:5;rv:abcdef12345678"),
            Some(0xabcdef12345678)
        );

        // rv with other vendor entries
        assert_eq!(
            parse_tracestate_rv("vendor1=foo,ot=rv:abcdef12345678,vendor2=bar"),
            Some(0xabcdef12345678)
        );

        // Short rv (left-padded with zeros on right)
        assert_eq!(parse_tracestate_rv("ot=rv:abc"), Some(0xabc00000000000));

        // No ot entry
        assert_eq!(parse_tracestate_rv("vendor1=foo"), None);

        // No rv sub-key
        assert_eq!(parse_tracestate_rv("ot=th:5"), None);
    }

    #[test]
    fn parse_trace_id_randomness_values() {
        // Standard 32-char trace ID: last 14 hex chars are the randomness source
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let result = parse_trace_id_randomness(trace_id);
        assert!(result.is_some());
        // "0af7651916cd43dd8448eb211c80319c"[18..32] = "48eb211c80319c"
        let expected = u64::from_str_radix("48eb211c80319c", 16).unwrap() & RANDOMNESS_MASK;
        assert_eq!(result.unwrap(), expected);

        // Too short
        assert_eq!(parse_trace_id_randomness("abc"), None);
    }
}
