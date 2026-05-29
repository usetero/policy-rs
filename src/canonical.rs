//! Canonical string mappings for enum-typed telemetry fields.
//!
//! When implementing [`Matchable`] for OTel records, certain fields hold
//! enum values (metric type, aggregation temporality, span status, span kind)
//! rather than free-form strings. The engine synthesizes an exact-match pattern
//! from the proto enum's canonical name and compares it against the value
//! returned by [`get_field`].
//!
//! Use the helpers in this module to produce the exact string the engine
//! expects. Passing a different representation (e.g. a numeric value, a
//! lowercase shorthand, or the OTel SDK's display name) will silently fail
//! to match.
//!
//! # Example
//!
//! ```ignore
//! use policy_rs::canonical;
//! use policy_rs::proto::tero::policy::v1::{MetricType, AggregationTemporality};
//!
//! // In your Matchable impl for a metric record:
//! MetricFieldSelector::Type => {
//!     let s = canonical::metric_type_str(self.metric_type);
//!     Some(Cow::Borrowed(s))
//! }
//! MetricFieldSelector::Temporality => {
//!     let s = canonical::aggregation_temporality_str(self.temporality);
//!     Some(Cow::Borrowed(s))
//! }
//! ```
//!
//! [`Matchable`]: crate::Matchable
//! [`get_field`]: crate::Matchable::get_field

use crate::proto::tero::policy::v1::{AggregationTemporality, MetricType, SpanKind, SpanStatusCode};

/// Returns the canonical policy string for a [`MetricType`] value.
///
/// Maps to the proto enum's `as_str_name()` output:
/// - `Gauge` → `"METRIC_TYPE_GAUGE"`
/// - `Sum` → `"METRIC_TYPE_SUM"`
/// - `Histogram` → `"METRIC_TYPE_HISTOGRAM"`
/// - `ExponentialHistogram` → `"METRIC_TYPE_EXPONENTIAL_HISTOGRAM"`
/// - `Unspecified` → `"METRIC_TYPE_UNSPECIFIED"`
pub fn metric_type_str(mt: MetricType) -> &'static str {
    mt.as_str_name()
}

/// Returns the canonical policy string for an [`AggregationTemporality`] value.
///
/// Maps to the proto enum's `as_str_name()` output:
/// - `Delta` → `"AGGREGATION_TEMPORALITY_DELTA"`
/// - `Cumulative` → `"AGGREGATION_TEMPORALITY_CUMULATIVE"`
/// - `Unspecified` → `"AGGREGATION_TEMPORALITY_UNSPECIFIED"`
pub fn aggregation_temporality_str(at: AggregationTemporality) -> &'static str {
    at.as_str_name()
}

/// Returns the canonical policy string for a [`SpanStatusCode`] value.
///
/// Maps to the proto enum's `as_str_name()` output:
/// - `Ok` → `"SPAN_STATUS_CODE_OK"`
/// - `Error` → `"SPAN_STATUS_CODE_ERROR"`
/// - `Unspecified` → `"SPAN_STATUS_CODE_UNSPECIFIED"`
///
/// # Note on Unset vs Unspecified
///
/// The OTel spec calls the default status "Unset". In the policy proto this
/// variant is named `Unspecified` (proto3 default). The policy JSON parser
/// accepts `"SPAN_STATUS_CODE_UNSET"` as an alias, but the engine always
/// matches against `"SPAN_STATUS_CODE_UNSPECIFIED"`. Return
/// `span_status_code_str(SpanStatusCode::Unspecified)` for an unset status.
pub fn span_status_code_str(sc: SpanStatusCode) -> &'static str {
    sc.as_str_name()
}

/// Returns the canonical policy string for a [`SpanKind`] value.
///
/// Maps to the proto enum's `as_str_name()` output:
/// - `Internal` → `"SPAN_KIND_INTERNAL"`
/// - `Server` → `"SPAN_KIND_SERVER"`
/// - `Client` → `"SPAN_KIND_CLIENT"`
/// - `Producer` → `"SPAN_KIND_PRODUCER"`
/// - `Consumer` → `"SPAN_KIND_CONSUMER"`
/// - `Unspecified` → `"SPAN_KIND_UNSPECIFIED"`
pub fn span_kind_str(sk: SpanKind) -> &'static str {
    sk.as_str_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_type_canonical_names() {
        assert_eq!(metric_type_str(MetricType::Gauge), "METRIC_TYPE_GAUGE");
        assert_eq!(metric_type_str(MetricType::Sum), "METRIC_TYPE_SUM");
        assert_eq!(
            metric_type_str(MetricType::Histogram),
            "METRIC_TYPE_HISTOGRAM"
        );
        assert_eq!(
            metric_type_str(MetricType::ExponentialHistogram),
            "METRIC_TYPE_EXPONENTIAL_HISTOGRAM"
        );
    }

    #[test]
    fn aggregation_temporality_canonical_names() {
        assert_eq!(
            aggregation_temporality_str(AggregationTemporality::Delta),
            "AGGREGATION_TEMPORALITY_DELTA"
        );
        assert_eq!(
            aggregation_temporality_str(AggregationTemporality::Cumulative),
            "AGGREGATION_TEMPORALITY_CUMULATIVE"
        );
    }

    #[test]
    fn span_status_code_canonical_names() {
        assert_eq!(
            span_status_code_str(SpanStatusCode::Ok),
            "SPAN_STATUS_CODE_OK"
        );
        assert_eq!(
            span_status_code_str(SpanStatusCode::Error),
            "SPAN_STATUS_CODE_ERROR"
        );
        // OTel "Unset" maps to proto Unspecified
        assert_eq!(
            span_status_code_str(SpanStatusCode::Unspecified),
            "SPAN_STATUS_CODE_UNSPECIFIED"
        );
    }

    #[test]
    fn span_kind_canonical_names() {
        assert_eq!(span_kind_str(SpanKind::Internal), "SPAN_KIND_INTERNAL");
        assert_eq!(span_kind_str(SpanKind::Server), "SPAN_KIND_SERVER");
        assert_eq!(span_kind_str(SpanKind::Client), "SPAN_KIND_CLIENT");
        assert_eq!(span_kind_str(SpanKind::Producer), "SPAN_KIND_PRODUCER");
        assert_eq!(span_kind_str(SpanKind::Consumer), "SPAN_KIND_CONSUMER");
    }
}
