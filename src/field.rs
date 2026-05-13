//! Field selection utilities for telemetry records.

use crate::proto::tero::policy::v1::{AttributePath, LogField, MetricField, TraceField};

/// Represents a field selector for log records.
///
/// Attribute selectors use a path (Vec<String>) to support nested attribute access.
/// For example, `["http", "method"]` accesses `attributes["http"]["method"]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogFieldSelector {
    /// Simple log field (body, severity_text, etc.)
    Simple(LogField),
    /// Log record attribute by path (e.g., `["http", "method"]`)
    LogAttribute(Vec<String>),
    /// Resource attribute by path
    ResourceAttribute(Vec<String>),
    /// Scope attribute by path
    ScopeAttribute(Vec<String>),
}

impl LogFieldSelector {
    /// Parse a field selector from JSON field type and optional key.
    ///
    /// For backward compatibility, a single key string is wrapped in a vec.
    pub fn from_json(field_type: &str, key: Option<&str>) -> Option<Self> {
        match field_type {
            "log_body" => Some(LogFieldSelector::Simple(LogField::Body)),
            "log_severity_text" => Some(LogFieldSelector::Simple(LogField::SeverityText)),
            "log_trace_id" => Some(LogFieldSelector::Simple(LogField::TraceId)),
            "log_span_id" => Some(LogFieldSelector::Simple(LogField::SpanId)),
            "log_event_name" => Some(LogFieldSelector::Simple(LogField::EventName)),
            "resource_schema_url" => Some(LogFieldSelector::Simple(LogField::ResourceSchemaUrl)),
            "scope_schema_url" => Some(LogFieldSelector::Simple(LogField::ScopeSchemaUrl)),
            "log_attribute" => key.map(|k| LogFieldSelector::LogAttribute(vec![k.to_string()])),
            "resource_attribute" => {
                key.map(|k| LogFieldSelector::ResourceAttribute(vec![k.to_string()]))
            }
            "scope_attribute" => key.map(|k| LogFieldSelector::ScopeAttribute(vec![k.to_string()])),
            _ => None,
        }
    }

    /// Create a LogFieldSelector from an AttributePath for log attributes.
    pub fn from_log_attribute(path: &AttributePath) -> Self {
        LogFieldSelector::LogAttribute(path.path.clone())
    }

    /// Create a LogFieldSelector from an AttributePath for resource attributes.
    pub fn from_resource_attribute(path: &AttributePath) -> Self {
        LogFieldSelector::ResourceAttribute(path.path.clone())
    }

    /// Create a LogFieldSelector from an AttributePath for scope attributes.
    pub fn from_scope_attribute(path: &AttributePath) -> Self {
        LogFieldSelector::ScopeAttribute(path.path.clone())
    }

    /// Returns the attribute path if this is an attribute selector.
    pub fn attribute_path(&self) -> Option<&[String]> {
        match self {
            LogFieldSelector::LogAttribute(p)
            | LogFieldSelector::ResourceAttribute(p)
            | LogFieldSelector::ScopeAttribute(p) => Some(p),
            LogFieldSelector::Simple(_) => None,
        }
    }

    /// Returns the first segment of the attribute path, for backward compatibility.
    ///
    /// This is useful when the attribute is a simple flat key (single-segment path).
    pub fn attribute_key(&self) -> Option<&str> {
        self.attribute_path()
            .and_then(|p| p.first())
            .map(|s| s.as_str())
    }
}

/// Represents a field selector for metric records.
///
/// Attribute selectors use a path (Vec<String>) to support nested attribute access.
/// For example, `["host", "name"]` accesses `attributes["host"]["name"]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricFieldSelector {
    /// Simple metric field (name, description, unit, etc.)
    Simple(MetricField),
    /// Data point attribute by path
    DatapointAttribute(Vec<String>),
    /// Resource attribute by path
    ResourceAttribute(Vec<String>),
    /// Scope attribute by path
    ScopeAttribute(Vec<String>),
    /// Metric type field — selects the metric's type (Gauge, Sum, Histogram, etc.)
    Type,
    /// Aggregation temporality field — selects the metric's temporality (Delta, Cumulative)
    Temporality,
}

impl MetricFieldSelector {
    /// Create a MetricFieldSelector from an AttributePath for datapoint attributes.
    pub fn from_datapoint_attribute(path: &AttributePath) -> Self {
        MetricFieldSelector::DatapointAttribute(path.path.clone())
    }

    /// Create a MetricFieldSelector from an AttributePath for resource attributes.
    pub fn from_resource_attribute(path: &AttributePath) -> Self {
        MetricFieldSelector::ResourceAttribute(path.path.clone())
    }

    /// Create a MetricFieldSelector from an AttributePath for scope attributes.
    pub fn from_scope_attribute(path: &AttributePath) -> Self {
        MetricFieldSelector::ScopeAttribute(path.path.clone())
    }

    /// Returns the attribute path if this is an attribute selector.
    pub fn attribute_path(&self) -> Option<&[String]> {
        match self {
            MetricFieldSelector::DatapointAttribute(p)
            | MetricFieldSelector::ResourceAttribute(p)
            | MetricFieldSelector::ScopeAttribute(p) => Some(p),
            MetricFieldSelector::Simple(_)
            | MetricFieldSelector::Type
            | MetricFieldSelector::Temporality => None,
        }
    }
}

/// Represents a field selector for trace/span records.
///
/// Attribute selectors use a path (Vec<String>) to support nested attribute access.
/// Enum fields (SpanKind, SpanStatus) and string fields (EventName, LinkTraceId)
/// use unit variants with synthesized exact-match patterns at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TraceFieldSelector {
    /// Simple trace field (name, trace_id, span_id, etc.)
    Simple(TraceField),
    /// Span attribute by path
    SpanAttribute(Vec<String>),
    /// Resource attribute by path
    ResourceAttribute(Vec<String>),
    /// Scope attribute by path
    ScopeAttribute(Vec<String>),
    /// Span kind — synthesized exact match on SpanKind::as_str_name()
    SpanKind,
    /// Span status code — synthesized exact match on SpanStatusCode::as_str_name()
    SpanStatus,
    /// Event name — synthesized exact match on event_name string value
    EventName,
    /// Event attribute by path
    EventAttribute(Vec<String>),
    /// Link trace ID — synthesized exact match on link_trace_id string value
    LinkTraceId,
    /// Sampling threshold — write-only field used by the engine to write the
    /// OTel `th` value to the span's tracestate via `Transformable::set_field`.
    SamplingThreshold,
}

impl TraceFieldSelector {
    /// Create a TraceFieldSelector from an AttributePath for span attributes.
    pub fn from_span_attribute(path: &AttributePath) -> Self {
        TraceFieldSelector::SpanAttribute(path.path.clone())
    }

    /// Create a TraceFieldSelector from an AttributePath for resource attributes.
    pub fn from_resource_attribute(path: &AttributePath) -> Self {
        TraceFieldSelector::ResourceAttribute(path.path.clone())
    }

    /// Create a TraceFieldSelector from an AttributePath for scope attributes.
    pub fn from_scope_attribute(path: &AttributePath) -> Self {
        TraceFieldSelector::ScopeAttribute(path.path.clone())
    }

    /// Create a TraceFieldSelector from an AttributePath for event attributes.
    pub fn from_event_attribute(path: &AttributePath) -> Self {
        TraceFieldSelector::EventAttribute(path.path.clone())
    }

    /// Returns the attribute path if this is an attribute selector.
    pub fn attribute_path(&self) -> Option<&[String]> {
        match self {
            TraceFieldSelector::SpanAttribute(p)
            | TraceFieldSelector::ResourceAttribute(p)
            | TraceFieldSelector::ScopeAttribute(p)
            | TraceFieldSelector::EventAttribute(p) => Some(p),
            TraceFieldSelector::Simple(_)
            | TraceFieldSelector::SpanKind
            | TraceFieldSelector::SpanStatus
            | TraceFieldSelector::EventName
            | TraceFieldSelector::LinkTraceId
            | TraceFieldSelector::SamplingThreshold => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_fields() {
        assert_eq!(
            LogFieldSelector::from_json("log_body", None),
            Some(LogFieldSelector::Simple(LogField::Body))
        );
        assert_eq!(
            LogFieldSelector::from_json("log_severity_text", None),
            Some(LogFieldSelector::Simple(LogField::SeverityText))
        );
    }

    #[test]
    fn parse_attribute_fields() {
        assert_eq!(
            LogFieldSelector::from_json("log_attribute", Some("ddsource")),
            Some(LogFieldSelector::LogAttribute(vec!["ddsource".to_string()]))
        );
        assert_eq!(
            LogFieldSelector::from_json("resource_attribute", Some("service.name")),
            Some(LogFieldSelector::ResourceAttribute(vec![
                "service.name".to_string()
            ]))
        );
    }

    #[test]
    fn parse_attribute_without_key_returns_none() {
        assert_eq!(LogFieldSelector::from_json("log_attribute", None), None);
    }

    #[test]
    fn parse_unknown_field_returns_none() {
        assert_eq!(LogFieldSelector::from_json("unknown", None), None);
    }

    #[test]
    fn from_attribute_path() {
        let path = AttributePath {
            path: vec!["http".to_string(), "method".to_string()],
        };
        let selector = LogFieldSelector::from_log_attribute(&path);
        assert_eq!(
            selector,
            LogFieldSelector::LogAttribute(vec!["http".to_string(), "method".to_string()])
        );
        assert_eq!(
            selector.attribute_path(),
            Some(&["http".to_string(), "method".to_string()][..])
        );
        assert_eq!(selector.attribute_key(), Some("http"));
    }

    #[test]
    fn attribute_key_backward_compat() {
        let selector = LogFieldSelector::LogAttribute(vec!["user_id".to_string()]);
        assert_eq!(selector.attribute_key(), Some("user_id"));
    }

    #[test]
    fn trace_field_selector_from_span_attribute() {
        let path = AttributePath {
            path: vec!["http.method".to_string()],
        };
        let selector = TraceFieldSelector::from_span_attribute(&path);
        assert_eq!(
            selector,
            TraceFieldSelector::SpanAttribute(vec!["http.method".to_string()])
        );
        assert_eq!(
            selector.attribute_path(),
            Some(&["http.method".to_string()][..])
        );
    }

    #[test]
    fn trace_field_selector_simple_has_no_path() {
        let selector = TraceFieldSelector::Simple(TraceField::Name);
        assert_eq!(selector.attribute_path(), None);
    }

    #[test]
    fn trace_field_selector_unit_variants_have_no_path() {
        assert_eq!(TraceFieldSelector::SpanKind.attribute_path(), None);
        assert_eq!(TraceFieldSelector::SpanStatus.attribute_path(), None);
        assert_eq!(TraceFieldSelector::EventName.attribute_path(), None);
        assert_eq!(TraceFieldSelector::LinkTraceId.attribute_path(), None);
        assert_eq!(TraceFieldSelector::SamplingThreshold.attribute_path(), None);
    }
}
