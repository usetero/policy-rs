//! Field selection utilities for log records.

use crate::proto::tero::policy::v1::LogField;

/// Represents a field selector for log records.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogFieldSelector {
    /// Simple log field (body, severity_text, etc.)
    Simple(LogField),
    /// Log record attribute by key
    LogAttribute(String),
    /// Resource attribute by key
    ResourceAttribute(String),
    /// Scope attribute by key
    ScopeAttribute(String),
}

impl LogFieldSelector {
    /// Parse a field selector from JSON field type and optional key.
    pub fn from_json(field_type: &str, key: Option<&str>) -> Option<Self> {
        match field_type {
            "log_body" => Some(LogFieldSelector::Simple(LogField::Body)),
            "log_severity_text" => Some(LogFieldSelector::Simple(LogField::SeverityText)),
            "log_trace_id" => Some(LogFieldSelector::Simple(LogField::TraceId)),
            "log_span_id" => Some(LogFieldSelector::Simple(LogField::SpanId)),
            "log_event_name" => Some(LogFieldSelector::Simple(LogField::EventName)),
            "resource_schema_url" => Some(LogFieldSelector::Simple(LogField::ResourceSchemaUrl)),
            "scope_schema_url" => Some(LogFieldSelector::Simple(LogField::ScopeSchemaUrl)),
            "log_attribute" => key.map(|k| LogFieldSelector::LogAttribute(k.to_string())),
            "resource_attribute" => key.map(|k| LogFieldSelector::ResourceAttribute(k.to_string())),
            "scope_attribute" => key.map(|k| LogFieldSelector::ScopeAttribute(k.to_string())),
            _ => None,
        }
    }

    /// Returns the attribute key if this is an attribute selector.
    pub fn attribute_key(&self) -> Option<&str> {
        match self {
            LogFieldSelector::LogAttribute(k)
            | LogFieldSelector::ResourceAttribute(k)
            | LogFieldSelector::ScopeAttribute(k) => Some(k),
            LogFieldSelector::Simple(_) => None,
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
            Some(LogFieldSelector::LogAttribute("ddsource".to_string()))
        );
        assert_eq!(
            LogFieldSelector::from_json("resource_attribute", Some("service.name")),
            Some(LogFieldSelector::ResourceAttribute(
                "service.name".to_string()
            ))
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
}
