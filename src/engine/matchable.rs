//! Matchable trait for field access.

use crate::field::LogFieldSelector;

/// Trait for types that can be matched against policies.
///
/// Implementors provide field access for log records by implementing
/// the single `get_field` method.
pub trait Matchable {
    /// Get a field value by selector.
    ///
    /// Returns `None` for fields that don't exist or aren't applicable.
    fn get_field(&self, field: &LogFieldSelector) -> Option<&str>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::LogField;
    use std::collections::HashMap;

    /// A simple test log record for testing.
    struct TestLog {
        body: String,
        severity_text: String,
        log_attributes: HashMap<String, String>,
        resource_attributes: HashMap<String, String>,
    }

    impl Matchable for TestLog {
        fn get_field(&self, field: &LogFieldSelector) -> Option<&str> {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => Some(&self.body),
                    LogField::SeverityText => Some(&self.severity_text),
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

    #[test]
    fn get_simple_field() {
        let log = TestLog {
            body: "test message".to_string(),
            severity_text: "ERROR".to_string(),
            log_attributes: HashMap::new(),
            resource_attributes: HashMap::new(),
        };

        assert_eq!(
            log.get_field(&LogFieldSelector::Simple(LogField::Body)),
            Some("test message")
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::Simple(LogField::SeverityText)),
            Some("ERROR")
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::Simple(LogField::TraceId)),
            None
        );
    }

    #[test]
    fn get_attribute_field() {
        let mut log_attrs = HashMap::new();
        log_attrs.insert("ddsource".to_string(), "nginx".to_string());

        let mut resource_attrs = HashMap::new();
        resource_attrs.insert("service.name".to_string(), "my-service".to_string());

        let log = TestLog {
            body: "test".to_string(),
            severity_text: "INFO".to_string(),
            log_attributes: log_attrs,
            resource_attributes: resource_attrs,
        };

        assert_eq!(
            log.get_field(&LogFieldSelector::LogAttribute("ddsource".to_string())),
            Some("nginx")
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::ResourceAttribute(
                "service.name".to_string()
            )),
            Some("my-service")
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::LogAttribute("missing".to_string())),
            None
        );
    }
}
