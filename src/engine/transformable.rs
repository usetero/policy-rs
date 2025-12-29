//! Transformable trait for applying mutations to log records.

use crate::field::LogFieldSelector;

/// Trait for types that can be transformed by policies.
///
/// This uses a visitor pattern where the policy engine calls these methods
/// to apply transformations, and the implementor handles the actual mutations
/// to their log data structure.
///
/// Each method returns `true` if the operation was successfully applied.
pub trait Transformable {
    /// Remove a field entirely.
    ///
    /// Returns `true` if the field existed and was removed.
    fn remove_field(&mut self, field: &LogFieldSelector) -> bool;

    /// Redact a field by replacing its value with the replacement string.
    ///
    /// Returns `true` if the field existed and was redacted.
    fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool;

    /// Rename a field by moving it from one location to another.
    ///
    /// The `to` parameter is the new attribute key name. For simple fields,
    /// this moves the value to a log attribute with the given name.
    ///
    /// If `upsert` is false and the target already exists, do nothing and return false.
    /// Returns `true` if the rename was performed.
    fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool;

    /// Add a new field with the given value.
    ///
    /// If `upsert` is false and the field already exists, do nothing and return false.
    /// Returns `true` if the field was added or updated.
    fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::LogField;
    use std::collections::HashMap;

    struct TestLog {
        body: Option<String>,
        severity: Option<String>,
        attributes: HashMap<String, String>,
    }

    impl TestLog {
        fn new() -> Self {
            Self {
                body: None,
                severity: None,
                attributes: HashMap::new(),
            }
        }

        fn with_body(mut self, body: &str) -> Self {
            self.body = Some(body.to_string());
            self
        }

        fn with_attr(mut self, key: &str, value: &str) -> Self {
            self.attributes.insert(key.to_string(), value.to_string());
            self
        }
    }

    impl Transformable for TestLog {
        fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.take().is_some(),
                    LogField::SeverityText => self.severity.take().is_some(),
                    _ => false,
                },
                LogFieldSelector::LogAttribute(key) => self.attributes.remove(key).is_some(),
                _ => false,
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
                        if self.severity.is_some() {
                            self.severity = Some(replacement.to_string());
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                },
                LogFieldSelector::LogAttribute(key) => {
                    if self.attributes.contains_key(key) {
                        self.attributes.insert(key.clone(), replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }

        fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
            // Check if target exists
            if !upsert && self.attributes.contains_key(to) {
                return false;
            }

            // Get the value from source
            let value = match from {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => self.body.take(),
                    LogField::SeverityText => self.severity.take(),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(key) => self.attributes.remove(key),
                _ => None,
            };

            // Set the value at target
            if let Some(v) = value {
                self.attributes.insert(to.to_string(), v);
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
                        if !upsert && self.severity.is_some() {
                            return false;
                        }
                        self.severity = Some(value.to_string());
                        true
                    }
                    _ => false,
                },
                LogFieldSelector::LogAttribute(key) => {
                    if !upsert && self.attributes.contains_key(key) {
                        return false;
                    }
                    self.attributes.insert(key.clone(), value.to_string());
                    true
                }
                _ => false,
            }
        }
    }

    #[test]
    fn remove_existing_field() {
        let mut log = TestLog::new().with_body("test");
        assert!(log.remove_field(&LogFieldSelector::Simple(LogField::Body)));
        assert!(log.body.is_none());
    }

    #[test]
    fn remove_nonexistent_field() {
        let mut log = TestLog::new();
        assert!(!log.remove_field(&LogFieldSelector::Simple(LogField::Body)));
    }

    #[test]
    fn remove_attribute() {
        let mut log = TestLog::new().with_attr("key", "value");
        assert!(log.remove_field(&LogFieldSelector::LogAttribute("key".to_string())));
        assert!(!log.attributes.contains_key("key"));
    }

    #[test]
    fn redact_existing_field() {
        let mut log = TestLog::new().with_body("secret data");
        assert!(log.redact_field(&LogFieldSelector::Simple(LogField::Body), "[REDACTED]"));
        assert_eq!(log.body, Some("[REDACTED]".to_string()));
    }

    #[test]
    fn redact_nonexistent_field() {
        let mut log = TestLog::new();
        assert!(!log.redact_field(&LogFieldSelector::Simple(LogField::Body), "[REDACTED]"));
    }

    #[test]
    fn rename_field_to_attribute() {
        let mut log = TestLog::new().with_body("original");
        assert!(log.rename_field(
            &LogFieldSelector::Simple(LogField::Body),
            "body_backup",
            false
        ));
        assert!(log.body.is_none());
        assert_eq!(
            log.attributes.get("body_backup"),
            Some(&"original".to_string())
        );
    }

    #[test]
    fn rename_attribute() {
        let mut log = TestLog::new().with_attr("old_key", "value");
        assert!(log.rename_field(
            &LogFieldSelector::LogAttribute("old_key".to_string()),
            "new_key",
            false
        ));
        assert!(!log.attributes.contains_key("old_key"));
        assert_eq!(log.attributes.get("new_key"), Some(&"value".to_string()));
    }

    #[test]
    fn rename_no_upsert_target_exists() {
        let mut log = TestLog::new()
            .with_attr("source", "source_value")
            .with_attr("target", "target_value");
        assert!(!log.rename_field(
            &LogFieldSelector::LogAttribute("source".to_string()),
            "target",
            false
        ));
        // Source should still exist
        assert_eq!(
            log.attributes.get("source"),
            Some(&"source_value".to_string())
        );
        // Target should be unchanged
        assert_eq!(
            log.attributes.get("target"),
            Some(&"target_value".to_string())
        );
    }

    #[test]
    fn rename_upsert_overwrites() {
        let mut log = TestLog::new()
            .with_attr("source", "source_value")
            .with_attr("target", "target_value");
        assert!(log.rename_field(
            &LogFieldSelector::LogAttribute("source".to_string()),
            "target",
            true
        ));
        assert!(!log.attributes.contains_key("source"));
        assert_eq!(
            log.attributes.get("target"),
            Some(&"source_value".to_string())
        );
    }

    #[test]
    fn add_new_field() {
        let mut log = TestLog::new();
        assert!(log.add_field(
            &LogFieldSelector::LogAttribute("new_key".to_string()),
            "new_value",
            false
        ));
        assert_eq!(
            log.attributes.get("new_key"),
            Some(&"new_value".to_string())
        );
    }

    #[test]
    fn add_no_upsert_exists() {
        let mut log = TestLog::new().with_attr("key", "original");
        assert!(!log.add_field(
            &LogFieldSelector::LogAttribute("key".to_string()),
            "new_value",
            false
        ));
        assert_eq!(log.attributes.get("key"), Some(&"original".to_string()));
    }

    #[test]
    fn add_upsert_overwrites() {
        let mut log = TestLog::new().with_attr("key", "original");
        assert!(log.add_field(
            &LogFieldSelector::LogAttribute("key".to_string()),
            "new_value",
            true
        ));
        assert_eq!(log.attributes.get("key"), Some(&"new_value".to_string()));
    }

    #[test]
    fn add_simple_field() {
        let mut log = TestLog::new();
        assert!(log.add_field(&LogFieldSelector::Simple(LogField::Body), "new body", false));
        assert_eq!(log.body, Some("new body".to_string()));
    }
}
