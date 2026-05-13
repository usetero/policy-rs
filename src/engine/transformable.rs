//! Transformable trait for applying mutations to telemetry records.

use super::matchable::Matchable;
use super::signal::Signal;

/// Trait for types that can be transformed by policies.
///
/// Implementors expose three minimal write primitives — `set_field`,
/// `delete_field`, and `move_field`. The engine drives the higher-level
/// transform ops (redact-with-regex, add-with-upsert, rename-with-upsert)
/// using these primitives plus the read side of [`Matchable`].
///
/// `Transformable` requires `Matchable` so the engine can read the current
/// value of a field (for regex redact) and check existence (for upsert
/// preconditions and source-absent no-ops on rename).
pub trait Transformable: Matchable {
    /// Set the value of `field`. If the field already exists, its value is
    /// overwritten; otherwise it is created.
    ///
    /// `value` is borrowed for the duration of the call — copy it if you
    /// need to retain it past the return.
    fn set_field(&mut self, field: &<Self::Signal as Signal>::FieldSelector, value: &str);

    /// Delete `field`. Returns `true` if the field existed and was deleted,
    /// `false` if it was absent.
    fn delete_field(&mut self, field: &<Self::Signal as Signal>::FieldSelector) -> bool;

    /// Move the value of `from` to the selector `to`.
    ///
    /// The engine constructs `to` via [`Signal::rename_target`], which
    /// preserves the source's attribute namespace — so a
    /// `ResourceAttribute → "foo"` rename arrives as `ResourceAttribute["foo"]`,
    /// keeping the move within the same namespace.
    ///
    /// The engine guarantees:
    /// - `from` exists at the time of the call (checked via
    ///   [`Matchable::field_exists`]).
    /// - Upsert preconditions on `to` have been validated.
    ///
    /// Implementors should therefore unconditionally perform the move and
    /// must not re-check existence or upsert semantics. The move should
    /// preserve the underlying value type (e.g. for OTel records, the
    /// non-string value variants should be copied as-is rather than
    /// stringified).
    fn move_field(
        &mut self,
        from: &<Self::Signal as Signal>::FieldSelector,
        to: &<Self::Signal as Signal>::FieldSelector,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signal::LogSignal;
    use crate::field::LogFieldSelector;
    use crate::proto::tero::policy::v1::LogField;
    use std::borrow::Cow;
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

    impl Matchable for TestLog {
        type Signal = LogSignal;

        fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                LogFieldSelector::Simple(LogField::Body) => {
                    self.body.as_deref().map(Cow::Borrowed)
                }
                LogFieldSelector::Simple(LogField::SeverityText) => {
                    self.severity.as_deref().map(Cow::Borrowed)
                }
                LogFieldSelector::LogAttribute(path) => path
                    .first()
                    .and_then(|key| self.attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                _ => None,
            }
        }
    }

    impl Transformable for TestLog {
        fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
            match field {
                LogFieldSelector::Simple(LogField::Body) => {
                    self.body = Some(value.to_string());
                }
                LogFieldSelector::Simple(LogField::SeverityText) => {
                    self.severity = Some(value.to_string());
                }
                LogFieldSelector::LogAttribute(path) => {
                    if let Some(key) = path.first() {
                        self.attributes.insert(key.clone(), value.to_string());
                    }
                }
                _ => {}
            }
        }

        fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
            match field {
                LogFieldSelector::Simple(LogField::Body) => self.body.take().is_some(),
                LogFieldSelector::Simple(LogField::SeverityText) => {
                    self.severity.take().is_some()
                }
                LogFieldSelector::LogAttribute(path) => path
                    .first()
                    .and_then(|key| self.attributes.remove(key))
                    .is_some(),
                _ => false,
            }
        }

        fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
            let value = match from {
                LogFieldSelector::Simple(LogField::Body) => self.body.take(),
                LogFieldSelector::Simple(LogField::SeverityText) => self.severity.take(),
                LogFieldSelector::LogAttribute(path) => {
                    path.first().and_then(|key| self.attributes.remove(key))
                }
                _ => None,
            };
            let target_key = match to {
                LogFieldSelector::LogAttribute(path) => path.first().cloned(),
                _ => None,
            };
            if let (Some(v), Some(k)) = (value, target_key) {
                self.attributes.insert(k, v);
            }
        }
    }

    #[test]
    fn set_simple_field_overwrites() {
        let mut log = TestLog::new().with_body("original");
        log.set_field(&LogFieldSelector::Simple(LogField::Body), "replaced");
        assert_eq!(log.body, Some("replaced".to_string()));
    }

    #[test]
    fn set_attribute_creates_when_absent() {
        let mut log = TestLog::new();
        log.set_field(
            &LogFieldSelector::LogAttribute(vec!["new".to_string()]),
            "value",
        );
        assert_eq!(log.attributes.get("new"), Some(&"value".to_string()));
    }

    #[test]
    fn delete_returns_true_when_present() {
        let mut log = TestLog::new().with_body("x");
        assert!(log.delete_field(&LogFieldSelector::Simple(LogField::Body)));
        assert!(log.body.is_none());
    }

    #[test]
    fn delete_returns_false_when_absent() {
        let mut log = TestLog::new();
        assert!(!log.delete_field(&LogFieldSelector::Simple(LogField::Body)));
    }

    #[test]
    fn move_field_relocates_value() {
        let mut log = TestLog::new().with_attr("old", "value");
        log.move_field(
            &LogFieldSelector::LogAttribute(vec!["old".to_string()]),
            &LogFieldSelector::LogAttribute(vec!["new".to_string()]),
        );
        assert!(!log.attributes.contains_key("old"));
        assert_eq!(log.attributes.get("new"), Some(&"value".to_string()));
    }
}
