//! Compiled transform structures for efficient application.

use regex::Regex;

use crate::error::PolicyError;
use crate::field::LogFieldSelector;
use crate::proto::tero::policy::v1::{
    LogField, LogTransform, log_add, log_redact, log_remove, log_rename,
};
use crate::registry::PolicyStats;

use super::signal::{LogSignal, Signal};
use super::transformable::Transformable;

/// A single transform operation.
#[derive(Debug, Clone)]
pub enum TransformOp<S: Signal> {
    /// Remove a field entirely.
    Remove { field: S::FieldSelector },
    /// Redact a field by replacing its value.
    ///
    /// When `regex` is `None`, the entire field value is replaced with
    /// `replacement`. When `regex` is `Some`, all non-overlapping matches of
    /// the pattern in the field value are replaced using `replacement` as a
    /// template (supports `$N`/`${name}` capture references). If no match is
    /// found, the field is left unchanged.
    Redact {
        field: S::FieldSelector,
        replacement: String,
        regex: Option<Regex>,
    },
    /// Rename a field to a new attribute key.
    Rename {
        from: S::FieldSelector,
        to: String,
        upsert: bool,
    },
    /// Add a new field with a value.
    Add {
        field: S::FieldSelector,
        value: String,
        upsert: bool,
    },
}

/// Compiled transforms for a single policy.
///
/// Operations are stored in execution order: remove, redact, rename, add.
#[derive(Debug, Clone)]
pub struct CompiledTransform<S: Signal> {
    /// Operations to apply, in order.
    pub ops: Vec<TransformOp<S>>,
}

impl<S: Signal> Default for CompiledTransform<S> {
    fn default() -> Self {
        Self { ops: Vec::new() }
    }
}

impl<S: Signal> CompiledTransform<S> {
    /// Apply all operations to a transformable record.
    ///
    /// Returns the number of operations that were successfully applied.
    pub fn apply<T: Transformable<Signal = S>>(&self, record: &mut T) -> usize {
        self.apply_with_stats(record, None)
    }

    /// Apply all operations to a transformable record, recording stats.
    ///
    /// Returns the number of operations that were successfully applied.
    ///
    /// The engine drives high-level semantics (regex matching, upsert
    /// preconditions, source-absent no-ops) by composing the record's three
    /// [`Transformable`] primitives — `set_field`, `delete_field`,
    /// `move_field` — with [`Matchable::field_exists`] and `get_field` checks.
    pub fn apply_with_stats<T: Transformable<Signal = S>>(
        &self,
        record: &mut T,
        stats: Option<&PolicyStats>,
    ) -> usize {
        let mut applied = 0;
        for op in &self.ops {
            let success = match op {
                TransformOp::Remove { field } => {
                    let result = record.delete_field(field);
                    if let Some(s) = stats {
                        if result {
                            s.remove.record_hit();
                        } else {
                            s.remove.record_miss();
                        }
                    }
                    result
                }
                TransformOp::Redact {
                    field,
                    replacement,
                    regex,
                } => {
                    // Per spec:
                    // - Redact on a nonexistent field MUST be a no-op.
                    // - When `regex` is set and produces no match, no
                    //   modification is applied.
                    // - When `regex` is unset, the entire value is replaced.
                    let result = match regex {
                        Some(re) => {
                            let current = record.get_field(field).map(|c| c.into_owned());
                            match current {
                                Some(current) => {
                                    let new_value = re.replace_all(&current, replacement.as_str());
                                    if new_value == current {
                                        false
                                    } else {
                                        let owned = new_value.into_owned();
                                        record.set_field(field, &owned);
                                        true
                                    }
                                }
                                None => false,
                            }
                        }
                        None => {
                            if record.field_exists(field) {
                                record.set_field(field, replacement);
                                true
                            } else {
                                false
                            }
                        }
                    };
                    if let Some(s) = stats {
                        if result {
                            s.redact.record_hit();
                        } else {
                            s.redact.record_miss();
                        }
                    }
                    result
                }
                TransformOp::Rename { from, to, upsert } => {
                    let result = if !record.field_exists(from) {
                        false
                    } else if let Some(to_selector) = S::rename_target(from, to) {
                        if !*upsert && record.field_exists(&to_selector) {
                            false
                        } else {
                            record.move_field(from, &to_selector);
                            true
                        }
                    } else {
                        // Rename of a simple field is a no-op (matches Go/Zig).
                        false
                    };
                    if let Some(s) = stats {
                        if result {
                            s.rename.record_hit();
                        } else {
                            s.rename.record_miss();
                        }
                    }
                    result
                }
                TransformOp::Add {
                    field,
                    value,
                    upsert,
                } => {
                    let result = if !*upsert && record.field_exists(field) {
                        false
                    } else {
                        record.set_field(field, value);
                        true
                    };
                    if let Some(s) = stats {
                        if result {
                            s.add.record_hit();
                        } else {
                            s.add.record_miss();
                        }
                    }
                    result
                }
            };
            if success {
                applied += 1;
            }
        }
        applied
    }

    /// Check if this transform has any operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Log-specific transform compilation from proto.
impl CompiledTransform<LogSignal> {
    /// Build from proto LogTransform.
    ///
    /// Returns an error if any redact regex fails to compile.
    pub fn from_proto(transform: &LogTransform, policy_id: &str) -> Result<Self, PolicyError> {
        let mut ops = Vec::new();

        // Remove operations first
        for remove in &transform.remove {
            if let Some(field) = Self::convert_remove_field(&remove.field) {
                ops.push(TransformOp::Remove { field });
            }
        }

        // Redact operations second
        for redact in &transform.redact {
            if let Some(field) = Self::convert_redact_field(&redact.field) {
                let regex = match &redact.regex {
                    Some(pattern) => {
                        Some(Regex::new(pattern).map_err(|e| PolicyError::InvalidPolicy {
                            policy_id: policy_id.to_string(),
                            reason: format!("invalid redact regex '{}': {}", pattern, e),
                        })?)
                    }
                    None => None,
                };
                ops.push(TransformOp::Redact {
                    field,
                    replacement: redact.replacement.clone(),
                    regex,
                });
            }
        }

        // Rename operations third
        for rename in &transform.rename {
            if let Some(from) = Self::convert_rename_from(&rename.from) {
                ops.push(TransformOp::Rename {
                    from,
                    to: rename.to.clone(),
                    upsert: rename.upsert,
                });
            }
        }

        // Add operations last
        for add in &transform.add {
            if let Some(field) = Self::convert_add_field(&add.field) {
                ops.push(TransformOp::Add {
                    field,
                    value: add.value.clone(),
                    upsert: add.upsert,
                });
            }
        }

        Ok(Self { ops })
    }

    fn convert_remove_field(field: &Option<log_remove::Field>) -> Option<LogFieldSelector> {
        match field {
            Some(log_remove::Field::LogField(f)) => {
                let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
                Some(LogFieldSelector::Simple(field))
            }
            Some(log_remove::Field::LogAttribute(path)) => {
                Some(LogFieldSelector::from_log_attribute(path))
            }
            Some(log_remove::Field::ResourceAttribute(path)) => {
                Some(LogFieldSelector::from_resource_attribute(path))
            }
            Some(log_remove::Field::ScopeAttribute(path)) => {
                Some(LogFieldSelector::from_scope_attribute(path))
            }
            None => None,
        }
    }

    fn convert_redact_field(field: &Option<log_redact::Field>) -> Option<LogFieldSelector> {
        match field {
            Some(log_redact::Field::LogField(f)) => {
                let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
                Some(LogFieldSelector::Simple(field))
            }
            Some(log_redact::Field::LogAttribute(path)) => {
                Some(LogFieldSelector::from_log_attribute(path))
            }
            Some(log_redact::Field::ResourceAttribute(path)) => {
                Some(LogFieldSelector::from_resource_attribute(path))
            }
            Some(log_redact::Field::ScopeAttribute(path)) => {
                Some(LogFieldSelector::from_scope_attribute(path))
            }
            None => None,
        }
    }

    fn convert_rename_from(from: &Option<log_rename::From>) -> Option<LogFieldSelector> {
        match from {
            Some(log_rename::From::FromLogField(f)) => {
                let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
                Some(LogFieldSelector::Simple(field))
            }
            Some(log_rename::From::FromLogAttribute(path)) => {
                Some(LogFieldSelector::from_log_attribute(path))
            }
            Some(log_rename::From::FromResourceAttribute(path)) => {
                Some(LogFieldSelector::from_resource_attribute(path))
            }
            Some(log_rename::From::FromScopeAttribute(path)) => {
                Some(LogFieldSelector::from_scope_attribute(path))
            }
            None => None,
        }
    }

    fn convert_add_field(field: &Option<log_add::Field>) -> Option<LogFieldSelector> {
        match field {
            Some(log_add::Field::LogField(f)) => {
                let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
                Some(LogFieldSelector::Simple(field))
            }
            Some(log_add::Field::LogAttribute(path)) => {
                Some(LogFieldSelector::from_log_attribute(path))
            }
            Some(log_add::Field::ResourceAttribute(path)) => {
                Some(LogFieldSelector::from_resource_attribute(path))
            }
            Some(log_add::Field::ScopeAttribute(path)) => {
                Some(LogFieldSelector::from_scope_attribute(path))
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signal::LogSignal;
    use crate::proto::tero::policy::v1::{LogAdd, LogRedact, LogRemove, LogRename};
    use std::collections::HashMap;

    struct TestLog {
        body: Option<String>,
        attributes: HashMap<String, String>,
    }

    impl TestLog {
        fn new() -> Self {
            Self {
                body: None,
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

    impl crate::engine::matchable::Matchable for TestLog {
        type Signal = LogSignal;
        fn get_field(&self, field: &LogFieldSelector) -> Option<std::borrow::Cow<'_, str>> {
            match field {
                LogFieldSelector::Simple(LogField::Body) => {
                    self.body.as_deref().map(std::borrow::Cow::Borrowed)
                }
                LogFieldSelector::LogAttribute(path) => path
                    .first()
                    .and_then(|key| self.attributes.get(key))
                    .map(|v| std::borrow::Cow::Borrowed(v.as_str())),
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
    fn from_proto_empty() {
        let proto = LogTransform::default();
        let compiled = CompiledTransform::<LogSignal>::from_proto(&proto, "p").unwrap();
        assert!(compiled.is_empty());
    }

    #[test]
    fn from_proto_with_remove() {
        let proto = LogTransform {
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogField(LogField::Body.into())),
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert_eq!(compiled.ops.len(), 1);
        assert!(matches!(&compiled.ops[0], TransformOp::Remove { field }
            if matches!(field, LogFieldSelector::Simple(LogField::Body))));
    }

    #[test]
    fn from_proto_with_redact() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(AttributePath {
                    path: vec!["secret".to_string()],
                })),
                replacement: "[REDACTED]".to_string(),
                regex: None,
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert_eq!(compiled.ops.len(), 1);
        assert!(matches!(
            &compiled.ops[0],
            TransformOp::Redact { field, replacement, regex: None }
            if matches!(field, LogFieldSelector::LogAttribute(p) if p == &vec!["secret".to_string()])
            && replacement == "[REDACTED]"
        ));
    }

    #[test]
    fn from_proto_with_redact_regex_compiles() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(AttributePath {
                    path: vec!["card".to_string()],
                })),
                replacement: "****".to_string(),
                regex: Some(r"\d{4}".to_string()),
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert!(matches!(
            &compiled.ops[0],
            TransformOp::Redact { regex: Some(_), .. }
        ));
    }

    #[test]
    fn from_proto_with_invalid_redact_regex_returns_error() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(AttributePath {
                    path: vec!["card".to_string()],
                })),
                replacement: "****".to_string(),
                regex: Some("(".to_string()),
            }],
            ..Default::default()
        };
        let err = CompiledTransform::from_proto(&proto, "bad-policy").unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidPolicy { ref policy_id, .. } if policy_id == "bad-policy"
        ));
    }

    #[test]
    fn from_proto_with_rename() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            rename: vec![LogRename {
                from: Some(log_rename::From::FromLogAttribute(AttributePath {
                    path: vec!["old".to_string()],
                })),
                to: "new".to_string(),
                upsert: true,
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert_eq!(compiled.ops.len(), 1);
        assert!(
            matches!(&compiled.ops[0], TransformOp::Rename { from, to, upsert }
            if matches!(from, LogFieldSelector::LogAttribute(p) if p == &vec!["old".to_string()])
            && to == "new" && *upsert)
        );
    }

    #[test]
    fn from_proto_with_add() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(AttributePath {
                    path: vec!["tag".to_string()],
                })),
                value: "production".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert_eq!(compiled.ops.len(), 1);
        assert!(
            matches!(&compiled.ops[0], TransformOp::Add { field, value, upsert }
            if matches!(field, LogFieldSelector::LogAttribute(p) if p == &vec!["tag".to_string()])
            && value == "production" && !*upsert)
        );
    }

    #[test]
    fn from_proto_ordering() {
        use crate::proto::tero::policy::v1::AttributePath;
        let proto = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute(AttributePath {
                    path: vec!["add".to_string()],
                })),
                value: "v".to_string(),
                upsert: false,
            }],
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogAttribute(AttributePath {
                    path: vec!["remove".to_string()],
                })),
            }],
            rename: vec![LogRename {
                from: Some(log_rename::From::FromLogAttribute(AttributePath {
                    path: vec!["rename".to_string()],
                })),
                to: "renamed".to_string(),
                upsert: false,
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute(AttributePath {
                    path: vec!["redact".to_string()],
                })),
                replacement: "X".to_string(),
                regex: None,
            }],
        };
        let compiled = CompiledTransform::from_proto(&proto, "p").unwrap();
        assert_eq!(compiled.ops.len(), 4);

        assert!(matches!(&compiled.ops[0], TransformOp::Remove { .. }));
        assert!(matches!(&compiled.ops[1], TransformOp::Redact { .. }));
        assert!(matches!(&compiled.ops[2], TransformOp::Rename { .. }));
        assert!(matches!(&compiled.ops[3], TransformOp::Add { .. }));
    }

    #[test]
    fn apply_multiple_ops() {
        let mut log = TestLog::new()
            .with_body("original body")
            .with_attr("secret", "password123")
            .with_attr("old_name", "value");

        let transform = CompiledTransform::<LogSignal> {
            ops: vec![
                TransformOp::Redact {
                    field: LogFieldSelector::LogAttribute(vec!["secret".to_string()]),
                    replacement: "[REDACTED]".to_string(),
                    regex: None,
                },
                TransformOp::Rename {
                    from: LogFieldSelector::LogAttribute(vec!["old_name".to_string()]),
                    to: "new_name".to_string(),
                    upsert: false,
                },
                TransformOp::Add {
                    field: LogFieldSelector::LogAttribute(vec!["env".to_string()]),
                    value: "prod".to_string(),
                    upsert: false,
                },
            ],
        };

        let applied = transform.apply(&mut log);
        assert_eq!(applied, 3);
        assert_eq!(
            log.attributes.get("secret"),
            Some(&"[REDACTED]".to_string())
        );
        assert!(!log.attributes.contains_key("old_name"));
        assert_eq!(log.attributes.get("new_name"), Some(&"value".to_string()));
        assert_eq!(log.attributes.get("env"), Some(&"prod".to_string()));
    }

    #[test]
    fn apply_returns_count_of_successful_ops() {
        let mut log = TestLog::new().with_body("test");

        let transform = CompiledTransform::<LogSignal> {
            ops: vec![
                TransformOp::Remove {
                    field: LogFieldSelector::Simple(LogField::Body),
                },
                TransformOp::Redact {
                    field: LogFieldSelector::LogAttribute(vec!["nonexistent".to_string()]),
                    replacement: "X".to_string(),
                    regex: None,
                },
            ],
        };

        let applied = transform.apply(&mut log);
        assert_eq!(applied, 1);
    }

    #[test]
    fn redact_nonexistent_attribute_does_not_create_it() {
        let mut log = TestLog::new()
            .with_body("test")
            .with_attr("existing", "keep-me");

        let transform = CompiledTransform::<LogSignal> {
            ops: vec![TransformOp::Redact {
                field: LogFieldSelector::LogAttribute(vec!["missing".to_string()]),
                replacement: "[REDACTED]".to_string(),
                regex: None,
            }],
        };

        let applied = transform.apply(&mut log);
        assert_eq!(applied, 0);
        // The "missing" attribute must NOT be created
        assert!(!log.attributes.contains_key("missing"));
        // Existing attributes must be unchanged
        assert_eq!(log.attributes.get("existing"), Some(&"keep-me".to_string()));
    }

    #[test]
    fn redact_with_regex_replaces_matching_substrings() {
        let mut log = TestLog::new().with_attr("body", "card 4111 2222 3333 4444 expires soon");
        let transform = CompiledTransform::<LogSignal> {
            ops: vec![TransformOp::Redact {
                field: LogFieldSelector::LogAttribute(vec!["body".to_string()]),
                replacement: "****".to_string(),
                regex: Some(Regex::new(r"\d{4}").unwrap()),
            }],
        };
        let applied = transform.apply(&mut log);
        assert_eq!(applied, 1);
        assert_eq!(
            log.attributes.get("body"),
            Some(&"card **** **** **** **** expires soon".to_string())
        );
    }

    #[test]
    fn redact_with_regex_no_match_leaves_value_unchanged() {
        let mut log = TestLog::new().with_attr("body", "no digits here");
        let transform = CompiledTransform::<LogSignal> {
            ops: vec![TransformOp::Redact {
                field: LogFieldSelector::LogAttribute(vec!["body".to_string()]),
                replacement: "****".to_string(),
                regex: Some(Regex::new(r"\d{4}").unwrap()),
            }],
        };
        let applied = transform.apply(&mut log);
        assert_eq!(applied, 0);
        assert_eq!(
            log.attributes.get("body"),
            Some(&"no digits here".to_string())
        );
    }

    #[test]
    fn redact_with_regex_supports_capture_group_template() {
        let mut log = TestLog::new().with_attr("body", "email alice@example.com here");
        let transform = CompiledTransform::<LogSignal> {
            ops: vec![TransformOp::Redact {
                field: LogFieldSelector::LogAttribute(vec!["body".to_string()]),
                replacement: "$1@***".to_string(),
                regex: Some(Regex::new(r"(\w+)@[\w.]+").unwrap()),
            }],
        };
        let applied = transform.apply(&mut log);
        assert_eq!(applied, 1);
        assert_eq!(
            log.attributes.get("body"),
            Some(&"email alice@*** here".to_string())
        );
    }

    #[test]
    fn redact_with_regex_on_nonexistent_field_is_noop() {
        let mut log = TestLog::new();
        let transform = CompiledTransform::<LogSignal> {
            ops: vec![TransformOp::Redact {
                field: LogFieldSelector::LogAttribute(vec!["missing".to_string()]),
                replacement: "****".to_string(),
                regex: Some(Regex::new(r"\d+").unwrap()),
            }],
        };
        let applied = transform.apply(&mut log);
        assert_eq!(applied, 0);
        assert!(!log.attributes.contains_key("missing"));
    }
}
