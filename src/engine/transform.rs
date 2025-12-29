//! Compiled transform structures for efficient application.

use crate::field::LogFieldSelector;
use crate::proto::tero::policy::v1::{
    LogField, LogTransform, log_add, log_redact, log_remove, log_rename,
};
use crate::registry::PolicyStats;

use super::transformable::Transformable;

/// A single transform operation.
#[derive(Debug, Clone)]
pub enum TransformOp {
    /// Remove a field entirely.
    Remove { field: LogFieldSelector },
    /// Redact a field by replacing its value.
    Redact {
        field: LogFieldSelector,
        replacement: String,
    },
    /// Rename a field to a new attribute key.
    Rename {
        from: LogFieldSelector,
        to: String,
        upsert: bool,
    },
    /// Add a new field with a value.
    Add {
        field: LogFieldSelector,
        value: String,
        upsert: bool,
    },
}

/// Compiled transforms for a single policy.
///
/// Operations are stored in execution order: remove, redact, rename, add.
#[derive(Debug, Clone, Default)]
pub struct CompiledTransform {
    /// Operations to apply, in order.
    pub ops: Vec<TransformOp>,
}

impl CompiledTransform {
    /// Build from proto LogTransform.
    pub fn from_proto(transform: &LogTransform) -> Self {
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
                ops.push(TransformOp::Redact {
                    field,
                    replacement: redact.replacement.clone(),
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

        Self { ops }
    }

    /// Apply all operations to a transformable log.
    ///
    /// Returns the number of operations that were successfully applied.
    pub fn apply<T: Transformable>(&self, log: &mut T) -> usize {
        self.apply_with_stats(log, None)
    }

    /// Apply all operations to a transformable log, recording stats.
    ///
    /// Returns the number of operations that were successfully applied.
    pub fn apply_with_stats<T: Transformable>(
        &self,
        log: &mut T,
        stats: Option<&PolicyStats>,
    ) -> usize {
        let mut applied = 0;
        for op in &self.ops {
            let success = match op {
                TransformOp::Remove { field } => {
                    let result = log.remove_field(field);
                    if let Some(s) = stats {
                        if result {
                            s.remove.record_hit();
                        } else {
                            s.remove.record_miss();
                        }
                    }
                    result
                }
                TransformOp::Redact { field, replacement } => {
                    let result = log.redact_field(field, replacement);
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
                    let result = log.rename_field(from, to, *upsert);
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
                    let result = log.add_field(field, value, *upsert);
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

    fn convert_remove_field(field: &Option<log_remove::Field>) -> Option<LogFieldSelector> {
        match field {
            Some(log_remove::Field::LogField(f)) => {
                let field = LogField::try_from(*f).unwrap_or(LogField::Unspecified);
                Some(LogFieldSelector::Simple(field))
            }
            Some(log_remove::Field::LogAttribute(key)) => {
                Some(LogFieldSelector::LogAttribute(key.clone()))
            }
            Some(log_remove::Field::ResourceAttribute(key)) => {
                Some(LogFieldSelector::ResourceAttribute(key.clone()))
            }
            Some(log_remove::Field::ScopeAttribute(key)) => {
                Some(LogFieldSelector::ScopeAttribute(key.clone()))
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
            Some(log_redact::Field::LogAttribute(key)) => {
                Some(LogFieldSelector::LogAttribute(key.clone()))
            }
            Some(log_redact::Field::ResourceAttribute(key)) => {
                Some(LogFieldSelector::ResourceAttribute(key.clone()))
            }
            Some(log_redact::Field::ScopeAttribute(key)) => {
                Some(LogFieldSelector::ScopeAttribute(key.clone()))
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
            Some(log_rename::From::FromLogAttribute(key)) => {
                Some(LogFieldSelector::LogAttribute(key.clone()))
            }
            Some(log_rename::From::FromResourceAttribute(key)) => {
                Some(LogFieldSelector::ResourceAttribute(key.clone()))
            }
            Some(log_rename::From::FromScopeAttribute(key)) => {
                Some(LogFieldSelector::ScopeAttribute(key.clone()))
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
            Some(log_add::Field::LogAttribute(key)) => {
                Some(LogFieldSelector::LogAttribute(key.clone()))
            }
            Some(log_add::Field::ResourceAttribute(key)) => {
                Some(LogFieldSelector::ResourceAttribute(key.clone()))
            }
            Some(log_add::Field::ScopeAttribute(key)) => {
                Some(LogFieldSelector::ScopeAttribute(key.clone()))
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    impl Transformable for TestLog {
        fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
            match field {
                LogFieldSelector::Simple(LogField::Body) => self.body.take().is_some(),
                LogFieldSelector::LogAttribute(key) => self.attributes.remove(key).is_some(),
                _ => false,
            }
        }

        fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
            match field {
                LogFieldSelector::Simple(LogField::Body) => {
                    if self.body.is_some() {
                        self.body = Some(replacement.to_string());
                        true
                    } else {
                        false
                    }
                }
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
            if !upsert && self.attributes.contains_key(to) {
                return false;
            }
            let value = match from {
                LogFieldSelector::Simple(LogField::Body) => self.body.take(),
                LogFieldSelector::LogAttribute(key) => self.attributes.remove(key),
                _ => None,
            };
            if let Some(v) = value {
                self.attributes.insert(to.to_string(), v);
                true
            } else {
                false
            }
        }

        fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
            match field {
                LogFieldSelector::Simple(LogField::Body) => {
                    if !upsert && self.body.is_some() {
                        return false;
                    }
                    self.body = Some(value.to_string());
                    true
                }
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
    fn from_proto_empty() {
        let proto = LogTransform::default();
        let compiled = CompiledTransform::from_proto(&proto);
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
        let compiled = CompiledTransform::from_proto(&proto);
        assert_eq!(compiled.ops.len(), 1);
        assert!(matches!(&compiled.ops[0], TransformOp::Remove { field }
            if matches!(field, LogFieldSelector::Simple(LogField::Body))));
    }

    #[test]
    fn from_proto_with_redact() {
        let proto = LogTransform {
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute("secret".to_string())),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto);
        assert_eq!(compiled.ops.len(), 1);
        assert!(
            matches!(&compiled.ops[0], TransformOp::Redact { field, replacement }
            if matches!(field, LogFieldSelector::LogAttribute(k) if k == "secret")
            && replacement == "[REDACTED]")
        );
    }

    #[test]
    fn from_proto_with_rename() {
        let proto = LogTransform {
            rename: vec![LogRename {
                from: Some(log_rename::From::FromLogAttribute("old".to_string())),
                to: "new".to_string(),
                upsert: true,
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto);
        assert_eq!(compiled.ops.len(), 1);
        assert!(
            matches!(&compiled.ops[0], TransformOp::Rename { from, to, upsert }
            if matches!(from, LogFieldSelector::LogAttribute(k) if k == "old")
            && to == "new" && *upsert)
        );
    }

    #[test]
    fn from_proto_with_add() {
        let proto = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute("tag".to_string())),
                value: "production".to_string(),
                upsert: false,
            }],
            ..Default::default()
        };
        let compiled = CompiledTransform::from_proto(&proto);
        assert_eq!(compiled.ops.len(), 1);
        assert!(
            matches!(&compiled.ops[0], TransformOp::Add { field, value, upsert }
            if matches!(field, LogFieldSelector::LogAttribute(k) if k == "tag")
            && value == "production" && !*upsert)
        );
    }

    #[test]
    fn from_proto_ordering() {
        // Verify order: remove, redact, rename, add
        let proto = LogTransform {
            add: vec![LogAdd {
                field: Some(log_add::Field::LogAttribute("add".to_string())),
                value: "v".to_string(),
                upsert: false,
            }],
            remove: vec![LogRemove {
                field: Some(log_remove::Field::LogAttribute("remove".to_string())),
            }],
            rename: vec![LogRename {
                from: Some(log_rename::From::FromLogAttribute("rename".to_string())),
                to: "renamed".to_string(),
                upsert: false,
            }],
            redact: vec![LogRedact {
                field: Some(log_redact::Field::LogAttribute("redact".to_string())),
                replacement: "X".to_string(),
            }],
        };
        let compiled = CompiledTransform::from_proto(&proto);
        assert_eq!(compiled.ops.len(), 4);

        // Check order
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

        let transform = CompiledTransform {
            ops: vec![
                TransformOp::Redact {
                    field: LogFieldSelector::LogAttribute("secret".to_string()),
                    replacement: "[REDACTED]".to_string(),
                },
                TransformOp::Rename {
                    from: LogFieldSelector::LogAttribute("old_name".to_string()),
                    to: "new_name".to_string(),
                    upsert: false,
                },
                TransformOp::Add {
                    field: LogFieldSelector::LogAttribute("env".to_string()),
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

        let transform = CompiledTransform {
            ops: vec![
                // This will succeed
                TransformOp::Remove {
                    field: LogFieldSelector::Simple(LogField::Body),
                },
                // This will fail (field doesn't exist)
                TransformOp::Redact {
                    field: LogFieldSelector::LogAttribute("nonexistent".to_string()),
                    replacement: "X".to_string(),
                },
            ],
        };

        let applied = transform.apply(&mut log);
        assert_eq!(applied, 1);
    }
}
