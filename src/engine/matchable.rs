//! Matchable trait for field access.

use std::borrow::Cow;

use crate::field::LogFieldSelector;

/// Trait for types that can be matched against policies.
///
/// Implementors provide field access for log records by implementing
/// the single `get_field` method. This enables the policy engine to
/// extract field values for pattern matching.
///
/// # Path-based Attribute Access
///
/// For attribute selectors (`LogAttribute`, `ResourceAttribute`, `ScopeAttribute`),
/// the path is a `Vec<String>` representing nested attribute access:
///
/// - Single segment `["user_id"]` - access a flat attribute
/// - Multiple segments `["http", "method"]` - traverse nested maps/objects
/// - Three+ segments `["request", "headers", "content_type"]` - deep nesting
///
/// # Implementation Guidelines
///
/// 1. **Simple Fields**: Return the field value directly for `LogFieldSelector::Simple`
/// 2. **Flat Attributes**: For single-segment paths, use the first element as the key
/// 3. **Nested Attributes**: For multi-segment paths, traverse the nested structure
/// 4. **Missing Fields**: Return `None` if the field or any intermediate path doesn't exist
/// 5. **Non-String Values**: Convert values to strings or return `None`
///
/// # Example Implementation
///
/// ```ignore
/// impl Matchable for MyLog {
///     fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
///         match field {
///             LogFieldSelector::Simple(f) => match f {
///                 LogField::Body => self.body.as_deref().map(Cow::Borrowed),
///                 _ => None,
///             },
///             LogFieldSelector::LogAttribute(path) => {
///                 // Traverse nested attributes using the path
///                 self.traverse_attributes(&self.log_attributes, path)
///             }
///             _ => None,
///         }
///     }
/// }
/// ```
pub trait Matchable {
    /// Get a field value by selector.
    ///
    /// Returns `None` for fields that don't exist or aren't applicable.
    /// Returns `Cow::Borrowed` for fields that exist as stored strings,
    /// or `Cow::Owned` for computed/converted fields.
    ///
    /// For attribute selectors with multi-segment paths, traverse the nested
    /// structure and return the leaf value as a string.
    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::LogField;
    use std::borrow::Cow;
    use std::collections::HashMap;

    /// A simple test log record for testing flat attributes.
    struct TestLog {
        body: String,
        severity_text: String,
        log_attributes: HashMap<String, String>,
        resource_attributes: HashMap<String, String>,
    }

    impl Matchable for TestLog {
        fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => Some(Cow::Borrowed(&self.body)),
                    LogField::SeverityText => Some(Cow::Borrowed(&self.severity_text)),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(path) => {
                    // For flat attributes, use first path segment as key
                    path.first()
                        .and_then(|key| self.log_attributes.get(key))
                        .map(|s| Cow::Borrowed(s.as_str()))
                }
                LogFieldSelector::ResourceAttribute(path) => path
                    .first()
                    .and_then(|key| self.resource_attributes.get(key))
                    .map(|s| Cow::Borrowed(s.as_str())),
                LogFieldSelector::ScopeAttribute(_) => None,
            }
        }
    }

    /// A nested attribute value that can hold strings or nested maps.
    #[derive(Clone, Debug)]
    enum NestedValue {
        String(String),
        Map(HashMap<String, NestedValue>),
    }

    impl NestedValue {
        fn as_str(&self) -> Option<&str> {
            match self {
                NestedValue::String(s) => Some(s),
                NestedValue::Map(_) => None,
            }
        }

        fn get(&self, key: &str) -> Option<&NestedValue> {
            match self {
                NestedValue::String(_) => None,
                NestedValue::Map(m) => m.get(key),
            }
        }

        /// Traverse a path and return the leaf value.
        fn traverse(&self, path: &[String]) -> Option<&NestedValue> {
            match path {
                [] => Some(self),
                [first, rest @ ..] => self.get(first).and_then(|v| v.traverse(rest)),
            }
        }
    }

    /// A test log record with nested attribute support.
    struct NestedTestLog {
        body: String,
        log_attributes: HashMap<String, NestedValue>,
        resource_attributes: HashMap<String, NestedValue>,
        scope_attributes: HashMap<String, NestedValue>,
    }

    impl NestedTestLog {
        fn new(body: &str) -> Self {
            Self {
                body: body.to_string(),
                log_attributes: HashMap::new(),
                resource_attributes: HashMap::new(),
                scope_attributes: HashMap::new(),
            }
        }

        fn with_log_attr(mut self, key: &str, value: NestedValue) -> Self {
            self.log_attributes.insert(key.to_string(), value);
            self
        }

        fn with_resource_attr(mut self, key: &str, value: NestedValue) -> Self {
            self.resource_attributes.insert(key.to_string(), value);
            self
        }

        fn with_scope_attr(mut self, key: &str, value: NestedValue) -> Self {
            self.scope_attributes.insert(key.to_string(), value);
            self
        }
    }

    impl Matchable for NestedTestLog {
        fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
            match field {
                LogFieldSelector::Simple(log_field) => match log_field {
                    LogField::Body => Some(Cow::Borrowed(&self.body)),
                    _ => None,
                },
                LogFieldSelector::LogAttribute(path) => {
                    if path.is_empty() {
                        return None;
                    }
                    let (first, rest) = path.split_first()?;
                    self.log_attributes
                        .get(first)
                        .and_then(|v| v.traverse(rest))
                        .and_then(|v| v.as_str())
                        .map(Cow::Borrowed)
                }
                LogFieldSelector::ResourceAttribute(path) => {
                    if path.is_empty() {
                        return None;
                    }
                    let (first, rest) = path.split_first()?;
                    self.resource_attributes
                        .get(first)
                        .and_then(|v| v.traverse(rest))
                        .and_then(|v| v.as_str())
                        .map(Cow::Borrowed)
                }
                LogFieldSelector::ScopeAttribute(path) => {
                    if path.is_empty() {
                        return None;
                    }
                    let (first, rest) = path.split_first()?;
                    self.scope_attributes
                        .get(first)
                        .and_then(|v| v.traverse(rest))
                        .and_then(|v| v.as_str())
                        .map(Cow::Borrowed)
                }
            }
        }
    }

    /// Helper to create a string value.
    fn str_val(s: &str) -> NestedValue {
        NestedValue::String(s.to_string())
    }

    /// Helper to create a map value.
    fn map_val(entries: Vec<(&str, NestedValue)>) -> NestedValue {
        NestedValue::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
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
            Some(Cow::Borrowed("test message"))
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::Simple(LogField::SeverityText)),
            Some(Cow::Borrowed("ERROR"))
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
            log.get_field(&LogFieldSelector::LogAttribute(vec![
                "ddsource".to_string()
            ])),
            Some(Cow::Borrowed("nginx"))
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::ResourceAttribute(vec![
                "service.name".to_string()
            ])),
            Some(Cow::Borrowed("my-service"))
        );
        assert_eq!(
            log.get_field(&LogFieldSelector::LogAttribute(vec!["missing".to_string()])),
            None
        );
    }

    #[test]
    fn get_field_returns_owned_value() {
        // Test that Cow::Owned values work correctly
        struct ComputedLog;

        impl Matchable for ComputedLog {
            fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
                match field {
                    LogFieldSelector::Simple(LogField::Body) => {
                        Some(Cow::Owned("computed value".to_string()))
                    }
                    _ => None,
                }
            }
        }

        let log = ComputedLog;
        let value = log.get_field(&LogFieldSelector::Simple(LogField::Body));
        assert_eq!(value.as_deref(), Some("computed value"));

        // Verify it's actually an owned value
        if let Some(Cow::Owned(s)) = value {
            assert_eq!(s, "computed value");
        } else {
            panic!("Expected Cow::Owned");
        }
    }

    // ==================== Nested Path Traversal Tests ====================

    #[test]
    fn nested_path_single_level() {
        // Single level: log_attribute: ["user_id"]
        let log = NestedTestLog::new("test").with_log_attr("user_id", str_val("12345"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]));
        assert_eq!(result.as_deref(), Some("12345"));
    }

    #[test]
    fn nested_path_two_levels() {
        // Two levels: log_attribute: ["http", "method"]
        let log = NestedTestLog::new("test").with_log_attr(
            "http",
            map_val(vec![
                ("method", str_val("GET")),
                ("status_code", str_val("200")),
            ]),
        );

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "http".to_string(),
            "method".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("GET"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "http".to_string(),
            "status_code".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("200"));
    }

    #[test]
    fn nested_path_three_levels() {
        // Three levels: log_attribute: ["request", "headers", "content_type"]
        let log = NestedTestLog::new("test").with_log_attr(
            "request",
            map_val(vec![
                (
                    "headers",
                    map_val(vec![
                        ("content_type", str_val("application/json")),
                        ("authorization", str_val("Bearer token123")),
                    ]),
                ),
                ("body", str_val("{\"key\": \"value\"}")),
            ]),
        );

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "request".to_string(),
            "headers".to_string(),
            "content_type".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("application/json"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "request".to_string(),
            "headers".to_string(),
            "authorization".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("Bearer token123"));

        // Also verify two-level access still works
        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "request".to_string(),
            "body".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("{\"key\": \"value\"}"));
    }

    #[test]
    fn nested_path_four_levels() {
        // Four levels: log_attribute: ["service", "config", "database", "host"]
        let log = NestedTestLog::new("test").with_log_attr(
            "service",
            map_val(vec![(
                "config",
                map_val(vec![(
                    "database",
                    map_val(vec![
                        ("host", str_val("localhost")),
                        ("port", str_val("5432")),
                    ]),
                )]),
            )]),
        );

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "service".to_string(),
            "config".to_string(),
            "database".to_string(),
            "host".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("localhost"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "service".to_string(),
            "config".to_string(),
            "database".to_string(),
            "port".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("5432"));
    }

    #[test]
    fn nested_path_missing_intermediate_key() {
        let log = NestedTestLog::new("test")
            .with_log_attr("http", map_val(vec![("method", str_val("GET"))]));

        // Try to access a path where an intermediate key doesn't exist
        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "http".to_string(),
            "nonexistent".to_string(),
            "field".to_string(),
        ]));
        assert_eq!(result, None);
    }

    #[test]
    fn nested_path_intermediate_is_string_not_map() {
        let log = NestedTestLog::new("test")
            .with_log_attr("http", map_val(vec![("method", str_val("GET"))]));

        // Try to traverse through a string value (should fail)
        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "http".to_string(),
            "method".to_string(),
            "something".to_string(),
        ]));
        assert_eq!(result, None);
    }

    #[test]
    fn nested_path_empty_returns_none() {
        let log = NestedTestLog::new("test").with_log_attr("user_id", str_val("12345"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![]));
        assert_eq!(result, None);
    }

    #[test]
    fn nested_path_resource_attributes() {
        // Test nested paths work for resource attributes too
        let log = NestedTestLog::new("test").with_resource_attr(
            "k8s",
            map_val(vec![
                (
                    "pod",
                    map_val(vec![
                        ("name", str_val("my-pod-abc123")),
                        ("namespace", str_val("production")),
                    ]),
                ),
                ("cluster", str_val("us-east-1")),
            ]),
        );

        let result = log.get_field(&LogFieldSelector::ResourceAttribute(vec![
            "k8s".to_string(),
            "pod".to_string(),
            "name".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("my-pod-abc123"));

        let result = log.get_field(&LogFieldSelector::ResourceAttribute(vec![
            "k8s".to_string(),
            "pod".to_string(),
            "namespace".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("production"));

        let result = log.get_field(&LogFieldSelector::ResourceAttribute(vec![
            "k8s".to_string(),
            "cluster".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn nested_path_scope_attributes() {
        // Test nested paths work for scope attributes too
        let log = NestedTestLog::new("test").with_scope_attr(
            "instrumentation",
            map_val(vec![
                ("name", str_val("opentelemetry-rust")),
                (
                    "version",
                    map_val(vec![
                        ("major", str_val("0")),
                        ("minor", str_val("21")),
                        ("patch", str_val("0")),
                    ]),
                ),
            ]),
        );

        let result = log.get_field(&LogFieldSelector::ScopeAttribute(vec![
            "instrumentation".to_string(),
            "name".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("opentelemetry-rust"));

        let result = log.get_field(&LogFieldSelector::ScopeAttribute(vec![
            "instrumentation".to_string(),
            "version".to_string(),
            "minor".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("21"));
    }

    #[test]
    fn nested_path_top_level_missing() {
        let log = NestedTestLog::new("test");

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "nonexistent".to_string(),
            "field".to_string(),
        ]));
        assert_eq!(result, None);
    }

    #[test]
    fn nested_path_accessing_map_as_value_returns_none() {
        // When the path points to a map (not a string), return None
        let log = NestedTestLog::new("test")
            .with_log_attr("http", map_val(vec![("method", str_val("GET"))]));

        // Accessing just "http" should return None because it's a map, not a string
        let result = log.get_field(&LogFieldSelector::LogAttribute(vec!["http".to_string()]));
        assert_eq!(result, None);
    }
}
