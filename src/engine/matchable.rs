//! Matchable trait for field access.

use std::borrow::Cow;

use super::compiled::TypedValue;
use super::signal::Signal;

/// Trait for types that can be matched against policies.
///
/// Implementors provide field access for telemetry records. The engine uses
/// two primitives:
///
/// - [`get_field`](Matchable::get_field) returns the field's string value for
///   pattern matching, or `None` when the field is absent **or** present but
///   not representable as a string (e.g. OTel `intValue: 42`).
/// - [`field_exists`](Matchable::field_exists) reports whether the field is
///   present at all, regardless of value type. The default body delegates to
///   `get_field(...).is_some()`, which is only correct when every present value
///   is a string. Records carrying non-string values **must** override this
///   method so that `exists: true` matchers fire correctly.
///
/// # Contract for OTel-compatible adapters
///
/// The rules below are derived from the policy conformance suite. Violating any
/// of them produces silent match failures — the engine never surfaces a "wrong
/// type" error, it simply treats the field as absent.
///
/// ### String fields (body, severity_text, span name, metric name, …)
/// - Return `Some(Cow::Borrowed(s))` for a non-empty string value.
/// - Return `Some(Cow::Borrowed(""))` for a present-but-empty string. The engine
///   will not match regex/exact/prefix patterns against an empty string, but
///   `field_exists` should still return `true` if the field is logically present.
/// - Return `None` when the field is absent.
///
/// ### Attribute fields (log/span/resource/scope attributes)
/// - An OTel `AnyValue` is **only matchable** when it is a `stringValue`. Any
///   other variant (`intValue`, `doubleValue`, `boolValue`, `bytesValue`,
///   `arrayValue`, `kvlistValue`) must return `None` from `get_field` but
///   `true` from `field_exists`, so that:
///   - String matchers (`regex`, `exact`, etc.) do not fire on non-string values.
///   - `exists: true` matchers still fire for any present value.
///
/// ### Enum fields (metric type, aggregation temporality, span status, span kind)
/// - Synthesize a string using the helpers in [`crate::canonical`]:
///   `canonical::metric_type_str(mt)`, `canonical::span_status_code_str(sc)`, etc.
/// - These return the proto enum's `as_str_name()` output, which is what the
///   engine compiles its exact-match pattern against.
/// - **SpanStatus / Unset**: OTel's `Unset` status maps to proto
///   `SpanStatusCode::Unspecified`. A span with an absent or default (proto3
///   zero-value) status code is still considered *present* — return
///   `canonical::span_status_code_str(SpanStatusCode::Unspecified)` rather
///   than `None`.
///
/// ### ID fields (trace_id, span_id)
/// - Must be encoded as lowercase hex strings (`[0-9a-f]`).
/// - `trace_id` is 32 hex chars (128-bit); `span_id` is 16 hex chars (64-bit).
/// - The sampling code slices the last 14 hex characters of `trace_id` for the
///   56-bit randomness value — a non-hex `trace_id` returns `None` from the
///   sampler rather than panicking, but consistent sampling will fall back.
///
/// ### Per-signal method mapping
///
/// | Signal  | Evaluation method                | Transform support |
/// |---------|----------------------------------|-------------------|
/// | Log     | `evaluate` / `evaluate_and_transform` | Yes (redact, remove, rename, add) |
/// | Metric  | `evaluate`                       | No                |
/// | Trace   | `evaluate_trace`                 | Yes (tracestate `th` update) |
///
/// # Path-based Attribute Access
///
/// For attribute selectors, the path is a `Vec<String>` representing nested
/// attribute access:
///
/// - Single segment `["user_id"]` — flat attribute
/// - Multiple segments `["http", "method"]` — nested map/struct traversal
///
/// # Example Implementation
///
/// ```ignore
/// impl Matchable for MyLog {
///     type Signal = LogSignal;
///
///     fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
///         match field {
///             LogFieldSelector::Simple(f) => match f {
///                 LogField::Body => self.body.as_deref().map(Cow::Borrowed),
///                 _ => None,
///             },
///             LogFieldSelector::LogAttribute(path) => {
///                 // Only return Some for stringValue; other OTel value types → None.
///                 path.first()
///                     .and_then(|k| self.attrs.get(k))
///                     .and_then(|v| v.as_string())
///                     .map(Cow::Borrowed)
///             }
///             _ => None,
///         }
///     }
///
///     // Override because attributes can hold non-string OTel values.
///     fn field_exists(&self, field: &LogFieldSelector) -> bool {
///         match field {
///             LogFieldSelector::LogAttribute(path) => path
///                 .first()
///                 .map(|k| self.attrs.contains_key(k))
///                 .unwrap_or(false),
///             _ => self.get_field(field).is_some(),
///         }
///     }
/// }
/// ```
pub trait Matchable {
    /// The telemetry signal type this implementation handles.
    type Signal: Signal;

    /// Get a field value by selector.
    ///
    /// Returns `None` when the field doesn't exist or isn't representable as
    /// a string. Returns `Cow::Borrowed` for fields stored as strings, or
    /// `Cow::Owned` for computed/converted fields.
    ///
    /// For attribute selectors with multi-segment paths, traverse the nested
    /// structure and return the leaf value as a string.
    fn get_field(&self, field: &<Self::Signal as Signal>::FieldSelector) -> Option<Cow<'_, str>>;

    /// Report whether the field is present, regardless of whether its value
    /// can be represented as a string.
    ///
    /// The default returns `self.get_field(field).is_some()`, which conflates
    /// "absent" with "present but non-string." Override this method when your
    /// records carry non-string values (numbers, booleans, structured values)
    /// that should still satisfy `exists: true` matchers.
    fn field_exists(&self, field: &<Self::Signal as Signal>::FieldSelector) -> bool {
        self.get_field(field).is_some()
    }

    /// Get a typed value for use with `equals`, `gt`, `gte`, `lt`, and `lte` matchers.
    ///
    /// The default implementation wraps [`get_field`] and returns the string value
    /// as `TypedValue::String`. Override this method to expose non-string field
    /// values (booleans, integers, floats, raw bytes) so that typed matchers
    /// can match them.
    ///
    /// Return `None` when the field is absent. A present-but-wrong-type value
    /// causes a non-match (not an error), consistent with the fail-open policy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn get_typed_value(&self, field: &LogFieldSelector) -> Option<TypedValue<'_>> {
    ///     if let LogFieldSelector::LogAttribute(path) = field {
    ///         let key = path.first()?;
    ///         return match self.attrs.get(key)? {
    ///             Attr::String(s)  => Some(TypedValue::String(Cow::Borrowed(s))),
    ///             Attr::Int(i)     => Some(TypedValue::Int(*i)),
    ///             Attr::Double(d)  => Some(TypedValue::Double(*d)),
    ///             Attr::Bool(b)    => Some(TypedValue::Bool(*b)),
    ///             Attr::Bytes(bs)  => Some(TypedValue::Bytes(bs)),
    ///         };
    ///     }
    ///     self.get_field(field).map(TypedValue::String)
    /// }
    /// ```
    ///
    /// [`get_field`]: Matchable::get_field
    fn get_typed_value(
        &self,
        field: &<Self::Signal as Signal>::FieldSelector,
    ) -> Option<TypedValue<'_>> {
        self.get_field(field).map(TypedValue::String)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signal::LogSignal;
    use crate::field::LogFieldSelector;
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
        type Signal = LogSignal;

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
        type Signal = LogSignal;

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
        struct ComputedLog;

        impl Matchable for ComputedLog {
            type Signal = LogSignal;

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

        if let Some(Cow::Owned(s)) = value {
            assert_eq!(s, "computed value");
        } else {
            panic!("Expected Cow::Owned");
        }
    }

    // ==================== Nested Path Traversal Tests ====================

    #[test]
    fn nested_path_single_level() {
        let log = NestedTestLog::new("test").with_log_attr("user_id", str_val("12345"));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec!["user_id".to_string()]));
        assert_eq!(result.as_deref(), Some("12345"));
    }

    #[test]
    fn nested_path_two_levels() {
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

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec![
            "request".to_string(),
            "body".to_string(),
        ]));
        assert_eq!(result.as_deref(), Some("{\"key\": \"value\"}"));
    }

    #[test]
    fn nested_path_four_levels() {
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
        let log = NestedTestLog::new("test")
            .with_log_attr("http", map_val(vec![("method", str_val("GET"))]));

        let result = log.get_field(&LogFieldSelector::LogAttribute(vec!["http".to_string()]));
        assert_eq!(result, None);
    }
}
