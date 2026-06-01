//! Reference adapter: generic record types with correct Matchable/Transformable impls.
//!
//! Integrating `policy-rs` requires implementing [`Matchable`] (and optionally
//! [`Transformable`]) for your telemetry types. Getting the field-access
//! semantics exactly right is non-trivial — see the [`Matchable`] contract docs
//! for the full list of rules.
//!
//! This module provides three ready-to-use record types that satisfy all
//! conformance requirements out of the box:
//!
//! | Type | Signal | Traits |
//! |------|--------|--------|
//! | [`LogRecord`] | [`LogSignal`] | `Matchable` + `Transformable` |
//! | [`MetricRecord`] | [`MetricSignal`] | `Matchable` |
//! | [`SpanRecord`] | [`TraceSignal`] | `Matchable` + `Transformable` |
//!
//! Each type wraps a simple attribute model that mirrors OTel's `AnyValue`
//! discrimination:
//! - [`Value::String`] values are matchable (returned by `get_field`).
//! - All other [`Value`] variants (int, float, bool, bytes) are present but
//!   non-matchable (`get_field` returns `None`, `field_exists` returns `true`).
//!
//! # Usage
//!
//! Wrap your OTel proto structs by extracting their fields into these types,
//! or use them as-is in tests and the conformance runner.
//!
//! ```
//! use policy_rs::adapter::{LogRecord, Value};
//! use policy_rs::{Matchable, LogSignal};
//! use policy_rs::field::LogFieldSelector;
//! use policy_rs::proto::tero::policy::v1::LogField;
//!
//! let mut log = LogRecord::new();
//! log.body = Some("error connecting to db".to_string());
//! log.set_log_attr("service", Value::String("api".to_string()));
//! log.set_resource_attr("env", Value::String("production".to_string()));
//! ```
//!
//! [`Matchable`]: crate::Matchable
//! [`Transformable`]: crate::Transformable
//! [`LogSignal`]: crate::LogSignal
//! [`MetricSignal`]: crate::MetricSignal
//! [`TraceSignal`]: crate::TraceSignal

use std::borrow::Cow;
use std::collections::HashMap;

use crate::canonical;
use crate::engine::{LogSignal, Matchable, MetricSignal, TraceSignal, Transformable};
use crate::field::{LogFieldSelector, MetricFieldSelector, TraceFieldSelector};
use crate::proto::tero::policy::v1::{
    AggregationTemporality, LogField, MetricField, MetricType, SpanKind, SpanStatusCode, TraceField,
};

// =============================================================================
// Value type
// =============================================================================

/// An attribute value that may or may not be matchable as a string.
///
/// The engine can only pattern-match against [`Value::String`]. Other variants
/// are "present but non-matchable" — `field_exists` returns `true` for them,
/// but `get_field` returns `None` so string matchers won't fire.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A UTF-8 string — the only variant returned by `get_field`.
    String(String),
    /// A 64-bit integer. Present but not matchable.
    Int(i64),
    /// A 64-bit float. Present but not matchable.
    Float(f64),
    /// A boolean. Present but not matchable.
    Bool(bool),
    /// Raw bytes. Present but not matchable.
    Bytes(Vec<u8>),
}

impl Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// =============================================================================
// Attribute map helper
// =============================================================================

/// A flat map from attribute key to [`Value`].
pub type Attrs = HashMap<String, Value>;

fn get_attr<'a>(attrs: &'a Attrs, path: &[String]) -> Option<Cow<'a, str>> {
    let key = path.first()?;
    attrs.get(key)?.as_str().map(Cow::Borrowed)
}

fn attr_exists(attrs: &Attrs, path: &[String]) -> bool {
    path.first().map(|k| attrs.contains_key(k)).unwrap_or(false)
}

fn set_attr(attrs: &mut Attrs, path: &[String], value: &str) {
    if let Some(key) = path.first() {
        attrs.insert(key.clone(), Value::String(value.to_string()));
    }
}

fn delete_attr(attrs: &mut Attrs, path: &[String]) -> bool {
    path.first().and_then(|k| attrs.remove(k)).is_some()
}

// =============================================================================
// LogRecord
// =============================================================================

/// A generic log record that satisfies the full `Matchable` + `Transformable`
/// contract for [`LogSignal`].
#[derive(Debug, Default, Clone)]
pub struct LogRecord {
    pub body: Option<String>,
    pub severity_text: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub event_name: Option<String>,
    pub resource_schema_url: Option<String>,
    pub scope_schema_url: Option<String>,
    pub log_attrs: Attrs,
    pub resource_attrs: Attrs,
    pub scope_attrs: Attrs,
}

impl LogRecord {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_log_attr(&mut self, key: impl Into<String>, value: Value) {
        self.log_attrs.insert(key.into(), value);
    }

    pub fn set_resource_attr(&mut self, key: impl Into<String>, value: Value) {
        self.resource_attrs.insert(key.into(), value);
    }

    pub fn set_scope_attr(&mut self, key: impl Into<String>, value: Value) {
        self.scope_attrs.insert(key.into(), value);
    }
}

impl Matchable for LogRecord {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => self.body.as_deref().map(Cow::Borrowed),
                LogField::SeverityText => self.severity_text.as_deref().map(Cow::Borrowed),
                LogField::TraceId => self.trace_id.as_deref().map(Cow::Borrowed),
                LogField::SpanId => self.span_id.as_deref().map(Cow::Borrowed),
                LogField::EventName => self.event_name.as_deref().map(Cow::Borrowed),
                LogField::ResourceSchemaUrl => {
                    self.resource_schema_url.as_deref().map(Cow::Borrowed)
                }
                LogField::ScopeSchemaUrl => self.scope_schema_url.as_deref().map(Cow::Borrowed),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => get_attr(&self.log_attrs, path),
            LogFieldSelector::ResourceAttribute(path) => get_attr(&self.resource_attrs, path),
            LogFieldSelector::ScopeAttribute(path) => get_attr(&self.scope_attrs, path),
        }
    }

    fn field_exists(&self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(_) => self.get_field(field).is_some(),
            LogFieldSelector::LogAttribute(path) => attr_exists(&self.log_attrs, path),
            LogFieldSelector::ResourceAttribute(path) => attr_exists(&self.resource_attrs, path),
            LogFieldSelector::ScopeAttribute(path) => attr_exists(&self.scope_attrs, path),
        }
    }
}

impl Transformable for LogRecord {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => self.body = Some(value.to_string()),
                LogField::SeverityText => self.severity_text = Some(value.to_string()),
                LogField::TraceId => self.trace_id = Some(value.to_string()),
                LogField::SpanId => self.span_id = Some(value.to_string()),
                LogField::EventName => self.event_name = Some(value.to_string()),
                LogField::ResourceSchemaUrl => self.resource_schema_url = Some(value.to_string()),
                LogField::ScopeSchemaUrl => self.scope_schema_url = Some(value.to_string()),
                _ => {}
            },
            LogFieldSelector::LogAttribute(path) => set_attr(&mut self.log_attrs, path, value),
            LogFieldSelector::ResourceAttribute(path) => {
                set_attr(&mut self.resource_attrs, path, value)
            }
            LogFieldSelector::ScopeAttribute(path) => set_attr(&mut self.scope_attrs, path, value),
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => self.body.take().is_some(),
                LogField::SeverityText => self.severity_text.take().is_some(),
                LogField::TraceId => self.trace_id.take().is_some(),
                LogField::SpanId => self.span_id.take().is_some(),
                LogField::EventName => self.event_name.take().is_some(),
                LogField::ResourceSchemaUrl => self.resource_schema_url.take().is_some(),
                LogField::ScopeSchemaUrl => self.scope_schema_url.take().is_some(),
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => delete_attr(&mut self.log_attrs, path),
            LogFieldSelector::ResourceAttribute(path) => {
                delete_attr(&mut self.resource_attrs, path)
            }
            LogFieldSelector::ScopeAttribute(path) => delete_attr(&mut self.scope_attrs, path),
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        let value = match from {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => self.body.take().map(Value::String),
                LogField::SeverityText => self.severity_text.take().map(Value::String),
                LogField::TraceId => self.trace_id.take().map(Value::String),
                LogField::SpanId => self.span_id.take().map(Value::String),
                LogField::EventName => self.event_name.take().map(Value::String),
                LogField::ResourceSchemaUrl => self.resource_schema_url.take().map(Value::String),
                LogField::ScopeSchemaUrl => self.scope_schema_url.take().map(Value::String),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => {
                path.first().and_then(|k| self.log_attrs.remove(k))
            }
            LogFieldSelector::ResourceAttribute(path) => {
                path.first().and_then(|k| self.resource_attrs.remove(k))
            }
            LogFieldSelector::ScopeAttribute(path) => {
                path.first().and_then(|k| self.scope_attrs.remove(k))
            }
        };
        let Some(v) = value else { return };
        match to {
            LogFieldSelector::LogAttribute(path) => {
                if let Some(k) = path.first() {
                    self.log_attrs.insert(k.clone(), v);
                }
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(k) = path.first() {
                    self.resource_attrs.insert(k.clone(), v);
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(k) = path.first() {
                    self.scope_attrs.insert(k.clone(), v);
                }
            }
            _ => {}
        }
    }
}

// =============================================================================
// MetricRecord
// =============================================================================

/// A generic metric record that satisfies the `Matchable` contract for
/// [`MetricSignal`].
///
/// Metric policies only filter (keep/drop) — there are no transforms.
/// `MetricRecord` therefore only implements `Matchable`, not `Transformable`.
#[derive(Debug, Default, Clone)]
pub struct MetricRecord {
    pub name: Option<String>,
    pub description: Option<String>,
    pub unit: Option<String>,
    pub resource_schema_url: Option<String>,
    pub scope_schema_url: Option<String>,
    pub scope_name: Option<String>,
    pub scope_version: Option<String>,
    /// Use [`canonical::metric_type_str`] to produce the right value.
    pub metric_type: Option<MetricType>,
    /// Use [`canonical::aggregation_temporality_str`] to produce the right value.
    pub temporality: Option<AggregationTemporality>,
    pub datapoint_attrs: Attrs,
    pub resource_attrs: Attrs,
    pub scope_attrs: Attrs,
}

impl MetricRecord {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Matchable for MetricRecord {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(f) => match f {
                MetricField::Name => self.name.as_deref().map(Cow::Borrowed),
                MetricField::Description => self.description.as_deref().map(Cow::Borrowed),
                MetricField::Unit => self.unit.as_deref().map(Cow::Borrowed),
                MetricField::ResourceSchemaUrl => {
                    self.resource_schema_url.as_deref().map(Cow::Borrowed)
                }
                MetricField::ScopeSchemaUrl => self.scope_schema_url.as_deref().map(Cow::Borrowed),
                MetricField::ScopeName => self.scope_name.as_deref().map(Cow::Borrowed),
                MetricField::ScopeVersion => self.scope_version.as_deref().map(Cow::Borrowed),
                _ => None,
            },
            MetricFieldSelector::Type => self
                .metric_type
                .map(|mt| Cow::Borrowed(canonical::metric_type_str(mt))),
            MetricFieldSelector::Temporality => self
                .temporality
                .map(|at| Cow::Borrowed(canonical::aggregation_temporality_str(at))),
            MetricFieldSelector::DatapointAttribute(path) => get_attr(&self.datapoint_attrs, path),
            MetricFieldSelector::ResourceAttribute(path) => get_attr(&self.resource_attrs, path),
            MetricFieldSelector::ScopeAttribute(path) => get_attr(&self.scope_attrs, path),
        }
    }

    fn field_exists(&self, field: &MetricFieldSelector) -> bool {
        match field {
            MetricFieldSelector::Type => self.metric_type.is_some(),
            MetricFieldSelector::Temporality => self.temporality.is_some(),
            MetricFieldSelector::DatapointAttribute(path) => {
                attr_exists(&self.datapoint_attrs, path)
            }
            MetricFieldSelector::ResourceAttribute(path) => attr_exists(&self.resource_attrs, path),
            MetricFieldSelector::ScopeAttribute(path) => attr_exists(&self.scope_attrs, path),
            _ => self.get_field(field).is_some(),
        }
    }
}

// =============================================================================
// SpanRecord
// =============================================================================

/// A generic trace span that satisfies the `Matchable` + `Transformable`
/// contract for [`TraceSignal`].
///
/// `trace_id` and `span_id` must be lowercase hex strings. The engine's
/// consistent-probability sampler slices the last 14 hex chars of `trace_id`
/// for the 56-bit randomness value.
///
/// After calling [`PolicyEngine::evaluate_trace`], check
/// [`SpanRecord::sampling_threshold`]: if `Some`, write its value into the
/// span's tracestate under the `th` sub-key of the `ot` entry.
///
/// [`PolicyEngine::evaluate_trace`]: crate::PolicyEngine::evaluate_trace
#[derive(Debug, Default, Clone)]
pub struct SpanRecord {
    pub name: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub trace_state: Option<String>,
    pub resource_schema_url: Option<String>,
    pub scope_schema_url: Option<String>,
    pub scope_name: Option<String>,
    pub scope_version: Option<String>,
    /// Use [`canonical::span_kind_str`] for the canonical string.
    pub span_kind: Option<SpanKind>,
    /// Use [`canonical::span_status_code_str`] for the canonical string.
    /// `SpanStatusCode::Unspecified` represents OTel's "Unset" status.
    pub span_status: Option<SpanStatusCode>,
    pub span_attrs: Attrs,
    pub resource_attrs: Attrs,
    pub scope_attrs: Attrs,
    /// Written by [`PolicyEngine::evaluate_trace`] when the span is sampled.
    /// The caller must propagate this into the tracestate `ot=th:<value>`.
    pub sampling_threshold: Option<String>,
}

impl SpanRecord {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Matchable for SpanRecord {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::Name => self.name.as_deref().map(Cow::Borrowed),
                TraceField::TraceId => self.trace_id.as_deref().map(Cow::Borrowed),
                TraceField::SpanId => self.span_id.as_deref().map(Cow::Borrowed),
                TraceField::ParentSpanId => self.parent_span_id.as_deref().map(Cow::Borrowed),
                TraceField::TraceState => self.trace_state.as_deref().map(Cow::Borrowed),
                TraceField::ResourceSchemaUrl => {
                    self.resource_schema_url.as_deref().map(Cow::Borrowed)
                }
                TraceField::ScopeSchemaUrl => self.scope_schema_url.as_deref().map(Cow::Borrowed),
                TraceField::ScopeName => self.scope_name.as_deref().map(Cow::Borrowed),
                TraceField::ScopeVersion => self.scope_version.as_deref().map(Cow::Borrowed),
                _ => None,
            },
            // SpanKind is a unit variant: return the span's current kind as its
            // canonical string so Vectorscan can match it.
            TraceFieldSelector::SpanKind => self
                .span_kind
                .map(|k| Cow::Borrowed(canonical::span_kind_str(k))),
            // SpanStatus is a unit variant: return the canonical string.
            // A proto3 default (Unspecified == Unset) is still "present".
            TraceFieldSelector::SpanStatus => {
                let sc = self.span_status.unwrap_or(SpanStatusCode::Unspecified);
                Some(Cow::Borrowed(canonical::span_status_code_str(sc)))
            }
            TraceFieldSelector::SpanAttribute(path) => get_attr(&self.span_attrs, path),
            TraceFieldSelector::ResourceAttribute(path) => get_attr(&self.resource_attrs, path),
            TraceFieldSelector::ScopeAttribute(path) => get_attr(&self.scope_attrs, path),
            // Event/link fields require iterating over event/link lists; not
            // supported in this flat record model.
            TraceFieldSelector::EventName | TraceFieldSelector::EventAttribute(_) => None,
            TraceFieldSelector::LinkTraceId => None,
            TraceFieldSelector::SamplingThreshold => {
                self.sampling_threshold.as_deref().map(Cow::Borrowed)
            }
        }
    }

    fn field_exists(&self, field: &TraceFieldSelector) -> bool {
        match field {
            TraceFieldSelector::SpanKind => self.span_kind.is_some(),
            // Status is always present — absent proto3 default ≡ Unspecified/Unset.
            TraceFieldSelector::SpanStatus => true,
            TraceFieldSelector::SpanAttribute(path) => attr_exists(&self.span_attrs, path),
            TraceFieldSelector::ResourceAttribute(path) => attr_exists(&self.resource_attrs, path),
            TraceFieldSelector::ScopeAttribute(path) => attr_exists(&self.scope_attrs, path),
            _ => self.get_field(field).is_some(),
        }
    }
}

impl Transformable for SpanRecord {
    fn set_field(&mut self, field: &TraceFieldSelector, value: &str) {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::Name => self.name = Some(value.to_string()),
                TraceField::TraceId => self.trace_id = Some(value.to_string()),
                TraceField::SpanId => self.span_id = Some(value.to_string()),
                TraceField::ParentSpanId => self.parent_span_id = Some(value.to_string()),
                TraceField::TraceState => self.trace_state = Some(value.to_string()),
                TraceField::ResourceSchemaUrl => self.resource_schema_url = Some(value.to_string()),
                TraceField::ScopeSchemaUrl => self.scope_schema_url = Some(value.to_string()),
                TraceField::ScopeName => self.scope_name = Some(value.to_string()),
                TraceField::ScopeVersion => self.scope_version = Some(value.to_string()),
                _ => {}
            },
            TraceFieldSelector::SpanAttribute(path) => set_attr(&mut self.span_attrs, path, value),
            TraceFieldSelector::ResourceAttribute(path) => {
                set_attr(&mut self.resource_attrs, path, value)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                set_attr(&mut self.scope_attrs, path, value)
            }
            TraceFieldSelector::SamplingThreshold => {
                self.sampling_threshold = Some(value.to_string());
            }
            _ => {}
        }
    }

    fn delete_field(&mut self, field: &TraceFieldSelector) -> bool {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::Name => self.name.take().is_some(),
                TraceField::TraceId => self.trace_id.take().is_some(),
                TraceField::SpanId => self.span_id.take().is_some(),
                TraceField::ParentSpanId => self.parent_span_id.take().is_some(),
                TraceField::TraceState => self.trace_state.take().is_some(),
                TraceField::ResourceSchemaUrl => self.resource_schema_url.take().is_some(),
                TraceField::ScopeSchemaUrl => self.scope_schema_url.take().is_some(),
                TraceField::ScopeName => self.scope_name.take().is_some(),
                TraceField::ScopeVersion => self.scope_version.take().is_some(),
                _ => false,
            },
            TraceFieldSelector::SpanAttribute(path) => delete_attr(&mut self.span_attrs, path),
            TraceFieldSelector::ResourceAttribute(path) => {
                delete_attr(&mut self.resource_attrs, path)
            }
            TraceFieldSelector::ScopeAttribute(path) => delete_attr(&mut self.scope_attrs, path),
            _ => false,
        }
    }

    fn move_field(&mut self, from: &TraceFieldSelector, to: &TraceFieldSelector) {
        let value = match from {
            TraceFieldSelector::SpanAttribute(path) => {
                path.first().and_then(|k| self.span_attrs.remove(k))
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                path.first().and_then(|k| self.resource_attrs.remove(k))
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                path.first().and_then(|k| self.scope_attrs.remove(k))
            }
            _ => None,
        };
        let Some(v) = value else { return };
        match to {
            TraceFieldSelector::SpanAttribute(path) => {
                if let Some(k) = path.first() {
                    self.span_attrs.insert(k.clone(), v);
                }
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                if let Some(k) = path.first() {
                    self.resource_attrs.insert(k.clone(), v);
                }
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                if let Some(k) = path.first() {
                    self.scope_attrs.insert(k.clone(), v);
                }
            }
            _ => {}
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::LogFieldSelector;
    use crate::proto::tero::policy::v1::LogField;

    #[test]
    fn log_record_string_value_is_matchable() {
        let mut rec = LogRecord::new();
        rec.body = Some("hello".to_string());
        rec.set_log_attr("k", Value::String("v".to_string()));

        assert_eq!(
            rec.get_field(&LogFieldSelector::Simple(LogField::Body)),
            Some(Cow::Borrowed("hello"))
        );
        assert_eq!(
            rec.get_field(&LogFieldSelector::LogAttribute(vec!["k".to_string()])),
            Some(Cow::Borrowed("v"))
        );
    }

    #[test]
    fn log_record_non_string_attr_is_present_but_not_matchable() {
        let mut rec = LogRecord::new();
        rec.set_log_attr("count", Value::Int(42));

        // get_field returns None (can't match a string pattern against an int)
        assert_eq!(
            rec.get_field(&LogFieldSelector::LogAttribute(vec!["count".to_string()])),
            None
        );
        // field_exists returns true (exists: true matcher should fire)
        assert!(rec.field_exists(&LogFieldSelector::LogAttribute(vec!["count".to_string()])));
    }

    #[test]
    fn metric_record_type_and_temporality_use_canonical_strings() {
        use crate::field::MetricFieldSelector;
        let mut rec = MetricRecord::new();
        rec.metric_type = Some(MetricType::Sum);
        rec.temporality = Some(AggregationTemporality::Delta);

        assert_eq!(
            rec.get_field(&MetricFieldSelector::Type),
            Some(Cow::Borrowed("METRIC_TYPE_SUM"))
        );
        assert_eq!(
            rec.get_field(&MetricFieldSelector::Temporality),
            Some(Cow::Borrowed("AGGREGATION_TEMPORALITY_DELTA"))
        );
    }

    #[test]
    fn span_record_sampling_threshold_set_by_set_field() {
        use crate::field::TraceFieldSelector;
        let mut span = SpanRecord::new();
        span.set_field(&TraceFieldSelector::SamplingThreshold, "8");
        assert_eq!(span.sampling_threshold, Some("8".to_string()));
    }

    #[test]
    fn span_record_span_status_is_always_present() {
        use crate::field::TraceFieldSelector;

        // Status is always present (proto3 default = Unspecified = Unset).
        let span = SpanRecord::new(); // no span_status set
        assert!(span.field_exists(&TraceFieldSelector::SpanStatus));
        assert_eq!(
            span.get_field(&TraceFieldSelector::SpanStatus),
            Some(Cow::Borrowed("SPAN_STATUS_CODE_UNSPECIFIED"))
        );

        // Explicit status is returned.
        let mut span2 = SpanRecord::new();
        span2.span_status = Some(SpanStatusCode::Error);
        assert_eq!(
            span2.get_field(&TraceFieldSelector::SpanStatus),
            Some(Cow::Borrowed("SPAN_STATUS_CODE_ERROR"))
        );
    }
}
