//! Signal types for multi-signal policy evaluation.
//!
//! Each telemetry signal (logs, metrics, traces) has its own marker type
//! that carries the associated field selector. This enables the engine
//! to be generic over signal types while staying fully monomorphized.

use std::fmt::Debug;
use std::hash::Hash;

use crate::field::{LogFieldSelector, MetricFieldSelector, TraceFieldSelector};
use crate::registry::PolicySnapshot;

use super::compiled::CompiledMatchers;

/// A telemetry signal type (logs, metrics, traces).
///
/// Implementations associate a field selector with the signal, enabling
/// the engine structs and evaluation methods to be generic over signals.
pub trait Signal: 'static {
    /// The field selector type for this signal.
    type FieldSelector: Clone + Eq + Hash + Debug;

    /// Get the compiled matchers for this signal from a snapshot.
    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>>
    where
        Self: Sized;

    /// Construct the rename target selector for moving `from` to `to_key`.
    ///
    /// The returned selector preserves the source's attribute namespace
    /// (log/resource/scope → the same namespace at `to_key`). Returns `None`
    /// when the source is a simple field selector — renaming simple fields is
    /// not expressed by the proto and is a no-op in all reference
    /// implementations.
    ///
    /// Used by the engine to evaluate rename-target upsert preconditions and
    /// to dispatch `Transformable::move_field` with a fully-formed target
    /// selector.
    fn rename_target(from: &Self::FieldSelector, to_key: &str) -> Option<Self::FieldSelector>;
}

/// Log telemetry signal.
#[derive(Debug)]
pub struct LogSignal;

impl Signal for LogSignal {
    type FieldSelector = LogFieldSelector;

    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>> {
        snapshot.compiled_log_matchers()
    }

    fn rename_target(from: &Self::FieldSelector, to_key: &str) -> Option<Self::FieldSelector> {
        let path = vec![to_key.to_string()];
        match from {
            LogFieldSelector::LogAttribute(_) => Some(LogFieldSelector::LogAttribute(path)),
            LogFieldSelector::ResourceAttribute(_) => {
                Some(LogFieldSelector::ResourceAttribute(path))
            }
            LogFieldSelector::ScopeAttribute(_) => Some(LogFieldSelector::ScopeAttribute(path)),
            LogFieldSelector::Simple(_) => None,
        }
    }
}

/// Metric telemetry signal.
#[derive(Debug)]
pub struct MetricSignal;

impl Signal for MetricSignal {
    type FieldSelector = MetricFieldSelector;

    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>> {
        snapshot.compiled_metric_matchers()
    }

    fn rename_target(from: &Self::FieldSelector, to_key: &str) -> Option<Self::FieldSelector> {
        let path = vec![to_key.to_string()];
        match from {
            MetricFieldSelector::DatapointAttribute(_) => {
                Some(MetricFieldSelector::DatapointAttribute(path))
            }
            MetricFieldSelector::ResourceAttribute(_) => {
                Some(MetricFieldSelector::ResourceAttribute(path))
            }
            MetricFieldSelector::ScopeAttribute(_) => {
                Some(MetricFieldSelector::ScopeAttribute(path))
            }
            // Renaming non-attribute fields is not expressible in the proto.
            MetricFieldSelector::Simple(_)
            | MetricFieldSelector::Type
            | MetricFieldSelector::Temporality => None,
        }
    }
}

/// Trace telemetry signal.
#[derive(Debug)]
pub struct TraceSignal;

impl Signal for TraceSignal {
    type FieldSelector = TraceFieldSelector;

    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>> {
        snapshot.compiled_trace_matchers()
    }

    fn rename_target(from: &Self::FieldSelector, to_key: &str) -> Option<Self::FieldSelector> {
        let path = vec![to_key.to_string()];
        match from {
            TraceFieldSelector::SpanAttribute(_) => Some(TraceFieldSelector::SpanAttribute(path)),
            TraceFieldSelector::ResourceAttribute(_) => {
                Some(TraceFieldSelector::ResourceAttribute(path))
            }
            TraceFieldSelector::ScopeAttribute(_) => Some(TraceFieldSelector::ScopeAttribute(path)),
            TraceFieldSelector::EventAttribute(_) => Some(TraceFieldSelector::EventAttribute(path)),
            // Renaming non-attribute fields is not expressible in the proto.
            TraceFieldSelector::Simple(_)
            | TraceFieldSelector::SpanKind
            | TraceFieldSelector::SpanStatus
            | TraceFieldSelector::EventName
            | TraceFieldSelector::LinkTraceId
            | TraceFieldSelector::SamplingThreshold => None,
        }
    }
}
