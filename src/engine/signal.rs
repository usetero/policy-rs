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
}

/// Log telemetry signal.
#[derive(Debug)]
pub struct LogSignal;

impl Signal for LogSignal {
    type FieldSelector = LogFieldSelector;

    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>> {
        snapshot.compiled_log_matchers()
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
}

/// Trace telemetry signal.
#[derive(Debug)]
pub struct TraceSignal;

impl Signal for TraceSignal {
    type FieldSelector = TraceFieldSelector;

    fn compiled_matchers(snapshot: &PolicySnapshot) -> Option<&CompiledMatchers<Self>> {
        snapshot.compiled_trace_matchers()
    }
}
