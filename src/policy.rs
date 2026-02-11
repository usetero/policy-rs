//! Policy wrapper type with convenience methods.

use crate::proto::tero::policy::v1::{LogTarget, MetricTarget, Policy as ProtoPolicy, TraceTarget};

/// A wrapper around the protobuf Policy with convenience methods.
#[derive(Debug, Clone)]
pub struct Policy {
    pub(crate) proto: ProtoPolicy,
}

impl Policy {
    /// Create a new Policy from a protobuf Policy.
    pub fn new(proto: ProtoPolicy) -> Self {
        Self { proto }
    }

    /// Get the policy ID.
    pub fn id(&self) -> &str {
        &self.proto.id
    }

    /// Get the policy name.
    pub fn name(&self) -> &str {
        &self.proto.name
    }

    /// Get the policy description.
    pub fn description(&self) -> &str {
        &self.proto.description
    }

    /// Check if the policy is enabled.
    pub fn enabled(&self) -> bool {
        self.proto.enabled
    }

    /// Get the log target if this is a log policy.
    pub fn log_target(&self) -> Option<&LogTarget> {
        match &self.proto.target {
            Some(crate::proto::tero::policy::v1::policy::Target::Log(t)) => Some(t),
            _ => None,
        }
    }

    /// Get the metric target if this is a metric policy.
    pub fn metric_target(&self) -> Option<&MetricTarget> {
        match &self.proto.target {
            Some(crate::proto::tero::policy::v1::policy::Target::Metric(t)) => Some(t),
            _ => None,
        }
    }

    /// Get the trace target if this is a trace policy.
    pub fn trace_target(&self) -> Option<&TraceTarget> {
        match &self.proto.target {
            Some(crate::proto::tero::policy::v1::policy::Target::Trace(t)) => Some(t),
            _ => None,
        }
    }

    /// Get the underlying protobuf Policy.
    pub fn proto(&self) -> &ProtoPolicy {
        &self.proto
    }

    /// Consume and return the underlying protobuf Policy.
    pub fn into_proto(self) -> ProtoPolicy {
        self.proto
    }
}

impl From<ProtoPolicy> for Policy {
    fn from(proto: ProtoPolicy) -> Self {
        Self::new(proto)
    }
}

impl From<Policy> for ProtoPolicy {
    fn from(policy: Policy) -> Self {
        policy.into_proto()
    }
}
