//! Policy library for working with protobuf-defined policy objects.
//!
//! This library provides a high-performance policy evaluation engine for log telemetry
//! using Vectorscan (Hyperscan) for pattern matching.
//!
//! # Features
//!
//! - **Pattern Matching**: Supports regex, exact, starts_with, ends_with, and contains matchers
//! - **Case-Insensitive Matching**: Optional case-insensitive flag for any matcher type
//! - **Nested Attribute Access**: Access nested attributes via path (e.g., `["http", "method"]`)
//! - **Sampling**: Percentage-based sampling with optional sample key for consistent decisions
//! - **Rate Limiting**: Per-second and per-minute rate limiting
//! - **Transforms**: Remove, redact, rename, and add fields to matching logs
//!
//! # Example
//!
//! ```ignore
//! use policy_rs::{PolicyEngine, PolicyRegistry, Matchable, EvaluateResult};
//!
//! // Create a registry and register policies
//! let registry = PolicyRegistry::new();
//! let handle = registry.register_provider();
//! handle.update(policies);
//!
//! // Create an engine and evaluate logs
//! let engine = PolicyEngine::new();
//! let snapshot = registry.snapshot();
//! let result = engine.evaluate(&snapshot, &log)?;
//!
//! match result {
//!     EvaluateResult::Keep { policy_id, .. } => println!("Keep: {}", policy_id),
//!     EvaluateResult::Drop { policy_id } => println!("Drop: {}", policy_id),
//!     EvaluateResult::Sample { keep, .. } => println!("Sample: keep={}", keep),
//!     EvaluateResult::NoMatch => println!("No matching policy"),
//!     _ => {}
//! }
//! ```

pub mod adapter;
pub mod canonical;
pub mod config;
pub mod engine;
pub mod error;
pub mod field;
mod policy;
pub mod proto;
pub mod provider;
pub mod registry;
pub mod volume;

pub use config::{ProviderConfig, register_providers};
pub use engine::{
    CompiledKeep, CompiledMatchers, CompiledPolicy, CompiledTraceSampling, CompiledTransform,
    EvaluateResult, LogSignal, MatchKey, Matchable, MetricSignal, PolicyEngine, RateLimiters,
    Signal, TraceSignal, TransformOp, Transformable,
};
pub use error::PolicyError;
pub use field::{LogFieldSelector, MetricFieldSelector, TraceFieldSelector};
pub use policy::Policy;
pub use proto::opentelemetry::proto::common::v1 as otel_common;
pub use provider::StatsCollector;
#[cfg(feature = "http")]
pub use provider::{ContentType, HttpProvider, HttpProviderConfig};
pub use provider::{FileProvider, PolicyCallback, PolicyProvider};
#[cfg(feature = "grpc")]
pub use provider::{GrpcProvider, GrpcProviderConfig};
pub use registry::{
    PolicyEntry, PolicyRegistry, PolicySnapshot, PolicyStats, PolicyStatsSnapshot, ProviderHandle,
    ProviderId, TransformStageStats,
};
pub use std::borrow::Cow;
pub use volume::VolumeTracker;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_policy() {
        let proto = proto::tero::policy::v1::Policy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            description: "A test policy".to_string(),
            enabled: true,
            ..Default::default()
        };
        let policy = Policy::new(proto);
        assert_eq!(policy.id(), "test-policy");
    }
}
