//! Policy library for working with protobuf-defined policy objects.

pub mod config;
pub mod engine;
pub mod error;
pub mod field;
mod policy;
pub mod proto;
pub mod provider;
pub mod registry;

pub use config::{ProviderConfig, register_providers};
pub use engine::{
    CompiledKeep, CompiledMatchers, CompiledPolicy, CompiledTransform, EvaluateResult, MatchKey,
    Matchable, PolicyEngine, RateLimiters, TransformOp, Transformable,
};
pub use error::PolicyError;
pub use field::LogFieldSelector;
pub use policy::Policy;
pub use proto::opentelemetry::proto::common::v1 as otel_common;
#[cfg(any(feature = "http", feature = "grpc"))]
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
