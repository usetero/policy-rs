//! Policy library for working with protobuf-defined policy objects.

pub mod error;
pub mod field;
mod policy;
pub mod proto;
pub mod provider;

pub use error::PolicyError;
pub use field::LogFieldSelector;
pub use policy::Policy;
pub use proto::opentelemetry::proto::common::v1 as otel_common;
pub use provider::{FileProvider, PolicyProvider};

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
