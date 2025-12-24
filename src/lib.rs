//! Policy library for working with protobuf-defined policy objects.

pub mod proto;

pub use proto::opentelemetry::proto::common::v1 as otel_common;
pub use proto::tero::policy::v1 as policy;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_policy() {
        let policy = policy::Policy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            description: "A test policy".to_string(),
            enabled: true,
            ..Default::default()
        };
        assert_eq!(policy.id, "test-policy");
    }
}
