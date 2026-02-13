use std::io::Result;

fn main() -> Result<()> {
    // Generate protobuf types with serde support for JSON and gRPC client
    // The gRPC client module is wrapped with #[cfg(feature = "grpc")]
    tonic_build::configure()
        .out_dir("src/proto")
        .build_server(false)
        .build_client(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        // Support flexible AttributePath deserialization:
        // - Canonical: { "path": ["a", "b"] }
        // - Shorthand array: ["a", "b"]
        // - Shorthand string: "user_id"
        // Use 'from' and 'into' with a wrapper type that implements the flexible deserialization
        .type_attribute(
            "tero.policy.v1.AttributePath",
            "#[serde(from = \"crate::proto::serde_helpers::attribute_path::AttributePathInput\", into = \"crate::proto::serde_helpers::attribute_path::AttributePathInput\")]",
        )
        // Default enabled to true (proto3 defaults bool to false, but policies should be enabled by default)
        .field_attribute(
            "tero.policy.v1.Policy.enabled",
            "#[serde(default = \"crate::proto::serde_helpers::default_true\")]",
        )
        // Allow omitting optional string/repeated fields in JSON (they default to empty)
        .field_attribute("tero.policy.v1.Policy.description", "#[serde(default)]")
        .field_attribute(
            "tero.policy.v1.Policy.created_at_unix_nano",
            "#[serde(default)]",
        )
        .field_attribute(
            "tero.policy.v1.Policy.modified_at_unix_nano",
            "#[serde(default)]",
        )
        .field_attribute("tero.policy.v1.Policy.labels", "#[serde(default)]")
        // Allow omitting negate/case_insensitive in matchers (default false)
        .field_attribute("tero.policy.v1.LogMatcher.negate", "#[serde(default)]")
        .field_attribute(
            "tero.policy.v1.LogMatcher.case_insensitive",
            "#[serde(default)]",
        )
        .field_attribute("tero.policy.v1.MetricMatcher.negate", "#[serde(default)]")
        .field_attribute(
            "tero.policy.v1.MetricMatcher.case_insensitive",
            "#[serde(default)]",
        )
        .field_attribute("tero.policy.v1.TraceMatcher.negate", "#[serde(default)]")
        .field_attribute(
            "tero.policy.v1.TraceMatcher.case_insensitive",
            "#[serde(default)]",
        )
        // Note: Enum fields inside oneofs (e.g. LogMatcher.log_field) serialize as i32
        // because tonic-build doesn't support per-variant serde attributes on oneof enums.
        // The standalone enum fields (like SyncResponse.sync_type) use string names via
        // custom serde helpers in proto::serde_helpers.
        // Flatten oneof fields to match proto3 JSON mapping
        .field_attribute(
            "opentelemetry.proto.common.v1.AnyValue.value",
            "#[serde(flatten)]",
        )
        .field_attribute("tero.policy.v1.Policy.target", "#[serde(flatten)]")
        // Use string encoding for 64-bit integers (proto3 JSON format)
        .field_attribute(
            "tero.policy.v1.Policy.created_at_unix_nano",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_u64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_u64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.Policy.modified_at_unix_nano",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_u64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_u64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.SyncRequest.last_sync_timestamp_unix_nano",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_u64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_u64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.SyncResponse.sync_timestamp_unix_nano",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_u64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_u64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.TransformStageStatus.hits",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_i64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_i64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.TransformStageStatus.misses",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_i64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_i64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.PolicySyncStatus.match_hits",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_i64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_i64_from_string\")]",
        )
        .field_attribute(
            "tero.policy.v1.PolicySyncStatus.match_misses",
            "#[serde(serialize_with = \"crate::proto::serde_helpers::serialize_i64_as_string\", deserialize_with = \"crate::proto::serde_helpers::deserialize_i64_from_string\")]",
        )
        // Handle enum fields as strings (proto3 JSON format)
        .field_attribute(
            "tero.policy.v1.SyncResponse.sync_type",
            "#[serde(with = \"crate::proto::serde_helpers::sync_type\")]",
        )
        .client_mod_attribute(".", "#[cfg(feature = \"grpc\")]")
        .compile_protos(
            &[
                "proto/tero/policy/v1/policy.proto",
                "proto/tero/policy/v1/log.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
