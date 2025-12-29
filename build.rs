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
