use std::io::Result;

fn main() -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let descriptor_path = format!("{}/policy_descriptor.bin", out_dir);

    // Generate protobuf types and gRPC client (no serde attributes —
    // pbjson-build generates proto3 JSON-compliant serde impls separately).
    tonic_build::configure()
        .out_dir("src/proto")
        .file_descriptor_set_path(&descriptor_path)
        .build_server(false)
        .build_client(true)
        .client_mod_attribute(".", "#[cfg(feature = \"grpc\")]")
        .compile_protos(
            &[
                "proto/tero/policy/v1/policy.proto",
                "proto/tero/policy/v1/log.proto",
            ],
            &["proto"],
        )?;

    // Generate proto3 JSON-compliant serde impls from the file descriptor set.
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(&descriptor_path)?)?
        .out_dir("src/proto")
        .build(&[
            ".tero.policy.v1",
            ".opentelemetry.proto.common.v1",
            ".google.api",
        ])?;

    Ok(())
}
