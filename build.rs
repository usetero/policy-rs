use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(
            &[
                "proto/tero/policy/v1/policy.proto",
                "proto/tero/policy/v1/log.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
