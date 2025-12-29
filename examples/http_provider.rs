//! HTTP provider example: Load policies from an HTTP endpoint.
//!
//! This example demonstrates using the HTTP provider to sync policies
//! from a remote control plane.
//!
//! Run with: cargo run --example http_provider --features http
//!
//! Requires TERO_ACCESS_TOKEN environment variable (can be set in .env file).

mod common;

use std::env;
use std::sync::Arc;
use std::time::Duration;

use common::LogRecord;
use policy_rs::{
    ContentType, EvaluateResult, HttpProvider, HttpProviderConfig, PolicyEngine, PolicyRegistry,
    otel_common::{AnyValue, KeyValue, any_value},
    proto::tero::policy::v1::ClientMetadata,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Get access token from environment
    let access_token =
        env::var("TERO_ACCESS_TOKEN").expect("TERO_ACCESS_TOKEN environment variable is required");

    // Helper to create a string KeyValue
    fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(value.to_string())),
            }),
        }
    }

    // Build client metadata with required fields
    let client_metadata = ClientMetadata {
        supported_policy_stages: vec![],
        labels: vec![kv("workspace.id", "example-workspace")],
        resource_attributes: vec![
            kv("service.instance.id", "http-provider-example-1"),
            kv("service.name", "http-provider-example"),
            kv("service.namespace", "examples"),
            kv("service.version", "0.1.0"),
        ],
    };

    // Configure the HTTP provider
    let config = HttpProviderConfig::new("http://control-plane-sync.orb.local:8090/v1/policy/sync")
        .poll_interval(Duration::from_secs(30))
        .header("Authorization", format!("Bearer {}", access_token))
        .content_type(ContentType::Json)
        .client_metadata(client_metadata);

    // Create the provider
    let provider = Arc::new(HttpProvider::new(config));

    // Create a registry and subscribe to the provider
    // Note: subscribe() uses block_on internally, so we run it via spawn_blocking
    let registry = Arc::new(PolicyRegistry::new());
    let registry_clone = registry.clone();
    let provider_clone = provider.clone();
    tokio::task::spawn_blocking(move || registry_clone.subscribe(provider_clone.as_ref()))
        .await??;

    println!(
        "Loaded {} policies from HTTP endpoint",
        registry.snapshot().len()
    );

    // Create the evaluation engine
    let engine = PolicyEngine::new();

    // Get a snapshot for evaluation
    let snapshot = registry.snapshot();

    // Example logs to evaluate
    let logs = vec![
        LogRecord::new("Application started successfully", "INFO"),
        LogRecord::new("Error: Connection timeout", "ERROR"),
        LogRecord::new("Debug: Cache miss for key xyz", "DEBUG"),
    ];

    // Evaluate each log
    for (i, log) in logs.iter().enumerate() {
        let result = engine.evaluate(&snapshot, log).await?;

        println!(
            "\nLog {}: [{}] {}",
            i + 1,
            log.severity.as_deref().unwrap_or(""),
            log.body.as_deref().unwrap_or("")
        );
        match result {
            EvaluateResult::NoMatch => {
                println!("  -> No policy matched, pass through");
            }
            EvaluateResult::Keep {
                policy_id,
                transformed,
            } => {
                let suffix = if transformed { " (transformed)" } else { "" };
                println!("  -> KEEP (policy: {}){}", policy_id, suffix);
            }
            EvaluateResult::Drop { policy_id } => {
                println!("  -> DROP (policy: {})", policy_id);
            }
            EvaluateResult::Sample {
                policy_id,
                percentage,
                keep,
                transformed,
            } => {
                let suffix = if transformed { " (transformed)" } else { "" };
                println!(
                    "  -> SAMPLE {}% (policy: {}) - {}{}",
                    percentage,
                    policy_id,
                    if keep { "kept" } else { "dropped" },
                    suffix
                );
            }
            EvaluateResult::RateLimit {
                policy_id,
                allowed,
                transformed,
            } => {
                let suffix = if transformed { " (transformed)" } else { "" };
                println!(
                    "  -> RATE LIMIT (policy: {}) - {}{}",
                    policy_id,
                    if allowed { "allowed" } else { "throttled" },
                    suffix
                );
            }
        }
    }

    Ok(())
}
