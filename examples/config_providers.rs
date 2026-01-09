//! Config-based provider example: Load providers from a configuration file.
//!
//! This example demonstrates using the config module to define policy providers
//! in a JSON configuration file, which can be embedded in your application's config.
//!
//! Run with: cargo run --example config_providers

mod common;

use common::LogRecord;
use policy_rs::{
    EvaluateResult, PolicyEngine, PolicyRegistry,
    config::{ProviderConfig, register_providers},
};
use serde::Deserialize;

/// Example application configuration that embeds policy providers.
#[derive(Debug, Deserialize)]
struct AppConfig {
    /// Application name
    service_name: String,
    /// Policy provider configurations
    policy_providers: Vec<ProviderConfig>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Parse provider configs from JSON
    let config_json = r#"{
        "service_name": "my-service",
        "policy_providers": [
            {
                "id": "local-policies",
                "type": "file",
                "path": "testdata/policies.json"
            }
        ]
    }"#;

    let app_config: AppConfig = serde_json::from_str(config_json)?;
    println!("Service: {}", app_config.service_name);
    println!(
        "Providers configured: {}",
        app_config.policy_providers.len()
    );

    // Create registry and register all providers from config
    let registry = PolicyRegistry::new();
    let provider_ids = register_providers(&app_config.policy_providers, &registry)?;

    println!("Registered {} providers", provider_ids.len());
    println!("Total policies loaded: {}", registry.snapshot().len());

    // Create the evaluation engine
    let engine = PolicyEngine::new();
    let snapshot = registry.snapshot();

    // List loaded policies
    println!("\n--- Loaded Policies ---");
    for entry in snapshot.iter() {
        println!(
            "  - {} (enabled: {})",
            entry.policy.id(),
            entry.policy.enabled()
        );
    }

    // Evaluate some test logs
    let logs = vec![
        LogRecord::new("Application started", "INFO"),
        LogRecord::new("Debug: internal state", "DEBUG"),
        LogRecord::new("Error: connection failed", "ERROR"),
    ];

    println!("\n--- Evaluating Logs ---");
    for log in &logs {
        let result = engine.evaluate(&snapshot, log).await?;

        let severity = log.severity.as_deref().unwrap_or("?");
        let body = log.body.as_deref().unwrap_or("");
        print!("[{}] {}: ", severity, body);

        match result {
            EvaluateResult::NoMatch => println!("pass through"),
            EvaluateResult::Keep { policy_id, .. } => println!("KEEP ({})", policy_id),
            EvaluateResult::Drop { policy_id } => println!("DROP ({})", policy_id),
            EvaluateResult::Sample {
                policy_id,
                percentage,
                keep,
                ..
            } => {
                println!(
                    "SAMPLE {}% ({}) -> {}",
                    percentage,
                    policy_id,
                    if keep { "kept" } else { "dropped" }
                )
            }
            EvaluateResult::RateLimit {
                policy_id, allowed, ..
            } => {
                println!(
                    "RATE LIMIT ({}) -> {}",
                    policy_id,
                    if allowed { "allowed" } else { "throttled" }
                )
            }
        }
    }

    // Example 2: Parse just the provider list (embeddable format)
    println!("\n--- Parsing Provider List Directly ---");
    let providers_json = r#"[
        {"id": "file1", "type": "file", "path": "policies1.json"},
        {"id": "file2", "type": "file", "path": "policies2.json"}
    ]"#;

    let providers: Vec<ProviderConfig> = serde_json::from_str(providers_json)?;
    println!("Parsed {} provider configs", providers.len());
    for provider in &providers {
        println!(
            "  - {} ({})",
            provider.id(),
            match provider {
                ProviderConfig::File(_) => "file",
                #[cfg(feature = "http")]
                ProviderConfig::Http(_) => "http",
                #[cfg(feature = "grpc")]
                ProviderConfig::Grpc(_) => "grpc",
            }
        );
    }

    Ok(())
}
