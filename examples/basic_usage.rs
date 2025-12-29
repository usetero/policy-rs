//! Basic usage example: Load policies and evaluate logs.
//!
//! Run with: cargo run --example basic_usage

mod common;

use common::LogRecord;
use policy_rs::{EvaluateResult, FileProvider, PolicyEngine, PolicyRegistry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a registry and load policies from a file
    let registry = PolicyRegistry::new();
    let provider = FileProvider::new("testdata/policies.json");
    registry.subscribe(&provider)?;

    println!("Loaded {} policies", registry.snapshot().len());

    // Create the evaluation engine
    let engine = PolicyEngine::new();

    // Get a snapshot for evaluation
    let snapshot = registry.snapshot();

    // Example logs to evaluate
    let logs = vec![
        LogRecord::new("Application started successfully", "INFO"),
        LogRecord::new("Error: Connection timeout", "ERROR"),
        LogRecord::new("Debug: Cache miss for key xyz", "DEBUG"),
        LogRecord::new("User login failed", "WARN").with_attr("user_id", "12345"),
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

    // Print policy stats
    println!("\n--- Policy Stats ---");
    for entry in snapshot.iter() {
        let hits = entry.stats.hits();
        let misses = entry.stats.misses();
        if hits > 0 || misses > 0 {
            println!("{}: {} hits, {} misses", entry.policy.id(), hits, misses);
        }
    }

    Ok(())
}
