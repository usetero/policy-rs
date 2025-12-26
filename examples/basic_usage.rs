//! Basic usage example: Load policies and evaluate logs.
//!
//! Run with: cargo run --example basic_usage

use policy_rs::proto::tero::policy::v1::LogField;
use policy_rs::{
    EvaluateResult, FileProvider, LogFieldSelector, Matchable, PolicyEngine, PolicyRegistry,
};
use std::collections::HashMap;

/// A simple log record for demonstration.
struct LogRecord {
    body: String,
    severity: String,
    attributes: HashMap<String, String>,
}

impl LogRecord {
    fn new(body: &str, severity: &str) -> Self {
        Self {
            body: body.to_string(),
            severity: severity.to_string(),
            attributes: HashMap::new(),
        }
    }

    fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

impl Matchable for LogRecord {
    fn get_field(&self, field: &LogFieldSelector) -> Option<&str> {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => Some(&self.body),
                LogField::SeverityText => Some(&self.severity),
                _ => None,
            },
            LogFieldSelector::LogAttribute(key) => self.attributes.get(key).map(|s| s.as_str()),
            _ => None,
        }
    }
}

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

        println!("\nLog {}: [{}] {}", i + 1, log.severity, log.body);
        match result {
            EvaluateResult::NoMatch => {
                println!("  -> No policy matched, pass through");
            }
            EvaluateResult::Keep { policy_id } => {
                println!("  -> KEEP (policy: {})", policy_id);
            }
            EvaluateResult::Drop { policy_id } => {
                println!("  -> DROP (policy: {})", policy_id);
            }
            EvaluateResult::Sample {
                policy_id,
                percentage,
                keep,
            } => {
                println!(
                    "  -> SAMPLE {}% (policy: {}) - {}",
                    percentage,
                    policy_id,
                    if keep { "kept" } else { "dropped" }
                );
            }
            EvaluateResult::RateLimit { policy_id, allowed } => {
                println!(
                    "  -> RATE LIMIT (policy: {}) - {}",
                    policy_id,
                    if allowed { "allowed" } else { "throttled" }
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
