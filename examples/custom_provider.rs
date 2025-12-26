//! Custom provider example: Implement a policy provider that fetches from an API.
//!
//! This example demonstrates how to implement the PolicyProvider trait
//! for a custom data source (simulated API in this case).
//!
//! Run with: cargo run --example custom_provider

use policy_rs::proto::tero::policy::v1::{
    LogField, LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher,
};
use policy_rs::{
    EvaluateResult, LogFieldSelector, Matchable, Policy, PolicyCallback, PolicyEngine, PolicyError,
    PolicyProvider, PolicyRegistry,
};
use std::sync::{Arc, RwLock};

/// A custom policy provider that simulates fetching policies from an API.
struct ApiPolicyProvider {
    /// Simulated API endpoint
    endpoint: String,
    /// Cached policies
    policies: RwLock<Vec<Policy>>,
    /// Subscribers to notify on updates
    subscribers: RwLock<Vec<PolicyCallback>>,
}

impl ApiPolicyProvider {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            policies: RwLock::new(Vec::new()),
            subscribers: RwLock::new(Vec::new()),
        }
    }

    /// Simulate fetching policies from an API.
    fn fetch_from_api(&self) -> Result<Vec<Policy>, PolicyError> {
        println!("Fetching policies from API: {}", self.endpoint);

        // In a real implementation, this would make an HTTP request
        // For this example, we return hardcoded policies
        let policies = vec![
            self.create_policy("api-drop-debug", "DEBUG", "none"),
            self.create_policy("api-sample-info", "INFO", "50%"),
            self.create_policy("api-keep-error", "ERROR", "all"),
        ];

        Ok(policies)
    }

    fn create_policy(&self, id: &str, severity: &str, keep: &str) -> Policy {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::SeverityText.into())),
            r#match: Some(log_matcher::Match::Exact(severity.to_string())),
            negate: false,
        };

        let log_target = LogTarget {
            r#match: vec![matcher],
            keep: keep.to_string(),
            transform: None,
        };

        let proto = ProtoPolicy {
            id: id.to_string(),
            name: format!("Policy from {}", self.endpoint),
            enabled: true,
            target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Log(
                log_target,
            )),
            ..Default::default()
        };

        Policy::new(proto)
    }

    /// Simulate receiving an update from the API (e.g., via webhook or polling).
    pub fn simulate_update(&self, new_policies: Vec<Policy>) {
        println!("API update received: {} policies", new_policies.len());

        // Update cached policies
        {
            let mut policies = self.policies.write().unwrap();
            *policies = new_policies.clone();
        }

        // Notify all subscribers
        let subscribers = self.subscribers.read().unwrap();
        for callback in subscribers.iter() {
            callback(new_policies.clone());
        }
    }
}

impl PolicyProvider for ApiPolicyProvider {
    fn load(&self) -> Result<Vec<Policy>, PolicyError> {
        let policies = self.fetch_from_api()?;

        // Cache the policies
        let mut cached = self.policies.write().unwrap();
        *cached = policies.clone();

        Ok(policies)
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        // Load initial policies
        let policies = self.load()?;

        // Invoke callback with initial policies
        callback(policies);

        // Store subscriber for future updates
        let mut subscribers = self.subscribers.write().unwrap();
        subscribers.push(callback);

        Ok(())
    }
}

/// A simple log record for demonstration.
struct LogRecord {
    body: String,
    severity: String,
}

impl LogRecord {
    fn new(body: &str, severity: &str) -> Self {
        Self {
            body: body.to_string(),
            severity: severity.to_string(),
        }
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
            _ => None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create registry with custom provider
    let registry = PolicyRegistry::new();
    let provider = Arc::new(ApiPolicyProvider::new("https://api.example.com/policies"));

    // Subscribe to the provider
    registry.subscribe(provider.as_ref())?;
    println!("Subscribed to API provider");

    let engine = PolicyEngine::new();

    // Evaluate some logs with initial policies
    println!("\n--- Initial Evaluation ---");
    let snapshot = registry.snapshot();
    println!("Policies loaded: {}", snapshot.len());

    let logs = vec![
        LogRecord::new("Debug trace", "DEBUG"),
        LogRecord::new("User action", "INFO"),
        LogRecord::new("Something failed", "ERROR"),
    ];

    for log in &logs {
        let result = engine.evaluate(&snapshot, log).await?;
        print!("[{}] {}: ", log.severity, log.body);
        match result {
            EvaluateResult::NoMatch => println!("pass through"),
            EvaluateResult::Keep { policy_id } => println!("KEEP ({})", policy_id),
            EvaluateResult::Drop { policy_id } => println!("DROP ({})", policy_id),
            EvaluateResult::Sample {
                policy_id,
                percentage,
                keep,
            } => {
                println!(
                    "SAMPLE {}% ({}) -> {}",
                    percentage,
                    policy_id,
                    if keep { "kept" } else { "dropped" }
                )
            }
            EvaluateResult::RateLimit { policy_id, allowed } => {
                println!(
                    "RATE LIMIT ({}) -> {}",
                    policy_id,
                    if allowed { "allowed" } else { "throttled" }
                )
            }
        }
    }

    // Simulate an API update (e.g., from a webhook)
    println!("\n--- Simulating API Update ---");
    provider.simulate_update(vec![
        provider.create_policy("api-drop-debug", "DEBUG", "none"),
        provider.create_policy("api-drop-info", "INFO", "none"), // Changed from sample to drop
        provider.create_policy("api-keep-error", "ERROR", "all"),
        provider.create_policy("api-keep-warn", "WARN", "all"), // New policy
    ]);

    // Get fresh snapshot after update
    let new_snapshot = registry.snapshot();
    println!("Policies after update: {}", new_snapshot.len());

    // Re-evaluate with updated policies
    println!("\n--- Evaluation After Update ---");
    for log in &logs {
        let result = engine.evaluate(&new_snapshot, log).await?;
        print!("[{}] {}: ", log.severity, log.body);
        match result {
            EvaluateResult::NoMatch => println!("pass through"),
            EvaluateResult::Keep { policy_id } => println!("KEEP ({})", policy_id),
            EvaluateResult::Drop { policy_id } => println!("DROP ({})", policy_id),
            EvaluateResult::Sample {
                policy_id,
                percentage,
                keep,
            } => {
                println!(
                    "SAMPLE {}% ({}) -> {}",
                    percentage,
                    policy_id,
                    if keep { "kept" } else { "dropped" }
                )
            }
            EvaluateResult::RateLimit { policy_id, allowed } => {
                println!(
                    "RATE LIMIT ({}) -> {}",
                    policy_id,
                    if allowed { "allowed" } else { "throttled" }
                )
            }
        }
    }

    Ok(())
}
