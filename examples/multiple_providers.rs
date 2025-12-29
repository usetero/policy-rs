//! Multiple providers example: Aggregate policies from multiple sources.
//!
//! Run with: cargo run --example multiple_providers

mod common;

use common::LogRecord;
use policy_rs::proto::tero::policy::v1::{
    LogField, LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher,
};
use policy_rs::{EvaluateResult, Policy, PolicyEngine, PolicyRegistry};

/// Create a policy programmatically.
fn create_policy(id: &str, field: log_matcher::Field, pattern: &str, keep: &str) -> Policy {
    let matcher = LogMatcher {
        field: Some(field),
        r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
        negate: false,
    };

    let log_target = LogTarget {
        r#match: vec![matcher],
        keep: keep.to_string(),
        transform: None,
    };

    let proto = ProtoPolicy {
        id: id.to_string(),
        name: id.to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Log(
            log_target,
        )),
        ..Default::default()
    };

    Policy::new(proto)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = PolicyRegistry::new();

    // Provider 1: Global policies (e.g., from central config)
    let global_handle = registry.register_provider();
    global_handle.update(vec![
        create_policy(
            "global-drop-debug",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            "^DEBUG$",
            "none",
        ),
        create_policy(
            "global-sample-info",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            "^INFO$",
            "10%",
        ),
    ]);
    println!("Provider 1 (Global): 2 policies");

    // Provider 2: Team-specific policies
    let team_handle = registry.register_provider();
    team_handle.update(vec![create_policy(
        "team-keep-auth-errors",
        log_matcher::Field::ResourceAttribute("service.name".to_string()),
        "auth-service",
        "all",
    )]);
    println!("Provider 2 (Team): 1 policy");

    // Provider 3: Service-specific policies
    let service_handle = registry.register_provider();
    service_handle.update(vec![create_policy(
        "service-rate-limit",
        log_matcher::Field::LogField(LogField::Body.into()),
        "health check",
        "100/s",
    )]);
    println!("Provider 3 (Service): 1 policy");

    let snapshot = registry.snapshot();
    println!("\nTotal policies: {}", snapshot.len());

    // Create engine and evaluate some logs
    let engine = PolicyEngine::new();

    let logs = vec![
        ("Debug log", LogRecord::new("Debug: trace info", "DEBUG")),
        ("Info log", LogRecord::new("User logged in", "INFO")),
        (
            "Auth error",
            LogRecord::new("Auth failed", "ERROR")
                .with_resource_attr("service.name", "auth-service"),
        ),
        ("Health check", LogRecord::new("health check ok", "INFO")),
    ];

    println!("\n--- Evaluating Logs ---");
    for (name, log) in &logs {
        let result = engine.evaluate(&snapshot, log).await?;
        print!("{}: ", name);
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

    // Demonstrate updating a provider
    println!("\n--- Updating Team Provider ---");
    team_handle.update(vec![
        create_policy(
            "team-keep-auth-errors",
            log_matcher::Field::ResourceAttribute("service.name".to_string()),
            "auth-service",
            "all",
        ),
        create_policy(
            "team-drop-payment-debug",
            log_matcher::Field::ResourceAttribute("service.name".to_string()),
            "payment-service",
            "none",
        ),
    ]);

    let new_snapshot = registry.snapshot();
    println!("Total policies after update: {}", new_snapshot.len());

    Ok(())
}
