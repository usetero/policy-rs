//! Transforms example: Apply log transformations using policies.
//!
//! This example demonstrates how to use `evaluate_and_transform` to:
//! - Remove sensitive fields
//! - Redact field values
//! - Rename fields
//! - Add new fields
//!
//! Run with: cargo run --example transforms

mod common;

use common::{LogRecord, print_log};
use policy_rs::proto::tero::policy::v1::{
    LogAdd, LogField, LogMatcher, LogRedact, LogRemove, LogRename, LogTarget, LogTransform,
    Policy as ProtoPolicy, log_add, log_matcher, log_redact, log_remove, log_rename,
};
use policy_rs::{Policy, PolicyEngine, PolicyRegistry};

/// Create a policy with matchers and transforms.
fn create_policy(
    id: &str,
    matchers: Vec<LogMatcher>,
    keep: &str,
    transform: Option<LogTransform>,
) -> Policy {
    let log_target = LogTarget {
        r#match: matchers,
        keep: keep.to_string(),
        transform,
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

fn body_regex_matcher(pattern: &str) -> LogMatcher {
    LogMatcher {
        field: Some(log_matcher::Field::LogField(LogField::Body.into())),
        r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
        negate: false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Policy Transforms Example ===\n");

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();

    // Policy 1: Redact passwords in authentication logs
    let auth_transform = LogTransform {
        redact: vec![
            LogRedact {
                field: Some(log_redact::Field::LogAttribute("password".to_string())),
                replacement: "[REDACTED]".to_string(),
            },
            LogRedact {
                field: Some(log_redact::Field::LogAttribute("api_key".to_string())),
                replacement: "[REDACTED]".to_string(),
            },
        ],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute("sanitized".to_string())),
            value: "true".to_string(),
            upsert: false,
        }],
        ..Default::default()
    };

    let auth_policy = create_policy(
        "redact-auth-secrets",
        vec![body_regex_matcher("auth|login|password")],
        "all",
        Some(auth_transform),
    );

    // Policy 2: Remove debug info and add processing metadata
    let cleanup_transform = LogTransform {
        remove: vec![
            LogRemove {
                field: Some(log_remove::Field::LogAttribute("debug_trace".to_string())),
            },
            LogRemove {
                field: Some(log_remove::Field::LogAttribute("internal_id".to_string())),
            },
        ],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute("processed_by".to_string())),
            value: "policy-engine-v1".to_string(),
            upsert: false,
        }],
        ..Default::default()
    };

    let cleanup_policy = create_policy(
        "cleanup-debug-info",
        vec![body_regex_matcher("order|processing")], // Match order processing logs
        "all",
        Some(cleanup_transform),
    );

    // Policy 3: Rename legacy field names
    let rename_transform = LogTransform {
        rename: vec![
            LogRename {
                from: Some(log_rename::From::FromLogAttribute("usr".to_string())),
                to: "user_id".to_string(),
                upsert: true,
            },
            LogRename {
                from: Some(log_rename::From::FromLogAttribute("ts".to_string())),
                to: "timestamp".to_string(),
                upsert: true,
            },
        ],
        ..Default::default()
    };

    let rename_policy = create_policy(
        "normalize-field-names",
        vec![body_regex_matcher("legacy")],
        "all",
        Some(rename_transform),
    );

    handle.update(vec![auth_policy, cleanup_policy, rename_policy]);
    println!("Registered 3 policies with transforms\n");

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    // Example 1: Authentication log with sensitive data
    println!("--- Example 1: Authentication Log ---");
    let mut log1 = LogRecord::new("User authentication attempt", "INFO")
        .with_attr("password", "super_secret_123")
        .with_attr("api_key", "sk-abc123xyz")
        .with_attr("username", "john_doe")
        .with_attr("debug_trace", "stack trace here...");

    println!("BEFORE:");
    print_log(&log1);

    let result1 = engine.evaluate_and_transform(&snapshot, &mut log1).await?;

    println!("\nAFTER:");
    print_log(&log1);
    println!("\nResult: {:?}", result1);

    // Example 2: Order processing log - matches cleanup policy
    println!("\n--- Example 2: Order Processing Log with Debug Info ---");
    let mut log2 = LogRecord::new("Processing order #12345", "INFO")
        .with_attr("order_id", "12345")
        .with_attr("debug_trace", "detailed debug info")
        .with_attr("internal_id", "int-999");

    println!("BEFORE:");
    print_log(&log2);

    let result2 = engine.evaluate_and_transform(&snapshot, &mut log2).await?;

    println!("\nAFTER:");
    print_log(&log2);
    println!("\nResult: {:?}", result2);

    // Example 3: Legacy format log with old field names
    println!("\n--- Example 3: Legacy Format Log ---");
    let mut log3 = LogRecord::new("legacy system event", "WARN")
        .with_attr("usr", "admin")
        .with_attr("ts", "2024-01-15T10:30:00Z")
        .with_attr("debug_trace", "legacy trace");

    println!("BEFORE:");
    print_log(&log3);

    let result3 = engine.evaluate_and_transform(&snapshot, &mut log3).await?;

    println!("\nAFTER:");
    print_log(&log3);
    println!("\nResult: {:?}", result3);

    // Show transform statistics
    println!("\n--- Transform Statistics ---");
    for entry in snapshot.iter() {
        let policy_id = entry.policy.id();
        let stats = &entry.stats;

        let remove_hits = stats.remove.hits();
        let remove_misses = stats.remove.misses();
        let redact_hits = stats.redact.hits();
        let redact_misses = stats.redact.misses();
        let rename_hits = stats.rename.hits();
        let rename_misses = stats.rename.misses();
        let add_hits = stats.add.hits();
        let add_misses = stats.add.misses();

        let has_stats = remove_hits
            + remove_misses
            + redact_hits
            + redact_misses
            + rename_hits
            + rename_misses
            + add_hits
            + add_misses
            > 0;

        if has_stats {
            println!("{}:", policy_id);
            if remove_hits + remove_misses > 0 {
                println!("  remove: {} hits, {} misses", remove_hits, remove_misses);
            }
            if redact_hits + redact_misses > 0 {
                println!("  redact: {} hits, {} misses", redact_hits, redact_misses);
            }
            if rename_hits + rename_misses > 0 {
                println!("  rename: {} hits, {} misses", rename_hits, rename_misses);
            }
            if add_hits + add_misses > 0 {
                println!("  add: {} hits, {} misses", add_hits, add_misses);
            }
        }
    }

    // Demonstrate the difference between evaluate and evaluate_and_transform
    println!("\n--- Compare: evaluate vs evaluate_and_transform ---");

    // Use two identical logs to compare
    let log_for_eval = LogRecord::new("User authentication request", "INFO")
        .with_attr("password", "secret123")
        .with_attr("api_key", "key-abc");
    let mut log_for_transform = log_for_eval.clone();

    println!("Original log:");
    print_log(&log_for_eval);

    // evaluate() - reads the log but does NOT modify it
    let result_eval = engine.evaluate(&snapshot, &log_for_eval).await?;
    println!("\nevaluate() result: {:?}", result_eval);
    println!("Log after evaluate() (unchanged):");
    print_log(&log_for_eval);

    // evaluate_and_transform() - reads AND modifies the log
    let result_transform = engine
        .evaluate_and_transform(&snapshot, &mut log_for_transform)
        .await?;
    println!("\nevaluate_and_transform() result: {:?}", result_transform);
    println!("Log after evaluate_and_transform() (transformed):");
    print_log(&log_for_transform);

    Ok(())
}
