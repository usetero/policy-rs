//! Basic usage example: Load policies and evaluate logs and metrics.
//!
//! Run with: cargo run --example basic_usage

mod common;

use common::{LogRecord, MetricRecord};
use policy_rs::proto::tero::policy::v1::{
    MetricField, MetricMatcher, MetricTarget, MetricType, Policy as ProtoPolicy, metric_matcher,
};
use policy_rs::{EvaluateResult, FileProvider, Policy, PolicyEngine, PolicyRegistry};

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

    // ==================== Metric Evaluation ====================

    println!("\n\n========== Metric Evaluation ==========\n");

    // Create a separate registry with metric policies (testdata only has log policies)
    let metric_registry = PolicyRegistry::new();
    let metric_handle = metric_registry.register_provider();

    // Policy: drop all Gauge metrics named "internal.*"
    let drop_internal_gauges = Policy::new(ProtoPolicy {
        id: "drop-internal-gauges".to_string(),
        name: "Drop internal gauge metrics".to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
            MetricTarget {
                r#match: vec![
                    MetricMatcher {
                        field: Some(metric_matcher::Field::MetricField(MetricField::Name.into())),
                        r#match: Some(metric_matcher::Match::Regex("internal\\..*".to_string())),
                        negate: false,
                        case_insensitive: false,
                    },
                    MetricMatcher {
                        field: Some(metric_matcher::Field::MetricType(MetricType::Gauge.into())),
                        r#match: None,
                        negate: false,
                        case_insensitive: false,
                    },
                ],
                keep: false,
            },
        )),
        ..Default::default()
    });

    // Policy: keep all metrics from production
    let keep_prod = Policy::new(ProtoPolicy {
        id: "keep-prod-metrics".to_string(),
        name: "Keep production metrics".to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
            MetricTarget {
                r#match: vec![MetricMatcher {
                    field: Some(metric_matcher::Field::DatapointAttribute(
                        policy_rs::proto::tero::policy::v1::AttributePath {
                            path: vec!["environment".to_string()],
                        },
                    )),
                    r#match: Some(metric_matcher::Match::Exact("production".to_string())),
                    negate: false,
                    case_insensitive: false,
                }],
                keep: true,
            },
        )),
        ..Default::default()
    });

    metric_handle.update(vec![drop_internal_gauges, keep_prod]);

    let metric_snapshot = metric_registry.snapshot();
    println!("Loaded {} metric policies", metric_snapshot.len());

    // Example metrics to evaluate
    let metrics = vec![
        MetricRecord::new("http.request.duration")
            .with_type(MetricType::Histogram)
            .with_datapoint_attr("environment", "production"),
        MetricRecord::new("internal.gc.pause")
            .with_type(MetricType::Gauge)
            .with_datapoint_attr("environment", "production"),
        MetricRecord::new("cpu.usage")
            .with_type(MetricType::Gauge)
            .with_datapoint_attr("environment", "staging"),
        MetricRecord::new("requests.total").with_type(MetricType::Sum),
    ];

    for (i, metric) in metrics.iter().enumerate() {
        let result = engine.evaluate(&metric_snapshot, metric).await?;

        let type_name = metric
            .metric_type
            .as_ref()
            .map(|t| t.as_str_name())
            .unwrap_or("unknown");

        println!("\nMetric {}: [{}] {}", i + 1, type_name, metric.name);
        match result {
            EvaluateResult::NoMatch => {
                println!("  -> No policy matched, pass through");
            }
            EvaluateResult::Keep { policy_id, .. } => {
                println!("  -> KEEP (policy: {})", policy_id);
            }
            EvaluateResult::Drop { policy_id } => {
                println!("  -> DROP (policy: {})", policy_id);
            }
            _ => {
                println!("  -> {:?}", result);
            }
        }
    }

    Ok(())
}
