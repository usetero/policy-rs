//! Benchmarks for the policy engine.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use policy_rs::proto::tero::policy::v1::{
    LogField, LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher,
};
use policy_rs::{LogFieldSelector, Matchable, Policy, PolicyEngine, PolicyRegistry};
use std::collections::HashMap;
use tokio::runtime::Runtime;

/// Test log record for benchmarking.
struct BenchLog {
    body: String,
    severity: String,
    attributes: HashMap<String, String>,
}

impl BenchLog {
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

impl Matchable for BenchLog {
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

fn create_multi_matcher_policy(id: &str, patterns: Vec<(&str, &str)>, keep: &str) -> Policy {
    let matchers: Vec<LogMatcher> = patterns
        .into_iter()
        .map(|(field_name, pattern)| {
            let field = match field_name {
                "body" => log_matcher::Field::LogField(LogField::Body.into()),
                "severity" => log_matcher::Field::LogField(LogField::SeverityText.into()),
                _ => log_matcher::Field::LogAttribute(field_name.to_string()),
            };
            LogMatcher {
                field: Some(field),
                r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
                negate: false,
            }
        })
        .collect();

    let log_target = LogTarget {
        r#match: matchers,
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

fn bench_evaluate_single_policy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![create_policy(
        "drop-errors",
        log_matcher::Field::LogField(LogField::Body.into()),
        "error",
        "none",
    )]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    // Matching log
    let matching_log = BenchLog::new("error: something went wrong", "ERROR");
    // Non-matching log
    let non_matching_log = BenchLog::new("info: all is well", "INFO");

    let mut group = c.benchmark_group("single_policy");

    group.bench_function("matching", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(engine.evaluate(&snapshot, &matching_log).await.unwrap()) })
    });

    group.bench_function("non_matching", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(engine.evaluate(&snapshot, &non_matching_log).await.unwrap())
        })
    });

    group.finish();
}

fn bench_evaluate_multiple_policies(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("policy_count");

    for policy_count in [1, 10, 50, 100] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policies: Vec<Policy> = (0..policy_count)
            .map(|i| {
                create_policy(
                    &format!("policy-{}", i),
                    log_matcher::Field::LogField(LogField::Body.into()),
                    &format!("pattern{}", i),
                    "none",
                )
            })
            .collect();
        handle.update(policies);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log that matches none of the policies
        let log = BenchLog::new("this log matches nothing", "INFO");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("evaluate", policy_count),
            &policy_count,
            |b, _| {
                b.to_async(&rt)
                    .iter(|| async { black_box(engine.evaluate(&snapshot, &log).await.unwrap()) })
            },
        );
    }

    group.finish();
}

fn bench_evaluate_multi_matcher(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("matcher_count");

    for matcher_count in [1, 2, 3, 5] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let patterns: Vec<(&str, &str)> = (0..matcher_count)
            .map(|i| match i % 3 {
                0 => ("body", "test"),
                1 => ("severity", "INFO"),
                _ => ("service", "my-service"),
            })
            .collect();

        handle.update(vec![create_multi_matcher_policy(
            "multi-matcher",
            patterns,
            "none",
        )]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Log that matches all matchers
        let log = BenchLog::new("test message", "INFO").with_attr("service", "my-service-prod");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("evaluate", matcher_count),
            &matcher_count,
            |b, _| {
                b.to_async(&rt)
                    .iter(|| async { black_box(engine.evaluate(&snapshot, &log).await.unwrap()) })
            },
        );
    }

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![
        create_policy(
            "drop-debug",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            "DEBUG",
            "none",
        ),
        create_policy(
            "sample-info",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            "INFO",
            "50%",
        ),
        create_policy(
            "keep-error",
            log_matcher::Field::LogField(LogField::SeverityText.into()),
            "ERROR",
            "all",
        ),
    ]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    // Create a batch of logs
    let logs: Vec<BenchLog> = (0..1000)
        .map(|i| {
            let severity = match i % 3 {
                0 => "DEBUG",
                1 => "INFO",
                _ => "ERROR",
            };
            BenchLog::new(&format!("Log message {}", i), severity)
        })
        .collect();

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(logs.len() as u64));

    group.bench_function("batch_1000", |b| {
        b.to_async(&rt).iter(|| async {
            for log in &logs {
                black_box(engine.evaluate(&snapshot, log).await.unwrap());
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_evaluate_single_policy,
    bench_evaluate_multiple_policies,
    bench_evaluate_multi_matcher,
    bench_throughput,
);

criterion_main!(benches);
