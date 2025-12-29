//! Benchmarks for the policy engine.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use policy_rs::proto::tero::policy::v1::{
    LogAdd, LogField, LogMatcher, LogRedact, LogRemove, LogRename, LogTarget, LogTransform,
    Policy as ProtoPolicy, log_add, log_matcher, log_redact, log_remove, log_rename,
};
use policy_rs::{LogFieldSelector, Matchable, Policy, PolicyEngine, PolicyRegistry, Transformable};
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

impl Transformable for BenchLog {
    fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => self.attributes.remove(key).is_some(),
            _ => false,
        }
    }

    fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => {
                if self.attributes.contains_key(key) {
                    self.attributes.insert(key.clone(), replacement.to_string());
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
        if !upsert && self.attributes.contains_key(to) {
            return false;
        }
        if let LogFieldSelector::LogAttribute(key) = from {
            if let Some(value) = self.attributes.remove(key) {
                self.attributes.insert(to.to_string(), value);
                return true;
            }
        }
        false
    }

    fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => {
                if !upsert && self.attributes.contains_key(key) {
                    return false;
                }
                self.attributes.insert(key.clone(), value.to_string());
                true
            }
            _ => false,
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

fn create_policy_with_transform(
    id: &str,
    field: log_matcher::Field,
    pattern: &str,
    keep: &str,
    transform: LogTransform,
) -> Policy {
    let matcher = LogMatcher {
        field: Some(field),
        r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
        negate: false,
    };

    let log_target = LogTarget {
        r#match: vec![matcher],
        keep: keep.to_string(),
        transform: Some(transform),
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

/// Benchmark individual transform operations.
fn bench_transform_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("transform_ops");

    // Benchmark each operation type individually
    let operations = [
        (
            "remove",
            LogTransform {
                remove: vec![LogRemove {
                    field: Some(log_remove::Field::LogAttribute("to_remove".to_string())),
                }],
                ..Default::default()
            },
        ),
        (
            "redact",
            LogTransform {
                redact: vec![LogRedact {
                    field: Some(log_redact::Field::LogAttribute("secret".to_string())),
                    replacement: "[REDACTED]".to_string(),
                }],
                ..Default::default()
            },
        ),
        (
            "rename",
            LogTransform {
                rename: vec![LogRename {
                    from: Some(log_rename::From::FromLogAttribute("old_key".to_string())),
                    to: "new_key".to_string(),
                    upsert: true,
                }],
                ..Default::default()
            },
        ),
        (
            "add",
            LogTransform {
                add: vec![LogAdd {
                    field: Some(log_add::Field::LogAttribute("new_field".to_string())),
                    value: "new_value".to_string(),
                    upsert: false,
                }],
                ..Default::default()
            },
        ),
    ];

    for (name, transform) in operations {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![create_policy_with_transform(
            &format!("transform-{}", name),
            log_matcher::Field::LogField(LogField::Body.into()),
            "test",
            "all",
            transform,
        )]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                // Create fresh log each iteration with fields that match the transform
                let mut log = BenchLog::new("test message", "INFO")
                    .with_attr("to_remove", "value")
                    .with_attr("secret", "password123")
                    .with_attr("old_key", "old_value");

                black_box(
                    engine
                        .evaluate_and_transform(&snapshot, &mut log)
                        .await
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

/// Benchmark combined transform operations (all 4 at once).
fn bench_transform_combined(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("transform_combined");

    // Test with increasing number of operations
    for op_count in [1, 2, 4, 8] {
        let mut transform = LogTransform::default();

        for i in 0..op_count {
            match i % 4 {
                0 => transform.remove.push(LogRemove {
                    field: Some(log_remove::Field::LogAttribute(format!("remove_{}", i))),
                }),
                1 => transform.redact.push(LogRedact {
                    field: Some(log_redact::Field::LogAttribute(format!("redact_{}", i))),
                    replacement: "[REDACTED]".to_string(),
                }),
                2 => transform.rename.push(LogRename {
                    from: Some(log_rename::From::FromLogAttribute(format!("rename_{}", i))),
                    to: format!("renamed_{}", i),
                    upsert: true,
                }),
                _ => transform.add.push(LogAdd {
                    field: Some(log_add::Field::LogAttribute(format!("add_{}", i))),
                    value: "added_value".to_string(),
                    upsert: false,
                }),
            }
        }

        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![create_policy_with_transform(
            "combined-transform",
            log_matcher::Field::LogField(LogField::Body.into()),
            "test",
            "all",
            transform,
        )]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        group.bench_with_input(
            BenchmarkId::new("operations", op_count),
            &op_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    // Create log with all possible fields
                    let mut log = BenchLog::new("test message", "INFO")
                        .with_attr("remove_0", "v")
                        .with_attr("remove_4", "v")
                        .with_attr("redact_1", "secret")
                        .with_attr("redact_5", "secret")
                        .with_attr("rename_2", "old")
                        .with_attr("rename_6", "old");

                    black_box(
                        engine
                            .evaluate_and_transform(&snapshot, &mut log)
                            .await
                            .unwrap(),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark transforms with multiple matching policies.
fn bench_transform_multiple_policies(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("transform_policy_count");

    for policy_count in [1, 2, 5, 10] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        // Create multiple policies, each with different transforms
        let policies: Vec<Policy> = (0..policy_count)
            .map(|i| {
                let transform = LogTransform {
                    redact: vec![LogRedact {
                        field: Some(log_redact::Field::LogAttribute(format!("secret_{}", i))),
                        replacement: "[REDACTED]".to_string(),
                    }],
                    add: vec![LogAdd {
                        field: Some(log_add::Field::LogAttribute(format!("processed_{}", i))),
                        value: "true".to_string(),
                        upsert: false,
                    }],
                    ..Default::default()
                };

                create_policy_with_transform(
                    &format!("policy-{}", i),
                    log_matcher::Field::LogField(LogField::Body.into()),
                    "test", // All match "test" in body
                    "all",
                    transform,
                )
            })
            .collect();

        handle.update(policies);
        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("matching_policies", policy_count),
            &policy_count,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    // Create log with secrets for all policies
                    let mut log = BenchLog::new("test message", "INFO");
                    for i in 0..count {
                        log.attributes
                            .insert(format!("secret_{}", i), "password".to_string());
                    }

                    black_box(
                        engine
                            .evaluate_and_transform(&snapshot, &mut log)
                            .await
                            .unwrap(),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark evaluate vs evaluate_and_transform overhead.
fn bench_transform_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let transform = LogTransform {
        redact: vec![LogRedact {
            field: Some(log_redact::Field::LogAttribute("password".to_string())),
            replacement: "[REDACTED]".to_string(),
        }],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute("sanitized".to_string())),
            value: "true".to_string(),
            upsert: false,
        }],
        ..Default::default()
    };

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![create_policy_with_transform(
        "transform-policy",
        log_matcher::Field::LogField(LogField::Body.into()),
        "test",
        "all",
        transform,
    )]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    let mut group = c.benchmark_group("transform_overhead");

    // Benchmark evaluate (no transform applied)
    group.bench_function("evaluate_only", |b| {
        b.to_async(&rt).iter(|| async {
            let log = BenchLog::new("test message", "INFO").with_attr("password", "secret123");
            black_box(engine.evaluate(&snapshot, &log).await.unwrap())
        })
    });

    // Benchmark evaluate_and_transform
    group.bench_function("evaluate_and_transform", |b| {
        b.to_async(&rt).iter(|| async {
            let mut log = BenchLog::new("test message", "INFO").with_attr("password", "secret123");
            black_box(
                engine
                    .evaluate_and_transform(&snapshot, &mut log)
                    .await
                    .unwrap(),
            )
        })
    });

    group.finish();
}

/// Benchmark transform throughput with batch of logs.
fn bench_transform_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let transform = LogTransform {
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
        remove: vec![LogRemove {
            field: Some(log_remove::Field::LogAttribute("debug_info".to_string())),
        }],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute("processed".to_string())),
            value: "true".to_string(),
            upsert: false,
        }],
        ..Default::default()
    };

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![create_policy_with_transform(
        "transform-policy",
        log_matcher::Field::LogField(LogField::Body.into()),
        ".", // Match everything
        "all",
        transform,
    )]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    let mut group = c.benchmark_group("transform_throughput");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("batch_1000", |b| {
        b.to_async(&rt).iter(|| async {
            for i in 0..1000 {
                let mut log = BenchLog::new(&format!("Log message {}", i), "INFO")
                    .with_attr("password", "secret")
                    .with_attr("api_key", "key-123")
                    .with_attr("debug_info", "trace data");

                black_box(
                    engine
                        .evaluate_and_transform(&snapshot, &mut log)
                        .await
                        .unwrap(),
                );
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
    bench_transform_operations,
    bench_transform_combined,
    bench_transform_multiple_policies,
    bench_transform_overhead,
    bench_transform_throughput,
);

criterion_main!(benches);
