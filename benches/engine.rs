//! Benchmarks for the policy engine.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use policy_rs::proto::tero::policy::v1::{
    AttributePath, LogAdd, LogField, LogMatcher, LogRedact, LogRemove, LogRename, LogTarget,
    LogTransform, MetricField, MetricMatcher, MetricTarget, MetricType, Policy as ProtoPolicy,
    SpanKind, TraceField, TraceMatcher, TraceSamplingConfig, TraceTarget, log_add, log_matcher,
    log_redact, log_remove, log_rename, metric_matcher, trace_matcher,
};
use policy_rs::{
    LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal, Policy,
    PolicyEngine, PolicyRegistry, TraceFieldSelector, TraceSignal, Transformable,
};
use std::borrow::Cow;
use std::collections::HashMap;
use tokio::runtime::Runtime;

fn attr_path(key: &str) -> AttributePath {
    AttributePath {
        path: vec![key.to_string()],
    }
}

// ==================== Log Benchmarks ====================

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
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => Some(Cow::Borrowed(&self.body)),
                LogField::SeverityText => Some(Cow::Borrowed(&self.severity)),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            _ => None,
        }
    }
}

impl Transformable for BenchLog {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        if let LogFieldSelector::LogAttribute(path) = field
            && let Some(key) = path.first()
        {
            self.attributes.insert(key.clone(), value.to_string());
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::LogAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.remove(key))
                .is_some(),
            _ => false,
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        if let LogFieldSelector::LogAttribute(path) = from
            && let Some(key) = path.first()
            && let Some(value) = self.attributes.remove(key)
            && let LogFieldSelector::LogAttribute(to_path) = to
            && let Some(to_key) = to_path.first()
        {
            self.attributes.insert(to_key.clone(), value);
        }
    }
}

fn create_policy(id: &str, field: log_matcher::Field, pattern: &str, keep: &str) -> Policy {
    let matcher = LogMatcher {
        field: Some(field),
        r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
        negate: false,
        case_insensitive: false,
    };

    let log_target = LogTarget {
        r#match: vec![matcher],
        keep: keep.to_string(),
        transform: None,
        sample_key: None,
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
        case_insensitive: false,
    };

    let log_target = LogTarget {
        r#match: vec![matcher],
        keep: keep.to_string(),
        transform: Some(transform),
        sample_key: None,
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
                _ => log_matcher::Field::LogAttribute(attr_path(field_name)),
            };
            LogMatcher {
                field: Some(field),
                r#match: Some(log_matcher::Match::Regex(pattern.to_string())),
                negate: false,
                case_insensitive: false,
            }
        })
        .collect();

    let log_target = LogTarget {
        r#match: matchers,
        keep: keep.to_string(),
        transform: None,
        sample_key: None,
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
                    field: Some(log_remove::Field::LogAttribute(attr_path("to_remove"))),
                }],
                ..Default::default()
            },
        ),
        (
            "redact",
            LogTransform {
                redact: vec![LogRedact {
                    field: Some(log_redact::Field::LogAttribute(attr_path("secret"))),
                    replacement: "[REDACTED]".to_string(),
                    regex: None,
                }],
                ..Default::default()
            },
        ),
        (
            "rename",
            LogTransform {
                rename: vec![LogRename {
                    from: Some(log_rename::From::FromLogAttribute(attr_path("old_key"))),
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
                    field: Some(log_add::Field::LogAttribute(attr_path("new_field"))),
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
                    field: Some(log_remove::Field::LogAttribute(attr_path(&format!(
                        "remove_{}",
                        i
                    )))),
                }),
                1 => transform.redact.push(LogRedact {
                    field: Some(log_redact::Field::LogAttribute(attr_path(&format!(
                        "redact_{}",
                        i
                    )))),
                    replacement: "[REDACTED]".to_string(),
                    regex: None,
                }),
                2 => transform.rename.push(LogRename {
                    from: Some(log_rename::From::FromLogAttribute(attr_path(&format!(
                        "rename_{}",
                        i
                    )))),
                    to: format!("renamed_{}", i),
                    upsert: true,
                }),
                _ => transform.add.push(LogAdd {
                    field: Some(log_add::Field::LogAttribute(attr_path(&format!(
                        "add_{}",
                        i
                    )))),
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
                        field: Some(log_redact::Field::LogAttribute(attr_path(&format!(
                            "secret_{}",
                            i
                        )))),
                        replacement: "[REDACTED]".to_string(),
                        regex: None,
                    }],
                    add: vec![LogAdd {
                        field: Some(log_add::Field::LogAttribute(attr_path(&format!(
                            "processed_{}",
                            i
                        )))),
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
            field: Some(log_redact::Field::LogAttribute(attr_path("password"))),
            replacement: "[REDACTED]".to_string(),
            regex: None,
        }],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute(attr_path("sanitized"))),
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
                field: Some(log_redact::Field::LogAttribute(attr_path("password"))),
                replacement: "[REDACTED]".to_string(),
                regex: None,
            },
            LogRedact {
                field: Some(log_redact::Field::LogAttribute(attr_path("api_key"))),
                replacement: "[REDACTED]".to_string(),
                regex: None,
            },
        ],
        remove: vec![LogRemove {
            field: Some(log_remove::Field::LogAttribute(attr_path("debug_info"))),
        }],
        add: vec![LogAdd {
            field: Some(log_add::Field::LogAttribute(attr_path("processed"))),
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

// ==================== Metric Benchmarks ====================

/// Test metric record for benchmarking.
struct BenchMetric {
    name: String,
    metric_type: Option<MetricType>,
    datapoint_attributes: HashMap<String, String>,
}

impl BenchMetric {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            metric_type: None,
            datapoint_attributes: HashMap::new(),
        }
    }

    fn with_type(mut self, t: MetricType) -> Self {
        self.metric_type = Some(t);
        self
    }

    fn with_datapoint_attr(mut self, key: &str, value: &str) -> Self {
        self.datapoint_attributes
            .insert(key.to_string(), value.to_string());
        self
    }
}

impl Matchable for BenchMetric {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(MetricField::Name) => Some(Cow::Borrowed(&self.name)),
            MetricFieldSelector::Simple(_) => None,
            MetricFieldSelector::DatapointAttribute(path) => path
                .first()
                .and_then(|key| self.datapoint_attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::Type => self
                .metric_type
                .as_ref()
                .map(|t| Cow::Borrowed(t.as_str_name())),
            _ => None,
        }
    }
}

fn create_metric_policy(
    id: &str,
    field: metric_matcher::Field,
    pattern: &str,
    keep: bool,
) -> Policy {
    let matcher = MetricMatcher {
        field: Some(field),
        r#match: Some(metric_matcher::Match::Regex(pattern.to_string())),
        negate: false,
        case_insensitive: false,
    };

    let metric_target = MetricTarget {
        r#match: vec![matcher],
        keep,
    };

    let proto = ProtoPolicy {
        id: id.to_string(),
        name: id.to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
            metric_target,
        )),
        ..Default::default()
    };

    Policy::new(proto)
}

fn bench_metric_evaluate_single_policy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![create_metric_policy(
        "drop-cpu",
        metric_matcher::Field::MetricField(MetricField::Name.into()),
        "cpu",
        false,
    )]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    let matching_metric = BenchMetric::new("cpu.usage").with_datapoint_attr("host", "prod-web-1");
    let non_matching_metric = BenchMetric::new("memory.usage");

    let mut group = c.benchmark_group("metric_single_policy");

    group.bench_function("matching", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(engine.evaluate(&snapshot, &matching_metric).await.unwrap())
        })
    });

    group.bench_function("non_matching", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                engine
                    .evaluate(&snapshot, &non_matching_metric)
                    .await
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_metric_evaluate_multiple_policies(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("metric_policy_count");

    for policy_count in [1, 10, 50, 100] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policies: Vec<Policy> = (0..policy_count)
            .map(|i| {
                create_metric_policy(
                    &format!("policy-{}", i),
                    metric_matcher::Field::MetricField(MetricField::Name.into()),
                    &format!("pattern{}", i),
                    false,
                )
            })
            .collect();
        handle.update(policies);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        // Metric that matches none of the policies
        let metric = BenchMetric::new("this.metric.matches.nothing");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("evaluate", policy_count),
            &policy_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    black_box(engine.evaluate(&snapshot, &metric).await.unwrap())
                })
            },
        );
    }

    group.finish();
}

fn bench_metric_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();

    // Create metric type matchers using the MetricType oneof field
    let gauge_matcher = MetricMatcher {
        field: Some(metric_matcher::Field::MetricType(MetricType::Gauge.into())),
        r#match: None,
        negate: false,
        case_insensitive: false,
    };
    let sum_matcher = MetricMatcher {
        field: Some(metric_matcher::Field::MetricType(MetricType::Sum.into())),
        r#match: None,
        negate: false,
        case_insensitive: false,
    };
    let histogram_matcher = MetricMatcher {
        field: Some(metric_matcher::Field::MetricType(
            MetricType::Histogram.into(),
        )),
        r#match: None,
        negate: false,
        case_insensitive: false,
    };

    let keep_gauges = {
        let proto = ProtoPolicy {
            id: "keep-gauges".to_string(),
            name: "keep-gauges".to_string(),
            enabled: true,
            target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
                MetricTarget {
                    r#match: vec![gauge_matcher],
                    keep: true,
                },
            )),
            ..Default::default()
        };
        Policy::new(proto)
    };
    let drop_sums = {
        let proto = ProtoPolicy {
            id: "drop-sums".to_string(),
            name: "drop-sums".to_string(),
            enabled: true,
            target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
                MetricTarget {
                    r#match: vec![sum_matcher],
                    keep: false,
                },
            )),
            ..Default::default()
        };
        Policy::new(proto)
    };
    let keep_histograms = {
        let proto = ProtoPolicy {
            id: "keep-histograms".to_string(),
            name: "keep-histograms".to_string(),
            enabled: true,
            target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Metric(
                MetricTarget {
                    r#match: vec![histogram_matcher],
                    keep: true,
                },
            )),
            ..Default::default()
        };
        Policy::new(proto)
    };

    handle.update(vec![keep_gauges, drop_sums, keep_histograms]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    // Create a batch of metrics
    let metrics: Vec<BenchMetric> = (0..1000)
        .map(|i| {
            let (name, metric_type) = match i % 3 {
                0 => ("cpu.usage", MetricType::Gauge),
                1 => ("requests.total", MetricType::Sum),
                _ => ("request.duration", MetricType::Histogram),
            };
            BenchMetric::new(name).with_type(metric_type)
        })
        .collect();

    let mut group = c.benchmark_group("metric_throughput");
    group.throughput(Throughput::Elements(metrics.len() as u64));

    group.bench_function("batch_1000", |b| {
        b.to_async(&rt).iter(|| async {
            for metric in &metrics {
                black_box(engine.evaluate(&snapshot, metric).await.unwrap());
            }
        })
    });

    group.finish();
}

// ==================== Trace Benchmarks ====================

/// Test span record for benchmarking.
struct BenchSpan {
    name: String,
    trace_id: String,
    tracestate: String,
    span_kind: Option<String>,
    span_status: Option<String>,
    attributes: HashMap<String, String>,
    th_value: Option<String>,
}

impl BenchSpan {
    fn new(name: &str, trace_id: &str) -> Self {
        Self {
            name: name.to_string(),
            trace_id: trace_id.to_string(),
            tracestate: String::new(),
            span_kind: None,
            span_status: None,
            attributes: HashMap::new(),
            th_value: None,
        }
    }

    fn with_span_kind(mut self, kind: &str) -> Self {
        self.span_kind = Some(kind.to_string());
        self
    }

    #[allow(dead_code)]
    fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

impl Matchable for BenchSpan {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(trace_field) => match trace_field {
                TraceField::Name => Some(Cow::Borrowed(&self.name)),
                TraceField::TraceId => Some(Cow::Borrowed(&self.trace_id)),
                TraceField::TraceState => {
                    if self.tracestate.is_empty() {
                        None
                    } else {
                        Some(Cow::Borrowed(&self.tracestate))
                    }
                }
                _ => None,
            },
            TraceFieldSelector::SpanAttribute(path) => path
                .first()
                .and_then(|key| self.attributes.get(key))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::SpanKind => self.span_kind.as_deref().map(Cow::Borrowed),
            TraceFieldSelector::SpanStatus => self.span_status.as_deref().map(Cow::Borrowed),
            _ => None,
        }
    }
}

impl Transformable for BenchSpan {
    fn set_field(&mut self, field: &TraceFieldSelector, value: &str) {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            self.th_value = Some(value.to_string());
        }
    }

    fn delete_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false
    }

    fn move_field(&mut self, _from: &TraceFieldSelector, _to: &TraceFieldSelector) {}
}

fn create_trace_policy(id: &str, field: trace_matcher::Field, percentage: f32) -> Policy {
    let matcher = TraceMatcher {
        field: Some(field),
        r#match: None,
        negate: false,
        case_insensitive: false,
    };

    let trace_target = TraceTarget {
        r#match: vec![matcher],
        keep: Some(TraceSamplingConfig {
            percentage,
            mode: None,
            sampling_precision: Some(4),
            hash_seed: None,
            fail_closed: Some(true),
        }),
    };

    let proto = ProtoPolicy {
        id: id.to_string(),
        name: id.to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Trace(
            trace_target,
        )),
        ..Default::default()
    };

    Policy::new(proto)
}

fn create_trace_policy_with_name_regex(id: &str, pattern: &str, percentage: f32) -> Policy {
    let matcher = TraceMatcher {
        field: Some(trace_matcher::Field::TraceField(TraceField::Name.into())),
        r#match: Some(trace_matcher::Match::Regex(pattern.to_string())),
        negate: false,
        case_insensitive: false,
    };

    let trace_target = TraceTarget {
        r#match: vec![matcher],
        keep: Some(TraceSamplingConfig {
            percentage,
            mode: None,
            sampling_precision: Some(4),
            hash_seed: None,
            fail_closed: Some(true),
        }),
    };

    let proto = ProtoPolicy {
        id: id.to_string(),
        name: id.to_string(),
        enabled: true,
        target: Some(policy_rs::proto::tero::policy::v1::policy::Target::Trace(
            trace_target,
        )),
        ..Default::default()
    };

    Policy::new(proto)
}

fn bench_trace_evaluate_single_policy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![create_trace_policy(
        "sample-server",
        trace_matcher::Field::SpanKind(SpanKind::Server.into()),
        50.0,
    )]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    let mut group = c.benchmark_group("trace_single_policy");

    group.bench_function("matching", |b| {
        b.to_async(&rt).iter(|| async {
            let mut span = BenchSpan::new("GET /api", "00000000000000000000000000000001")
                .with_span_kind("SPAN_KIND_SERVER");
            black_box(engine.evaluate_trace(&snapshot, &mut span).await.unwrap())
        })
    });

    group.bench_function("non_matching", |b| {
        b.to_async(&rt).iter(|| async {
            let mut span = BenchSpan::new("internal-task", "00000000000000000000000000000001")
                .with_span_kind("SPAN_KIND_INTERNAL");
            black_box(engine.evaluate_trace(&snapshot, &mut span).await.unwrap())
        })
    });

    group.finish();
}

fn bench_trace_evaluate_multiple_policies(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("trace_policy_count");

    for policy_count in [1, 10, 50, 100] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policies: Vec<Policy> = (0..policy_count)
            .map(|i| {
                create_trace_policy_with_name_regex(
                    &format!("policy-{}", i),
                    &format!("pattern{}", i),
                    50.0,
                )
            })
            .collect();
        handle.update(policies);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("evaluate", policy_count),
            &policy_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let mut span =
                        BenchSpan::new("no-match-span", "00000000000000000000000000000001");
                    black_box(engine.evaluate_trace(&snapshot, &mut span).await.unwrap())
                })
            },
        );
    }

    group.finish();
}

fn bench_trace_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let registry = PolicyRegistry::new();
    let handle = registry.register_provider();
    handle.update(vec![
        create_trace_policy(
            "sample-server",
            trace_matcher::Field::SpanKind(SpanKind::Server.into()),
            50.0,
        ),
        create_trace_policy(
            "sample-client",
            trace_matcher::Field::SpanKind(SpanKind::Client.into()),
            75.0,
        ),
        create_trace_policy(
            "keep-consumer",
            trace_matcher::Field::SpanKind(SpanKind::Consumer.into()),
            100.0,
        ),
    ]);

    let snapshot = registry.snapshot();
    let engine = PolicyEngine::new();

    let mut group = c.benchmark_group("trace_throughput");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("batch_1000", |b| {
        b.to_async(&rt).iter(|| async {
            for i in 0..1000u64 {
                let kind = match i % 3 {
                    0 => "SPAN_KIND_SERVER",
                    1 => "SPAN_KIND_CLIENT",
                    _ => "SPAN_KIND_CONSUMER",
                };
                let trace_id = format!("{:032x}", i);
                let mut span = BenchSpan::new("span-op", &trace_id).with_span_kind(kind);
                black_box(engine.evaluate_trace(&snapshot, &mut span).await.unwrap());
            }
        })
    });

    group.finish();
}

fn bench_trace_sampling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("trace_sampling");

    for percentage in [1.0f32, 10.0, 50.0, 99.0, 100.0] {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![create_trace_policy_with_name_regex(
            "sample-all",
            ".+",
            percentage,
        )]);

        let snapshot = registry.snapshot();
        let engine = PolicyEngine::new();

        group.bench_with_input(
            BenchmarkId::new("percentage", format!("{}", percentage)),
            &percentage,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let mut span = BenchSpan::new("test-span", "00000000000000000000000000000001");
                    black_box(engine.evaluate_trace(&snapshot, &mut span).await.unwrap())
                })
            },
        );
    }

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
    bench_metric_evaluate_single_policy,
    bench_metric_evaluate_multiple_policies,
    bench_metric_throughput,
    bench_trace_evaluate_single_policy,
    bench_trace_evaluate_multiple_policies,
    bench_trace_throughput,
    bench_trace_sampling,
);

criterion_main!(benches);
