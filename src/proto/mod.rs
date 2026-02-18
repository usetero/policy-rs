#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

pub mod google {
    pub mod api {
        include!("google.api.rs");
        include!("google.api.serde.rs");
    }
}

pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!("opentelemetry.proto.common.v1.rs");
                include!("opentelemetry.proto.common.v1.serde.rs");
            }
        }
    }
}

pub mod tero {
    pub mod policy {
        pub mod v1 {
            include!("tero.policy.v1.rs");
            include!("tero.policy.v1.serde.rs");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tero::policy::v1::*;

    // ==================== Enum fields inside oneofs serialize as string names ====================
    // This was the core bug in ENG-198: enum fields inside oneofs (e.g. LogMatcher.field = LogField)
    // were serialized as i32 integers instead of proto3 JSON string names.

    #[test]
    fn log_matcher_enum_field_serializes_as_string() {
        let matcher = LogMatcher {
            field: Some(log_matcher::Field::LogField(LogField::Body as i32)),
            r#match: Some(log_matcher::Match::Exact("hello".to_string())),
            ..Default::default()
        };
        let json = serde_json::to_value(&matcher).unwrap();
        assert_eq!(json["logField"], "LOG_FIELD_BODY");
        assert_eq!(json["exact"], "hello");
    }

    #[test]
    fn log_matcher_enum_field_deserializes_from_string() {
        let json = serde_json::json!({
            "logField": "LOG_FIELD_SEVERITY_TEXT",
            "regex": "ERROR|WARN"
        });
        let matcher: LogMatcher = serde_json::from_value(json).unwrap();
        assert_eq!(
            matcher.field,
            Some(log_matcher::Field::LogField(LogField::SeverityText as i32))
        );
        assert_eq!(
            matcher.r#match,
            Some(log_matcher::Match::Regex("ERROR|WARN".to_string()))
        );
    }

    #[test]
    fn metric_matcher_enum_field_serializes_as_string() {
        let matcher = MetricMatcher {
            field: Some(metric_matcher::Field::MetricField(MetricField::Name as i32)),
            r#match: Some(metric_matcher::Match::StartsWith("cpu.".to_string())),
            ..Default::default()
        };
        let json = serde_json::to_value(&matcher).unwrap();
        assert_eq!(json["metricField"], "METRIC_FIELD_NAME");
        assert_eq!(json["startsWith"], "cpu.");
    }

    #[test]
    fn metric_matcher_type_field_serializes_as_string() {
        let matcher = MetricMatcher {
            field: Some(metric_matcher::Field::MetricType(
                MetricType::Histogram as i32,
            )),
            r#match: Some(metric_matcher::Match::Exists(true)),
            ..Default::default()
        };
        let json = serde_json::to_value(&matcher).unwrap();
        assert_eq!(json["metricType"], "METRIC_TYPE_HISTOGRAM");
    }

    #[test]
    fn metric_matcher_aggregation_temporality_serializes_as_string() {
        let matcher = MetricMatcher {
            field: Some(metric_matcher::Field::AggregationTemporality(
                AggregationTemporality::Delta as i32,
            )),
            r#match: Some(metric_matcher::Match::Exists(true)),
            ..Default::default()
        };
        let json = serde_json::to_value(&matcher).unwrap();
        assert_eq!(
            json["aggregationTemporality"],
            "AGGREGATION_TEMPORALITY_DELTA"
        );
    }

    #[test]
    fn trace_matcher_span_kind_serializes_as_string() {
        let matcher = TraceMatcher {
            field: Some(trace_matcher::Field::SpanKind(SpanKind::Server as i32)),
            r#match: Some(trace_matcher::Match::Exists(true)),
            ..Default::default()
        };
        let json = serde_json::to_value(&matcher).unwrap();
        assert_eq!(json["spanKind"], "SPAN_KIND_SERVER");
    }

    // ==================== 64-bit integers serialize as strings ====================

    #[test]
    fn u64_fields_serialize_as_strings() {
        let policy = Policy {
            id: "p1".to_string(),
            name: "test".to_string(),
            enabled: true,
            created_at_unix_nano: 1700000000000000000,
            modified_at_unix_nano: 1700000000000000001,
            ..Default::default()
        };
        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json["createdAtUnixNano"], "1700000000000000000");
        assert_eq!(json["modifiedAtUnixNano"], "1700000000000000001");
    }

    #[test]
    fn u64_fields_deserialize_from_strings() {
        let json = serde_json::json!({
            "id": "p1",
            "name": "test",
            "enabled": true,
            "createdAtUnixNano": "1700000000000000000",
            "modifiedAtUnixNano": "1700000000000000001"
        });
        let policy: Policy = serde_json::from_value(json).unwrap();
        assert_eq!(policy.created_at_unix_nano, 1700000000000000000);
        assert_eq!(policy.modified_at_unix_nano, 1700000000000000001);
    }

    #[test]
    fn i64_fields_serialize_as_strings() {
        let status = PolicySyncStatus {
            id: "p1".to_string(),
            match_hits: 42,
            match_misses: 100,
            ..Default::default()
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["matchHits"], "42");
        assert_eq!(json["matchMisses"], "100");
    }

    // ==================== Standalone enum fields serialize as string names ====================

    #[test]
    fn sync_type_serializes_as_string() {
        let response = SyncResponse {
            hash: "abc".to_string(),
            sync_type: SyncType::Full as i32,
            sync_timestamp_unix_nano: 1700000000000000000,
            ..Default::default()
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["syncType"], "SYNC_TYPE_FULL");
    }

    #[test]
    fn sync_type_deserializes_from_string() {
        let json = serde_json::json!({
            "syncType": "SYNC_TYPE_FULL",
            "hash": "abc",
            "syncTimestampUnixNano": "1700000000000000000"
        });
        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.sync_type, SyncType::Full as i32);
    }

    // ==================== Oneof fields are flattened ====================

    #[test]
    fn policy_target_oneof_is_flattened() {
        let policy = Policy {
            id: "p1".to_string(),
            name: "log policy".to_string(),
            enabled: true,
            target: Some(policy::Target::Log(LogTarget {
                keep: "all".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let json = serde_json::to_value(&policy).unwrap();
        // The "log" key should be at the top level, not nested under "target"
        assert!(
            json.get("target").is_none(),
            "target should not appear as a key"
        );
        assert!(json.get("log").is_some(), "log should be a top-level key");
    }

    #[test]
    fn policy_target_oneof_deserializes_from_flattened() {
        let json = serde_json::json!({
            "id": "p1",
            "name": "metric policy",
            "enabled": true,
            "metric": {
                "keep": true
            }
        });
        let policy: Policy = serde_json::from_value(json).unwrap();
        assert!(matches!(policy.target, Some(policy::Target::Metric(_))));
    }

    // ==================== camelCase field names ====================

    #[test]
    fn fields_use_camel_case() {
        let request = SyncRequest {
            full_sync: true,
            last_sync_timestamp_unix_nano: 123,
            last_successful_hash: "h".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("fullSync").is_some());
        assert!(json.get("lastSyncTimestampUnixNano").is_some());
        assert!(json.get("lastSuccessfulHash").is_some());
        // snake_case keys should not be present
        assert!(json.get("full_sync").is_none());
        assert!(json.get("last_sync_timestamp_unix_nano").is_none());
    }

    // ==================== Full round-trip ====================

    #[test]
    fn sync_response_round_trip() {
        let response = SyncResponse {
            policies: vec![Policy {
                id: "p1".to_string(),
                name: "Drop debug logs".to_string(),
                enabled: true,
                created_at_unix_nano: 1700000000000000000,
                target: Some(policy::Target::Log(LogTarget {
                    r#match: vec![LogMatcher {
                        field: Some(log_matcher::Field::LogField(LogField::SeverityText as i32)),
                        r#match: Some(log_matcher::Match::Exact("DEBUG".to_string())),
                        ..Default::default()
                    }],
                    keep: "none".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            hash: "abc123".to_string(),
            sync_timestamp_unix_nano: 1700000000000000000,
            recommended_sync_interval_seconds: 30,
            sync_type: SyncType::Full as i32,
            ..Default::default()
        };

        let json_str = serde_json::to_string(&response).unwrap();
        let deserialized: SyncResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(response, deserialized);
    }

    #[test]
    fn sync_response_deserializes_from_proto3_json() {
        let json = serde_json::json!({
            "policies": [{
                "id": "p1",
                "name": "Match metric",
                "enabled": true,
                "metric": {
                    "match": [{
                        "metricField": "METRIC_FIELD_NAME",
                        "exact": "http.request.duration"
                    }],
                    "keep": true
                }
            }],
            "hash": "def456",
            "syncTimestampUnixNano": "1700000000000000000",
            "recommendedSyncIntervalSeconds": 60,
            "syncType": "SYNC_TYPE_FULL"
        });
        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.policies.len(), 1);
        assert_eq!(response.policies[0].id, "p1");
        assert_eq!(response.sync_type, SyncType::Full as i32);
        assert_eq!(response.sync_timestamp_unix_nano, 1700000000000000000);

        // Verify the metric matcher field deserialized as the enum value
        if let Some(policy::Target::Metric(metric)) = &response.policies[0].target {
            assert_eq!(metric.r#match.len(), 1);
            assert_eq!(
                metric.r#match[0].field,
                Some(metric_matcher::Field::MetricField(MetricField::Name as i32))
            );
        } else {
            panic!("expected metric target");
        }
    }

    // ==================== Go protojson server realistic payloads ====================
    // These tests simulate what a Go server using protojson.MarshalOptions{EmitDefaultValues: true}
    // would emit. This is the format the HTTP provider must handle.

    #[test]
    fn deserialize_go_server_response_with_default_values() {
        // Go's protojson with EmitDefaultValues emits zero-value fields explicitly.
        let json = serde_json::json!({
            "policies": [],
            "hash": "",
            "errorMessage": "",
            "syncTimestampUnixNano": "0",
            "recommendedSyncIntervalSeconds": 0,
            "syncType": "SYNC_TYPE_UNSPECIFIED"
        });
        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert!(response.policies.is_empty());
        assert_eq!(response.hash, "");
        assert_eq!(response.error_message, "");
        assert_eq!(response.sync_timestamp_unix_nano, 0);
        assert_eq!(response.recommended_sync_interval_seconds, 0);
        assert_eq!(response.sync_type, SyncType::Unspecified as i32);
    }

    #[test]
    fn deserialize_go_server_log_policy_with_attribute_matchers() {
        // Realistic Go server response with log attribute matchers.
        let json = serde_json::json!({
            "policies": [{
                "id": "drop-nginx-debug",
                "name": "Drop nginx debug logs",
                "description": "Filters out debug-level logs from nginx services",
                "enabled": true,
                "createdAtUnixNano": "1700000000000000000",
                "modifiedAtUnixNano": "1700000000000000000",
                "labels": [],
                "log": {
                    "match": [
                        {
                            "logField": "LOG_FIELD_SEVERITY_TEXT",
                            "exact": "DEBUG",
                            "negate": false,
                            "caseInsensitive": true
                        },
                        {
                            "resourceAttribute": {"path": ["service", "name"]},
                            "regex": "nginx-.*",
                            "negate": false,
                            "caseInsensitive": false
                        }
                    ],
                    "keep": "none"
                }
            }],
            "hash": "abc123",
            "errorMessage": "",
            "syncTimestampUnixNano": "1700000000000000000",
            "recommendedSyncIntervalSeconds": 30,
            "syncType": "SYNC_TYPE_FULL"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.policies.len(), 1);

        let policy = &response.policies[0];
        assert_eq!(policy.id, "drop-nginx-debug");
        assert_eq!(
            policy.description,
            "Filters out debug-level logs from nginx services"
        );
        assert!(policy.enabled);
        assert_eq!(policy.created_at_unix_nano, 1700000000000000000);

        let log = match &policy.target {
            Some(policy::Target::Log(log)) => log,
            _ => panic!("expected log target"),
        };
        assert_eq!(log.keep, "none");
        assert_eq!(log.r#match.len(), 2);

        // First matcher: logField enum oneof + exact match
        let m0 = &log.r#match[0];
        assert_eq!(
            m0.field,
            Some(log_matcher::Field::LogField(LogField::SeverityText as i32))
        );
        assert_eq!(
            m0.r#match,
            Some(log_matcher::Match::Exact("DEBUG".to_string()))
        );
        assert!(!m0.negate);
        assert!(m0.case_insensitive);

        // Second matcher: resourceAttribute message oneof + regex match
        let m1 = &log.r#match[1];
        match &m1.field {
            Some(log_matcher::Field::ResourceAttribute(attr)) => {
                assert_eq!(attr.path, vec!["service", "name"]);
            }
            other => panic!("expected ResourceAttribute, got {:?}", other),
        }
        assert_eq!(
            m1.r#match,
            Some(log_matcher::Match::Regex("nginx-.*".to_string()))
        );
    }

    #[test]
    fn deserialize_go_server_metric_policy_with_type_and_temporality() {
        // Metric policy that matches by metric type and aggregation temporality —
        // these are enum-valued oneof variants, not MetricField enum values.
        let json = serde_json::json!({
            "policies": [
                {
                    "id": "drop-delta-histograms",
                    "name": "Drop delta histograms",
                    "description": "",
                    "enabled": true,
                    "createdAtUnixNano": "0",
                    "modifiedAtUnixNano": "0",
                    "labels": [],
                    "metric": {
                        "match": [
                            {
                                "metricType": "METRIC_TYPE_HISTOGRAM",
                                "exists": true,
                                "negate": false,
                                "caseInsensitive": false
                            },
                            {
                                "aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA",
                                "exists": true,
                                "negate": false,
                                "caseInsensitive": false
                            }
                        ],
                        "keep": false
                    }
                },
                {
                    "id": "keep-cpu-metrics",
                    "name": "Keep CPU metrics",
                    "description": "",
                    "enabled": true,
                    "createdAtUnixNano": "0",
                    "modifiedAtUnixNano": "0",
                    "labels": [],
                    "metric": {
                        "match": [
                            {
                                "metricField": "METRIC_FIELD_NAME",
                                "startsWith": "system.cpu.",
                                "negate": false,
                                "caseInsensitive": false
                            }
                        ],
                        "keep": true
                    }
                }
            ],
            "hash": "metrics-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "1700000000000000000",
            "recommendedSyncIntervalSeconds": 60,
            "syncType": "SYNC_TYPE_FULL"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.policies.len(), 2);

        // First policy: metric type + aggregation temporality
        let p0 = &response.policies[0];
        let metric0 = match &p0.target {
            Some(policy::Target::Metric(m)) => m,
            _ => panic!("expected metric target for policy 0"),
        };
        assert!(!metric0.keep);
        assert_eq!(metric0.r#match.len(), 2);
        assert_eq!(
            metric0.r#match[0].field,
            Some(metric_matcher::Field::MetricType(
                MetricType::Histogram as i32
            ))
        );
        assert_eq!(
            metric0.r#match[1].field,
            Some(metric_matcher::Field::AggregationTemporality(
                AggregationTemporality::Delta as i32
            ))
        );

        // Second policy: metricField enum + startsWith
        let p1 = &response.policies[1];
        let metric1 = match &p1.target {
            Some(policy::Target::Metric(m)) => m,
            _ => panic!("expected metric target for policy 1"),
        };
        assert!(metric1.keep);
        assert_eq!(
            metric1.r#match[0].field,
            Some(metric_matcher::Field::MetricField(MetricField::Name as i32))
        );
        assert_eq!(
            metric1.r#match[0].r#match,
            Some(metric_matcher::Match::StartsWith("system.cpu.".to_string()))
        );
    }

    #[test]
    fn deserialize_go_server_trace_policy() {
        let json = serde_json::json!({
            "policies": [{
                "id": "sample-server-spans",
                "name": "Sample server spans",
                "description": "",
                "enabled": true,
                "createdAtUnixNano": "0",
                "modifiedAtUnixNano": "0",
                "labels": [],
                "trace": {
                    "match": [
                        {
                            "spanKind": "SPAN_KIND_SERVER",
                            "exists": true,
                            "negate": false,
                            "caseInsensitive": false
                        },
                        {
                            "traceField": "TRACE_FIELD_NAME",
                            "regex": "GET /api/.*",
                            "negate": false,
                            "caseInsensitive": false
                        },
                        {
                            "spanAttribute": {"path": ["http", "method"]},
                            "exact": "GET",
                            "negate": false,
                            "caseInsensitive": false
                        }
                    ],
                    "keep": {
                        "percentage": 10.5,
                        "mode": "SAMPLING_MODE_HASH_SEED",
                        "samplingPrecision": 4,
                        "hashSeed": 42,
                        "failClosed": true
                    }
                }
            }],
            "hash": "trace-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "1700000000000000000",
            "recommendedSyncIntervalSeconds": 30,
            "syncType": "SYNC_TYPE_FULL"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.policies.len(), 1);

        let policy = &response.policies[0];
        let trace = match &policy.target {
            Some(policy::Target::Trace(t)) => t,
            _ => panic!("expected trace target"),
        };

        assert_eq!(trace.r#match.len(), 3);

        // spanKind enum oneof
        assert_eq!(
            trace.r#match[0].field,
            Some(trace_matcher::Field::SpanKind(SpanKind::Server as i32))
        );

        // traceField enum oneof
        assert_eq!(
            trace.r#match[1].field,
            Some(trace_matcher::Field::TraceField(TraceField::Name as i32))
        );
        assert_eq!(
            trace.r#match[1].r#match,
            Some(trace_matcher::Match::Regex("GET /api/.*".to_string()))
        );

        // spanAttribute message oneof
        match &trace.r#match[2].field {
            Some(trace_matcher::Field::SpanAttribute(attr)) => {
                assert_eq!(attr.path, vec!["http", "method"]);
            }
            other => panic!("expected SpanAttribute, got {:?}", other),
        }

        // Sampling config
        let keep = trace.keep.as_ref().unwrap();
        assert!((keep.percentage - 10.5).abs() < f32::EPSILON);
        assert_eq!(keep.mode, Some(SamplingMode::HashSeed as i32));
        assert_eq!(keep.sampling_precision, Some(4));
        assert_eq!(keep.hash_seed, Some(42));
        assert_eq!(keep.fail_closed, Some(true));
    }

    #[test]
    fn deserialize_go_server_log_policy_with_sample_key() {
        let json = serde_json::json!({
            "policies": [{
                "id": "sample-by-trace",
                "name": "Sample logs by trace ID",
                "description": "",
                "enabled": true,
                "createdAtUnixNano": "0",
                "modifiedAtUnixNano": "0",
                "labels": [],
                "log": {
                    "match": [{
                        "logField": "LOG_FIELD_BODY",
                        "regex": ".*",
                        "negate": false,
                        "caseInsensitive": false
                    }],
                    "keep": "50%",
                    "sampleKey": {
                        "logField": "LOG_FIELD_TRACE_ID"
                    }
                }
            }],
            "hash": "sk-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "0",
            "recommendedSyncIntervalSeconds": 0,
            "syncType": "SYNC_TYPE_UNSPECIFIED"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        let log = match &response.policies[0].target {
            Some(policy::Target::Log(l)) => l,
            _ => panic!("expected log target"),
        };
        assert_eq!(log.keep, "50%");

        let sample_key = log.sample_key.as_ref().unwrap();
        assert_eq!(
            sample_key.field,
            Some(log_sample_key::Field::LogField(LogField::TraceId as i32))
        );
    }

    #[test]
    fn deserialize_go_server_log_policy_with_attribute_sample_key() {
        let json = serde_json::json!({
            "policies": [{
                "id": "sample-by-request-id",
                "name": "Sample logs by request ID",
                "description": "",
                "enabled": true,
                "createdAtUnixNano": "0",
                "modifiedAtUnixNano": "0",
                "labels": [],
                "log": {
                    "match": [{
                        "logField": "LOG_FIELD_BODY",
                        "regex": ".*",
                        "negate": false,
                        "caseInsensitive": false
                    }],
                    "keep": "25%",
                    "sampleKey": {
                        "logAttribute": {"path": ["request_id"]}
                    }
                }
            }],
            "hash": "sk2-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "0",
            "recommendedSyncIntervalSeconds": 0,
            "syncType": "SYNC_TYPE_UNSPECIFIED"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        let log = match &response.policies[0].target {
            Some(policy::Target::Log(l)) => l,
            _ => panic!("expected log target"),
        };

        let sample_key = log.sample_key.as_ref().unwrap();
        match &sample_key.field {
            Some(log_sample_key::Field::LogAttribute(attr)) => {
                assert_eq!(attr.path, vec!["request_id"]);
            }
            other => panic!("expected LogAttribute, got {:?}", other),
        }
    }

    #[test]
    fn deserialize_go_server_mixed_signal_response() {
        // A response containing log, metric, and trace policies together.
        let json = serde_json::json!({
            "policies": [
                {
                    "id": "log-policy",
                    "name": "Log policy",
                    "description": "",
                    "enabled": true,
                    "createdAtUnixNano": "0",
                    "modifiedAtUnixNano": "0",
                    "labels": [],
                    "log": {
                        "match": [{
                            "logField": "LOG_FIELD_BODY",
                            "contains": "error",
                            "negate": false,
                            "caseInsensitive": false
                        }],
                        "keep": "all"
                    }
                },
                {
                    "id": "metric-policy",
                    "name": "Metric policy",
                    "description": "",
                    "enabled": true,
                    "createdAtUnixNano": "0",
                    "modifiedAtUnixNano": "0",
                    "labels": [],
                    "metric": {
                        "match": [{
                            "metricField": "METRIC_FIELD_NAME",
                            "exact": "http.duration",
                            "negate": false,
                            "caseInsensitive": false
                        }],
                        "keep": true
                    }
                },
                {
                    "id": "trace-policy",
                    "name": "Trace policy",
                    "description": "",
                    "enabled": true,
                    "createdAtUnixNano": "0",
                    "modifiedAtUnixNano": "0",
                    "labels": [],
                    "trace": {
                        "match": [{
                            "traceField": "TRACE_FIELD_NAME",
                            "exact": "my-span",
                            "negate": false,
                            "caseInsensitive": false
                        }],
                        "keep": {
                            "percentage": 100.0
                        }
                    }
                }
            ],
            "hash": "mixed-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "1700000000000000000",
            "recommendedSyncIntervalSeconds": 30,
            "syncType": "SYNC_TYPE_FULL"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.policies.len(), 3);

        assert!(matches!(
            response.policies[0].target,
            Some(policy::Target::Log(_))
        ));
        assert!(matches!(
            response.policies[1].target,
            Some(policy::Target::Metric(_))
        ));
        assert!(matches!(
            response.policies[2].target,
            Some(policy::Target::Trace(_))
        ));
    }

    #[test]
    fn deserialize_go_server_negate_matcher() {
        let json = serde_json::json!({
            "logField": "LOG_FIELD_BODY",
            "regex": "health_?check",
            "negate": true,
            "caseInsensitive": true
        });
        let matcher: LogMatcher = serde_json::from_value(json).unwrap();
        assert!(matcher.negate);
        assert!(matcher.case_insensitive);
        assert_eq!(
            matcher.field,
            Some(log_matcher::Field::LogField(LogField::Body as i32))
        );
        assert_eq!(
            matcher.r#match,
            Some(log_matcher::Match::Regex("health_?check".to_string()))
        );
    }

    #[test]
    fn sync_request_serializes_for_go_server() {
        // Verify the SyncRequest we serialize matches what a Go protojson server expects.
        let request = SyncRequest {
            client_metadata: Some(ClientMetadata {
                supported_policy_stages: vec![],
                labels: vec![],
                resource_attributes: vec![],
            }),
            full_sync: true,
            last_sync_timestamp_unix_nano: 1700000000000000000,
            last_successful_hash: "prev-hash".to_string(),
            policy_statuses: vec![PolicySyncStatus {
                id: "p1".to_string(),
                match_hits: 100,
                match_misses: 50,
                ..Default::default()
            }],
        };

        let json = serde_json::to_value(&request).unwrap();

        // camelCase field names
        assert!(json.get("clientMetadata").is_some());
        assert!(json.get("fullSync").is_some());
        assert!(json.get("lastSyncTimestampUnixNano").is_some());
        assert!(json.get("lastSuccessfulHash").is_some());
        assert!(json.get("policyStatuses").is_some());

        // No snake_case leaking through
        assert!(json.get("client_metadata").is_none());
        assert!(json.get("full_sync").is_none());
        assert!(json.get("last_sync_timestamp_unix_nano").is_none());
        assert!(json.get("policy_statuses").is_none());

        // u64 encoded as string
        assert_eq!(json["lastSyncTimestampUnixNano"], "1700000000000000000");

        // i64 in policy statuses encoded as strings
        let status = &json["policyStatuses"][0];
        assert_eq!(status["matchHits"], "100");
        assert_eq!(status["matchMisses"], "50");

        // Verify round-trip: a Go server would deserialize our JSON and send it back
        let roundtripped: SyncRequest = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped, request);
    }

    #[test]
    fn deserialize_go_server_response_with_labels() {
        // Policies can have KeyValue labels; Go emits them with the OTel common.v1 format.
        let json = serde_json::json!({
            "policies": [{
                "id": "labeled-policy",
                "name": "Labeled policy",
                "description": "",
                "enabled": true,
                "createdAtUnixNano": "0",
                "modifiedAtUnixNano": "0",
                "labels": [
                    {"key": "team", "value": {"stringValue": "platform"}},
                    {"key": "tier", "value": {"stringValue": "production"}}
                ],
                "log": {
                    "match": [{
                        "logField": "LOG_FIELD_BODY",
                        "regex": ".*",
                        "negate": false,
                        "caseInsensitive": false
                    }],
                    "keep": "all"
                }
            }],
            "hash": "label-hash",
            "errorMessage": "",
            "syncTimestampUnixNano": "0",
            "recommendedSyncIntervalSeconds": 0,
            "syncType": "SYNC_TYPE_UNSPECIFIED"
        });

        let response: SyncResponse = serde_json::from_value(json).unwrap();
        let policy = &response.policies[0];
        assert_eq!(policy.labels.len(), 2);
        assert_eq!(policy.labels[0].key, "team");
        assert_eq!(policy.labels[1].key, "tier");
    }

    #[test]
    fn deserialize_go_server_metric_datapoint_attribute() {
        let json = serde_json::json!({
            "datapointAttribute": {"path": ["host", "name"]},
            "exact": "prod-web-01",
            "negate": false,
            "caseInsensitive": false
        });
        let matcher: MetricMatcher = serde_json::from_value(json).unwrap();
        match &matcher.field {
            Some(metric_matcher::Field::DatapointAttribute(attr)) => {
                assert_eq!(attr.path, vec!["host", "name"]);
            }
            other => panic!("expected DatapointAttribute, got {:?}", other),
        }
        assert_eq!(
            matcher.r#match,
            Some(metric_matcher::Match::Exact("prod-web-01".to_string()))
        );
    }

    #[test]
    fn deserialize_go_server_trace_event_and_link_fields() {
        // Trace matchers can match on event names, event attributes, and link trace IDs.
        let event_name_json = serde_json::json!({
            "eventName": "exception",
            "exact": "exception",
            "negate": false,
            "caseInsensitive": false
        });
        let matcher: TraceMatcher = serde_json::from_value(event_name_json).unwrap();
        assert_eq!(
            matcher.field,
            Some(trace_matcher::Field::EventName("exception".to_string()))
        );

        let link_json = serde_json::json!({
            "linkTraceId": "abc123",
            "exact": "abc123",
            "negate": false,
            "caseInsensitive": false
        });
        let matcher: TraceMatcher = serde_json::from_value(link_json).unwrap();
        assert_eq!(
            matcher.field,
            Some(trace_matcher::Field::LinkTraceId("abc123".to_string()))
        );

        let event_attr_json = serde_json::json!({
            "eventAttribute": {"path": ["exception", "type"]},
            "exact": "NullPointerException",
            "negate": false,
            "caseInsensitive": false
        });
        let matcher: TraceMatcher = serde_json::from_value(event_attr_json).unwrap();
        match &matcher.field {
            Some(trace_matcher::Field::EventAttribute(attr)) => {
                assert_eq!(attr.path, vec!["exception", "type"]);
            }
            other => panic!("expected EventAttribute, got {:?}", other),
        }
    }

    #[test]
    fn deserialize_go_server_span_status_matcher() {
        let json = serde_json::json!({
            "spanStatus": "SPAN_STATUS_CODE_ERROR",
            "exists": true,
            "negate": false,
            "caseInsensitive": false
        });
        let matcher: TraceMatcher = serde_json::from_value(json).unwrap();
        assert_eq!(
            matcher.field,
            Some(trace_matcher::Field::SpanStatus(
                SpanStatusCode::Error as i32
            ))
        );
    }

    #[test]
    fn deserialize_all_log_field_variants() {
        let fields = [
            ("LOG_FIELD_BODY", LogField::Body),
            ("LOG_FIELD_SEVERITY_TEXT", LogField::SeverityText),
            ("LOG_FIELD_TRACE_ID", LogField::TraceId),
            ("LOG_FIELD_SPAN_ID", LogField::SpanId),
            ("LOG_FIELD_EVENT_NAME", LogField::EventName),
            ("LOG_FIELD_RESOURCE_SCHEMA_URL", LogField::ResourceSchemaUrl),
            ("LOG_FIELD_SCOPE_SCHEMA_URL", LogField::ScopeSchemaUrl),
        ];
        for (name, expected) in fields {
            let json = serde_json::json!({
                "logField": name,
                "exists": true
            });
            let matcher: LogMatcher = serde_json::from_value(json).unwrap();
            assert_eq!(
                matcher.field,
                Some(log_matcher::Field::LogField(expected as i32)),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn deserialize_all_metric_field_variants() {
        let fields = [
            ("METRIC_FIELD_NAME", MetricField::Name),
            ("METRIC_FIELD_DESCRIPTION", MetricField::Description),
            ("METRIC_FIELD_UNIT", MetricField::Unit),
            (
                "METRIC_FIELD_RESOURCE_SCHEMA_URL",
                MetricField::ResourceSchemaUrl,
            ),
            ("METRIC_FIELD_SCOPE_SCHEMA_URL", MetricField::ScopeSchemaUrl),
            ("METRIC_FIELD_SCOPE_NAME", MetricField::ScopeName),
            ("METRIC_FIELD_SCOPE_VERSION", MetricField::ScopeVersion),
        ];
        for (name, expected) in fields {
            let json = serde_json::json!({
                "metricField": name,
                "exact": "test"
            });
            let matcher: MetricMatcher = serde_json::from_value(json).unwrap();
            assert_eq!(
                matcher.field,
                Some(metric_matcher::Field::MetricField(expected as i32)),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn deserialize_all_metric_type_variants() {
        let types = [
            ("METRIC_TYPE_GAUGE", MetricType::Gauge),
            ("METRIC_TYPE_SUM", MetricType::Sum),
            ("METRIC_TYPE_HISTOGRAM", MetricType::Histogram),
            (
                "METRIC_TYPE_EXPONENTIAL_HISTOGRAM",
                MetricType::ExponentialHistogram,
            ),
            ("METRIC_TYPE_SUMMARY", MetricType::Summary),
        ];
        for (name, expected) in types {
            let json = serde_json::json!({
                "metricType": name,
                "exists": true
            });
            let matcher: MetricMatcher = serde_json::from_value(json).unwrap();
            assert_eq!(
                matcher.field,
                Some(metric_matcher::Field::MetricType(expected as i32)),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn deserialize_all_match_type_variants_on_log_matcher() {
        let cases: Vec<(serde_json::Value, log_matcher::Match)> = vec![
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "exact": "foo"}),
                log_matcher::Match::Exact("foo".to_string()),
            ),
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "regex": "fo+"}),
                log_matcher::Match::Regex("fo+".to_string()),
            ),
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "exists": true}),
                log_matcher::Match::Exists(true),
            ),
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "startsWith": "foo"}),
                log_matcher::Match::StartsWith("foo".to_string()),
            ),
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "endsWith": "bar"}),
                log_matcher::Match::EndsWith("bar".to_string()),
            ),
            (
                serde_json::json!({"logField": "LOG_FIELD_BODY", "contains": "baz"}),
                log_matcher::Match::Contains("baz".to_string()),
            ),
        ];
        for (json, expected_match) in cases {
            let matcher: LogMatcher = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(matcher.r#match, Some(expected_match), "failed for {json}");
        }
    }
}
