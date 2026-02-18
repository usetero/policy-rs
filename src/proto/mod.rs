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
}
