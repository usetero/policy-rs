//! File-based policy provider.
//!
//! This module provides a policy provider that loads policies from JSON files
//! using the proto-based format shared across all policy implementations.
//!
//! # JSON Format
//!
//! Policies use the proto-based JSON format with explicit signal targets:
//!
//! ```json
//! {
//!   "policies": [
//!     {
//!       "id": "drop-debug-logs",
//!       "name": "drop-debug-logs",
//!       "log": {
//!         "match": [
//!           { "log_field": "body", "regex": "debug" }
//!         ],
//!         "keep": "none"
//!       }
//!     }
//!   ]
//! }
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::{
    self as pb, AttributePath, log_matcher, log_sample_key, metric_matcher, policy, trace_matcher,
};

use super::{PolicyCallback, PolicyProvider};

/// A policy provider that loads policies from a JSON file.
pub struct FileProvider {
    path: PathBuf,
}

impl FileProvider {
    /// Create a new file provider for the given path.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Parse policies from file contents.
    fn parse(&self, contents: &str) -> Result<Vec<Policy>, PolicyError> {
        let file: JsonPolicyFile =
            serde_json::from_str(contents).map_err(|e| PolicyError::ParseError {
                path: self.path.clone(),
                message: e.to_string(),
            })?;

        file.policies
            .into_iter()
            .map(|p| p.into_proto().map(|proto| Policy { proto }))
            .collect()
    }
}

impl PolicyProvider for FileProvider {
    fn load(&self) -> Result<Vec<Policy>, PolicyError> {
        let contents = fs::read_to_string(&self.path).map_err(|e| PolicyError::FileRead {
            path: self.path.clone(),
            source: e,
        })?;

        self.parse(&contents)
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        let policies = self.load()?;
        callback(policies);
        Ok(())
    }
}

// =============================================================================
// JSON serde types — these mirror the canonical JSON format exactly.
//
// The canonical format uses snake_case keys and flattened oneofs. Each matcher
// object contains both a field selector and a match type as sibling keys:
//
//   { "log_field": "body", "regex": "error", "case_insensitive": true }
//
// This is achieved via `#[serde(flatten)]` on both the field and match enums.
// =============================================================================

fn default_true() -> bool {
    true
}

/// Top-level JSON file wrapper: `{ "policies": [...] }`.
#[derive(Deserialize)]
struct JsonPolicyFile {
    policies: Vec<JsonPolicy>,
}

/// A single policy with an id, name, and exactly one signal target.
#[derive(Deserialize)]
struct JsonPolicy {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    /// Defaults to true when omitted.
    #[serde(default = "default_true")]
    enabled: bool,
    /// The signal target (`log`, `metric`, or `trace`), flattened into the
    /// policy object so the JSON key name selects the variant.
    #[serde(flatten)]
    target: JsonTarget,
}

/// Signal target — exactly one of `"log"`, `"metric"`, or `"trace"`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonTarget {
    Log(JsonLogTarget),
    Metric(JsonMetricTarget),
    Trace(JsonTraceTarget),
}

// -- Log types ----------------------------------------------------------------

/// Log target: matchers (AND logic), keep action, optional sample key.
#[derive(Deserialize)]
struct JsonLogTarget {
    /// Matchers that must all match for the policy to apply.
    r#match: Vec<JsonLogMatcher>,
    /// Keep action: `"all"`, `"none"`, `"N%"`, `"N/s"`, `"N/m"`.
    keep: String,
    /// Optional field for consistent sampling.
    #[serde(default)]
    sample_key: Option<JsonLogSampleKey>,
}

/// A single log matcher with a field selector and match type as flattened siblings.
#[derive(Deserialize)]
struct JsonLogMatcher {
    /// Which field to match (e.g. `"log_field": "body"`).
    #[serde(flatten)]
    field: JsonLogField,
    /// How to match (e.g. `"regex": "error"`).
    #[serde(flatten)]
    match_type: JsonMatchType,
    /// Invert the match result.
    #[serde(default)]
    negate: bool,
    /// Apply case-insensitive matching.
    #[serde(default)]
    case_insensitive: bool,
}

/// Log field selector — one of: `log_field`, `log_attribute`,
/// `resource_attribute`, `scope_attribute`.
///
/// `log_field` takes a short name (`"body"`, `"severity_text"`, etc.).
/// Attribute fields take an `AttributePath`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonLogField {
    LogField(String),
    LogAttribute(JsonAttributePath),
    ResourceAttribute(JsonAttributePath),
    ScopeAttribute(JsonAttributePath),
}

/// Sample key for consistent sampling — uses the same field selector as matchers.
#[derive(Deserialize)]
struct JsonLogSampleKey {
    #[serde(flatten)]
    field: JsonLogField,
}

// -- Metric types -------------------------------------------------------------

/// Metric target: matchers (AND logic) and a boolean keep/drop decision.
#[derive(Deserialize)]
struct JsonMetricTarget {
    r#match: Vec<JsonMetricMatcher>,
    /// `true` to keep matching metrics, `false` to drop them.
    keep: bool,
}

/// A single metric matcher.
#[derive(Deserialize)]
struct JsonMetricMatcher {
    #[serde(flatten)]
    field: JsonMetricField,
    #[serde(flatten)]
    match_type: JsonMatchType,
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    case_insensitive: bool,
}

/// Metric field selector — includes `metric_type` and `aggregation_temporality`
/// which take full proto enum names (e.g. `"METRIC_TYPE_GAUGE"`).
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonMetricField {
    /// Short name: `"name"`, `"description"`, `"unit"`, etc.
    MetricField(String),
    DatapointAttribute(JsonAttributePath),
    ResourceAttribute(JsonAttributePath),
    ScopeAttribute(JsonAttributePath),
    /// Full proto name, e.g. `"METRIC_TYPE_GAUGE"`.
    MetricType(String),
    /// Full proto name, e.g. `"AGGREGATION_TEMPORALITY_DELTA"`.
    AggregationTemporality(String),
}

// -- Trace types --------------------------------------------------------------

/// Trace target: matchers (AND logic) and a probabilistic sampling config.
#[derive(Deserialize)]
struct JsonTraceTarget {
    r#match: Vec<JsonTraceMatcher>,
    keep: JsonTraceSamplingConfig,
}

/// A single trace/span matcher.
#[derive(Deserialize)]
struct JsonTraceMatcher {
    #[serde(flatten)]
    field: JsonTraceField,
    #[serde(flatten)]
    match_type: JsonMatchType,
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    case_insensitive: bool,
}

/// Trace field selector. `trace_field`, `span_kind`, and `span_status` take
/// full proto enum names (e.g. `"TRACE_FIELD_NAME"`, `"SPAN_KIND_INTERNAL"`).
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonTraceField {
    /// Full proto name, e.g. `"TRACE_FIELD_NAME"`.
    TraceField(String),
    SpanAttribute(JsonAttributePath),
    ResourceAttribute(JsonAttributePath),
    ScopeAttribute(JsonAttributePath),
    /// Full proto name, e.g. `"SPAN_KIND_INTERNAL"`.
    SpanKind(String),
    /// Full proto name, e.g. `"SPAN_STATUS_CODE_ERROR"`.
    SpanStatus(String),
    EventName(String),
    EventAttribute(JsonAttributePath),
    LinkTraceId(String),
}

/// Probabilistic sampling configuration for trace policies.
#[derive(Deserialize)]
struct JsonTraceSamplingConfig {
    /// Sampling percentage (0-100). >= 100 keeps all, 0 drops all.
    percentage: f32,
    /// Sampling mode, full proto name (e.g. `"SAMPLING_MODE_HASH_SEED"`).
    #[serde(default)]
    mode: Option<String>,
    /// Hex digits for encoding the tracestate threshold (1-14, default 4).
    #[serde(default)]
    sampling_precision: Option<u32>,
    /// Seed for deterministic hash-based sampling.
    #[serde(default)]
    hash_seed: Option<u32>,
    /// If true (default), reject spans when sampling errors occur.
    #[serde(default)]
    fail_closed: Option<bool>,
}

// -- Shared types -------------------------------------------------------------

/// Match type, shared across all signal matchers. Exactly one variant is
/// expected per matcher object (e.g. `"regex": "error"` or `"exact": "FOO"`).
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonMatchType {
    Exact(String),
    Regex(String),
    Exists(bool),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
}

/// Attribute path supporting three JSON representations:
/// - String: `"user_id"` (single segment)
/// - Array: `["http", "method"]` (nested path)
/// - Canonical: `{ "path": ["http", "method"] }`
#[derive(Deserialize)]
#[serde(untagged)]
enum JsonAttributePath {
    Canonical { path: Vec<String> },
    Array(Vec<String>),
    String(String),
}

// =============================================================================
// Conversion to proto types
// =============================================================================

impl JsonPolicy {
    fn into_proto(self) -> Result<pb::Policy, PolicyError> {
        let target = match self.target {
            JsonTarget::Log(log) => policy::Target::Log(log.into_proto(&self.id)?),
            JsonTarget::Metric(metric) => policy::Target::Metric(metric.into_proto(&self.id)?),
            JsonTarget::Trace(trace) => policy::Target::Trace(trace.into_proto(&self.id)?),
        };
        Ok(pb::Policy {
            id: self.id,
            name: self.name,
            description: self.description,
            enabled: self.enabled,
            created_at_unix_nano: 0,
            modified_at_unix_nano: 0,
            labels: vec![],
            target: Some(target),
        })
    }
}

impl JsonLogTarget {
    fn into_proto(self, policy_id: &str) -> Result<pb::LogTarget, PolicyError> {
        let matchers: Result<Vec<_>, _> = self
            .r#match
            .into_iter()
            .map(|m| m.into_proto(policy_id))
            .collect();
        let sample_key = self
            .sample_key
            .map(|sk| sk.into_proto(policy_id))
            .transpose()?;
        Ok(pb::LogTarget {
            r#match: matchers?,
            keep: self.keep,
            transform: None,
            sample_key,
        })
    }
}

impl JsonLogMatcher {
    fn into_proto(self, policy_id: &str) -> Result<pb::LogMatcher, PolicyError> {
        Ok(pb::LogMatcher {
            field: Some(self.field.into_log_matcher_field(policy_id)?),
            r#match: Some(self.match_type.into_log_match()),
            negate: self.negate,
            case_insensitive: self.case_insensitive,
        })
    }
}

impl JsonLogSampleKey {
    fn into_proto(self, policy_id: &str) -> Result<pb::LogSampleKey, PolicyError> {
        Ok(pb::LogSampleKey {
            field: Some(self.field.into_sample_key_field(policy_id)?),
        })
    }
}

impl JsonLogField {
    fn into_log_matcher_field(self, policy_id: &str) -> Result<log_matcher::Field, PolicyError> {
        match self {
            Self::LogField(name) => {
                let f = parse_log_field_name(policy_id, &name)?;
                Ok(log_matcher::Field::LogField(f as i32))
            }
            Self::LogAttribute(path) => Ok(log_matcher::Field::LogAttribute(path.into_proto())),
            Self::ResourceAttribute(path) => {
                Ok(log_matcher::Field::ResourceAttribute(path.into_proto()))
            }
            Self::ScopeAttribute(path) => Ok(log_matcher::Field::ScopeAttribute(path.into_proto())),
        }
    }

    fn into_sample_key_field(self, policy_id: &str) -> Result<log_sample_key::Field, PolicyError> {
        match self {
            Self::LogField(name) => {
                let f = parse_log_field_name(policy_id, &name)?;
                Ok(log_sample_key::Field::LogField(f as i32))
            }
            Self::LogAttribute(path) => Ok(log_sample_key::Field::LogAttribute(path.into_proto())),
            Self::ResourceAttribute(path) => {
                Ok(log_sample_key::Field::ResourceAttribute(path.into_proto()))
            }
            Self::ScopeAttribute(path) => {
                Ok(log_sample_key::Field::ScopeAttribute(path.into_proto()))
            }
        }
    }
}

impl JsonMetricTarget {
    fn into_proto(self, policy_id: &str) -> Result<pb::MetricTarget, PolicyError> {
        let matchers: Result<Vec<_>, _> = self
            .r#match
            .into_iter()
            .map(|m| m.into_proto(policy_id))
            .collect();
        Ok(pb::MetricTarget {
            r#match: matchers?,
            keep: self.keep,
        })
    }
}

impl JsonMetricMatcher {
    fn into_proto(self, policy_id: &str) -> Result<pb::MetricMatcher, PolicyError> {
        Ok(pb::MetricMatcher {
            field: Some(self.field.into_proto(policy_id)?),
            r#match: Some(self.match_type.into_metric_match()),
            negate: self.negate,
            case_insensitive: self.case_insensitive,
        })
    }
}

impl JsonMetricField {
    fn into_proto(self, policy_id: &str) -> Result<metric_matcher::Field, PolicyError> {
        match self {
            Self::MetricField(name) => {
                let f = parse_metric_field_name(policy_id, &name)?;
                Ok(metric_matcher::Field::MetricField(f as i32))
            }
            Self::DatapointAttribute(path) => {
                Ok(metric_matcher::Field::DatapointAttribute(path.into_proto()))
            }
            Self::ResourceAttribute(path) => {
                Ok(metric_matcher::Field::ResourceAttribute(path.into_proto()))
            }
            Self::ScopeAttribute(path) => {
                Ok(metric_matcher::Field::ScopeAttribute(path.into_proto()))
            }
            Self::MetricType(name) => {
                let mt = pb::MetricType::from_str_name(&name)
                    .ok_or_else(|| invalid(policy_id, &format!("unknown metric_type: '{name}'")))?;
                Ok(metric_matcher::Field::MetricType(mt as i32))
            }
            Self::AggregationTemporality(name) => {
                let at = pb::AggregationTemporality::from_str_name(&name).ok_or_else(|| {
                    invalid(
                        policy_id,
                        &format!("unknown aggregation_temporality: '{name}'"),
                    )
                })?;
                Ok(metric_matcher::Field::AggregationTemporality(at as i32))
            }
        }
    }
}

impl JsonTraceTarget {
    fn into_proto(self, policy_id: &str) -> Result<pb::TraceTarget, PolicyError> {
        let matchers: Result<Vec<_>, _> = self
            .r#match
            .into_iter()
            .map(|m| m.into_proto(policy_id))
            .collect();
        Ok(pb::TraceTarget {
            r#match: matchers?,
            keep: Some(self.keep.into_proto(policy_id)?),
        })
    }
}

impl JsonTraceMatcher {
    fn into_proto(self, policy_id: &str) -> Result<pb::TraceMatcher, PolicyError> {
        Ok(pb::TraceMatcher {
            field: Some(self.field.into_proto(policy_id)?),
            r#match: Some(self.match_type.into_trace_match()),
            negate: self.negate,
            case_insensitive: self.case_insensitive,
        })
    }
}

impl JsonTraceField {
    fn into_proto(self, policy_id: &str) -> Result<trace_matcher::Field, PolicyError> {
        match self {
            Self::TraceField(name) => {
                let f = pb::TraceField::from_str_name(&name)
                    .ok_or_else(|| invalid(policy_id, &format!("unknown trace_field: '{name}'")))?;
                Ok(trace_matcher::Field::TraceField(f as i32))
            }
            Self::SpanAttribute(path) => Ok(trace_matcher::Field::SpanAttribute(path.into_proto())),
            Self::ResourceAttribute(path) => {
                Ok(trace_matcher::Field::ResourceAttribute(path.into_proto()))
            }
            Self::ScopeAttribute(path) => {
                Ok(trace_matcher::Field::ScopeAttribute(path.into_proto()))
            }
            Self::SpanKind(name) => {
                let k = pb::SpanKind::from_str_name(&name)
                    .ok_or_else(|| invalid(policy_id, &format!("unknown span_kind: '{name}'")))?;
                Ok(trace_matcher::Field::SpanKind(k as i32))
            }
            Self::SpanStatus(name) => {
                let s = pb::SpanStatusCode::from_str_name(&name)
                    .ok_or_else(|| invalid(policy_id, &format!("unknown span_status: '{name}'")))?;
                Ok(trace_matcher::Field::SpanStatus(s as i32))
            }
            Self::EventName(name) => Ok(trace_matcher::Field::EventName(name)),
            Self::EventAttribute(path) => {
                Ok(trace_matcher::Field::EventAttribute(path.into_proto()))
            }
            Self::LinkTraceId(id) => Ok(trace_matcher::Field::LinkTraceId(id)),
        }
    }
}

impl JsonTraceSamplingConfig {
    fn into_proto(self, policy_id: &str) -> Result<pb::TraceSamplingConfig, PolicyError> {
        let mode = self
            .mode
            .map(|name| {
                pb::SamplingMode::from_str_name(&name)
                    .map(|m| m as i32)
                    .ok_or_else(|| invalid(policy_id, &format!("unknown sampling mode: '{name}'")))
            })
            .transpose()?;
        Ok(pb::TraceSamplingConfig {
            percentage: self.percentage,
            mode,
            sampling_precision: self.sampling_precision,
            hash_seed: self.hash_seed,
            fail_closed: self.fail_closed,
        })
    }
}

impl JsonMatchType {
    fn into_log_match(self) -> log_matcher::Match {
        match self {
            Self::Exact(v) => log_matcher::Match::Exact(v),
            Self::Regex(v) => log_matcher::Match::Regex(v),
            Self::Exists(v) => log_matcher::Match::Exists(v),
            Self::StartsWith(v) => log_matcher::Match::StartsWith(v),
            Self::EndsWith(v) => log_matcher::Match::EndsWith(v),
            Self::Contains(v) => log_matcher::Match::Contains(v),
        }
    }

    fn into_metric_match(self) -> metric_matcher::Match {
        match self {
            Self::Exact(v) => metric_matcher::Match::Exact(v),
            Self::Regex(v) => metric_matcher::Match::Regex(v),
            Self::Exists(v) => metric_matcher::Match::Exists(v),
            Self::StartsWith(v) => metric_matcher::Match::StartsWith(v),
            Self::EndsWith(v) => metric_matcher::Match::EndsWith(v),
            Self::Contains(v) => metric_matcher::Match::Contains(v),
        }
    }

    fn into_trace_match(self) -> trace_matcher::Match {
        match self {
            Self::Exact(v) => trace_matcher::Match::Exact(v),
            Self::Regex(v) => trace_matcher::Match::Regex(v),
            Self::Exists(v) => trace_matcher::Match::Exists(v),
            Self::StartsWith(v) => trace_matcher::Match::StartsWith(v),
            Self::EndsWith(v) => trace_matcher::Match::EndsWith(v),
            Self::Contains(v) => trace_matcher::Match::Contains(v),
        }
    }
}

impl JsonAttributePath {
    fn into_proto(self) -> AttributePath {
        AttributePath {
            path: match self {
                Self::Canonical { path } => path,
                Self::Array(arr) => arr,
                Self::String(s) => vec![s],
            },
        }
    }
}

// =============================================================================
// Enum name helpers
// =============================================================================

fn parse_log_field_name(policy_id: &str, name: &str) -> Result<pb::LogField, PolicyError> {
    match name {
        "body" => Ok(pb::LogField::Body),
        "severity_text" => Ok(pb::LogField::SeverityText),
        "trace_id" => Ok(pb::LogField::TraceId),
        "span_id" => Ok(pb::LogField::SpanId),
        "event_name" => Ok(pb::LogField::EventName),
        "resource_schema_url" => Ok(pb::LogField::ResourceSchemaUrl),
        "scope_schema_url" => Ok(pb::LogField::ScopeSchemaUrl),
        _ => Err(invalid(policy_id, &format!("unknown log_field: '{name}'"))),
    }
}

fn parse_metric_field_name(policy_id: &str, name: &str) -> Result<pb::MetricField, PolicyError> {
    match name {
        "name" => Ok(pb::MetricField::Name),
        "description" => Ok(pb::MetricField::Description),
        "unit" => Ok(pb::MetricField::Unit),
        "resource_schema_url" => Ok(pb::MetricField::ResourceSchemaUrl),
        "scope_schema_url" => Ok(pb::MetricField::ScopeSchemaUrl),
        "scope_name" => Ok(pb::MetricField::ScopeName),
        "scope_version" => Ok(pb::MetricField::ScopeVersion),
        _ => Err(invalid(
            policy_id,
            &format!("unknown metric_field: '{name}'"),
        )),
    }
}

fn invalid(policy_id: &str, reason: &str) -> PolicyError {
    PolicyError::InvalidPolicy {
        policy_id: policy_id.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_policy_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn load_simple_policy() {
        let content = r#"{
            "policies": [
                {
                    "id": "test-policy",
                    "name": "Test Policy",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": "error" }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id(), "test-policy");
        assert_eq!(policies[0].name(), "Test Policy");
        assert!(policies[0].enabled());
    }

    #[test]
    fn load_policy_with_attribute_matcher() {
        let content = r#"{
            "policies": [
                {
                    "id": "attr-policy",
                    "name": "Attribute Policy",
                    "log": {
                        "match": [
                            { "log_attribute": "ddsource", "regex": "nginx" }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 1);
    }

    #[test]
    fn load_policy_with_multiple_matchers() {
        let content = r#"{
            "policies": [
                {
                    "id": "multi-matcher",
                    "name": "Multi Matcher",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": "debug" },
                            { "log_field": "body", "regex": "trace" }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 2);
    }

    #[test]
    fn load_multiple_policies() {
        let content = r#"{
            "policies": [
                {
                    "id": "policy-1",
                    "name": "Policy 1",
                    "log": {
                        "match": [{ "log_field": "body", "regex": "error" }],
                        "keep": "all"
                    }
                },
                {
                    "id": "policy-2",
                    "name": "Policy 2",
                    "log": {
                        "match": [{ "log_field": "severity_text", "regex": "DEBUG" }],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].id(), "policy-1");
        assert_eq!(policies[1].id(), "policy-2");
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let provider = FileProvider::new("/nonexistent/path/policies.json");
        let result = provider.load();
        assert!(result.is_err());
    }

    #[test]
    fn load_invalid_json_returns_error() {
        let file = create_temp_policy_file("{ invalid json }");
        let provider = FileProvider::new(file.path());
        let result = provider.load();
        assert!(result.is_err());
    }

    #[test]
    fn load_testdata_policies() {
        let provider = FileProvider::new("testdata/policies.json");
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 16);

        // Verify some policy IDs
        let ids: Vec<&str> = policies.iter().map(|p| p.id()).collect();
        assert!(ids.contains(&"drop-echo-logs"));
        assert!(ids.contains(&"drop-debug-logs"));
        assert!(ids.contains(&"drop-no-such-file-or-directory-logs"));
        assert!(ids.contains(&"drop-debug-level"));
        assert!(ids.contains(&"drop-edge-logs"));
        assert!(ids.contains(&"keep-error-logs"));
        assert!(ids.contains(&"drop-system-load-metric"));
        assert!(ids.contains(&"sample-ping-spans-by-name"));

        // Verify log keep values
        for policy in &policies {
            if let Some(log_target) = policy.log_target() {
                if policy.id() == "keep-error-logs" {
                    assert_eq!(log_target.keep, "all");
                } else {
                    assert_eq!(log_target.keep, "none");
                }
            }
        }

        // Verify metric policies
        for policy in &policies {
            if let Some(metric_target) = policy.metric_target() {
                assert!(!metric_target.keep);
            }
        }
    }

    #[test]
    fn load_policy_with_scope_attribute() {
        let content = r#"{
            "policies": [
                {
                    "id": "scope-policy",
                    "name": "Scope Attribute Policy",
                    "log": {
                        "match": [
                            { "scope_attribute": "scope.name", "regex": "test" }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 1);
    }

    #[test]
    fn load_policy_with_case_insensitive_matcher() {
        let content = r#"{
            "policies": [
                {
                    "id": "case-insensitive-policy",
                    "name": "Case Insensitive Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "body",
                                "regex": "error",
                                "case_insensitive": true
                            }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 1);
        assert!(log_target.r#match[0].case_insensitive);
    }

    #[test]
    fn load_policy_with_exact_match_type() {
        let content = r#"{
            "policies": [
                {
                    "id": "exact-match-policy",
                    "name": "Exact Match Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "severity_text",
                                "exact": "ERROR"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];
        assert!(matches!(
            matcher.r#match,
            Some(log_matcher::Match::Exact(_))
        ));
    }

    #[test]
    fn load_policy_with_starts_with_match_type() {
        let content = r#"{
            "policies": [
                {
                    "id": "starts-with-policy",
                    "name": "Starts With Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "body",
                                "starts_with": "ERROR:"
                            }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];
        assert!(matches!(
            matcher.r#match,
            Some(log_matcher::Match::StartsWith(_))
        ));
    }

    #[test]
    fn load_policy_with_ends_with_match_type() {
        let content = r#"{
            "policies": [
                {
                    "id": "ends-with-policy",
                    "name": "Ends With Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "body",
                                "ends_with": ".json"
                            }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];
        assert!(matches!(
            matcher.r#match,
            Some(log_matcher::Match::EndsWith(_))
        ));
    }

    #[test]
    fn load_policy_with_contains_match_type() {
        let content = r#"{
            "policies": [
                {
                    "id": "contains-policy",
                    "name": "Contains Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "body",
                                "contains": "error"
                            }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];
        assert!(matches!(
            matcher.r#match,
            Some(log_matcher::Match::Contains(_))
        ));
    }

    #[test]
    fn load_policy_with_sample_key() {
        let content = r#"{
            "policies": [
                {
                    "id": "sample-key-policy",
                    "name": "Sample Key Policy",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": ".*" }
                        ],
                        "keep": "50%",
                        "sample_key": {
                            "log_attribute": "request_id"
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert!(log_target.sample_key.is_some());

        let sample_key = log_target.sample_key.as_ref().unwrap();
        assert!(matches!(
            sample_key.field,
            Some(log_sample_key::Field::LogAttribute(_))
        ));
    }

    #[test]
    fn load_policy_with_sample_key_simple_field() {
        let content = r#"{
            "policies": [
                {
                    "id": "sample-key-trace-policy",
                    "name": "Sample Key Trace Policy",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": ".*" }
                        ],
                        "keep": "10%",
                        "sample_key": {
                            "log_field": "trace_id"
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert!(log_target.sample_key.is_some());

        let sample_key = log_target.sample_key.as_ref().unwrap();
        assert!(matches!(
            sample_key.field,
            Some(log_sample_key::Field::LogField(_))
        ));
    }

    #[test]
    fn load_policy_with_all_features() {
        let content = r#"{
            "policies": [
                {
                    "id": "full-featured-policy",
                    "name": "Full Featured Policy",
                    "log": {
                        "match": [
                            {
                                "log_field": "body",
                                "contains": "error",
                                "case_insensitive": true
                            },
                            {
                                "resource_attribute": "service.name",
                                "exact": "my-service"
                            }
                        ],
                        "keep": "25%",
                        "sample_key": {
                            "log_attribute": "trace_id"
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();

        assert_eq!(log_target.r#match.len(), 2);
        assert!(log_target.r#match[0].case_insensitive);
        assert!(matches!(
            log_target.r#match[0].r#match,
            Some(log_matcher::Match::Contains(_))
        ));

        assert!(!log_target.r#match[1].case_insensitive);
        assert!(matches!(
            log_target.r#match[1].r#match,
            Some(log_matcher::Match::Exact(_))
        ));

        assert!(log_target.sample_key.is_some());
    }

    // ==================== AttributePath Format Tests ====================

    #[test]
    fn attribute_path_canonical_format() {
        let content = r#"{
            "policies": [
                {
                    "id": "canonical-path-policy",
                    "name": "Canonical Path Policy",
                    "log": {
                        "match": [
                            {
                                "log_attribute": { "path": ["http", "method"] },
                                "exact": "POST"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["http", "method"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_shorthand_array_format() {
        let content = r#"{
            "policies": [
                {
                    "id": "array-path-policy",
                    "name": "Array Path Policy",
                    "log": {
                        "match": [
                            {
                                "log_attribute": ["http", "status_code"],
                                "exact": "200"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["http", "status_code"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_shorthand_string_format() {
        let content = r#"{
            "policies": [
                {
                    "id": "string-path-policy",
                    "name": "String Path Policy",
                    "log": {
                        "match": [
                            {
                                "log_attribute": "user_id",
                                "exact": "u123"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["user_id"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_all_three_formats_in_one_policy() {
        let content = r#"{
            "policies": [
                {
                    "id": "mixed-path-policy",
                    "name": "Mixed Path Formats Policy",
                    "log": {
                        "match": [
                            {
                                "log_attribute": { "path": ["service", "name"] },
                                "exact": "api"
                            },
                            {
                                "resource_attribute": ["deployment", "environment"],
                                "exact": "production"
                            },
                            {
                                "scope_attribute": "version",
                                "starts_with": "1.0"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 3);

        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &log_target.r#match[0].field {
            assert_eq!(attr_path.path, vec!["service", "name"]);
        } else {
            panic!("Expected LogAttribute field for first matcher");
        }

        if let Some(log_matcher::Field::ResourceAttribute(attr_path)) = &log_target.r#match[1].field
        {
            assert_eq!(attr_path.path, vec!["deployment", "environment"]);
        } else {
            panic!("Expected ResourceAttribute field for second matcher");
        }

        if let Some(log_matcher::Field::ScopeAttribute(attr_path)) = &log_target.r#match[2].field {
            assert_eq!(attr_path.path, vec!["version"]);
        } else {
            panic!("Expected ScopeAttribute field for third matcher");
        }
    }

    #[test]
    fn attribute_path_deeply_nested() {
        let content = r#"{
            "policies": [
                {
                    "id": "deep-nested-policy",
                    "name": "Deeply Nested Path Policy",
                    "log": {
                        "match": [
                            {
                                "log_attribute": ["service", "config", "database", "host"],
                                "exact": "localhost"
                            }
                        ],
                        "keep": "all"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(
                attr_path.path,
                vec!["service", "config", "database", "host"]
            );
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn sample_key_attribute_path_formats() {
        let content = r#"{
            "policies": [
                {
                    "id": "sample-key-nested-policy",
                    "name": "Sample Key Nested Path Policy",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": ".*" }
                        ],
                        "keep": "50%",
                        "sample_key": {
                            "log_attribute": ["request", "id"]
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let sample_key = log_target.sample_key.as_ref().unwrap();

        if let Some(log_sample_key::Field::LogAttribute(attr_path)) = &sample_key.field {
            assert_eq!(attr_path.path, vec!["request", "id"]);
        } else {
            panic!("Expected LogAttribute field in sample_key");
        }
    }

    #[test]
    fn load_metric_policy() {
        let content = r#"{
            "policies": [
                {
                    "id": "drop-debug-metrics",
                    "name": "Drop Debug Metrics",
                    "metric": {
                        "match": [
                            { "metric_field": "name", "regex": "debug.*" }
                        ],
                        "keep": false
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id(), "drop-debug-metrics");
        let metric_target = policies[0].metric_target().unwrap();
        assert!(!metric_target.keep);
    }

    #[test]
    fn load_metric_policy_with_datapoint_attribute() {
        let content = r#"{
            "policies": [
                {
                    "id": "drop-logs-datatype",
                    "name": "Drop logs data type metric",
                    "metric": {
                        "match": [
                            { "datapoint_attribute": "data_type", "exact": "logs" }
                        ],
                        "keep": false
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let metric_target = policies[0].metric_target().unwrap();
        assert_eq!(metric_target.r#match.len(), 1);
        assert!(matches!(
            metric_target.r#match[0].r#match,
            Some(metric_matcher::Match::Exact(_))
        ));
    }

    #[test]
    fn load_trace_policy() {
        let content = r#"{
            "policies": [
                {
                    "id": "sample-ping",
                    "name": "Sample ping spans at 50%",
                    "trace": {
                        "match": [
                            { "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }
                        ],
                        "keep": {
                            "percentage": 50.0,
                            "mode": "SAMPLING_MODE_HASH_SEED",
                            "sampling_precision": 4
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let trace_target = policies[0].trace_target().unwrap();
        assert_eq!(trace_target.r#match.len(), 1);

        let keep = trace_target.keep.as_ref().unwrap();
        assert_eq!(keep.percentage, 50.0);
        assert_eq!(keep.mode, Some(pb::SamplingMode::HashSeed as i32));
        assert_eq!(keep.sampling_precision, Some(4));
    }

    #[test]
    fn load_trace_policy_with_span_kind() {
        let content = r#"{
            "policies": [
                {
                    "id": "sample-internal",
                    "name": "Sample internal spans",
                    "trace": {
                        "match": [
                            { "span_kind": "SPAN_KIND_INTERNAL", "exists": true }
                        ],
                        "keep": {
                            "percentage": 75.0
                        }
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let trace_target = policies[0].trace_target().unwrap();
        let matcher = &trace_target.r#match[0];
        assert!(matches!(
            matcher.field,
            Some(trace_matcher::Field::SpanKind(k)) if k == pb::SpanKind::Internal as i32
        ));
    }

    #[test]
    fn load_disabled_policy() {
        let content = r#"{
            "policies": [
                {
                    "id": "disabled-policy",
                    "name": "Disabled Policy",
                    "enabled": false,
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": "error" }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        assert!(!policies[0].enabled());
    }

    #[test]
    fn enabled_defaults_to_true() {
        let content = r#"{
            "policies": [
                {
                    "id": "default-enabled",
                    "name": "Default Enabled",
                    "log": {
                        "match": [
                            { "log_field": "body", "regex": "error" }
                        ],
                        "keep": "none"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        assert!(policies[0].enabled());
    }
}
