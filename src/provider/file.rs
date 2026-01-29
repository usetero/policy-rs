//! File-based policy provider.
//!
//! This module provides a policy provider that loads policies from JSON files.
//!
//! # JSON Format
//!
//! Policies are defined in a JSON file with the following structure:
//!
//! ```json
//! {
//!   "policies": [
//!     {
//!       "id": "policy-id",
//!       "name": "Policy Name",
//!       "description": "Optional description",
//!       "enabled": true,
//!       "matchers": [
//!         {
//!           "field": "log_body",
//!           "pattern": "error",
//!           "match_type": "contains",
//!           "case_insensitive": true,
//!           "negate": false
//!         }
//!       ],
//!       "keep": "none",
//!       "sample_key": {
//!         "field": "log_attribute",
//!         "key": "request_id"
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! ## Matcher Fields
//!
//! - `field`: Field to match against. Options:
//!   - `log_body`, `log_severity_text`, `log_trace_id`, `log_span_id`, `log_event_name`
//!   - `log_attribute`, `resource_attribute`, `scope_attribute` (requires `key`)
//! - `key`: For attribute fields, the attribute key (single segment for backward compat)
//! - `pattern`: The pattern to match
//! - `match_type`: `"regex"` (default), `"exact"`, `"starts_with"`, `"ends_with"`, `"contains"`
//! - `case_insensitive`: Whether to match case-insensitively (default: false)
//! - `negate`: Whether to negate the match (default: false)
//!
//! ## Keep Values
//!
//! - `"all"` - Keep all matching logs
//! - `"none"` - Drop all matching logs
//! - `"N%"` - Sample N percent (e.g., `"50%"`)
//! - `"N/s"` - Rate limit to N per second (e.g., `"100/s"`)
//! - `"N/m"` - Rate limit to N per minute (e.g., `"1000/m"`)
//!
//! ## Sample Key (optional)
//!
//! For percentage-based sampling, you can specify a `sample_key` to enable
//! consistent sampling. Logs with the same sample key value will consistently
//! be either kept or dropped together.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::PolicyError;

use crate::policy::Policy;
use crate::proto::tero::policy::v1::{
    AttributePath, LogMatcher, LogSampleKey, LogTarget, Policy as ProtoPolicy, log_matcher,
    log_sample_key,
};

use super::{PolicyCallback, PolicyProvider};

/// A policy provider that loads policies from a JSON file.
///
/// This provider loads policies from a JSON file on disk. It supports
/// subscribing to updates, though file watching is not yet implemented -
/// the callback is invoked once with the initial policies.
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
        let json_file: JsonPolicyFile =
            serde_json::from_str(contents).map_err(|e| PolicyError::ParseError {
                path: self.path.clone(),
                message: e.to_string(),
            })?;

        json_file
            .policies
            .into_iter()
            .map(convert_json_policy)
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
        // Load policies and invoke callback immediately
        let policies = self.load()?;
        callback(policies);

        // TODO: File watching can be added here in the future
        // For now, this is a one-shot subscription

        Ok(())
    }
}

/// JSON representation of a policy file.
#[derive(Debug, serde::Deserialize)]
struct JsonPolicyFile {
    policies: Vec<JsonPolicy>,
}

/// JSON representation of a policy.
#[derive(Debug, serde::Deserialize)]
struct JsonPolicy {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    matchers: Vec<JsonMatcher>,
    keep: String,
    /// Optional sample key for consistent sampling.
    #[serde(default)]
    sample_key: Option<JsonSampleKey>,
}

/// JSON representation of a sample key.
#[derive(Debug, serde::Deserialize)]
struct JsonSampleKey {
    field: String,
    /// Attribute key/path. Supports three formats:
    /// - String: "user_id" (single segment)
    /// - Array: ["http", "method"] (nested path)
    /// - Canonical: { "path": ["http", "method"] }
    #[serde(default)]
    key: Option<AttributePath>,
}

fn default_enabled() -> bool {
    true
}

/// JSON representation of a matcher.
#[derive(Debug, serde::Deserialize)]
struct JsonMatcher {
    field: String,
    /// Attribute key/path. Supports three formats:
    /// - String: "user_id" (single segment)
    /// - Array: ["http", "method"] (nested path)
    /// - Canonical: { "path": ["http", "method"] }
    #[serde(default)]
    key: Option<AttributePath>,
    pattern: String,
    #[serde(default)]
    negate: bool,
    /// Whether to match case-insensitively.
    #[serde(default)]
    case_insensitive: bool,
    /// Match type: "regex" (default), "exact", "starts_with", "ends_with", "contains".
    #[serde(default = "default_match_type")]
    match_type: String,
}

fn default_match_type() -> String {
    "regex".to_string()
}

/// Convert a JSON policy to a proto Policy.
fn convert_json_policy(json: JsonPolicy) -> Result<Policy, PolicyError> {
    let matchers: Result<Vec<LogMatcher>, PolicyError> = json
        .matchers
        .into_iter()
        .map(|m| convert_json_matcher(&json.id, m))
        .collect();

    // Convert sample key if present
    let sample_key = json
        .sample_key
        .map(|sk| convert_json_sample_key(&json.id, sk))
        .transpose()?;

    let log_target = LogTarget {
        r#match: matchers?,
        keep: json.keep,
        transform: None,
        sample_key,
    };

    let proto = ProtoPolicy {
        id: json.id.clone(),
        name: json.name,
        description: json.description,
        enabled: json.enabled,
        created_at_unix_nano: 0,
        modified_at_unix_nano: 0,
        labels: vec![],
        target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
            log_target,
        )),
    };

    Ok(Policy { proto })
}

/// Convert a JSON matcher to a proto LogMatcher.
fn convert_json_matcher(policy_id: &str, json: JsonMatcher) -> Result<LogMatcher, PolicyError> {
    let field = convert_field_to_proto(policy_id, &json.field, json.key.as_ref())?;

    // Determine match type based on match_type field
    let match_type = match json.match_type.as_str() {
        "exact" => log_matcher::Match::Exact(json.pattern),
        "starts_with" => log_matcher::Match::StartsWith(json.pattern),
        "ends_with" => log_matcher::Match::EndsWith(json.pattern),
        "contains" => log_matcher::Match::Contains(json.pattern),
        _ => log_matcher::Match::Regex(json.pattern), // Default to regex
    };

    Ok(LogMatcher {
        field: Some(field),
        r#match: Some(match_type),
        negate: json.negate,
        case_insensitive: json.case_insensitive,
    })
}

/// Convert a JSON sample key to a proto LogSampleKey.
fn convert_json_sample_key(
    policy_id: &str,
    json: JsonSampleKey,
) -> Result<LogSampleKey, PolicyError> {
    let matcher_field = convert_field_to_proto(policy_id, &json.field, json.key.as_ref())?;

    // Convert log_matcher::Field to log_sample_key::Field
    let field = match matcher_field {
        log_matcher::Field::LogField(f) => log_sample_key::Field::LogField(f),
        log_matcher::Field::LogAttribute(path) => log_sample_key::Field::LogAttribute(path),
        log_matcher::Field::ResourceAttribute(path) => {
            log_sample_key::Field::ResourceAttribute(path)
        }
        log_matcher::Field::ScopeAttribute(path) => log_sample_key::Field::ScopeAttribute(path),
    };

    Ok(LogSampleKey { field: Some(field) })
}

/// Convert a JSON field specification to a proto log_matcher::Field.
fn convert_field_to_proto(
    policy_id: &str,
    field_type: &str,
    key: Option<&AttributePath>,
) -> Result<log_matcher::Field, PolicyError> {
    use crate::proto::tero::policy::v1::LogField;

    match field_type {
        "log_body" => Ok(log_matcher::Field::LogField(LogField::Body.into())),
        "log_severity_text" => Ok(log_matcher::Field::LogField(LogField::SeverityText.into())),
        "log_trace_id" => Ok(log_matcher::Field::LogField(LogField::TraceId.into())),
        "log_span_id" => Ok(log_matcher::Field::LogField(LogField::SpanId.into())),
        "log_event_name" => Ok(log_matcher::Field::LogField(LogField::EventName.into())),
        "resource_schema_url" => Ok(log_matcher::Field::LogField(
            LogField::ResourceSchemaUrl.into(),
        )),
        "scope_schema_url" => Ok(log_matcher::Field::LogField(
            LogField::ScopeSchemaUrl.into(),
        )),
        "log_attribute" => {
            let path = key.ok_or_else(|| PolicyError::InvalidPolicy {
                policy_id: policy_id.to_string(),
                reason: format!("field '{}' requires a 'key'", field_type),
            })?;
            Ok(log_matcher::Field::LogAttribute(path.clone()))
        }
        "resource_attribute" => {
            let path = key.ok_or_else(|| PolicyError::InvalidPolicy {
                policy_id: policy_id.to_string(),
                reason: format!("field '{}' requires a 'key'", field_type),
            })?;
            Ok(log_matcher::Field::ResourceAttribute(path.clone()))
        }
        "scope_attribute" => {
            let path = key.ok_or_else(|| PolicyError::InvalidPolicy {
                policy_id: policy_id.to_string(),
                reason: format!("field '{}' requires a 'key'", field_type),
            })?;
            Ok(log_matcher::Field::ScopeAttribute(path.clone()))
        }
        _ => Err(PolicyError::InvalidPolicy {
            policy_id: policy_id.to_string(),
            reason: format!("unknown field type '{}'", field_type),
        }),
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
                    "matchers": [
                        { "field": "log_body", "pattern": "error" }
                    ],
                    "keep": "none"
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
                    "matchers": [
                        { "field": "log_attribute", "key": "ddsource", "pattern": "nginx" }
                    ],
                    "keep": "all"
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
                    "matchers": [
                        { "field": "log_body", "pattern": "debug" },
                        { "field": "log_body", "pattern": "trace" }
                    ],
                    "keep": "none"
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
                    "matchers": [{ "field": "log_body", "pattern": "error" }],
                    "keep": "all"
                },
                {
                    "id": "policy-2",
                    "name": "Policy 2",
                    "matchers": [{ "field": "log_severity_text", "pattern": "DEBUG" }],
                    "keep": "none"
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

        assert_eq!(policies.len(), 6);

        // Verify policy IDs
        let ids: Vec<&str> = policies.iter().map(|p| p.id()).collect();
        assert!(ids.contains(&"drop-echo-logs"));
        assert!(ids.contains(&"drop-debug-logs"));
        assert!(ids.contains(&"drop-no-such-file-or-directory-logs"));
        assert!(ids.contains(&"drop-debug-level"));
        assert!(ids.contains(&"drop-edge-logs"));
        assert!(ids.contains(&"keep-error-logs"));

        // Verify keep values
        for policy in &policies {
            let log_target = policy.log_target().unwrap();
            if policy.id() == "keep-error-logs" {
                assert_eq!(log_target.keep, "all");
            } else {
                assert_eq!(log_target.keep, "none");
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
                    "matchers": [
                        { "field": "scope_attribute", "key": "scope.name", "pattern": "test" }
                    ],
                    "keep": "all"
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

    // ==================== New Feature Tests (v1.2.0) ====================

    #[test]
    fn load_policy_with_case_insensitive_matcher() {
        let content = r#"{
            "policies": [
                {
                    "id": "case-insensitive-policy",
                    "name": "Case Insensitive Policy",
                    "matchers": [
                        {
                            "field": "log_body",
                            "pattern": "error",
                            "case_insensitive": true
                        }
                    ],
                    "keep": "none"
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
                    "matchers": [
                        {
                            "field": "log_severity_text",
                            "pattern": "ERROR",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "all"
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
                    "matchers": [
                        {
                            "field": "log_body",
                            "pattern": "ERROR:",
                            "match_type": "starts_with"
                        }
                    ],
                    "keep": "none"
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
                    "matchers": [
                        {
                            "field": "log_body",
                            "pattern": ".json",
                            "match_type": "ends_with"
                        }
                    ],
                    "keep": "none"
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
                    "matchers": [
                        {
                            "field": "log_body",
                            "pattern": "error",
                            "match_type": "contains"
                        }
                    ],
                    "keep": "none"
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
                    "matchers": [
                        { "field": "log_body", "pattern": ".*" }
                    ],
                    "keep": "50%",
                    "sample_key": {
                        "field": "log_attribute",
                        "key": "request_id"
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
                    "matchers": [
                        { "field": "log_body", "pattern": ".*" }
                    ],
                    "keep": "10%",
                    "sample_key": {
                        "field": "log_trace_id"
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
    fn load_policy_with_all_new_features() {
        let content = r#"{
            "policies": [
                {
                    "id": "full-featured-policy",
                    "name": "Full Featured Policy",
                    "matchers": [
                        {
                            "field": "log_body",
                            "pattern": "error",
                            "match_type": "contains",
                            "case_insensitive": true
                        },
                        {
                            "field": "resource_attribute",
                            "key": "service.name",
                            "pattern": "my-service",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "25%",
                    "sample_key": {
                        "field": "log_attribute",
                        "key": "trace_id"
                    }
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();

        // Verify first matcher (contains, case-insensitive)
        assert_eq!(log_target.r#match.len(), 2);
        assert!(log_target.r#match[0].case_insensitive);
        assert!(matches!(
            log_target.r#match[0].r#match,
            Some(log_matcher::Match::Contains(_))
        ));

        // Verify second matcher (exact)
        assert!(!log_target.r#match[1].case_insensitive);
        assert!(matches!(
            log_target.r#match[1].r#match,
            Some(log_matcher::Match::Exact(_))
        ));

        // Verify sample key
        assert!(log_target.sample_key.is_some());
    }

    // ==================== AttributePath Format Tests ====================
    // Tests for the three ways of specifying attribute paths:
    // 1. Canonical: { "path": ["http", "method"] }
    // 2. Shorthand array: ["http", "method"]
    // 3. Shorthand string: "user_id"

    #[test]
    fn attribute_path_canonical_format() {
        // Canonical format: { "path": ["http", "method"] }
        let content = r#"{
            "policies": [
                {
                    "id": "canonical-path-policy",
                    "name": "Canonical Path Policy",
                    "matchers": [
                        {
                            "field": "log_attribute",
                            "key": { "path": ["http", "method"] },
                            "pattern": "POST",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "all"
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        // Verify it parsed correctly with nested path
        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["http", "method"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_shorthand_array_format() {
        // Shorthand array format: ["http", "method"]
        let content = r#"{
            "policies": [
                {
                    "id": "array-path-policy",
                    "name": "Array Path Policy",
                    "matchers": [
                        {
                            "field": "log_attribute",
                            "key": ["http", "status_code"],
                            "pattern": "200",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "all"
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        // Verify it parsed correctly with nested path
        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["http", "status_code"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_shorthand_string_format() {
        // Shorthand string format: "user_id" (single segment)
        let content = r#"{
            "policies": [
                {
                    "id": "string-path-policy",
                    "name": "String Path Policy",
                    "matchers": [
                        {
                            "field": "log_attribute",
                            "key": "user_id",
                            "pattern": "u123",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "all"
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        let matcher = &log_target.r#match[0];

        // Verify it parsed correctly with single-segment path
        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &matcher.field {
            assert_eq!(attr_path.path, vec!["user_id"]);
        } else {
            panic!("Expected LogAttribute field");
        }
    }

    #[test]
    fn attribute_path_all_three_formats_in_one_policy() {
        // Test all three formats together
        let content = r#"{
            "policies": [
                {
                    "id": "mixed-path-policy",
                    "name": "Mixed Path Formats Policy",
                    "matchers": [
                        {
                            "field": "log_attribute",
                            "key": { "path": ["service", "name"] },
                            "pattern": "api",
                            "match_type": "exact"
                        },
                        {
                            "field": "resource_attribute",
                            "key": ["deployment", "environment"],
                            "pattern": "production",
                            "match_type": "exact"
                        },
                        {
                            "field": "scope_attribute",
                            "key": "version",
                            "pattern": "1.0",
                            "match_type": "starts_with"
                        }
                    ],
                    "keep": "all"
                }
            ]
        }"#;

        let file = create_temp_policy_file(content);
        let provider = FileProvider::new(file.path());
        let policies = provider.load().unwrap();

        assert_eq!(policies.len(), 1);
        let log_target = policies[0].log_target().unwrap();
        assert_eq!(log_target.r#match.len(), 3);

        // First matcher: canonical format
        if let Some(log_matcher::Field::LogAttribute(attr_path)) = &log_target.r#match[0].field {
            assert_eq!(attr_path.path, vec!["service", "name"]);
        } else {
            panic!("Expected LogAttribute field for first matcher");
        }

        // Second matcher: shorthand array format
        if let Some(log_matcher::Field::ResourceAttribute(attr_path)) = &log_target.r#match[1].field
        {
            assert_eq!(attr_path.path, vec!["deployment", "environment"]);
        } else {
            panic!("Expected ResourceAttribute field for second matcher");
        }

        // Third matcher: shorthand string format
        if let Some(log_matcher::Field::ScopeAttribute(attr_path)) = &log_target.r#match[2].field {
            assert_eq!(attr_path.path, vec!["version"]);
        } else {
            panic!("Expected ScopeAttribute field for third matcher");
        }
    }

    #[test]
    fn attribute_path_deeply_nested() {
        // Test deeply nested path (4 levels)
        let content = r#"{
            "policies": [
                {
                    "id": "deep-nested-policy",
                    "name": "Deeply Nested Path Policy",
                    "matchers": [
                        {
                            "field": "log_attribute",
                            "key": ["service", "config", "database", "host"],
                            "pattern": "localhost",
                            "match_type": "exact"
                        }
                    ],
                    "keep": "all"
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
        // Test attribute path formats in sample_key
        let content = r#"{
            "policies": [
                {
                    "id": "sample-key-nested-policy",
                    "name": "Sample Key Nested Path Policy",
                    "matchers": [
                        { "field": "log_body", "pattern": ".*" }
                    ],
                    "keep": "50%",
                    "sample_key": {
                        "field": "log_attribute",
                        "key": ["request", "id"]
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
}
