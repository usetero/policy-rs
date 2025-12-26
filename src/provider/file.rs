//! File-based policy provider.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::PolicyError;
use crate::field::LogFieldSelector;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::{LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher};

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
}

fn default_enabled() -> bool {
    true
}

/// JSON representation of a matcher.
#[derive(Debug, serde::Deserialize)]
struct JsonMatcher {
    field: String,
    #[serde(default)]
    key: Option<String>,
    pattern: String,
    #[serde(default)]
    negate: bool,
}

/// Convert a JSON policy to a proto Policy.
fn convert_json_policy(json: JsonPolicy) -> Result<Policy, PolicyError> {
    let matchers: Result<Vec<LogMatcher>, PolicyError> = json
        .matchers
        .into_iter()
        .map(|m| convert_json_matcher(&json.id, m))
        .collect();

    let log_target = LogTarget {
        r#match: matchers?,
        keep: json.keep,
        transform: None,
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
    let field_selector = LogFieldSelector::from_json(&json.field, json.key.as_deref()).ok_or(
        PolicyError::InvalidPolicy {
            policy_id: policy_id.to_string(),
            reason: format!("invalid field '{}' with key {:?}", json.field, json.key),
        },
    )?;

    let field = match field_selector {
        LogFieldSelector::Simple(f) => log_matcher::Field::LogField(f.into()),
        LogFieldSelector::LogAttribute(k) => log_matcher::Field::LogAttribute(k),
        LogFieldSelector::ResourceAttribute(k) => log_matcher::Field::ResourceAttribute(k),
        LogFieldSelector::ScopeAttribute(k) => log_matcher::Field::ScopeAttribute(k),
    };

    // Determine match type - use regex for patterns
    let match_type = log_matcher::Match::Regex(json.pattern);

    Ok(LogMatcher {
        field: Some(field),
        r#match: Some(match_type),
        negate: json.negate,
    })
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
}
