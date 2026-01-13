//! Configuration types for policy providers.
//!
//! This module provides configuration structures that can be deserialized from JSON/TOML
//! and used to instantiate policy providers. The configuration is designed to be embeddable
//! into larger application configurations.
//!
//! # Example
//!
//! ```ignore
//! use policy_rs::config::{ProviderConfig, register_providers};
//! use policy_rs::registry::PolicyRegistry;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct AppConfig {
//!     service_name: String,
//!     policy_providers: Vec<ProviderConfig>,
//! }
//!
//! let json = r#"{
//!     "service_name": "my-app",
//!     "policy_providers": [
//!         {"id": "local", "type": "file", "path": "policies.json"}
//!     ]
//! }"#;
//!
//! let app_config: AppConfig = serde_json::from_str(json).unwrap();
//! let registry = PolicyRegistry::new();
//! register_providers(&app_config.policy_providers, &registry).unwrap();
//! ```

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;
use crate::provider::FileProvider;
use crate::registry::{PolicyRegistry, ProviderId};

/// Provider configuration.
///
/// This enum represents the configuration for different types of policy providers.
/// It uses serde's tagged enum representation for clean JSON/TOML serialization.
///
/// # JSON Format
///
/// ```json
/// [
///   {"id": "local", "type": "file", "path": "policies.json"},
///   {"id": "remote", "type": "http", "url": "https://api.example.com/policies"}
/// ]
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProviderConfig {
    /// File-based policy provider configuration.
    File(FileProviderConfig),

    /// HTTP-based policy provider configuration.
    #[cfg(feature = "http")]
    Http(HttpProviderConfig),

    /// gRPC-based policy provider configuration.
    #[cfg(feature = "grpc")]
    Grpc(GrpcProviderConfig),
}

/// Configuration for a file-based policy provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileProviderConfig {
    /// Unique identifier for this provider.
    pub id: String,
    /// Path to the policy JSON file.
    pub path: String,
}

/// Configuration for an HTTP-based policy provider.
#[cfg(feature = "http")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpProviderConfig {
    /// Unique identifier for this provider.
    pub id: String,
    /// URL of the policy sync endpoint.
    pub url: String,
    /// HTTP headers to include in requests.
    #[serde(default)]
    pub headers: Vec<Header>,
    /// Polling interval in seconds (default: 60).
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    /// Content type for requests: "protobuf" or "json" (default: "protobuf").
    #[serde(default)]
    pub content_type: Option<String>,
}

/// Configuration for a gRPC-based policy provider.
#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrpcProviderConfig {
    /// Unique identifier for this provider.
    pub id: String,
    /// URL of the gRPC policy service.
    pub url: String,
    /// gRPC metadata headers to include in requests.
    #[serde(default)]
    pub headers: Vec<Header>,
    /// Polling interval in seconds (default: 60).
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
}

/// An HTTP header with name and value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Header {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

impl ProviderConfig {
    /// Get the provider ID from the configuration.
    pub fn id(&self) -> &str {
        match self {
            ProviderConfig::File(c) => &c.id,
            #[cfg(feature = "http")]
            ProviderConfig::Http(c) => &c.id,
            #[cfg(feature = "grpc")]
            ProviderConfig::Grpc(c) => &c.id,
        }
    }

    /// Create a provider from this configuration and register it with the registry.
    ///
    /// This is an async function that performs the initial policy fetch before
    /// registering the provider. For HTTP and gRPC providers, this ensures
    /// policies are available immediately after registration without blocking.
    ///
    /// Returns the provider ID assigned by the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial policy fetch fails or if registration fails.
    pub async fn register(&self, registry: &PolicyRegistry) -> Result<ProviderId, PolicyError> {
        match self {
            ProviderConfig::File(config) => {
                let provider = FileProvider::new(&config.path);
                registry.subscribe(&provider)
            }
            #[cfg(feature = "http")]
            ProviderConfig::Http(config) => {
                use crate::provider::{
                    ContentType, HttpProvider, HttpProviderConfig as HttpConfig,
                };
                use std::time::Duration;

                let mut http_config = HttpConfig::new(&config.url);

                // Add headers
                for header in &config.headers {
                    http_config = http_config.header(&header.name, &header.value);
                }

                // Set poll interval if specified
                if let Some(secs) = config.poll_interval_secs {
                    http_config = http_config.poll_interval(Duration::from_secs(secs));
                }

                // Set content type if specified
                if let Some(ref ct) = config.content_type {
                    let content_type = match ct.to_lowercase().as_str() {
                        "json" => ContentType::Json,
                        _ => ContentType::Protobuf,
                    };
                    http_config = http_config.content_type(content_type);
                }

                // Use async initialization to avoid blocking
                let provider = HttpProvider::new_with_initial_fetch(http_config).await?;
                registry.subscribe(&provider)
            }
            #[cfg(feature = "grpc")]
            ProviderConfig::Grpc(config) => {
                use crate::provider::{GrpcProvider, GrpcProviderConfig as GrpcConfig};
                use std::time::Duration;

                let mut grpc_config = GrpcConfig::new(&config.url);

                // Add headers
                for header in &config.headers {
                    grpc_config = grpc_config.header(&header.name, &header.value);
                }

                // Set poll interval if specified
                if let Some(secs) = config.poll_interval_secs {
                    grpc_config = grpc_config.poll_interval(Duration::from_secs(secs));
                }

                // Use async initialization to avoid blocking
                let provider = GrpcProvider::new_with_initial_fetch(grpc_config).await?;
                registry.subscribe(&provider)
            }
        }
    }
}

/// Register multiple providers from configuration.
///
/// This is an async convenience function that registers all providers from a list of configurations.
/// Providers are registered sequentially to ensure deterministic ordering.
/// Returns a vector of provider IDs in the same order as the input configurations.
///
/// # Example
///
/// ```ignore
/// use policy_rs::config::{ProviderConfig, register_providers};
/// use policy_rs::registry::PolicyRegistry;
///
/// let configs: Vec<ProviderConfig> = serde_json::from_str(json)?;
/// let registry = PolicyRegistry::new();
/// let provider_ids = register_providers(&configs, &registry).await?;
/// ```
pub async fn register_providers(
    configs: &[ProviderConfig],
    registry: &PolicyRegistry,
) -> Result<Vec<ProviderId>, PolicyError> {
    let mut provider_ids = Vec::with_capacity(configs.len());
    for config in configs {
        let id = config.register(registry).await?;
        provider_ids.push(id);
    }
    Ok(provider_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_provider_config() {
        let json = r#"{"id": "local", "type": "file", "path": "policies.json"}"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();

        match config {
            ProviderConfig::File(c) => {
                assert_eq!(c.id, "local");
                assert_eq!(c.path, "policies.json");
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected File provider config"),
        }
    }

    #[test]
    fn parse_provider_config_list() {
        let json = r#"[
            {"id": "local", "type": "file", "path": "policies.json"},
            {"id": "backup", "type": "file", "path": "backup.json"}
        ]"#;
        let configs: Vec<ProviderConfig> = serde_json::from_str(json).unwrap();

        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].id(), "local");
        assert_eq!(configs[1].id(), "backup");
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_http_provider_config() {
        let json = r#"{
            "id": "remote",
            "type": "http",
            "url": "https://api.example.com/policies",
            "headers": [
                {"name": "Authorization", "value": "Bearer token123"}
            ],
            "poll_interval_secs": 30,
            "content_type": "json"
        }"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();

        match config {
            ProviderConfig::Http(c) => {
                assert_eq!(c.id, "remote");
                assert_eq!(c.url, "https://api.example.com/policies");
                assert_eq!(c.headers.len(), 1);
                assert_eq!(c.headers[0].name, "Authorization");
                assert_eq!(c.headers[0].value, "Bearer token123");
                assert_eq!(c.poll_interval_secs, Some(30));
                assert_eq!(c.content_type, Some("json".to_string()));
            }
            _ => panic!("Expected Http provider config"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_http_provider_config_minimal() {
        let json = r#"{"id": "remote", "type": "http", "url": "https://api.example.com/policies"}"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();

        match config {
            ProviderConfig::Http(c) => {
                assert_eq!(c.id, "remote");
                assert_eq!(c.url, "https://api.example.com/policies");
                assert!(c.headers.is_empty());
                assert!(c.poll_interval_secs.is_none());
                assert!(c.content_type.is_none());
            }
            _ => panic!("Expected Http provider config"),
        }
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn parse_grpc_provider_config() {
        let json = r#"{
            "id": "grpc-remote",
            "type": "grpc",
            "url": "https://grpc.example.com:50051",
            "headers": [
                {"name": "authorization", "value": "Bearer token123"}
            ],
            "poll_interval_secs": 120
        }"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();

        match config {
            ProviderConfig::Grpc(c) => {
                assert_eq!(c.id, "grpc-remote");
                assert_eq!(c.url, "https://grpc.example.com:50051");
                assert_eq!(c.headers.len(), 1);
                assert_eq!(c.poll_interval_secs, Some(120));
            }
            _ => panic!("Expected Grpc provider config"),
        }
    }

    #[test]
    fn provider_config_id() {
        let json = r#"{"id": "test-id", "type": "file", "path": "test.json"}"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.id(), "test-id");
    }

    #[tokio::test]
    async fn register_file_provider() {
        let config = ProviderConfig::File(FileProviderConfig {
            id: "test".to_string(),
            path: "testdata/policies.json".to_string(),
        });

        let registry = PolicyRegistry::new();
        let provider_id = config.register(&registry).await.unwrap();

        // Verify provider was registered
        assert_eq!(registry.provider_count(), 1);

        // Verify policies were loaded
        let snapshot = registry.snapshot();
        assert!(!snapshot.is_empty());

        // Provider ID was returned successfully
        let _ = provider_id;
    }

    #[tokio::test]
    async fn register_multiple_providers() {
        let configs = vec![
            ProviderConfig::File(FileProviderConfig {
                id: "provider1".to_string(),
                path: "testdata/policies.json".to_string(),
            }),
            ProviderConfig::File(FileProviderConfig {
                id: "provider2".to_string(),
                path: "testdata/policies.json".to_string(),
            }),
        ];

        let registry = PolicyRegistry::new();
        let provider_ids = register_providers(&configs, &registry).await.unwrap();

        assert_eq!(provider_ids.len(), 2);
        assert_eq!(registry.provider_count(), 2);
    }

    #[test]
    fn serialize_provider_config() {
        let config = ProviderConfig::File(FileProviderConfig {
            id: "test".to_string(),
            path: "policies.json".to_string(),
        });

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"file\""));
        assert!(json.contains("\"id\":\"test\""));
        assert!(json.contains("\"path\":\"policies.json\""));
    }
}
