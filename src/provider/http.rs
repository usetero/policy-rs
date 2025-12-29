//! HTTP-based policy provider.
//!
//! This provider polls an HTTP endpoint for policy updates using the
//! SyncRequest/SyncResponse protobuf protocol.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::{ClientMetadata, SyncRequest, SyncResponse};

use super::sync::{StatsCollector, collect_policy_statuses};
use super::{PolicyCallback, PolicyProvider};

/// Configuration for the HTTP provider.
#[derive(Debug, Clone)]
pub struct HttpProviderConfig {
    /// The URL to poll for policy updates.
    pub url: String,
    /// Headers to include in requests.
    pub headers: HashMap<String, String>,
    /// Polling interval in nanoseconds.
    pub poll_interval_ns: u64,
    /// Client metadata to include in sync requests.
    pub client_metadata: Option<ClientMetadata>,
    /// Content type for requests (application/x-protobuf or application/json).
    pub content_type: ContentType,
}

/// Content type for HTTP requests.
#[derive(Debug, Clone, Copy, Default)]
pub enum ContentType {
    /// Protobuf encoding (default, more efficient).
    #[default]
    Protobuf,
    /// JSON encoding (useful for debugging).
    Json,
}

impl HttpProviderConfig {
    /// Create a new HTTP provider config with the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: HashMap::new(),
            poll_interval_ns: Duration::from_secs(60).as_nanos() as u64,
            client_metadata: None,
            content_type: ContentType::default(),
        }
    }

    /// Set a header.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set multiple headers.
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Set the polling interval.
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval_ns = interval.as_nanos() as u64;
        self
    }

    /// Set the polling interval in nanoseconds.
    pub fn poll_interval_ns(mut self, ns: u64) -> Self {
        self.poll_interval_ns = ns;
        self
    }

    /// Set the client metadata.
    pub fn client_metadata(mut self, metadata: ClientMetadata) -> Self {
        self.client_metadata = Some(metadata);
        self
    }

    /// Set the content type.
    pub fn content_type(mut self, content_type: ContentType) -> Self {
        self.content_type = content_type;
        self
    }
}

/// HTTP-based policy provider.
///
/// This provider polls an HTTP endpoint at a configurable interval,
/// sending SyncRequest messages and receiving SyncResponse messages.
pub struct HttpProvider {
    config: HttpProviderConfig,
    client: reqwest::Client,
    /// Last successful sync hash for change detection.
    last_hash: RwLock<Option<String>>,
    /// Last sync timestamp.
    last_sync_timestamp: RwLock<u64>,
    /// Whether the provider is running.
    running: AtomicBool,
    /// Stats collector for reporting policy statistics.
    stats_collector: RwLock<Option<StatsCollector>>,
}

impl HttpProvider {
    /// Create a new HTTP provider with the given configuration.
    pub fn new(config: HttpProviderConfig) -> Self {
        let client = reqwest::Client::new();
        Self {
            config,
            client,
            last_hash: RwLock::new(None),
            last_sync_timestamp: RwLock::new(0),
            running: AtomicBool::new(false),
            stats_collector: RwLock::new(None),
        }
    }

    /// Set the stats collector for reporting policy statistics.
    ///
    /// The collector function is called before each sync to gather
    /// current policy statistics, which are included in the SyncRequest.
    pub fn set_stats_collector(&self, collector: StatsCollector) {
        *self.stats_collector.write().unwrap() = Some(collector);
    }

    /// Build a sync request with current state.
    fn build_sync_request(&self, full_sync: bool) -> SyncRequest {
        let last_hash = self.last_hash.read().unwrap().clone().unwrap_or_default();
        let last_timestamp = *self.last_sync_timestamp.read().unwrap();
        let policy_statuses = collect_policy_statuses(&self.stats_collector.read().unwrap());

        SyncRequest {
            client_metadata: self.config.client_metadata.clone(),
            full_sync,
            last_sync_timestamp_unix_nano: last_timestamp,
            last_successful_hash: last_hash,
            policy_statuses,
        }
    }

    /// Perform a single sync operation.
    async fn sync(&self, full_sync: bool) -> Result<Vec<Policy>, PolicyError> {
        let request = self.build_sync_request(full_sync);

        // Build HTTP request
        let mut http_request = self.client.post(&self.config.url);

        // Add headers
        for (key, value) in &self.config.headers {
            http_request = http_request.header(key, value);
        }

        // Encode and send request based on content type
        let response = match self.config.content_type {
            ContentType::Protobuf => {
                let body = request.encode_to_vec();
                http_request
                    .header("Content-Type", "application/x-protobuf")
                    .header("Accept", "application/x-protobuf")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| PolicyError::HttpError(e.to_string()))?
            }
            ContentType::Json => {
                // For JSON, we need to serialize using serde
                // Note: This requires the proto types to derive Serialize
                http_request
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| PolicyError::HttpError(e.to_string()))?
            }
        };

        // Check response status
        if !response.status().is_success() {
            return Err(PolicyError::HttpError(format!(
                "HTTP error: {} - {}",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "unknown".to_string())
            )));
        }

        // Decode response
        let sync_response: SyncResponse = match self.config.content_type {
            ContentType::Protobuf => {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| PolicyError::HttpError(e.to_string()))?;
                SyncResponse::decode(bytes).map_err(|e| PolicyError::HttpError(e.to_string()))?
            }
            ContentType::Json => {
                let text = response
                    .text()
                    .await
                    .map_err(|e| PolicyError::HttpError(e.to_string()))?;
                serde_json::from_str(&text).map_err(|e| {
                    PolicyError::HttpError(format!(
                        "JSON decode error: {} - response: {}",
                        e,
                        &text[..text.len().min(500)]
                    ))
                })?
            }
        };

        // Check for errors in response
        if !sync_response.error_message.is_empty() {
            return Err(PolicyError::HttpError(format!(
                "Sync error: {}",
                sync_response.error_message
            )));
        }

        // Update state
        if !sync_response.hash.is_empty() {
            *self.last_hash.write().unwrap() = Some(sync_response.hash);
        }
        if sync_response.sync_timestamp_unix_nano > 0 {
            *self.last_sync_timestamp.write().unwrap() = sync_response.sync_timestamp_unix_nano;
        }

        // Convert proto policies to Policy objects
        let policies = sync_response
            .policies
            .into_iter()
            .map(Policy::new)
            .collect();

        Ok(policies)
    }

    /// Start the polling loop.
    ///
    /// Returns a channel receiver that will receive policy updates.
    /// Each successful result includes the hash and the policies.
    pub fn start_polling(
        &self,
    ) -> mpsc::Receiver<Result<(Option<String>, Vec<Policy>), PolicyError>> {
        let (tx, rx) = mpsc::channel(16);

        self.running.store(true, Ordering::SeqCst);

        let config = self.config.clone();
        let client = self.client.clone();
        let last_hash = Arc::new(RwLock::new(None::<String>));
        let last_sync_timestamp = Arc::new(RwLock::new(0u64));
        let stats_collector = self.stats_collector.read().unwrap().clone();
        let running = Arc::new(AtomicBool::new(true));

        let running_clone = running.clone();
        let last_hash_clone = last_hash.clone();
        let last_sync_timestamp_clone = last_sync_timestamp.clone();

        tokio::spawn(async move {
            let poll_duration = Duration::from_nanos(config.poll_interval_ns);
            let mut interval = interval(poll_duration);

            // Do an initial full sync
            let mut first = true;

            while running_clone.load(Ordering::SeqCst) {
                interval.tick().await;

                let request = {
                    let last_hash = last_hash_clone.read().unwrap().clone().unwrap_or_default();
                    let last_timestamp = *last_sync_timestamp_clone.read().unwrap();
                    let policy_statuses = collect_policy_statuses(&stats_collector);

                    SyncRequest {
                        client_metadata: config.client_metadata.clone(),
                        full_sync: first,
                        last_sync_timestamp_unix_nano: last_timestamp,
                        last_successful_hash: last_hash,
                        policy_statuses,
                    }
                };

                first = false;

                // Build HTTP request
                let mut http_request = client.post(&config.url);
                for (key, value) in &config.headers {
                    http_request = http_request.header(key, value);
                }

                let result = async {
                    let response = match config.content_type {
                        ContentType::Protobuf => {
                            let body = request.encode_to_vec();
                            http_request
                                .header("Content-Type", "application/x-protobuf")
                                .header("Accept", "application/x-protobuf")
                                .body(body)
                                .send()
                                .await
                                .map_err(|e| PolicyError::HttpError(e.to_string()))?
                        }
                        ContentType::Json => http_request
                            .header("Content-Type", "application/json")
                            .header("Accept", "application/json")
                            .json(&request)
                            .send()
                            .await
                            .map_err(|e| PolicyError::HttpError(e.to_string()))?,
                    };

                    if !response.status().is_success() {
                        return Err(PolicyError::HttpError(format!(
                            "HTTP error: {} - {}",
                            response.status(),
                            response
                                .text()
                                .await
                                .unwrap_or_else(|_| "unknown".to_string())
                        )));
                    }

                    let sync_response: SyncResponse = match config.content_type {
                        ContentType::Protobuf => {
                            let bytes = response
                                .bytes()
                                .await
                                .map_err(|e| PolicyError::HttpError(e.to_string()))?;
                            SyncResponse::decode(bytes)
                                .map_err(|e| PolicyError::HttpError(e.to_string()))?
                        }
                        ContentType::Json => response
                            .json()
                            .await
                            .map_err(|e| PolicyError::HttpError(e.to_string()))?,
                    };

                    if !sync_response.error_message.is_empty() {
                        return Err(PolicyError::HttpError(format!(
                            "Sync error: {}",
                            sync_response.error_message
                        )));
                    }

                    // Update state and capture the new hash
                    let new_hash = if !sync_response.hash.is_empty() {
                        let hash = Some(sync_response.hash);
                        *last_hash_clone.write().unwrap() = hash.clone();
                        hash
                    } else {
                        None
                    };
                    if sync_response.sync_timestamp_unix_nano > 0 {
                        *last_sync_timestamp_clone.write().unwrap() =
                            sync_response.sync_timestamp_unix_nano;
                    }

                    let policies: Vec<Policy> = sync_response
                        .policies
                        .into_iter()
                        .map(Policy::new)
                        .collect();

                    Ok((new_hash, policies))
                }
                .await;

                if tx.send(result).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        rx
    }

    /// Stop the polling loop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl PolicyProvider for HttpProvider {
    fn load(&self) -> Result<Vec<Policy>, PolicyError> {
        // Use tokio runtime to run the async sync
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| PolicyError::HttpError("No tokio runtime available".to_string()))?;

        rt.block_on(self.sync(true))
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        // Do an initial sync
        let policies = self.load()?;
        callback(policies);

        // Get the initial hash to track changes
        let initial_hash = self.last_hash.read().unwrap().clone();

        // Start polling in background
        let mut rx = self.start_polling();
        let callback = callback.clone();

        tokio::spawn(async move {
            let mut last_known_hash = initial_hash;

            while let Some(result) = rx.recv().await {
                match result {
                    Ok((new_hash, policies)) => {
                        // Only call callback if the hash has changed
                        if new_hash != last_known_hash {
                            last_known_hash = new_hash;
                            callback(policies);
                        }
                    }
                    Err(e) => {
                        eprintln!("HTTP provider sync error: {}", e);
                        // Continue polling on error - fail open
                    }
                }
            }
        });

        Ok(())
    }
}
