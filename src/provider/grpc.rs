//! gRPC-based policy provider.
//!
//! This provider polls a gRPC endpoint for policy updates using the
//! PolicyService.Sync RPC.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::policy_service_client::PolicyServiceClient;
use crate::proto::tero::policy::v1::{ClientMetadata, SyncRequest};

use super::sync::{StatsCollector, collect_policy_statuses};
use super::{PolicyCallback, PolicyProvider};

/// Configuration for the gRPC provider.
#[derive(Debug, Clone)]
pub struct GrpcProviderConfig {
    /// The gRPC endpoint URL.
    pub url: String,
    /// Headers to include as gRPC metadata.
    pub headers: HashMap<String, String>,
    /// Polling interval in nanoseconds.
    pub poll_interval_ns: u64,
    /// Client metadata to include in sync requests.
    pub client_metadata: Option<ClientMetadata>,
}

impl GrpcProviderConfig {
    /// Create a new gRPC provider config with the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: HashMap::new(),
            poll_interval_ns: Duration::from_secs(60).as_nanos() as u64,
            client_metadata: None,
        }
    }

    /// Set a header (will be sent as gRPC metadata).
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
}

/// gRPC-based policy provider.
///
/// This provider polls a gRPC endpoint at a configurable interval,
/// using the PolicyService.Sync RPC.
pub struct GrpcProvider {
    config: GrpcProviderConfig,
    /// Last successful sync hash for change detection.
    last_hash: RwLock<Option<String>>,
    /// Last sync timestamp.
    last_sync_timestamp: RwLock<u64>,
    /// Whether the provider is running.
    running: AtomicBool,
    /// Stats collector for reporting policy statistics.
    stats_collector: RwLock<Option<StatsCollector>>,
    /// Cached policies from initial async fetch (used to avoid blocking in subscribe).
    initial_policies: RwLock<Option<Vec<Policy>>>,
}

impl GrpcProvider {
    /// Create a new gRPC provider with the given configuration.
    ///
    /// This is synchronous and does not perform an initial fetch.
    /// Use [`GrpcProvider::new_with_initial_fetch`] if you need to fetch
    /// policies during construction.
    pub fn new(config: GrpcProviderConfig) -> Self {
        Self {
            config,
            last_hash: RwLock::new(None),
            last_sync_timestamp: RwLock::new(0),
            running: AtomicBool::new(false),
            stats_collector: RwLock::new(None),
            initial_policies: RwLock::new(None),
        }
    }

    /// Create a new gRPC provider and perform an initial fetch.
    ///
    /// This async constructor fetches policies immediately during construction,
    /// which is useful when you need policies available before starting the
    /// polling loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial gRPC fetch fails.
    pub async fn new_with_initial_fetch(config: GrpcProviderConfig) -> Result<Self, PolicyError> {
        let provider = Self::new(config);
        // Perform initial sync and cache the policies to avoid blocking in subscribe()
        let policies = provider.sync(true).await?;
        *provider.initial_policies.write().unwrap() = Some(policies);
        Ok(provider)
    }

    /// Fetch policies from the gRPC endpoint.
    ///
    /// This is an async method that can be used to manually trigger a sync.
    /// Returns the fetched policies.
    pub async fn fetch_policies(&self) -> Result<Vec<Policy>, PolicyError> {
        self.sync(true).await
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

    /// Create a gRPC channel with configured settings.
    async fn create_channel(&self) -> Result<Channel, PolicyError> {
        let endpoint = Endpoint::from_shared(self.config.url.clone())
            .map_err(|e| PolicyError::GrpcError(format!("Invalid URL: {}", e)))?;

        endpoint
            .connect()
            .await
            .map_err(|e| PolicyError::GrpcError(format!("Connection failed: {}", e)))
    }

    /// Create a request with metadata headers.
    fn create_request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);

        for (key, value) in &self.config.headers {
            if let (Ok(key), Ok(value)) = (
                key.parse::<tonic::metadata::MetadataKey<_>>(),
                value.parse::<MetadataValue<_>>(),
            ) {
                request.metadata_mut().insert(key, value);
            }
        }

        request
    }

    /// Perform a single sync operation.
    async fn sync(&self, full_sync: bool) -> Result<Vec<Policy>, PolicyError> {
        let channel = self.create_channel().await?;
        let mut client = PolicyServiceClient::new(channel);

        let sync_request = self.build_sync_request(full_sync);
        let request = self.create_request(sync_request);

        let response = client
            .sync(request)
            .await
            .map_err(|e| PolicyError::GrpcError(format!("Sync RPC failed: {}", e)))?;

        let sync_response = response.into_inner();

        // Check for errors in response
        if !sync_response.error_message.is_empty() {
            return Err(PolicyError::GrpcError(format!(
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
        let last_hash = Arc::new(RwLock::new(None::<String>));
        let last_sync_timestamp = Arc::new(RwLock::new(0u64));
        let stats_collector = self.stats_collector.read().unwrap().clone();
        let running = Arc::new(AtomicBool::new(true));

        let running_clone = running.clone();
        let last_hash_clone = last_hash.clone();
        let last_sync_timestamp_clone = last_sync_timestamp.clone();

        tokio::spawn(async move {
            let poll_duration = Duration::from_nanos(config.poll_interval_ns);
            let mut interval_timer = interval(poll_duration);

            // Do an initial full sync
            let mut first = true;

            while running_clone.load(Ordering::SeqCst) {
                interval_timer.tick().await;

                let result = async {
                    // Create channel
                    let endpoint = Endpoint::from_shared(config.url.clone())
                        .map_err(|e| PolicyError::GrpcError(format!("Invalid URL: {}", e)))?;

                    let channel = endpoint
                        .connect()
                        .await
                        .map_err(|e| PolicyError::GrpcError(format!("Connection failed: {}", e)))?;

                    let mut client = PolicyServiceClient::new(channel);

                    // Build request
                    let last_hash_val = last_hash_clone.read().unwrap().clone().unwrap_or_default();
                    let last_timestamp = *last_sync_timestamp_clone.read().unwrap();
                    let policy_statuses = collect_policy_statuses(&stats_collector);

                    let sync_request = SyncRequest {
                        client_metadata: config.client_metadata.clone(),
                        full_sync: first,
                        last_sync_timestamp_unix_nano: last_timestamp,
                        last_successful_hash: last_hash_val,
                        policy_statuses,
                    };

                    let mut request = Request::new(sync_request);
                    for (key, value) in &config.headers {
                        if let (Ok(key), Ok(value)) = (
                            key.parse::<tonic::metadata::MetadataKey<_>>(),
                            value.parse::<MetadataValue<_>>(),
                        ) {
                            request.metadata_mut().insert(key, value);
                        }
                    }

                    let response = client
                        .sync(request)
                        .await
                        .map_err(|e| PolicyError::GrpcError(format!("Sync RPC failed: {}", e)))?;

                    let sync_response = response.into_inner();

                    if !sync_response.error_message.is_empty() {
                        return Err(PolicyError::GrpcError(format!(
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

                first = false;

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

impl PolicyProvider for GrpcProvider {
    fn load(&self) -> Result<Vec<Policy>, PolicyError> {
        // Use tokio runtime to run the async sync
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| PolicyError::GrpcError("No tokio runtime available".to_string()))?;

        rt.block_on(self.sync(true))
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        // Use cached policies from async init if available, otherwise do a blocking load
        let policies = self
            .initial_policies
            .write()
            .unwrap()
            .take()
            .map(Ok)
            .unwrap_or_else(|| self.load())?;
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
                        eprintln!("gRPC provider sync error: {}", e);
                        // Continue polling on error - fail open
                    }
                }
            }
        });

        Ok(())
    }
}
