//! gRPC-based policy provider.
//!
//! This provider polls a gRPC endpoint for policy updates using the
//! PolicyService.Sync RPC.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::policy_service_client::PolicyServiceClient;
use crate::proto::tero::policy::v1::{ClientMetadata, SyncRequest, SyncResponse};

use super::sync::{PendingVolume, collect_policy_statuses};
use super::{PolicyCallback, PolicyProvider, StatsCollector, SyncResult};
use crate::volume::VolumeTracker;

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
///
/// Keep the provider alive for as long as you poll. [`PolicyRegistry::subscribe`]
/// borrows the provider, and the poll loop holds only shared state, so a dropped
/// provider leaves the loop running with no way to reach [`Self::flush`] or
/// [`Self::stop`].
///
/// [`PolicyRegistry::subscribe`]: crate::PolicyRegistry::subscribe
pub struct GrpcProvider {
    inner: Arc<Inner>,
    polling_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Cached policies from initial async fetch (used to avoid blocking in subscribe).
    initial_policies: RwLock<Option<Vec<Policy>>>,
}

/// Sync state shared by polling and on-demand requests.
struct Inner {
    config: GrpcProviderConfig,
    /// Last successful sync hash for change detection.
    last_hash: RwLock<Option<String>>,
    /// Last sync timestamp.
    last_sync_timestamp: RwLock<u64>,
    /// Serialize requests and callbacks so an older response cannot overwrite a newer one.
    sync_lock: tokio::sync::Mutex<()>,
    /// Stats collector for reporting policy statistics.
    stats_collector: RwLock<Option<StatsCollector>>,
    /// Tracker for reporting total observed telemetry volume.
    volume_tracker: RwLock<Option<Arc<VolumeTracker>>>,
    /// Subscriber callback, invoked when a sync returns a new hash.
    callback: RwLock<Option<PolicyCallback>>,
}

impl Inner {
    /// Build a sync request with current state.
    fn build_sync_request(&self, full_sync: bool) -> (SyncRequest, PendingVolume) {
        let last_hash = self.last_hash.read().unwrap().clone().unwrap_or_default();
        let last_timestamp = *self.last_sync_timestamp.read().unwrap();
        let policy_statuses = collect_policy_statuses(&self.stats_collector.read().unwrap());
        let volume = PendingVolume::new(self.volume_tracker.read().unwrap().clone());

        let request = SyncRequest {
            client_metadata: self.config.client_metadata.clone(),
            full_sync,
            last_sync_timestamp_unix_nano: last_timestamp,
            last_successful_hash: last_hash,
            policy_statuses,
            volume: volume.stats(),
        };
        (request, volume)
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

    /// Perform a single sync: send the request, then apply the response.
    ///
    /// Returns the new hash, which is `None` when the response carries none, and
    /// the policies. Unacknowledged volume returns to its original tracker on
    /// errors or cancellation (including a caller's timeout).
    async fn sync(&self, full_sync: bool) -> SyncResult {
        let _sync = self.sync_lock.lock().await;
        let (request, volume) = self.build_sync_request(full_sync);
        let response = self.send(request).await?;
        volume.commit();
        Ok(self.apply(response))
    }

    /// Send a sync request over a fresh channel.
    async fn send(&self, request: SyncRequest) -> Result<SyncResponse, PolicyError> {
        let endpoint = Endpoint::from_shared(self.config.url.clone())
            .map_err(|e| PolicyError::GrpcError(format!("Invalid URL: {}", e)))?;

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| PolicyError::GrpcError(format!("Connection failed: {}", e)))?;

        let mut client = PolicyServiceClient::new(channel);

        let response = client
            .sync(self.create_request(request))
            .await
            .map_err(|e| PolicyError::GrpcError(format!("Sync RPC failed: {}", e)))?;

        let sync_response = response.into_inner();

        if !sync_response.error_message.is_empty() {
            return Err(PolicyError::GrpcError(format!(
                "Sync error: {}",
                sync_response.error_message
            )));
        }

        Ok(sync_response)
    }

    /// Store the new state and notify the subscriber when the hash changed.
    fn apply(&self, response: SyncResponse) -> (Option<String>, Vec<Policy>) {
        let new_hash = (!response.hash.is_empty()).then_some(response.hash);

        let changed = {
            let mut last_hash = self.last_hash.write().unwrap();
            let changed = new_hash.is_some() && new_hash != *last_hash;
            if changed {
                last_hash.clone_from(&new_hash);
            }
            changed
        };
        if response.sync_timestamp_unix_nano > 0 {
            *self.last_sync_timestamp.write().unwrap() = response.sync_timestamp_unix_nano;
        }

        let policies: Vec<Policy> = response.policies.into_iter().map(Policy::new).collect();

        if changed {
            // Clone the callback out first: it must not run under the lock.
            let callback = self.callback.read().unwrap().clone();
            if let Some(callback) = callback {
                callback(policies.clone());
            }
        }

        (new_hash, policies)
    }
}

impl GrpcProvider {
    /// Create a new gRPC provider with the given configuration.
    ///
    /// This is synchronous and does not perform an initial fetch.
    /// Use [`GrpcProvider::new_with_initial_fetch`] if you need to fetch
    /// policies during construction.
    pub fn new(config: GrpcProviderConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                last_hash: RwLock::new(None),
                last_sync_timestamp: RwLock::new(0),
                sync_lock: tokio::sync::Mutex::new(()),
                stats_collector: RwLock::new(None),
                volume_tracker: RwLock::new(None),
                callback: RwLock::new(None),
            }),
            polling_task: Mutex::new(None),
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
        let policies = provider.inner.sync(true).await?.1;
        *provider.initial_policies.write().unwrap() = Some(policies);
        Ok(provider)
    }

    /// Load policies from the gRPC endpoint.
    ///
    /// This performs a one-shot async fetch and returns the current policies.
    pub async fn load(&self) -> Result<Vec<Policy>, PolicyError> {
        Ok(self.inner.sync(true).await?.1)
    }

    /// Send the pending policy statuses and volume now, and wait for the result.
    ///
    /// The poll loop is a timer, so a process that loses its CPU between
    /// invocations, such as an AWS Lambda extension, cannot rely on it. Call
    /// this at a point where the process is sure to run, such as the end of an
    /// invocation and at shutdown. A failed flush keeps the volume for the next
    /// one, including when the flush future is cancelled. Concurrent syncs wait
    /// for the current request to finish.
    ///
    /// This is an incremental sync. Policy changes in the response reach the
    /// subscriber through the same callback the poll loop uses.
    ///
    /// # Errors
    ///
    /// Returns an error if the gRPC request fails.
    pub async fn flush(&self) -> Result<(), PolicyError> {
        self.inner.sync(false).await.map(|_| ())
    }

    /// Start the polling loop.
    ///
    /// Returns a channel receiver that will receive policy updates.
    /// Each successful result includes the hash and the policies. Starting a
    /// new loop cancels any previous loop, including its in-flight request.
    pub fn start_polling(&self) -> mpsc::Receiver<SyncResult> {
        let (tx, rx) = mpsc::channel(16);

        let inner = Arc::clone(&self.inner);
        let mut polling_task = self.polling_task.lock().unwrap();
        if let Some(task) = polling_task.take() {
            task.abort();
        }

        let task = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_nanos(inner.config.poll_interval_ns));

            // Do an initial full sync
            let mut first = true;

            loop {
                ticker.tick().await;
                let result = inner.sync(first).await;
                first = false;

                if tx.send(result).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });
        *polling_task = Some(task.abort_handle());

        rx
    }

    /// Cancel the polling loop, including any in-flight request.
    ///
    /// Cancellation takes effect when the runtime next polls the task and
    /// restores unacknowledged volume. On-demand [`Self::flush`] remains usable.
    pub fn stop(&self) {
        if let Some(task) = self.polling_task.lock().unwrap().take() {
            task.abort();
        }
    }
}

impl PolicyProvider for GrpcProvider {
    fn set_stats_collector(&self, collector: StatsCollector) {
        *self.inner.stats_collector.write().unwrap() = Some(collector);
    }

    fn set_volume_tracker(&self, tracker: Arc<VolumeTracker>) {
        *self.inner.volume_tracker.write().unwrap() = Some(tracker);
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        // Use cached policies from new_with_initial_fetch()
        let policies = self
            .initial_policies
            .write()
            .unwrap()
            .take()
            .expect("GrpcProvider::subscribe() requires new_with_initial_fetch()");
        callback(policies);
        *self.inner.callback.write().unwrap() = Some(callback);

        // Start polling in background. Every sync applies the callback itself,
        // so this only drains the channel and reports errors.
        let mut rx = self.start_polling();

        tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                if let Err(e) = result {
                    eprintln!("gRPC provider sync error: {}", e);
                    // Continue polling on error - fail open
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider pointed at a port nothing listens on, so every sync fails.
    fn unreachable_provider() -> (GrpcProvider, Arc<VolumeTracker>) {
        let provider = GrpcProvider::new(
            GrpcProviderConfig::new("http://127.0.0.1:1").poll_interval(Duration::from_secs(3600)),
        );
        let tracker = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(Arc::clone(&tracker));
        (provider, tracker)
    }

    #[test]
    fn sync_request_omits_untracked_volume() {
        let (provider, _tracker) = unreachable_provider();
        assert!(provider.inner.build_sync_request(true).0.volume.is_none());
    }

    #[test]
    fn sync_request_drains_observed_volume() {
        let (provider, tracker) = unreachable_provider();
        tracker.record_span();
        tracker.add_span_bytes(11);

        let (request, pending) = provider.inner.build_sync_request(true);
        let volume = request.volume.unwrap();
        assert_eq!(volume.spans, 1);
        assert_eq!(volume.span_bytes, 11);

        pending.commit();
        // A successful sync does not report the delta again.
        assert!(provider.inner.build_sync_request(true).0.volume.is_none());
    }

    #[tokio::test]
    async fn failed_sync_keeps_volume_for_the_next_one() {
        let (provider, tracker) = unreachable_provider();
        tracker.record_span();
        tracker.add_span_bytes(11);

        assert!(provider.flush().await.is_err());

        // The server never received the delta, so it is still there to report.
        let volume = tracker.collect().unwrap();
        assert_eq!(volume.spans, 1);
        assert_eq!(volume.span_bytes, 11);
    }

    #[tokio::test]
    async fn stop_ends_the_poll_loop() {
        let (provider, _tracker) = unreachable_provider();

        let mut rx = provider.start_polling();
        assert!(rx.recv().await.is_some(), "the loop polls at least once");

        provider.stop();

        // Cancellation closes the channel without waiting for another tick.
        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.recv().await.is_some() {}
        })
        .await;
        assert!(drained.is_ok(), "the poll loop ran on after stop()");
    }
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use tonic::codegen::{Body, BoxFuture, Service, StdError, http};

    struct Exchange {
        request: SyncRequest,
        reply: oneshot::Sender<Result<SyncResponse, tonic::Status>>,
    }

    // Minimal real tonic service so tests exercise encoding, RPC failures and
    // responses without adding server code to the library's generated API.
    #[derive(Clone)]
    struct TestService(mpsc::Sender<Exchange>);

    impl tonic::server::NamedService for TestService {
        const NAME: &'static str = "tero.policy.v1.PolicyService";
    }

    impl tonic::server::UnaryService<SyncRequest> for TestService {
        type Response = SyncResponse;
        type Future = BoxFuture<tonic::Response<SyncResponse>, tonic::Status>;

        fn call(&mut self, request: tonic::Request<SyncRequest>) -> Self::Future {
            let tx = self.0.clone();
            Box::pin(async move {
                let (reply, response) = oneshot::channel();
                tx.send(Exchange {
                    request: request.into_inner(),
                    reply,
                })
                .await
                .unwrap();
                response.await.unwrap().map(tonic::Response::new)
            })
        }
    }

    impl<B> Service<http::Request<B>> for TestService
    where
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            assert_eq!(request.uri().path(), "/tero.policy.v1.PolicyService/Sync");
            let service = self.clone();
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic::codec::ProstCodec::default());
                Ok(grpc.unary(service, request).await)
            })
        }
    }

    async fn server() -> (Arc<GrpcProvider>, mpsc::Receiver<Exchange>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = Arc::new(GrpcProvider::new(GrpcProviderConfig::new(format!(
            "http://{}",
            listener.local_addr().unwrap()
        ))));
        let (tx, rx) = mpsc::channel(16);
        let incoming =
            tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TestService(tx))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        (provider, rx)
    }

    async fn next(rx: &mut mpsc::Receiver<Exchange>) -> Exchange {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn flush_task(
        provider: &Arc<GrpcProvider>,
    ) -> tokio::task::JoinHandle<Result<(), PolicyError>> {
        let provider = provider.clone();
        tokio::spawn(async move { provider.flush().await })
    }

    #[tokio::test]
    async fn flush_reports_stats_and_shares_ordered_state_with_polling_and_load() {
        let (provider, mut requests) = server().await;
        let tracker = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(tracker.clone());
        let (updates, mut callbacks) = mpsc::unbounded_channel();
        *provider.inner.callback.write().unwrap() = Some(Arc::new(move |policies| {
            updates.send(policies.len()).unwrap();
        }));
        let mut polling = provider.start_polling();
        let request = next(&mut requests).await;
        assert!(request.request.full_sync);
        request
            .reply
            .send(Ok(SyncResponse {
                hash: "polled".into(),
                sync_timestamp_unix_nano: 1,
                ..Default::default()
            }))
            .unwrap();
        polling.recv().await.unwrap().unwrap();
        assert_eq!(callbacks.recv().await, Some(0));
        tracker.record_span();
        tracker.add_span_bytes(42);
        provider.set_stats_collector(Arc::new(|| {
            vec![(
                "policy-1".into(),
                crate::PolicyStatsSnapshot {
                    match_hits: 3,
                    ..Default::default()
                },
            )]
        }));
        let flush = flush_task(&provider);
        let request = next(&mut requests).await;
        assert!(!flush.is_finished());
        assert!(!request.request.full_sync);
        assert_eq!(request.request.last_successful_hash, "polled");
        assert_eq!(request.request.last_sync_timestamp_unix_nano, 1);
        assert_eq!(request.request.volume.unwrap().span_bytes, 42);
        assert_eq!(request.request.policy_statuses[0].match_hits, 3);
        let load = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.load().await })
        };
        assert!(
            timeout(Duration::from_millis(30), requests.recv())
                .await
                .is_err()
        );
        request
            .reply
            .send(Ok(SyncResponse {
                hash: "flushed".into(),
                sync_timestamp_unix_nano: 2,
                policies: vec![Default::default()],
                ..Default::default()
            }))
            .unwrap();
        flush.await.unwrap().unwrap();
        assert_eq!(callbacks.recv().await, Some(1));
        let request = next(&mut requests).await;
        assert!(request.request.full_sync);
        assert_eq!(request.request.last_successful_hash, "flushed");
        assert_eq!(request.request.last_sync_timestamp_unix_nano, 2);
        assert!(request.request.volume.is_none());
        request
            .reply
            .send(Ok(SyncResponse {
                hash: "flushed".into(),
                ..Default::default()
            }))
            .unwrap();
        load.await.unwrap().unwrap();
        assert!(callbacks.try_recv().is_err());
        provider.stop();
    }

    #[tokio::test]
    async fn rpc_and_sync_errors_retry_volume_until_success() {
        let (provider, mut requests) = server().await;
        let tracker = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(tracker.clone());
        tracker.record_span();
        for failure in 0..2 {
            let flush = flush_task(&provider);
            let request = next(&mut requests).await;
            assert_eq!(request.request.volume.unwrap().spans, failure + 1);
            tracker.record_span();
            request
                .reply
                .send(if failure == 0 {
                    Err(tonic::Status::unavailable("retry later"))
                } else {
                    Ok(SyncResponse {
                        error_message: "retry later".into(),
                        ..Default::default()
                    })
                })
                .unwrap();
            assert!(flush.await.unwrap().is_err());
        }
        let flush = flush_task(&provider);
        let request = next(&mut requests).await;
        assert_eq!(request.request.volume.unwrap().spans, 3);
        request.reply.send(Ok(SyncResponse::default())).unwrap();
        flush.await.unwrap().unwrap();
        assert!(tracker.collect().is_none());
    }

    #[tokio::test]
    async fn cancelled_flush_restores_to_original_tracker() {
        let (provider, mut requests) = server().await;
        let original = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(original.clone());
        original.record_span();
        let flush = flush_task(&provider);
        let _request = next(&mut requests).await;
        let replacement = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(replacement.clone());
        original.record_span();
        flush.abort();
        assert!(flush.await.unwrap_err().is_cancelled());
        assert_eq!(original.collect().unwrap().spans, 2);
        assert!(replacement.collect().is_none());
    }

    #[tokio::test]
    async fn stop_cancels_in_flight_poll_and_flush_remains_available() {
        let (provider, mut requests) = server().await;
        let tracker = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(tracker.clone());
        tracker.record_span();
        let mut polling = provider.start_polling();
        let _request = next(&mut requests).await;
        provider.stop();
        assert!(
            timeout(Duration::from_secs(1), polling.recv())
                .await
                .unwrap()
                .is_none()
        );
        let flush = flush_task(&provider);
        let request = next(&mut requests).await;
        assert_eq!(request.request.volume.unwrap().spans, 1);
        request.reply.send(Ok(SyncResponse::default())).unwrap();
        flush.await.unwrap().unwrap();
        assert!(tracker.collect().is_none());
    }

    #[tokio::test]
    async fn stop_cancels_a_poll_blocked_on_a_full_channel() {
        let (provider, _) = unreachable_provider();
        // A very short interval fills the output channel without a consumer.
        let mut config = provider.inner.config.clone();
        config.poll_interval_ns = 1;
        let provider = GrpcProvider::new(config);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        provider.set_stats_collector(Arc::new(move || {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Vec::new()
        }));
        let mut rx = provider.start_polling();
        timeout(Duration::from_secs(5), async {
            while calls.load(std::sync::atomic::Ordering::SeqCst) < 17 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        provider.stop();
        timeout(Duration::from_secs(1), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("stop must cancel a blocked sender");
    }

    #[tokio::test]
    async fn restarting_polling_does_not_revive_the_previous_loop() {
        let (provider, _) = unreachable_provider();
        let mut old = provider.start_polling();
        assert!(old.recv().await.unwrap().is_err());
        provider.stop();
        let mut new = provider.start_polling();
        assert!(
            timeout(Duration::from_secs(1), old.recv())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            timeout(Duration::from_secs(1), new.recv())
                .await
                .unwrap()
                .is_some()
        );
        provider.stop();
        assert!(
            timeout(Duration::from_secs(1), new.recv())
                .await
                .unwrap()
                .is_none()
        );
    }
}
