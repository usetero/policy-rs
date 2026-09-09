//! HTTP-based policy provider.
//!
//! This provider polls an HTTP endpoint for policy updates using the
//! SyncRequest/SyncResponse protobuf protocol.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::proto::tero::policy::v1::{ClientMetadata, SyncRequest, SyncResponse};

use super::sync::{PendingVolume, collect_policy_statuses};
use super::{PolicyCallback, PolicyProvider, StatsCollector, SyncResult};
use crate::volume::VolumeTracker;

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
///
/// Keep the provider alive for as long as you poll. [`PolicyRegistry::subscribe`]
/// borrows the provider, and the poll loop holds only shared state, so a dropped
/// provider leaves the loop running with no way to reach [`Self::flush`] or
/// [`Self::stop`].
///
/// [`PolicyRegistry::subscribe`]: crate::PolicyRegistry::subscribe
pub struct HttpProvider {
    inner: Arc<Inner>,
    polling_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Cached policies from initial async fetch (used to avoid blocking in subscribe).
    initial_policies: RwLock<Option<Vec<Policy>>>,
}

/// Sync state shared by polling and on-demand requests.
struct Inner {
    config: HttpProviderConfig,
    client: reqwest::Client,
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

/// Request timeout of the client that [`HttpProvider::new`] builds.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Send a sync request and decode the response.
    async fn send(&self, request: SyncRequest) -> Result<SyncResponse, PolicyError> {
        let mut http_request = self.client.post(&self.config.url);

        for (key, value) in &self.config.headers {
            http_request = http_request.header(key, value);
        }

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
                        text.chars().take(500).collect::<String>()
                    ))
                })?
            }
        };

        if !sync_response.error_message.is_empty() {
            return Err(PolicyError::HttpError(format!(
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

impl HttpProvider {
    /// Create a new HTTP provider with the given configuration.
    ///
    /// This is synchronous and does not perform an initial fetch.
    /// Use [`HttpProvider::new_with_initial_fetch`] if you need to fetch
    /// policies during construction.
    ///
    /// The client it builds uses a 30 second request timeout. Use
    /// [`HttpProvider::with_client`] to supply your own client instead.
    ///
    /// # Panics
    ///
    /// Panics if no rustls crypto provider is available, which is the case under
    /// the `http-no-roots` feature until the consumer supplies one (a root
    /// feature such as `webpki-roots`, or a process-default provider it installs
    /// itself). The `http` feature includes both. Also panics if the HTTP client
    /// cannot be built.
    pub fn new(config: HttpProviderConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");
        Self::with_client(config, client)
    }

    /// Create a new HTTP provider that sends every request with `client`.
    ///
    /// Use this when the client needs settings this crate does not expose, such
    /// as a FIPS-validated TLS backend. Set a request timeout on the client:
    /// `reqwest` has no default, so a request that stalls can hang.
    pub fn with_client(config: HttpProviderConfig, client: reqwest::Client) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                client,
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

    /// Create a new HTTP provider and perform an initial fetch.
    ///
    /// This async constructor fetches policies immediately during construction,
    /// which is useful when you need policies available before starting the
    /// polling loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial HTTP fetch fails.
    pub async fn new_with_initial_fetch(config: HttpProviderConfig) -> Result<Self, PolicyError> {
        let provider = Self::new(config);
        provider.fetch_initial().await?;
        Ok(provider)
    }

    /// Fetch the initial policies that [`PolicyProvider::subscribe`] requires.
    ///
    /// [`HttpProvider::new_with_initial_fetch`] calls this for you. Call it
    /// directly after [`HttpProvider::with_client`], which has no async form.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP fetch fails.
    pub async fn fetch_initial(&self) -> Result<(), PolicyError> {
        let policies = self.inner.sync(true).await?.1;
        *self.initial_policies.write().unwrap() = Some(policies);
        Ok(())
    }

    /// Load policies from the HTTP endpoint.
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
    /// Returns an error if the HTTP request fails.
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

impl PolicyProvider for HttpProvider {
    fn set_stats_collector(&self, collector: StatsCollector) {
        *self.inner.stats_collector.write().unwrap() = Some(collector);
    }

    fn set_volume_tracker(&self, tracker: Arc<VolumeTracker>) {
        *self.inner.volume_tracker.write().unwrap() = Some(tracker);
    }

    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
        // Use cached policies from new_with_initial_fetch()
        let policies = self.initial_policies.write().unwrap().take().expect(
            "HttpProvider::subscribe() requires fetch_initial() or new_with_initial_fetch()",
        );
        callback(policies);
        *self.inner.callback.write().unwrap() = Some(callback);

        // Start polling in background. Every sync applies the callback itself,
        // so this only drains the channel and reports errors.
        let mut rx = self.start_polling();

        tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                if let Err(e) = result {
                    eprintln!("HTTP provider sync error: {}", e);
                    // Continue polling on error - fail open
                }
            }
        });

        Ok(())
    }
}

// `reqwest::Client::new()` panics with "No provider set" unless a crypto
// provider is compiled in, and `http-no-roots` deliberately omits one.
#[cfg(all(test, any(feature = "webpki-roots", feature = "native-roots")))]
mod tests {
    use super::*;

    /// A provider pointed at a port nothing listens on, so every sync fails.
    fn unreachable_provider() -> (HttpProvider, Arc<VolumeTracker>) {
        let provider = HttpProvider::new(
            HttpProviderConfig::new("http://127.0.0.1:1").poll_interval(Duration::from_secs(3600)),
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
        tracker.record_log();
        tracker.add_log_bytes(400);

        let (request, pending) = provider.inner.build_sync_request(true);
        let volume = request.volume.unwrap();
        assert_eq!(volume.log_records, 1);
        assert_eq!(volume.log_bytes, 400);

        pending.commit();
        // A successful sync does not report the delta again.
        assert!(provider.inner.build_sync_request(true).0.volume.is_none());
    }

    #[tokio::test]
    async fn failed_sync_keeps_volume_for_the_next_one() {
        let (provider, tracker) = unreachable_provider();
        tracker.record_log();
        tracker.add_log_bytes(400);

        assert!(provider.flush().await.is_err());

        // The server never received the delta, so it is still there to report.
        let volume = tracker.collect().unwrap();
        assert_eq!(volume.log_records, 1);
        assert_eq!(volume.log_bytes, 400);
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
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    struct Exchange {
        request: SyncRequest,
        headers: String,
        reply: oneshot::Sender<(u16, Vec<u8>)>,
    }

    impl Exchange {
        fn respond(self, content_type: ContentType, response: SyncResponse) {
            let body = match content_type {
                ContentType::Protobuf => response.encode_to_vec(),
                ContentType::Json => serde_json::to_vec(&response).unwrap(),
            };
            self.reply.send((200, body)).unwrap();
        }
    }

    async fn server(content_type: ContentType) -> (String, mpsc::Receiver<Exchange>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut socket = BufReader::new(socket);
                    let mut headers = String::new();
                    loop {
                        let mut line = String::new();
                        if socket.read_line(&mut line).await.unwrap() == 0 {
                            return;
                        }
                        headers.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    let request = match content_type {
                        ContentType::Protobuf => SyncRequest::decode(body.as_slice()).unwrap(),
                        ContentType::Json => serde_json::from_slice(&body).unwrap(),
                    };
                    let (reply, response) = oneshot::channel();
                    if tx
                        .send(Exchange {
                            request,
                            headers,
                            reply,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if let Ok((status, body)) = response.await {
                        let headers = format!(
                            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        if socket.get_mut().write_all(headers.as_bytes()).await.is_ok() {
                            let _ = socket.get_mut().write_all(&body).await;
                        }
                    }
                });
            }
        });
        (url, rx)
    }

    async fn next(rx: &mut mpsc::Receiver<Exchange>) -> Exchange {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn flush_task(
        provider: &Arc<HttpProvider>,
    ) -> tokio::task::JoinHandle<Result<(), PolicyError>> {
        let provider = provider.clone();
        tokio::spawn(async move { provider.flush().await })
    }

    #[tokio::test]
    async fn flush_reports_stats_and_shares_ordered_state_with_polling_and_load() {
        for content_type in [ContentType::Protobuf, ContentType::Json] {
            let (url, mut requests) = server(content_type).await;
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("x-custom-client", "present".parse().unwrap());
            let client = reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .unwrap();
            let provider = Arc::new(HttpProvider::with_client(
                HttpProviderConfig::new(url).content_type(content_type),
                client,
            ));
            let initial = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.fetch_initial().await })
            };
            let request = next(&mut requests).await;
            assert!(request.request.full_sync);
            request.respond(
                content_type,
                SyncResponse {
                    hash: "initial".into(),
                    sync_timestamp_unix_nano: 1,
                    ..Default::default()
                },
            );
            initial.await.unwrap().unwrap();

            let (updates, mut callbacks) = mpsc::unbounded_channel();
            provider
                .subscribe(Arc::new(move |policies| {
                    updates.send(policies.len()).unwrap();
                }))
                .unwrap();
            assert_eq!(callbacks.recv().await, Some(0));
            let poll = next(&mut requests).await;
            assert_eq!(poll.request.last_successful_hash, "initial");
            assert_eq!(poll.request.last_sync_timestamp_unix_nano, 1);
            poll.respond(
                content_type,
                SyncResponse {
                    hash: "polled".into(),
                    sync_timestamp_unix_nano: 2,
                    ..Default::default()
                },
            );
            assert_eq!(
                timeout(Duration::from_secs(5), callbacks.recv())
                    .await
                    .unwrap(),
                Some(0)
            );

            let tracker = Arc::new(VolumeTracker::new());
            provider.set_volume_tracker(tracker.clone());
            tracker.record_log();
            tracker.add_log_bytes(42);
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
            assert!(request.headers.contains("x-custom-client: present"));
            assert_eq!(request.request.last_successful_hash, "polled");
            assert_eq!(request.request.last_sync_timestamp_unix_nano, 2);
            assert_eq!(request.request.volume.unwrap().log_bytes, 42);
            assert_eq!(request.request.policy_statuses[0].id, "policy-1");
            assert_eq!(request.request.policy_statuses[0].match_hits, 3);

            let load = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.load().await })
            };
            assert!(
                timeout(Duration::from_millis(30), requests.recv())
                    .await
                    .is_err(),
                "concurrent load must wait for flush"
            );
            request.respond(
                content_type,
                SyncResponse {
                    hash: "flushed".into(),
                    sync_timestamp_unix_nano: 3,
                    policies: vec![Default::default()],
                    ..Default::default()
                },
            );
            flush.await.unwrap().unwrap();
            assert_eq!(callbacks.recv().await, Some(1));
            let request = next(&mut requests).await;
            assert!(request.request.full_sync);
            assert_eq!(request.request.last_successful_hash, "flushed");
            assert_eq!(request.request.last_sync_timestamp_unix_nano, 3);
            assert!(request.request.volume.is_none());
            request.respond(
                content_type,
                SyncResponse {
                    hash: "flushed".into(),
                    sync_timestamp_unix_nano: 4,
                    ..Default::default()
                },
            );
            load.await.unwrap().unwrap();
            assert!(
                callbacks.try_recv().is_err(),
                "unchanged hash must not clear policies"
            );
            provider.stop();
        }
    }

    #[tokio::test]
    async fn http_and_decode_and_sync_errors_retry_volume_until_success() {
        for content_type in [ContentType::Protobuf, ContentType::Json] {
            let (url, mut requests) = server(content_type).await;
            let provider = Arc::new(HttpProvider::new(
                HttpProviderConfig::new(url).content_type(content_type),
            ));
            let tracker = Arc::new(VolumeTracker::new());
            provider.set_volume_tracker(tracker.clone());
            tracker.record_log();
            for failure in 0..3 {
                let flush = flush_task(&provider);
                let request = next(&mut requests).await;
                assert_eq!(request.request.volume.unwrap().log_records, failure + 1);
                tracker.record_log(); // New observations must survive restoration too.
                match failure {
                    0 => request.reply.send((503, Vec::new())).unwrap(),
                    1 => request
                        .reply
                        .send((200, "€".repeat(300).into_bytes()))
                        .unwrap(),
                    _ => request.respond(
                        content_type,
                        SyncResponse {
                            error_message: "retry later".into(),
                            ..Default::default()
                        },
                    ),
                }
                assert!(flush.await.unwrap().is_err());
            }
            let flush = flush_task(&provider);
            let request = next(&mut requests).await;
            assert_eq!(request.request.volume.unwrap().log_records, 4);
            request.respond(content_type, SyncResponse::default());
            flush.await.unwrap().unwrap();
            assert!(tracker.collect().is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_flush_restores_to_original_tracker() {
        let (url, mut requests) = server(ContentType::Protobuf).await;
        let provider = Arc::new(HttpProvider::new(HttpProviderConfig::new(url)));
        let original = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(original.clone());
        original.record_log();
        let flush = flush_task(&provider);
        let _request = next(&mut requests).await;
        let replacement = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(replacement.clone());
        original.record_log();
        flush.abort();
        assert!(flush.await.unwrap_err().is_cancelled());
        assert_eq!(original.collect().unwrap().log_records, 2);
        assert!(replacement.collect().is_none());
    }

    #[tokio::test]
    async fn stop_cancels_in_flight_poll_and_flush_remains_available() {
        let (url, mut requests) = server(ContentType::Protobuf).await;
        let provider = Arc::new(HttpProvider::new(HttpProviderConfig::new(url)));
        let tracker = Arc::new(VolumeTracker::new());
        provider.set_volume_tracker(tracker.clone());
        tracker.record_log();
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
        assert_eq!(request.request.volume.unwrap().log_records, 1);
        request.respond(ContentType::Protobuf, SyncResponse::default());
        flush.await.unwrap().unwrap();
        assert!(tracker.collect().is_none());
    }

    #[tokio::test]
    async fn default_and_custom_client_timeouts_restore_volume() {
        for custom_timeout in [None, Some(Duration::from_secs(2))] {
            let (url, mut requests) = server(ContentType::Protobuf).await;
            let config = HttpProviderConfig::new(url);
            let provider = Arc::new(match custom_timeout {
                None => HttpProvider::new(config),
                Some(timeout) => HttpProvider::with_client(
                    config,
                    reqwest::Client::builder().timeout(timeout).build().unwrap(),
                ),
            });
            let tracker = Arc::new(VolumeTracker::new());
            provider.set_volume_tracker(tracker.clone());
            tracker.record_log();
            let flush = flush_task(&provider);
            let _request = next(&mut requests).await;
            tokio::time::pause();
            tokio::time::advance(
                custom_timeout.unwrap_or(Duration::from_secs(30)) + Duration::from_secs(1),
            )
            .await;
            assert!(
                timeout(Duration::from_secs(5), flush)
                    .await
                    .expect("client timeout did not fire")
                    .unwrap()
                    .is_err()
            );
            tokio::time::resume();
            assert_eq!(tracker.collect().unwrap().log_records, 1);
        }
    }

    #[tokio::test]
    async fn stop_cancels_a_poll_blocked_on_a_full_channel() {
        let (provider, _) = unreachable_provider();
        // A very short interval fills the output channel without a consumer.
        let mut config = provider.inner.config.clone();
        config.poll_interval_ns = 1;
        let provider = HttpProvider::new(config);
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
