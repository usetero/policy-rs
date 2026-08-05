//! Total observed telemetry volume, reported via `SyncRequest.volume`.
//!
//! Match statistics ([`PolicyStats`](crate::PolicyStats)) only count records a
//! policy matched. A [`VolumeTracker`] counts the denominator: everything that
//! entered policy evaluation, whether or not any policy matched it.
//!
//! Record counts are automatic — [`PolicyEngine`](crate::PolicyEngine) counts
//! every record it evaluates, including records that match nothing and records
//! evaluated with no policies loaded for their signal. Byte counts are opt-in:
//! call [`VolumeTracker::add_log_bytes`] and friends with the uncompressed OTLP
//! protobuf size of the records as received (an estimate is fine). A size in any
//! other encoding must never be reported — leave it at zero instead.

use std::sync::atomic::{AtomicI64, Ordering};

use crate::proto::tero::policy::v1::VolumeStats;

/// Counts telemetry entering policy evaluation, regardless of policy match.
///
/// Reachable from a registry via [`PolicyRegistry::volume()`], which is also how
/// the HTTP and gRPC providers report it: each sync request drains the counters.
///
/// Counting happens before the keep and transform stages, so dropped,
/// sampled-out, and redacted records are all included at their pre-policy size.
///
/// [`PolicyRegistry::volume()`]: crate::PolicyRegistry::volume
///
/// # Example
///
/// ```ignore
/// let registry = PolicyRegistry::new();
/// registry.subscribe(&provider)?;
///
/// // Optional: byte counts, which the engine cannot measure for you.
/// registry.volume().add_log_bytes(request.encoded_len() as i64);
///
/// // Record counts happen here, automatically.
/// engine.evaluate(&registry.snapshot(), &record)?;
/// ```
#[derive(Debug, Default)]
pub struct VolumeTracker {
    log_records: AtomicI64,
    log_bytes: AtomicI64,
    metric_data_points: AtomicI64,
    metric_bytes: AtomicI64,
    spans: AtomicI64,
    span_bytes: AtomicI64,
}

impl VolumeTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one log record entering evaluation.
    pub(crate) fn record_log(&self) {
        self.log_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one metric data point entering evaluation.
    pub(crate) fn record_metric(&self) {
        self.metric_data_points.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one span entering evaluation.
    pub(crate) fn record_span(&self) {
        self.spans.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to the reported log byte volume.
    ///
    /// Records are counted automatically by the engine; bytes are opt-in and
    /// must be the uncompressed OTLP protobuf serialized size of the records as
    /// received. Leave them unreported rather than reporting another encoding.
    pub fn add_log_bytes(&self, bytes: i64) {
        self.log_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to the reported metric byte volume. See [`Self::add_log_bytes`].
    pub fn add_metric_bytes(&self, bytes: i64) {
        self.metric_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to the reported span byte volume. See [`Self::add_log_bytes`].
    pub fn add_span_bytes(&self, bytes: i64) {
        self.span_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Atomically read and reset the counters, returning the delta since the
    /// last call.
    ///
    /// Returns `None` when nothing has been observed — the spec says to omit
    /// `volume` rather than send a zero-valued message. Counters reset on read
    /// whether or not the sync carrying them succeeds: a failed sync drops its
    /// interval rather than replaying it, since the server cannot tell a replay
    /// from new telemetry. Reported volume is a lower bound, not an exact total.
    pub fn collect(&self) -> Option<VolumeStats> {
        let stats = VolumeStats {
            log_records: self.log_records.swap(0, Ordering::Relaxed),
            log_bytes: self.log_bytes.swap(0, Ordering::Relaxed),
            metric_data_points: self.metric_data_points.swap(0, Ordering::Relaxed),
            metric_bytes: self.metric_bytes.swap(0, Ordering::Relaxed),
            spans: self.spans.swap(0, Ordering::Relaxed),
            span_bytes: self.span_bytes.swap(0, Ordering::Relaxed),
        };

        (stats != VolumeStats::default()).then_some(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_reports_nothing() {
        assert!(VolumeTracker::new().collect().is_none());
    }

    #[test]
    fn counts_records_per_signal() {
        let t = VolumeTracker::new();
        t.record_log();
        t.record_log();
        t.record_metric();
        t.record_span();

        let stats = t.collect().unwrap();
        assert_eq!(stats.log_records, 2);
        assert_eq!(stats.metric_data_points, 1);
        assert_eq!(stats.spans, 1);
        assert_eq!(stats.log_bytes, 0, "bytes are opt-in");
    }

    #[test]
    fn bytes_are_opt_in() {
        let t = VolumeTracker::new();
        t.add_log_bytes(120);
        t.add_log_bytes(30);
        t.add_metric_bytes(7);
        t.add_span_bytes(9);

        let stats = t.collect().unwrap();
        assert_eq!(stats.log_bytes, 150);
        assert_eq!(stats.metric_bytes, 7);
        assert_eq!(stats.span_bytes, 9);
        assert_eq!(stats.log_records, 0);
    }

    #[test]
    fn collect_drains_so_deltas_never_repeat() {
        let t = VolumeTracker::new();
        t.record_log();

        assert_eq!(t.collect().unwrap().log_records, 1);
        assert!(t.collect().is_none());
    }

    /// Overlapping syncs each drain a disjoint delta, so the total reported
    /// across all of them is exactly what was observed — no double counting,
    /// no loss.
    #[test]
    fn concurrent_collects_do_not_double_count() {
        use std::sync::Arc;
        use std::thread;

        const RECORDS: i64 = 500;

        let tracker = Arc::new(VolumeTracker::new());
        for _ in 0..RECORDS {
            tracker.record_log();
        }

        let drainers: Vec<_> = (0..8)
            .map(|_| {
                let tracker = Arc::clone(&tracker);
                thread::spawn(move || tracker.collect().map(|s| s.log_records).unwrap_or_default())
            })
            .collect();

        let reported: i64 = drainers.into_iter().map(|h| h.join().unwrap()).sum();
        let left = tracker.collect().map(|s| s.log_records).unwrap_or_default();
        assert_eq!(reported + left, RECORDS);
    }
}
