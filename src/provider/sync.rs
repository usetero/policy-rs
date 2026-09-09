//! Shared sync utilities for HTTP and gRPC providers.

use std::sync::{Arc, Mutex};

use crate::policy::Policy;
use crate::proto::tero::policy::v1::{PolicySyncStatus, TransformStageStatus, VolumeStats};
use crate::registry::PolicyStatsSnapshot;
use crate::volume::VolumeTracker;

use super::{PolicyCallback, StatsCollector};

/// Serializes initial delivery and later updates, retaining the latest update
/// until the subscriber is ready. The mutex covers callback execution so an
/// update cannot overtake the initial callback.
#[derive(Default)]
pub(super) struct PolicySubscription {
    state: Mutex<SubscriptionState>,
}

#[derive(Default)]
struct SubscriptionState {
    pending: Option<Vec<Policy>>,
    callback: Option<PolicyCallback>,
}

impl PolicySubscription {
    pub(super) fn subscribe(&self, initial: Vec<Policy>, callback: PolicyCallback) {
        let mut state = self.state.lock().unwrap();
        callback(state.pending.take().unwrap_or(initial));
        state.callback = Some(callback);
    }

    pub(super) fn update(&self, policies: Vec<Policy>) {
        let mut state = self.state.lock().unwrap();
        if let Some(callback) = &state.callback {
            callback(policies);
        } else {
            state.pending = Some(policies);
        }
    }
}

/// Convert a PolicyStatsSnapshot to a PolicySyncStatus for reporting.
pub fn stats_to_sync_status(id: String, stats: PolicyStatsSnapshot) -> PolicySyncStatus {
    PolicySyncStatus {
        id,
        match_hits: stats.match_hits as i64,
        match_misses: stats.match_misses as i64,
        errors: stats.compilation_errors,
        remove: Some(TransformStageStatus {
            hits: stats.remove.0 as i64,
            misses: stats.remove.1 as i64,
        }),
        redact: Some(TransformStageStatus {
            hits: stats.redact.0 as i64,
            misses: stats.redact.1 as i64,
        }),
        rename: Some(TransformStageStatus {
            hits: stats.rename.0 as i64,
            misses: stats.rename.1 as i64,
        }),
        add: Some(TransformStageStatus {
            hits: stats.add.0 as i64,
            misses: stats.add.1 as i64,
        }),
    }
}

/// A drained delta that returns to its original tracker unless acknowledged.
/// Drop also covers cancelled requests and aborted polling tasks.
pub(super) struct PendingVolume {
    tracker: Option<Arc<VolumeTracker>>,
    stats: Option<VolumeStats>,
}

impl PendingVolume {
    pub(super) fn new(tracker: Option<Arc<VolumeTracker>>) -> Self {
        let stats = tracker.as_ref().and_then(|tracker| tracker.collect());
        Self { tracker, stats }
    }

    pub(super) fn stats(&self) -> Option<VolumeStats> {
        self.stats
    }

    pub(super) fn commit(mut self) {
        self.stats = None;
    }
}

impl Drop for PendingVolume {
    fn drop(&mut self) {
        if let (Some(tracker), Some(stats)) = (&self.tracker, &self.stats) {
            tracker.restore(stats);
        }
    }
}

/// Collect policy statuses from a stats collector.
pub fn collect_policy_statuses(collector: &Option<StatsCollector>) -> Vec<PolicySyncStatus> {
    collector
        .as_ref()
        .map(|c| {
            c().into_iter()
                .map(|(id, stats)| stats_to_sync_status(id, stats))
                .collect()
        })
        .unwrap_or_default()
}
