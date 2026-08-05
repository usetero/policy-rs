//! Shared sync utilities for HTTP and gRPC providers.

use std::sync::Arc;

use crate::proto::tero::policy::v1::{PolicySyncStatus, TransformStageStatus, VolumeStats};
use crate::registry::PolicyStatsSnapshot;
use crate::volume::VolumeTracker;

use super::StatsCollector;

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

/// Drain observed volume into a sync request, or `None` if there is nothing to
/// report. Each drain is a disjoint delta, so overlapping syncs never report the
/// same volume twice — but a sync that fails must hand its delta back with
/// [`return_volume`].
pub fn collect_volume(tracker: &Option<Arc<VolumeTracker>>) -> Option<VolumeStats> {
    tracker.as_ref().and_then(|t| t.collect())
}

/// Hand a drained delta back after a failed sync, so the next request reports
/// it. The spec requires the counters to be retained, not dropped.
pub fn return_volume(tracker: &Option<Arc<VolumeTracker>>, drained: Option<VolumeStats>) {
    if let (Some(tracker), Some(drained)) = (tracker, drained) {
        tracker.add(drained);
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
