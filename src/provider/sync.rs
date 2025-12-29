//! Shared sync utilities for HTTP and gRPC providers.

use std::sync::Arc;

use crate::proto::tero::policy::v1::{PolicySyncStatus, TransformStageStatus};
use crate::registry::PolicyStatsSnapshot;

/// Stats collector function type.
/// Returns a list of policy IDs with their stats snapshots.
pub type StatsCollector = Arc<dyn Fn() -> Vec<(String, PolicyStatsSnapshot)> + Send + Sync>;

/// Convert a PolicyStatsSnapshot to a PolicySyncStatus for reporting.
pub fn stats_to_sync_status(id: String, stats: PolicyStatsSnapshot) -> PolicySyncStatus {
    PolicySyncStatus {
        id,
        match_hits: stats.match_hits as i64,
        match_misses: stats.match_misses as i64,
        errors: vec![],
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
