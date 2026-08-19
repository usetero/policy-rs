//! Policy providers for loading policies from various sources.

mod file;
#[cfg(feature = "grpc")]
mod grpc;
#[cfg(feature = "reqwest")]
mod http;
#[cfg(any(feature = "reqwest", feature = "grpc"))]
mod sync;

pub use file::FileProvider;
#[cfg(feature = "grpc")]
pub use grpc::{GrpcProvider, GrpcProviderConfig};
#[cfg(feature = "reqwest")]
pub use http::{ContentType, HttpProvider, HttpProviderConfig};
use std::sync::Arc;

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::registry::PolicyStatsSnapshot;
use crate::volume::VolumeTracker;

/// Callback type for policy updates.
pub type PolicyCallback = Arc<dyn Fn(Vec<Policy>) + Send + Sync>;

/// Stats collector function type.
/// Returns a list of policy IDs with their stats snapshots.
pub type StatsCollector = Arc<dyn Fn() -> Vec<(String, PolicyStatsSnapshot)> + Send + Sync>;

/// Trait for policy providers.
///
/// Providers notify subscribers when policies change. For one-shot loading,
/// use the `load()` method on the concrete provider type directly.
pub trait PolicyProvider: Send + Sync {
    /// Subscribe to policy updates.
    ///
    /// The callback will be invoked whenever the provider detects policy changes.
    /// The provider should also invoke the callback immediately with the current
    /// policies upon subscription.
    ///
    /// Returns an error if the initial load fails.
    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError>;

    /// Set a stats collector for reporting policy statistics back to the server.
    ///
    /// Called automatically by [`PolicyRegistry::subscribe()`]. Providers that
    /// report stats (HTTP, gRPC) should override this; the default is a no-op.
    fn set_stats_collector(&self, _collector: StatsCollector) {}

    /// Set the tracker for reporting total observed telemetry volume.
    ///
    /// Called automatically by [`PolicyRegistry::subscribe()`]. Providers that
    /// report volume (HTTP, gRPC) should override this; the default is a no-op.
    fn set_volume_tracker(&self, _tracker: Arc<VolumeTracker>) {}
}
