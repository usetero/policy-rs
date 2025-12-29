//! Policy providers for loading policies from various sources.

mod file;
#[cfg(feature = "grpc")]
mod grpc;
#[cfg(feature = "http")]
mod http;
#[cfg(any(feature = "http", feature = "grpc"))]
mod sync;

pub use file::FileProvider;
#[cfg(feature = "grpc")]
pub use grpc::{GrpcProvider, GrpcProviderConfig};
#[cfg(feature = "http")]
pub use http::{ContentType, HttpProvider, HttpProviderConfig};
#[cfg(any(feature = "http", feature = "grpc"))]
pub use sync::StatsCollector;

use std::sync::Arc;

use crate::error::PolicyError;
use crate::policy::Policy;

/// Callback type for policy updates.
pub type PolicyCallback = Arc<dyn Fn(Vec<Policy>) + Send + Sync>;

/// Trait for policy providers.
///
/// Providers load policies and notify subscribers when policies change.
pub trait PolicyProvider: Send + Sync {
    /// Load policies from the provider.
    ///
    /// This performs an immediate load and returns the current policies.
    fn load(&self) -> Result<Vec<Policy>, PolicyError>;

    /// Subscribe to policy updates.
    ///
    /// The callback will be invoked whenever the provider detects policy changes.
    /// The provider should also invoke the callback immediately with the current
    /// policies upon subscription.
    ///
    /// Returns an error if the initial load fails.
    fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError>;
}
