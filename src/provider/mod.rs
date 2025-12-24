//! Policy providers for loading policies from various sources.

mod file;

pub use file::FileProvider;

use crate::error::PolicyError;
use crate::policy::Policy;

/// Trait for policy providers.
pub trait PolicyProvider: Send + Sync {
    /// Load policies from the provider.
    fn load(&self) -> Result<Vec<Policy>, PolicyError>;
}
