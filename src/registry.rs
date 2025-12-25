//! Policy registry for managing policies from multiple providers.
//!
//! The registry aggregates policies from multiple providers and provides
//! lock-free access to an immutable snapshot of all policies.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::Policy;
use crate::engine::CompiledMatchers;
use crate::error::PolicyError;
use crate::provider::PolicyProvider;

/// Unique identifier for a registered provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderId(u64);

/// Statistics for a single policy.
#[derive(Debug, Default)]
pub struct PolicyStats {
    pub match_hits: AtomicU64,
    pub match_misses: AtomicU64,
}

impl PolicyStats {
    /// Increment match hits.
    pub fn record_hit(&self) {
        self.match_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment match misses.
    pub fn record_miss(&self) {
        self.match_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current hit count.
    pub fn hits(&self) -> u64 {
        self.match_hits.load(Ordering::Relaxed)
    }

    /// Get current miss count.
    pub fn misses(&self) -> u64 {
        self.match_misses.load(Ordering::Relaxed)
    }

    /// Reset stats and return previous values.
    pub fn reset(&self) -> (u64, u64) {
        let hits = self.match_hits.swap(0, Ordering::Relaxed);
        let misses = self.match_misses.swap(0, Ordering::Relaxed);
        (hits, misses)
    }
}

/// A policy with its associated provider and stats.
#[derive(Debug)]
pub struct PolicyEntry {
    /// The policy itself.
    pub policy: Policy,
    /// The provider this policy came from.
    pub provider_id: ProviderId,
    /// Statistics for this policy.
    pub stats: Arc<PolicyStats>,
}

/// An immutable snapshot of all policies.
///
/// This is cheap to clone (just an Arc) and provides lock-free read access.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    inner: Arc<SnapshotInner>,
}

#[derive(Debug)]
struct SnapshotInner {
    /// All policies indexed by ID.
    policies: Vec<PolicyEntry>,
    /// Index from policy ID to position in policies vec.
    index: HashMap<String, usize>,
    /// Compiled matchers for efficient evaluation.
    compiled: Option<CompiledMatchers>,
}

impl PolicySnapshot {
    /// Create an empty snapshot.
    fn empty() -> Self {
        Self {
            inner: Arc::new(SnapshotInner {
                policies: Vec::new(),
                index: HashMap::new(),
                compiled: None,
            }),
        }
    }

    /// Get all policies.
    pub fn policies(&self) -> &[PolicyEntry] {
        &self.inner.policies
    }

    /// Get a policy by ID.
    pub fn get(&self, id: &str) -> Option<&PolicyEntry> {
        self.inner
            .index
            .get(id)
            .map(|&idx| &self.inner.policies[idx])
    }

    /// Get the number of policies.
    pub fn len(&self) -> usize {
        self.inner.policies.len()
    }

    /// Check if the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.policies.is_empty()
    }

    /// Iterate over all policies.
    pub fn iter(&self) -> impl Iterator<Item = &PolicyEntry> {
        self.inner.policies.iter()
    }

    /// Get the compiled matchers for efficient evaluation.
    pub fn compiled_matchers(&self) -> Option<&CompiledMatchers> {
        self.inner.compiled.as_ref()
    }
}

/// A policy with its stats, used internally by the registry.
type PolicyWithStats = (Policy, Arc<PolicyStats>);

/// Policies grouped by provider.
type ProviderPolicies = HashMap<ProviderId, Vec<PolicyWithStats>>;

/// Callback handle returned when registering a provider.
///
/// The provider uses this to notify the registry of policy updates.
#[derive(Clone)]
pub struct ProviderHandle {
    provider_id: ProviderId,
    registry: Arc<RegistryInner>,
}

impl ProviderHandle {
    /// Update the policies for this provider.
    ///
    /// This replaces all policies from this provider with the new set.
    pub fn update(&self, policies: Vec<Policy>) {
        self.registry.update_provider(self.provider_id, policies);
    }

    /// Get the provider ID.
    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
}

/// Internal state of the registry.
struct RegistryInner {
    /// Counter for generating unique provider IDs.
    next_provider_id: AtomicU64,
    /// Policies grouped by provider, protected by a lock for writes.
    providers: RwLock<ProviderPolicies>,
    /// The current snapshot, atomically swapped on updates.
    snapshot: RwLock<PolicySnapshot>,
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            next_provider_id: AtomicU64::new(0),
            providers: RwLock::new(HashMap::new()),
            snapshot: RwLock::new(PolicySnapshot::empty()),
        }
    }

    fn register_provider(&self) -> ProviderId {
        let id = ProviderId(self.next_provider_id.fetch_add(1, Ordering::Relaxed));
        let mut providers = self.providers.write().unwrap();
        providers.insert(id, Vec::new());
        id
    }

    fn update_provider(&self, provider_id: ProviderId, policies: Vec<Policy>) {
        // Create new stats for each policy, preserving existing stats where possible
        let mut providers = self.providers.write().unwrap();

        // Build a map of existing stats by policy ID
        let existing_stats: HashMap<String, Arc<PolicyStats>> = providers
            .get(&provider_id)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(p, s)| (p.id().to_string(), Arc::clone(s)))
                    .collect()
            })
            .unwrap_or_default();

        // Create new entries, reusing stats where policy ID matches
        let new_entries: Vec<(Policy, Arc<PolicyStats>)> = policies
            .into_iter()
            .map(|policy| {
                let stats = existing_stats.get(policy.id()).cloned().unwrap_or_default();
                (policy, stats)
            })
            .collect();

        providers.insert(provider_id, new_entries);

        // Rebuild the snapshot
        self.rebuild_snapshot(&providers);
    }

    fn rebuild_snapshot(&self, providers: &ProviderPolicies) {
        let mut policies = Vec::new();
        let mut index = HashMap::new();

        // Collect all policies with their stats for compilation
        let mut policies_for_compile: Vec<(Policy, Arc<PolicyStats>)> = Vec::new();

        for (&provider_id, entries) in providers {
            for (policy, stats) in entries {
                let idx = policies.len();
                index.insert(policy.id().to_string(), idx);
                policies.push(PolicyEntry {
                    policy: policy.clone(),
                    provider_id,
                    stats: Arc::clone(stats),
                });
                policies_for_compile.push((policy.clone(), Arc::clone(stats)));
            }
        }

        // Compile matchers
        let compiled = match CompiledMatchers::build(policies_for_compile.into_iter()) {
            Ok(matchers) => Some(matchers),
            Err(e) => {
                // Log error but continue - fail open
                eprintln!("Failed to compile policy matchers: {}", e);
                None
            }
        };

        let new_snapshot = PolicySnapshot {
            inner: Arc::new(SnapshotInner {
                policies,
                index,
                compiled,
            }),
        };

        let mut snapshot = self.snapshot.write().unwrap();
        *snapshot = new_snapshot;
    }

    fn snapshot(&self) -> PolicySnapshot {
        self.snapshot.read().unwrap().clone()
    }
}

/// Registry for managing policies from multiple providers.
///
/// The registry aggregates policies from multiple providers and provides
/// lock-free access to an immutable snapshot of all policies.
///
/// # Example
///
/// ```ignore
/// let registry = PolicyRegistry::new();
///
/// // Subscribe to a provider - the registry will receive updates automatically
/// let provider = FileProvider::new("policies.json");
/// registry.subscribe(&provider)?;
///
/// // Engine gets a snapshot for evaluation (O(1), lock-free)
/// let snapshot = registry.snapshot();
/// for entry in snapshot.iter() {
///     // evaluate policy...
///     entry.stats.record_hit();
/// }
/// ```
pub struct PolicyRegistry {
    inner: Arc<RegistryInner>,
}

impl PolicyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner::new()),
        }
    }

    /// Subscribe to a policy provider.
    ///
    /// The registry will receive policy updates from this provider automatically.
    /// The provider's callback will be invoked immediately with the current policies,
    /// and again whenever the provider detects changes.
    ///
    /// Returns the provider ID on success, or an error if the initial load fails.
    pub fn subscribe(&self, provider: &dyn PolicyProvider) -> Result<ProviderId, PolicyError> {
        let handle = self.register_provider();
        let provider_id = handle.provider_id();

        // Create a callback that updates the registry
        let callback = {
            let handle = handle.clone();
            Arc::new(move |policies: Vec<Policy>| {
                handle.update(policies);
            })
        };

        // Subscribe to the provider - this will invoke the callback immediately
        provider.subscribe(callback)?;

        Ok(provider_id)
    }

    /// Register a new provider and return a handle for manual updates.
    ///
    /// This is a lower-level API for providers that don't implement the
    /// subscription model. Prefer `subscribe()` when possible.
    ///
    /// The handle can be cloned and used from any thread to push
    /// policy updates to the registry.
    fn register_provider(&self) -> ProviderHandle {
        let provider_id = self.inner.register_provider();
        ProviderHandle {
            provider_id,
            registry: Arc::clone(&self.inner),
        }
    }

    /// Get a snapshot of all policies.
    ///
    /// This is O(1) and lock-free - it just clones an Arc.
    /// The snapshot is immutable and can be used without blocking
    /// the registry from receiving updates.
    pub fn snapshot(&self) -> PolicySnapshot {
        self.inner.snapshot()
    }

    /// Get the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.inner.providers.read().unwrap().len()
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::Policy as ProtoPolicy;

    fn make_policy(id: &str) -> Policy {
        Policy::new(ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            ..Default::default()
        })
    }

    #[test]
    fn empty_registry() {
        let registry = PolicyRegistry::new();
        let snapshot = registry.snapshot();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.len(), 0);
    }

    #[test]
    fn register_provider() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        assert_eq!(registry.provider_count(), 1);
        assert_eq!(handle.provider_id(), ProviderId(0));

        let handle2 = registry.register_provider();
        assert_eq!(registry.provider_count(), 2);
        assert_eq!(handle2.provider_id(), ProviderId(1));
    }

    #[test]
    fn update_policies() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        let policies = vec![make_policy("policy-1"), make_policy("policy-2")];
        handle.update(policies);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.get("policy-1").is_some());
        assert!(snapshot.get("policy-2").is_some());
    }

    #[test]
    fn multiple_providers() {
        let registry = PolicyRegistry::new();
        let handle1 = registry.register_provider();
        let handle2 = registry.register_provider();

        handle1.update(vec![make_policy("provider1-policy")]);
        handle2.update(vec![make_policy("provider2-policy")]);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 2);

        let entry1 = snapshot.get("provider1-policy").unwrap();
        let entry2 = snapshot.get("provider2-policy").unwrap();
        assert_eq!(entry1.provider_id, ProviderId(0));
        assert_eq!(entry2.provider_id, ProviderId(1));
    }

    #[test]
    fn update_replaces_policies() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        handle.update(vec![make_policy("old-policy")]);
        assert_eq!(registry.snapshot().len(), 1);
        assert!(registry.snapshot().get("old-policy").is_some());

        handle.update(vec![make_policy("new-policy")]);
        assert_eq!(registry.snapshot().len(), 1);
        assert!(registry.snapshot().get("old-policy").is_none());
        assert!(registry.snapshot().get("new-policy").is_some());
    }

    #[test]
    fn stats_preserved_on_update() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        handle.update(vec![make_policy("policy-1")]);
        let snapshot1 = registry.snapshot();
        let entry1 = snapshot1.get("policy-1").unwrap();
        entry1.stats.record_hit();
        entry1.stats.record_hit();
        assert_eq!(entry1.stats.hits(), 2);

        // Update with same policy ID - stats should be preserved
        handle.update(vec![make_policy("policy-1")]);
        let snapshot2 = registry.snapshot();
        let entry2 = snapshot2.get("policy-1").unwrap();
        assert_eq!(entry2.stats.hits(), 2);
    }

    #[test]
    fn snapshot_is_immutable() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();

        handle.update(vec![make_policy("policy-1")]);
        let snapshot1 = registry.snapshot();
        assert_eq!(snapshot1.len(), 1);

        // Update registry
        handle.update(vec![make_policy("policy-1"), make_policy("policy-2")]);

        // Original snapshot unchanged
        assert_eq!(snapshot1.len(), 1);

        // New snapshot has updates
        let snapshot2 = registry.snapshot();
        assert_eq!(snapshot2.len(), 2);
    }

    #[test]
    fn snapshot_clone_is_cheap() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![make_policy("policy-1")]);

        let snapshot1 = registry.snapshot();
        let snapshot2 = snapshot1.clone();

        // Both point to same underlying data
        assert!(Arc::ptr_eq(&snapshot1.inner, &snapshot2.inner));
    }

    #[test]
    fn stats_recording() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![make_policy("policy-1")]);

        let snapshot = registry.snapshot();
        let entry = snapshot.get("policy-1").unwrap();

        entry.stats.record_hit();
        entry.stats.record_hit();
        entry.stats.record_miss();

        assert_eq!(entry.stats.hits(), 2);
        assert_eq!(entry.stats.misses(), 1);

        let (hits, misses) = entry.stats.reset();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
        assert_eq!(entry.stats.hits(), 0);
        assert_eq!(entry.stats.misses(), 0);
    }

    #[test]
    fn iterate_policies() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![
            make_policy("policy-1"),
            make_policy("policy-2"),
            make_policy("policy-3"),
        ]);

        let snapshot = registry.snapshot();
        let ids: Vec<&str> = snapshot.iter().map(|e| e.policy.id()).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"policy-1"));
        assert!(ids.contains(&"policy-2"));
        assert!(ids.contains(&"policy-3"));
    }

    #[test]
    fn subscribe_to_file_provider() {
        use crate::provider::FileProvider;

        let registry = PolicyRegistry::new();
        let provider = FileProvider::new("testdata/policies.json");

        let provider_id = registry.subscribe(&provider).unwrap();
        assert_eq!(provider_id, ProviderId(0));
        assert_eq!(registry.provider_count(), 1);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 6);

        // Verify policies came from the correct provider
        for entry in snapshot.iter() {
            assert_eq!(entry.provider_id, provider_id);
        }
    }

    #[test]
    fn subscribe_to_multiple_providers() {
        use crate::provider::FileProvider;

        let registry = PolicyRegistry::new();

        // Subscribe to same file twice (simulating multiple providers)
        let provider1 = FileProvider::new("testdata/policies.json");
        let provider2 = FileProvider::new("testdata/policies.json");

        let id1 = registry.subscribe(&provider1).unwrap();
        let id2 = registry.subscribe(&provider2).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(registry.provider_count(), 2);

        // Each provider contributes its own policies, so we have 12 total
        // (6 from each provider). The snapshot index will map each policy ID
        // to the last occurrence, but all 12 entries are in the policies vec.
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 12);

        // Verify we have policies from both providers
        let provider1_count = snapshot.iter().filter(|e| e.provider_id == id1).count();
        let provider2_count = snapshot.iter().filter(|e| e.provider_id == id2).count();
        assert_eq!(provider1_count, 6);
        assert_eq!(provider2_count, 6);
    }

    #[test]
    fn snapshot_policies_method() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![make_policy("policy-1"), make_policy("policy-2")]);

        let snapshot = registry.snapshot();
        let policies = snapshot.policies();

        assert_eq!(policies.len(), 2);
        assert!(policies.iter().any(|e| e.policy.id() == "policy-1"));
        assert!(policies.iter().any(|e| e.policy.id() == "policy-2"));
    }

    #[test]
    fn registry_default() {
        let registry = PolicyRegistry::default();
        assert!(registry.snapshot().is_empty());
        assert_eq!(registry.provider_count(), 0);
    }
}
