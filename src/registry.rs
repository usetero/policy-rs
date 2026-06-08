//! Policy registry for managing policies from multiple providers.
//!
//! The registry aggregates policies from multiple providers and provides
//! lock-free access to an immutable snapshot of all policies.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::Policy;
use crate::engine::CompiledMatchers;
use crate::engine::signal::{LogSignal, MetricSignal, TraceSignal};
use crate::error::PolicyError;
use crate::provider::{PolicyProvider, StatsCollector};

/// Unique identifier for a registered provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderId(u64);

/// Statistics for a transform stage (remove, redact, rename, add).
#[derive(Debug, Default)]
pub struct TransformStageStats {
    /// Number of times this stage was applied successfully.
    pub hits: AtomicU64,
    /// Number of times this stage was evaluated but the field selected nothing.
    pub misses: AtomicU64,
}

impl TransformStageStats {
    /// Record a successful transform application.
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed transform application (field not found).
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current hit count.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get current miss count.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Reset stats and return previous values.
    pub fn reset(&self) -> (u64, u64) {
        let hits = self.hits.swap(0, Ordering::Relaxed);
        let misses = self.misses.swap(0, Ordering::Relaxed);
        (hits, misses)
    }
}

/// Statistics for a single policy.
#[derive(Debug, Default)]
pub struct PolicyStats {
    /// Number of times this policy matched telemetry.
    pub match_hits: AtomicU64,
    /// Number of times this policy was evaluated but did not match.
    pub match_misses: AtomicU64,
    /// Statistics for the remove transform stage.
    pub remove: TransformStageStats,
    /// Statistics for the redact transform stage.
    pub redact: TransformStageStats,
    /// Statistics for the rename transform stage.
    pub rename: TransformStageStats,
    /// Statistics for the add transform stage.
    pub add: TransformStageStats,
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

    /// Reset match stats and return previous values.
    pub fn reset(&self) -> (u64, u64) {
        let hits = self.match_hits.swap(0, Ordering::Relaxed);
        let misses = self.match_misses.swap(0, Ordering::Relaxed);
        (hits, misses)
    }

    /// Reset all stats (match + transform stages) and return previous values.
    ///
    /// `compilation_errors` is always empty here; the registry's stats collector
    /// fills it in from the snapshot after calling this method.
    pub fn reset_all(&self) -> PolicyStatsSnapshot {
        PolicyStatsSnapshot {
            match_hits: self.match_hits.swap(0, Ordering::Relaxed),
            match_misses: self.match_misses.swap(0, Ordering::Relaxed),
            remove: self.remove.reset(),
            redact: self.redact.reset(),
            rename: self.rename.reset(),
            add: self.add.reset(),
            compilation_errors: Vec::new(),
        }
    }
}

/// A snapshot of all policy stats for reporting.
#[derive(Debug, Clone, Default)]
pub struct PolicyStatsSnapshot {
    pub match_hits: u64,
    pub match_misses: u64,
    pub remove: (u64, u64),
    pub redact: (u64, u64),
    pub rename: (u64, u64),
    pub add: (u64, u64),
    /// Compilation errors for this policy, if any.
    /// Populated by the registry's stats collector from the current snapshot.
    pub compilation_errors: Vec<String>,
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
    /// Compiled matchers for log policies.
    compiled_logs: Option<CompiledMatchers<LogSignal>>,
    /// Compiled matchers for metric policies.
    compiled_metrics: Option<CompiledMatchers<MetricSignal>>,
    /// Compiled matchers for trace policies.
    compiled_traces: Option<CompiledMatchers<TraceSignal>>,
    /// Per-policy compilation errors collected across all signal batches.
    compilation_errors: HashMap<String, Vec<String>>,
}

impl PolicySnapshot {
    /// Create an empty snapshot.
    fn empty() -> Self {
        Self {
            inner: Arc::new(SnapshotInner {
                policies: Vec::new(),
                index: HashMap::new(),
                compiled_logs: None,
                compiled_metrics: None,
                compiled_traces: None,
                compilation_errors: HashMap::new(),
            }),
        }
    }

    /// Return the compilation errors for a policy, or an empty slice if none.
    pub fn compilation_errors_for(&self, policy_id: &str) -> &[String] {
        self.inner
            .compilation_errors
            .get(policy_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
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

    /// Get the compiled log matchers for efficient evaluation.
    pub fn compiled_log_matchers(&self) -> Option<&CompiledMatchers<LogSignal>> {
        self.inner.compiled_logs.as_ref()
    }

    /// Get the compiled metric matchers for efficient evaluation.
    pub fn compiled_metric_matchers(&self) -> Option<&CompiledMatchers<MetricSignal>> {
        self.inner.compiled_metrics.as_ref()
    }

    /// Get the compiled trace matchers for efficient evaluation.
    pub fn compiled_trace_matchers(&self) -> Option<&CompiledMatchers<TraceSignal>> {
        self.inner.compiled_traces.as_ref()
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

        // Collect all policies with their stats, partitioned by signal type
        let mut log_policies: Vec<(Policy, Arc<PolicyStats>)> = Vec::new();
        let mut metric_policies: Vec<(Policy, Arc<PolicyStats>)> = Vec::new();
        let mut trace_policies: Vec<(Policy, Arc<PolicyStats>)> = Vec::new();

        for (&provider_id, entries) in providers {
            for (policy, stats) in entries {
                let idx = policies.len();
                index.insert(policy.id().to_string(), idx);
                policies.push(PolicyEntry {
                    policy: policy.clone(),
                    provider_id,
                    stats: Arc::clone(stats),
                });

                if policy.log_target().is_some() {
                    log_policies.push((policy.clone(), Arc::clone(stats)));
                } else if policy.metric_target().is_some() {
                    metric_policies.push((policy.clone(), Arc::clone(stats)));
                } else if policy.trace_target().is_some() {
                    trace_policies.push((policy.clone(), Arc::clone(stats)));
                }
            }
        }

        // Sort by policy ID for deterministic transform ordering (spec requirement)
        log_policies.sort_by(|a, b| a.0.id().cmp(b.0.id()));
        metric_policies.sort_by(|a, b| a.0.id().cmp(b.0.id()));
        trace_policies.sort_by(|a, b| a.0.id().cmp(b.0.id()));

        let mut compilation_errors: HashMap<String, Vec<String>> = HashMap::new();

        // Compile log matchers
        let compiled_logs = if !log_policies.is_empty() {
            match CompiledMatchers::<LogSignal>::build(log_policies.into_iter()) {
                Ok(matchers) => {
                    compilation_errors.extend(matchers.compilation_errors.clone());
                    Some(matchers)
                }
                Err(e) => {
                    eprintln!("Failed to compile log policy matchers: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Compile metric matchers
        let compiled_metrics = if !metric_policies.is_empty() {
            match CompiledMatchers::<MetricSignal>::build(metric_policies.into_iter()) {
                Ok(matchers) => {
                    compilation_errors.extend(matchers.compilation_errors.clone());
                    Some(matchers)
                }
                Err(e) => {
                    eprintln!("Failed to compile metric policy matchers: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Compile trace matchers
        let compiled_traces = if !trace_policies.is_empty() {
            match CompiledMatchers::<TraceSignal>::build(trace_policies.into_iter()) {
                Ok(matchers) => {
                    compilation_errors.extend(matchers.compilation_errors.clone());
                    Some(matchers)
                }
                Err(e) => {
                    eprintln!("Failed to compile trace policy matchers: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let new_snapshot = PolicySnapshot {
            inner: Arc::new(SnapshotInner {
                policies,
                index,
                compiled_logs,
                compiled_metrics,
                compiled_traces,
                compilation_errors,
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

        // Wire up stats collection so providers can report policy statistics
        let inner = Arc::clone(&self.inner);
        let collector: StatsCollector = Arc::new(move || {
            let snapshot = inner.snapshot();
            snapshot
                .iter()
                .map(|entry| {
                    let id = entry.policy.id().to_string();
                    let mut stats = entry.stats.reset_all();
                    stats.compilation_errors =
                        snapshot.compilation_errors_for(&id).to_vec();
                    (id, stats)
                })
                .collect()
        });
        provider.set_stats_collector(collector);

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
    pub fn register_provider(&self) -> ProviderHandle {
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
        assert_eq!(snapshot.len(), 16);

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

        // Each provider contributes its own policies, so we have 32 total
        // (16 from each provider). The snapshot index will map each policy ID
        // to the last occurrence, but all 32 entries are in the policies vec.
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 32);

        // Verify we have policies from both providers
        let provider1_count = snapshot.iter().filter(|e| e.provider_id == id1).count();
        let provider2_count = snapshot.iter().filter(|e| e.provider_id == id2).count();
        assert_eq!(provider1_count, 16);
        assert_eq!(provider2_count, 16);
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

    #[test]
    fn subscribe_auto_wires_stats_collector() {
        use crate::provider::{PolicyCallback, PolicyProvider, StatsCollector};
        use std::sync::RwLock;

        /// A test provider that captures the stats collector set by the registry.
        struct SpyProvider {
            policies: Vec<Policy>,
            collector: RwLock<Option<StatsCollector>>,
        }

        impl PolicyProvider for SpyProvider {
            fn set_stats_collector(&self, collector: StatsCollector) {
                *self.collector.write().unwrap() = Some(collector);
            }

            fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
                callback(self.policies.clone());
                Ok(())
            }
        }

        let provider = SpyProvider {
            policies: vec![make_policy("policy-1"), make_policy("policy-2")],
            collector: RwLock::new(None),
        };

        let registry = PolicyRegistry::new();
        registry.subscribe(&provider).unwrap();

        // Verify the collector was set
        let collector = provider.collector.read().unwrap();
        assert!(collector.is_some(), "stats collector should be auto-wired");

        // Record some stats
        let snapshot = registry.snapshot();
        let entry = snapshot.get("policy-1").unwrap();
        entry.stats.record_hit();
        entry.stats.record_hit();
        entry.stats.record_miss();

        // Call the collector and verify it returns the stats
        let stats = collector.as_ref().unwrap()();
        assert_eq!(stats.len(), 2);

        let p1_stats = stats.iter().find(|(id, _)| id == "policy-1").unwrap();
        assert_eq!(p1_stats.1.match_hits, 2);
        assert_eq!(p1_stats.1.match_misses, 1);

        // Stats should be reset after collection
        let stats_again = collector.as_ref().unwrap()();
        let p1_again = stats_again.iter().find(|(id, _)| id == "policy-1").unwrap();
        assert_eq!(p1_again.1.match_hits, 0);
        assert_eq!(p1_again.1.match_misses, 0);
    }

    fn make_log_policy_with_invalid_regex(id: &str) -> Policy {
        use crate::proto::tero::policy::v1::{
            LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher,
        };
        let proto = ProtoPolicy {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                LogTarget {
                    r#match: vec![LogMatcher {
                        field: Some(log_matcher::Field::LogField(
                            crate::proto::tero::policy::v1::LogField::Body.into(),
                        )),
                        r#match: Some(log_matcher::Match::Regex("([unclosed".to_string())),
                        negate: false,
                        case_insensitive: false,
                    }],
                    keep: "none".to_string(),
                    transform: None,
                    sample_key: None,
                },
            )),
            ..Default::default()
        };
        Policy::new(proto)
    }

    #[test]
    fn invalid_policy_compilation_errors_appear_in_snapshot() {
        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![make_log_policy_with_invalid_regex("broken")]);

        let snapshot = registry.snapshot();
        // The policy still appears in the snapshot even though it failed to compile.
        assert!(snapshot.get("broken").is_some(), "invalid policy still in snapshot");
        let errs = snapshot.compilation_errors_for("broken");
        assert!(!errs.is_empty(), "compilation errors must be in snapshot");
        assert!(
            errs[0].contains("invalid regex"),
            "error must describe the problem: {}", errs[0]
        );
    }

    #[test]
    fn invalid_policy_does_not_block_valid_peer() {
        use crate::proto::tero::policy::v1::{
            LogMatcher, LogTarget, Policy as ProtoPolicy, log_matcher,
        };

        let valid = Policy::new(ProtoPolicy {
            id: "valid".to_string(),
            name: "valid".to_string(),
            enabled: true,
            target: Some(crate::proto::tero::policy::v1::policy::Target::Log(
                LogTarget {
                    r#match: vec![LogMatcher {
                        field: Some(log_matcher::Field::LogField(
                            crate::proto::tero::policy::v1::LogField::Body.into(),
                        )),
                        r#match: Some(log_matcher::Match::Exact("error".to_string())),
                        negate: false,
                        case_insensitive: false,
                    }],
                    keep: "none".to_string(),
                    transform: None,
                    sample_key: None,
                },
            )),
            ..Default::default()
        });

        let registry = PolicyRegistry::new();
        let handle = registry.register_provider();
        handle.update(vec![make_log_policy_with_invalid_regex("broken"), valid]);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 2, "both policies are in the snapshot");
        // Valid policy compiles — compiled_log_matchers is Some with 1 policy
        let matchers = snapshot
            .compiled_log_matchers()
            .expect("log matchers compiled despite broken peer");
        assert_eq!(matchers.policies.len(), 1);
        assert_eq!(matchers.policies[0].id, "valid");
        // Broken policy has errors, valid does not
        assert!(!snapshot.compilation_errors_for("broken").is_empty());
        assert!(snapshot.compilation_errors_for("valid").is_empty());
    }

    #[test]
    fn stats_collector_includes_compilation_errors() {
        use crate::provider::{PolicyCallback, PolicyProvider, StatsCollector};
        use std::sync::RwLock;

        struct SpyProvider {
            policies: Vec<Policy>,
            collector: RwLock<Option<StatsCollector>>,
        }
        impl PolicyProvider for SpyProvider {
            fn set_stats_collector(&self, c: StatsCollector) {
                *self.collector.write().unwrap() = Some(c);
            }
            fn subscribe(&self, callback: PolicyCallback) -> Result<(), PolicyError> {
                callback(self.policies.clone());
                Ok(())
            }
        }

        let provider = SpyProvider {
            policies: vec![make_log_policy_with_invalid_regex("broken")],
            collector: RwLock::new(None),
        };

        let registry = PolicyRegistry::new();
        registry.subscribe(&provider).unwrap();

        let collector = provider.collector.read().unwrap();
        let stats = collector.as_ref().unwrap()();
        let broken = stats.iter().find(|(id, _)| id == "broken").unwrap();
        assert!(
            !broken.1.compilation_errors.is_empty(),
            "compilation errors must flow through stats collector"
        );
        assert!(
            broken.1.compilation_errors[0].contains("invalid regex"),
            "error text must be preserved: {}", broken.1.compilation_errors[0]
        );
    }
}
