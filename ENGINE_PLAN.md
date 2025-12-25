# Policy Engine Implementation Plan

This document outlines the implementation plan for the policy evaluation engine
using hyperscan-tokio for high-performance multi-pattern matching.

## Overview

The engine evaluates log records against policies using a two-phase approach:

1. **Scan Phase**: Use Hyperscan to find all pattern matches across all fields
   in a single pass
2. **Evaluate Phase**: Determine which policies fully match (all matchers
   satisfied) and select the most restrictive keep action

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PolicySnapshot                               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    CompiledSnapshot                          │    │
│  │  ┌─────────────────────────────────────────────────────┐    │    │
│  │  │  FieldDatabases: HashMap<MatchKey, HyperscanDb>     │    │    │
│  │  │                                                      │    │    │
│  │  │  MatchKey = (LogFieldSelector, bool)  // (field, negated)│   │
│  │  │                                                      │    │    │
│  │  │  log_body (positive)     → DB with patterns [0,1,2]  │    │    │
│  │  │  log_body (negative)     → DB with patterns [3]      │    │    │
│  │  │  log_attribute:ddsource  → DB with patterns [4,5]    │    │    │
│  │  │  resource_attribute:svc  → DB with patterns [6]      │    │    │
│  │  └─────────────────────────────────────────────────────┘    │    │
│  │                                                              │    │
│  │  ┌─────────────────────────────────────────────────────┐    │    │
│  │  │  PolicyIndex: Vec<CompiledPolicyEntry>               │    │    │
│  │  │                                                      │    │    │
│  │  │  policy_id: "drop-debug"                             │    │    │
│  │  │  required_matches: [(log_body, false, pattern_id:0)] │    │    │
│  │  │  keep: CompiledKeep::None                            │    │    │
│  │  │  ...                                                 │    │    │
│  │  └─────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### MatchKey

Identifies a unique field + negation combination for grouping patterns:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchKey {
    pub field: LogFieldSelector,
    pub negated: bool,
}
```

### CompiledSnapshot

Extends PolicySnapshot with compiled Hyperscan databases:

```rust
pub struct CompiledSnapshot {
    /// Original snapshot for policy metadata and stats
    snapshot: PolicySnapshot,

    /// Hyperscan databases keyed by (field, negated)
    /// Each DB contains all patterns for that field/negation combo
    databases: HashMap<MatchKey, Scanner>,

    /// Maps pattern_id within each DB back to (policy_id, matcher_index)
    pattern_map: HashMap<MatchKey, Vec<(String, usize)>>,

    /// Compiled policy entries with match requirements
    policies: Vec<CompiledPolicyEntry>,
}
```

### CompiledPolicyEntry

Tracks what each policy needs to fully match:

```rust
pub struct CompiledPolicyEntry {
    /// Policy ID
    pub id: String,

    /// Reference to stats for recording hits/misses
    pub stats: Arc<PolicyStats>,

    /// Number of positive matchers that must match
    pub required_positive_matches: usize,

    /// Number of negative matchers that must NOT match (i.e., pattern must not be found)
    pub required_negative_non_matches: usize,

    /// The matchers with their pattern IDs in each database
    /// Vec<(MatchKey, pattern_id_in_db)>
    pub matcher_refs: Vec<(MatchKey, u32)>,

    /// Compiled keep action
    pub keep: CompiledKeep,

    /// Whether policy is enabled
    pub enabled: bool,
}
```

### CompiledKeep

```rust
#[derive(Debug, Clone)]
pub enum CompiledKeep {
    All,
    None,
    Percentage(f64),           // 0.0 to 1.0
    RatePerSecond(u64),        // N/s
    RatePerMinute(u64),        // N/m
}

impl CompiledKeep {
    /// Parse keep string: "all", "none", "50%", "100/s", "1000/m"
    pub fn parse(s: &str) -> Result<Self, PolicyError>;

    /// Restrictiveness score for comparison (higher = more restrictive)
    /// none=1000, percentage=100-N, rate=10, all=0
    pub fn restrictiveness(&self) -> u32;
}
```

## Engine API

### PolicyEngine

```rust
pub struct PolicyEngine {
    /// Current compiled snapshot
    compiled: Arc<RwLock<Option<CompiledSnapshot>>>,

    /// Rate limiter state (shared across evaluations)
    rate_limiters: Arc<RwLock<HashMap<String, RateLimiterState>>>,
}

impl PolicyEngine {
    pub fn new() -> Self;

    /// Update the compiled snapshot from a PolicySnapshot
    /// Called by registry when policies change
    pub async fn compile(&self, snapshot: PolicySnapshot) -> Result<(), PolicyError>;

    /// Evaluate a log record against all policies
    /// Returns the evaluation result
    pub async fn evaluate(&self, log: &LogRecord) -> EvaluateResult;
}
```

### EvaluateResult

```rust
pub enum EvaluateResult {
    /// No policies matched - pass through
    NoMatch,

    /// Matched policy says keep all
    Keep,

    /// Matched policy says drop
    Drop,

    /// Matched policy says sample at percentage
    Sample { percentage: f64, keep: bool },

    /// Matched policy says rate limit
    RateLimit { policy_id: String, allowed: bool },
}
```

## Compilation Process

When `PolicyEngine::compile()` is called:

### Step 1: Extract All Matchers

```rust
// For each policy, extract matchers grouped by MatchKey
let mut patterns_by_key: HashMap<MatchKey, Vec<(String, usize, String)>> = HashMap::new();
// key -> Vec<(policy_id, matcher_index, pattern)>

for policy in snapshot.iter() {
    if !policy.enabled() { continue; }

    let log_target = policy.log_target()?;
    for (idx, matcher) in log_target.match.iter().enumerate() {
        let key = MatchKey {
            field: extract_field(matcher),
            negated: matcher.negate,
        };
        let pattern = extract_pattern(matcher); // regex or exact-as-regex
        patterns_by_key.entry(key).or_default().push((policy.id().to_string(), idx, pattern));
    }
}
```

### Step 2: Build Hyperscan Databases

```rust
let mut databases: HashMap<MatchKey, Scanner> = HashMap::new();
let mut pattern_map: HashMap<MatchKey, Vec<(String, usize)>> = HashMap::new();

for (key, patterns) in patterns_by_key {
    let mut builder = DatabaseBuilder::new();
    let mut mapping = Vec::new();

    for (pattern_id, (policy_id, matcher_idx, pattern)) in patterns.iter().enumerate() {
        builder = builder.add_pattern(
            Pattern::new(&pattern).id(pattern_id as u32)
        );
        mapping.push((policy_id.clone(), *matcher_idx));
    }

    let db = builder.build()?;
    let scanner = Scanner::new(db)?;

    databases.insert(key.clone(), scanner);
    pattern_map.insert(key, mapping);
}
```

### Step 3: Build Policy Index

```rust
let mut policies: Vec<CompiledPolicyEntry> = Vec::new();

for entry in snapshot.iter() {
    let policy = &entry.policy;
    if !policy.enabled() { continue; }

    let log_target = policy.log_target()?;
    let mut matcher_refs = Vec::new();
    let mut required_positive = 0;
    let mut required_negative = 0;

    for (idx, matcher) in log_target.match.iter().enumerate() {
        let key = MatchKey {
            field: extract_field(matcher),
            negated: matcher.negate,
        };

        // Find the pattern_id in this database
        let pattern_id = find_pattern_id(&pattern_map, &key, policy.id(), idx);
        matcher_refs.push((key.clone(), pattern_id));

        if matcher.negate {
            required_negative += 1;
        } else {
            required_positive += 1;
        }
    }

    policies.push(CompiledPolicyEntry {
        id: policy.id().to_string(),
        stats: Arc::clone(&entry.stats),
        required_positive_matches: required_positive,
        required_negative_non_matches: required_negative,
        matcher_refs,
        keep: CompiledKeep::parse(&log_target.keep)?,
        enabled: true,
    });
}
```

## Evaluation Process

When `PolicyEngine::evaluate()` is called:

### Step 1: Extract Field Values

```rust
// Build a map of field -> value for the log record
let mut field_values: HashMap<LogFieldSelector, String> = HashMap::new();

field_values.insert(LogFieldSelector::Simple(LogField::Body), log.body.clone());
field_values.insert(LogFieldSelector::Simple(LogField::SeverityText), log.severity_text.clone());
// ... etc for all simple fields

for attr in &log.attributes {
    field_values.insert(LogFieldSelector::LogAttribute(attr.key.clone()), attr.value.clone());
}
for attr in &log.resource.attributes {
    field_values.insert(LogFieldSelector::ResourceAttribute(attr.key.clone()), attr.value.clone());
}
// ... etc
```

### Step 2: Scan All Databases

```rust
// Collect all matches: HashMap<MatchKey, HashSet<pattern_id>>
let mut matches: HashMap<MatchKey, HashSet<u32>> = HashMap::new();

for (key, scanner) in &compiled.databases {
    // Get the field value for this key
    if let Some(value) = field_values.get(&key.field) {
        let scan_matches = scanner.scan_bytes(value.as_bytes()).await?;

        let pattern_ids: HashSet<u32> = scan_matches
            .iter()
            .map(|m| m.pattern_id)
            .collect();

        matches.insert(key.clone(), pattern_ids);
    }
}
```

### Step 3: Evaluate Each Policy

```rust
let mut matching_policies: Vec<&CompiledPolicyEntry> = Vec::new();

for policy in &compiled.policies {
    let mut positive_matches = 0;
    let mut negative_matches = 0;  // patterns that DID match (bad for negated)

    for (key, pattern_id) in &policy.matcher_refs {
        let matched = matches
            .get(key)
            .map(|set| set.contains(pattern_id))
            .unwrap_or(false);

        if key.negated {
            if matched {
                negative_matches += 1;  // This is bad - negated matcher found a match
            }
        } else {
            if matched {
                positive_matches += 1;
            }
        }
    }

    // Policy matches if:
    // - All positive matchers matched
    // - No negative matchers matched (i.e., negative_matches == 0)
    let policy_matches =
        positive_matches == policy.required_positive_matches &&
        negative_matches == 0;

    if policy_matches {
        policy.stats.record_hit();
        matching_policies.push(policy);
    } else {
        policy.stats.record_miss();
    }
}
```

### Step 4: Select Most Restrictive Policy

```rust
if matching_policies.is_empty() {
    return EvaluateResult::NoMatch;
}

// Sort by restrictiveness (descending)
matching_policies.sort_by(|a, b| {
    b.keep.restrictiveness().cmp(&a.keep.restrictiveness())
});

let winner = &matching_policies[0];

match &winner.keep {
    CompiledKeep::None => EvaluateResult::Drop,
    CompiledKeep::All => EvaluateResult::Keep,
    CompiledKeep::Percentage(p) => {
        let keep = rand::random::<f64>() < *p;
        EvaluateResult::Sample { percentage: *p * 100.0, keep }
    }
    CompiledKeep::RatePerSecond(n) | CompiledKeep::RatePerMinute(n) => {
        let allowed = self.check_rate_limit(&winner.id, *n, /* window */);
        EvaluateResult::RateLimit { policy_id: winner.id.clone(), allowed }
    }
}
```

## Integration with Registry

The registry needs to trigger recompilation when policies change:

```rust
impl PolicyRegistry {
    pub fn subscribe_with_engine(
        &self,
        provider: &dyn PolicyProvider,
        engine: Arc<PolicyEngine>,
    ) -> Result<ProviderId, PolicyError> {
        let handle = self.register_provider();
        let provider_id = handle.provider_id();

        let callback = {
            let handle = handle.clone();
            let registry_inner = Arc::clone(&self.inner);
            let engine = Arc::clone(&engine);

            Arc::new(move |policies: Vec<Policy>| {
                handle.update(policies);

                // Trigger recompilation
                let snapshot = registry_inner.snapshot();
                tokio::spawn(async move {
                    if let Err(e) = engine.compile(snapshot).await {
                        tracing::error!(error = %e, "failed to compile policies");
                    }
                });
            })
        };

        provider.subscribe(callback)?;
        Ok(provider_id)
    }
}
```

## Module Structure

```
src/
├── engine/
│   ├── mod.rs           # PolicyEngine, EvaluateResult
│   ├── compiled.rs      # CompiledSnapshot, CompiledPolicyEntry
│   ├── keep.rs          # CompiledKeep, parsing, restrictiveness
│   ├── match_key.rs     # MatchKey
│   └── rate_limiter.rs  # Rate limiting state
```

## Dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
hyperscan-tokio = "0.3"
tokio = { version = "1", features = ["sync", "time", "rt"] }
rand = "0.8"  # For percentage sampling
```

## Handling Edge Cases

### Exact Match

Convert exact match to regex by escaping special characters:

```rust
fn exact_to_regex(s: &str) -> String {
    format!("^{}$", regex::escape(s))
}
```

### Exists Match

For `exists: true/false`, we don't add to Hyperscan. Instead, check field
presence directly:

```rust
// In evaluation, before Hyperscan scan
for policy in &compiled.policies {
    for matcher in &policy.existence_matchers {
        let exists = field_values.contains_key(&matcher.field);
        let matches = exists == matcher.should_exist;
        // Track in separate existence_matches map
    }
}
```

### Missing Fields

If a field doesn't exist in the log record:

- Positive matcher: Does not match (required pattern not found)
- Negative matcher: Matches (pattern definitely not found, which is what we
  want)

### Empty Patterns

Skip empty patterns during compilation (or treat as always-match).

## Performance Considerations

1. **Single Hyperscan Scan Per Field**: All patterns for a field are in one
   database, so we scan each field value only once.

2. **Pre-allocated Match Sets**: Use `HashSet` with capacity hint based on
   expected matches.

3. **Arc for Compiled Snapshot**: The compiled snapshot is immutable and shared
   via `Arc` to avoid copying.

4. **Lazy Field Extraction**: Only extract field values that are actually used
   in patterns.

5. **Rate Limiter Efficiency**: Use atomic operations and sliding window for
   rate limiting.

## Testing Strategy

1. **Unit Tests**:
   - `CompiledKeep::parse()` for all formats
   - `CompiledKeep::restrictiveness()` ordering
   - Pattern extraction and regex escaping

2. **Integration Tests**:
   - Compile policies from testdata/policies.json
   - Evaluate sample log records
   - Verify correct policy selection

3. **Property Tests**:
   - Restrictiveness ordering is total
   - Compilation never panics on valid policies
   - Evaluation is deterministic (except sampling/rate-limit)
