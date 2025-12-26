# Policy Provider Implementation Plan

This document outlines the implementation plan for the `policy-rs` library,
which provides policy management functionality for telemetry data processing.

## Architecture Overview

```
+------------------+     +------------------+     +------------------+
|  Policy Provider |---->|  Policy Store    |---->|  Policy Engine   |
|  (File/HTTP)     |     |  (Aggregation)   |     |  (Evaluation)    |
+------------------+     +------------------+     +------------------+
                                                          |
                                                          v
                                                  +------------------+
                                                  |  Transform       |
                                                  |  Pipeline        |
                                                  +------------------+
```

## Module Structure

```
src/
├── lib.rs                 # Public API exports
├── proto/                 # Generated protobuf code (existing)
├── provider/              # Policy providers
│   ├── mod.rs
│   ├── traits.rs          # Provider trait definition
│   ├── file.rs            # File-based provider
│   └── http.rs            # HTTP-based provider
├── store.rs               # Policy storage and aggregation
├── engine/                # Policy evaluation engine
│   ├── mod.rs
│   ├── matcher.rs         # Log matching logic
│   ├── keep.rs            # Keep/sampling logic
│   └── transform.rs       # Transform pipeline
├── field.rs               # Field selection utilities
└── error.rs               # Error types
```

## Implementation Phases

### Phase 1: Core Infrastructure

#### 1.1 Error Types (`src/error.rs`)

Define error types for the library:

```rust
pub enum PolicyError {
    /// Provider failed to load policies
    ProviderError { source: Box<dyn std::error::Error + Send + Sync> },

    /// Invalid policy configuration
    InvalidPolicy { policy_id: String, reason: String },

    /// Regex compilation failed
    RegexError { pattern: String, source: regex::Error },

    /// Invalid keep expression
    InvalidKeepExpression { expression: String, reason: String },

    /// Field selection error
    FieldError { reason: String },
}
```

Key principles:

- All errors should be `Send + Sync` for async compatibility
- Include enough context for debugging
- Fail-open: errors should not block telemetry processing

#### 1.2 Field Selection (`src/field.rs`)

Unified field selection for logs:

```rust
pub enum LogFieldSelector {
    Simple(LogField),
    LogAttribute(String),
    ResourceAttribute(String),
    ScopeAttribute(String),
}

impl LogFieldSelector {
    /// Extract from LogMatcher field oneof
    pub fn from_matcher(matcher: &LogMatcher) -> Option<Self>;

    /// Extract from LogRemove field oneof
    pub fn from_remove(remove: &LogRemove) -> Option<Self>;

    // ... similar for LogRedact, LogRename, LogAdd

    /// Get the field value from a log record
    pub fn get_value<'a>(&self, log: &'a LogRecord) -> Option<&'a str>;

    /// Set the field value on a log record
    pub fn set_value(&self, log: &mut LogRecord, value: String);

    /// Remove the field from a log record
    pub fn remove(&self, log: &mut LogRecord) -> bool;
}
```

This centralizes field access logic and ensures consistency across matchers and
transforms.

### Phase 2: Policy Provider

#### 2.1 Provider Trait (`src/provider/traits.rs`)

```rust
#[async_trait]
pub trait PolicyProvider: Send + Sync {
    /// Load policies from the provider
    async fn load(&self) -> Result<Vec<Policy>, PolicyError>;

    /// Sync policies with status feedback
    async fn sync(&self, request: SyncRequest) -> Result<SyncResponse, PolicyError>;

    /// Check if provider supports watching for changes
    fn supports_watch(&self) -> bool;

    /// Watch for policy changes (optional)
    fn watch(&self) -> Option<BoxStream<'static, Result<Vec<Policy>, PolicyError>>>;
}
```

#### 2.2 File Provider (`src/provider/file.rs`)

Loads policies from local files:

```rust
pub struct FileProvider {
    path: PathBuf,
    format: FileFormat,  // JSON, YAML, or Protobuf binary
}

pub enum FileFormat {
    Json,
    Yaml,
    Protobuf,
}

impl FileProvider {
    pub fn new(path: impl Into<PathBuf>, format: FileFormat) -> Self;

    /// Watch for file changes using notify crate
    pub fn watch_changes(&self) -> impl Stream<Item = ()>;
}
```

Supported formats:

- JSON (using `serde_json`)
- YAML (using `serde_yaml`)
- Protobuf binary (using `prost`)

#### 2.3 HTTP Provider (`src/provider/http.rs`)

Fetches policies from HTTP endpoint:

```rust
pub struct HttpProvider {
    endpoint: Url,
    client: reqwest::Client,
    auth: Option<AuthConfig>,
    sync_interval: Duration,
}

pub enum AuthConfig {
    Bearer(String),
    Basic { username: String, password: String },
    Custom(Box<dyn Fn(&mut Request) + Send + Sync>),
}

impl HttpProvider {
    pub fn builder() -> HttpProviderBuilder;

    /// Background sync loop
    pub async fn start_sync_loop(&self, store: Arc<PolicyStore>);
}
```

The HTTP provider implements the sync protocol:

1. Sends `SyncRequest` with client metadata and policy statuses
2. Receives `SyncResponse` with updated policies
3. Respects `recommended_sync_interval_seconds`
4. Handles `SYNC_TYPE_FULL` for complete replacement

### Phase 3: Policy Store

#### 3.1 Policy Store (`src/store.rs`)

Aggregates policies from multiple providers:

```rust
pub struct PolicyStore {
    policies: RwLock<HashMap<String, Policy>>,
    compiled: RwLock<HashMap<String, CompiledPolicy>>,
    stats: RwLock<HashMap<String, PolicyStats>>,
}

pub struct PolicyStats {
    pub match_hits: AtomicU64,
    pub match_misses: AtomicU64,
    pub remove_stats: TransformStats,
    pub redact_stats: TransformStats,
    pub rename_stats: TransformStats,
    pub add_stats: TransformStats,
}

pub struct TransformStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl PolicyStore {
    pub fn new() -> Self;

    /// Update policies atomically
    pub fn update(&self, policies: Vec<Policy>);

    /// Get all enabled policies for a stage
    pub fn get_policies(&self, stage: PolicyStage) -> Vec<&CompiledPolicy>;

    /// Get stats for sync reporting
    pub fn get_stats(&self) -> Vec<PolicySyncStatus>;

    /// Reset stats after sync
    pub fn reset_stats(&self);
}
```

The store:

- Maintains compiled regex patterns for efficiency
- Tracks per-policy statistics for sync feedback
- Provides atomic updates for thread safety
- Filters by `enabled` flag

### Phase 4: Policy Engine

#### 4.1 Compiled Policy (`src/engine/mod.rs`)

Pre-compiled policy for efficient evaluation:

```rust
pub struct CompiledPolicy {
    pub id: String,
    pub policy: Policy,
    pub matchers: Vec<CompiledMatcher>,
    pub keep: CompiledKeep,
    pub transform: CompiledTransform,
}

impl CompiledPolicy {
    pub fn compile(policy: Policy) -> Result<Self, PolicyError>;
}
```

#### 4.2 Matcher Engine (`src/engine/matcher.rs`)

Evaluates log matchers:

```rust
pub struct CompiledMatcher {
    field: LogFieldSelector,
    match_type: CompiledMatchType,
    negate: bool,
}

pub enum CompiledMatchType {
    Exact(String),
    Regex(Regex),  // Pre-compiled RE2 regex
    Exists,
}

impl CompiledMatcher {
    pub fn compile(matcher: &LogMatcher) -> Result<Self, PolicyError>;

    /// Evaluate matcher against a log record
    pub fn matches(&self, log: &LogRecord) -> bool;
}
```

Match evaluation rules:

- All matchers in a policy are ANDed together
- `negate` inverts the individual matcher result
- Missing fields: `exists: true` returns false, `exists: false` returns true
- Regex uses RE2 syntax (via `regex` crate which is RE2-compatible)

#### 4.3 Keep Logic (`src/engine/keep.rs`)

Implements keep/sampling/rate-limiting:

```rust
pub enum CompiledKeep {
    All,
    None,
    Percentage(f64),  // 0.0 to 1.0
    RateLimit(RateLimiter),
}

pub struct RateLimiter {
    limit: u64,
    window: Duration,
    state: Mutex<RateLimiterState>,
}

impl CompiledKeep {
    pub fn compile(keep: &str) -> Result<Self, PolicyError>;

    /// Determine if the record should be kept
    pub fn should_keep(&self) -> bool;
}
```

Keep expression parsing:

- `"all"` or empty → `CompiledKeep::All`
- `"none"` → `CompiledKeep::None`
- `"N%"` → `CompiledKeep::Percentage(N / 100.0)`
- `"N/s"` → `CompiledKeep::RateLimit` with 1-second window
- `"N/m"` → `CompiledKeep::RateLimit` with 1-minute window

#### 4.4 Transform Pipeline (`src/engine/transform.rs`)

Executes transforms in order:

```rust
pub struct CompiledTransform {
    removes: Vec<CompiledRemove>,
    redacts: Vec<CompiledRedact>,
    renames: Vec<CompiledRename>,
    adds: Vec<CompiledAdd>,
}

impl CompiledTransform {
    pub fn compile(transform: &LogTransform) -> Result<Self, PolicyError>;

    /// Apply transforms to a log record
    /// Order: Remove → Redact → Rename → Add
    pub fn apply(&self, log: &mut LogRecord, stats: &TransformStats);
}
```

Transform order is critical and must be:

1. **Remove** - Delete unwanted fields
2. **Redact** - Mask sensitive values
3. **Rename** - Change field names
4. **Add** - Insert new fields

Each stage tracks hits (field existed and was modified) and misses (field did
not exist).

### Phase 5: Public API

#### 5.1 Engine Interface (`src/lib.rs`)

High-level API for policy evaluation:

```rust
pub struct PolicyEngine {
    store: Arc<PolicyStore>,
}

impl PolicyEngine {
    pub fn new() -> Self;

    /// Add a policy provider
    pub fn add_provider(&self, provider: Box<dyn PolicyProvider>);

    /// Process a log record through all matching policies
    /// Returns None if the log should be dropped
    pub fn process_log(&self, log: &mut LogRecord) -> Option<()>;

    /// Get sync request for a provider
    pub fn create_sync_request(&self) -> SyncRequest;

    /// Apply sync response from a provider
    pub fn apply_sync_response(&self, response: SyncResponse);
}
```

Processing flow:

1. Iterate through enabled policies (order by specificity/priority)
2. For each policy: a. Evaluate all matchers (AND logic) b. If matched, evaluate
   keep logic c. If kept, apply transforms
3. Return `Some(())` if log survives, `None` if dropped

### Phase 6: Dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
prost = "0.13"
thiserror = "2"           # Error handling
regex = "1"               # RE2-compatible regex
async-trait = "0.1"       # Async trait support
tokio = { version = "1", features = ["sync", "time"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"          # JSON policy files
serde_yaml = "0.9"        # YAML policy files (optional)

[dependencies.reqwest]
version = "0.12"
features = ["json"]
optional = true

[features]
default = ["file-provider"]
file-provider = []
http-provider = ["reqwest"]
```

## Design Principles

### Fail-Open

All errors during policy evaluation should be logged but not block telemetry:

```rust
impl PolicyEngine {
    pub fn process_log(&self, log: &mut LogRecord) -> Option<()> {
        for policy in self.get_policies() {
            match self.evaluate_policy(policy, log) {
                Ok(result) => { /* handle result */ }
                Err(e) => {
                    // Log error but continue - fail open
                    tracing::warn!(policy_id = %policy.id, error = %e, "policy evaluation failed");
                    continue;
                }
            }
        }
        Some(())
    }
}
```

### Idempotency

Policies can be applied multiple times safely. This is achieved by:

- Using `upsert` flags for add/rename operations
- Checking field existence before operations
- Not maintaining state between evaluations (except rate limiters)

### Atomic Updates

Policy updates are atomic:

- New policies are compiled before updating the store
- If compilation fails, the update is rejected
- Store uses `RwLock` for thread-safe concurrent access

### Statistics Tracking

All operations track statistics for sync feedback:

- Match hits/misses per policy
- Transform hits/misses per stage per policy
- Stats are reset after successful sync

## Testing Strategy

### Unit Tests

- Matcher compilation and evaluation
- Keep expression parsing
- Transform operations
- Field selection utilities

### Integration Tests

- File provider loading
- HTTP provider sync protocol
- Full policy evaluation pipeline

### Property Tests

- Regex patterns compile correctly
- Rate limiters respect limits
- Transform order is maintained

## Implementation Order

1. `error.rs` - Error types
2. `field.rs` - Field selection utilities
3. `engine/matcher.rs` - Matcher compilation and evaluation
4. `engine/keep.rs` - Keep logic
5. `engine/transform.rs` - Transform pipeline
6. `engine/mod.rs` - CompiledPolicy
7. `store.rs` - Policy store
8. `provider/traits.rs` - Provider trait
9. `provider/file.rs` - File provider
10. `provider/http.rs` - HTTP provider (optional)
11. `lib.rs` - Public API integration

Each step should include unit tests before moving to the next.
