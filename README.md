# policy-rs

Rust implementation of the
[Tero Policy Specification](https://github.com/usetero/policy) for
high-performance log policy evaluation and transformation.

Another implementation of this specification is available in
[Tero Edge](https://github.com/usetero/edge), a Zig-based observability edge
runtime, providing the policy evaluation engine for filtering, sampling, and
transforming telemetry data.

## Features

- **High-performance pattern matching** using
  [Hyperscan](https://github.com/intel/hyperscan) for parallel regex evaluation
- **Policy-based log filtering** with keep, drop, sample, and rate-limit actions
- **Log transformations** including field removal, redaction, renaming, and
  addition
- **Multiple policy providers** with live reload support
- **Zero-allocation field access** through the `Matchable` trait
- **Async-first design** built on Tokio

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
policy-rs = { git = "https://github.com/usetero/policy-rs" }
```

## Quick Start

```rust
use policy_rs::{EvaluateResult, FileProvider, PolicyEngine, PolicyRegistry, Matchable, LogFieldSelector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create registry and load policies
    let registry = PolicyRegistry::new();
    let provider = FileProvider::new("policies.json");
    registry.subscribe(&provider)?;

    // Create engine and get snapshot
    let engine = PolicyEngine::new();
    let snapshot = registry.snapshot();

    // Evaluate a log record
    let log = MyLogRecord::new("Error: connection timeout", "ERROR");
    let result = engine.evaluate(&snapshot, &log).await?;

    match result {
        EvaluateResult::NoMatch => println!("Pass through"),
        EvaluateResult::Keep { policy_id, .. } => println!("Keep: {}", policy_id),
        EvaluateResult::Drop { policy_id } => println!("Drop: {}", policy_id),
        EvaluateResult::Sample { keep, .. } => println!("Sampled: {}", keep),
        EvaluateResult::RateLimit { allowed, .. } => println!("Rate limited: {}", allowed),
    }

    Ok(())
}
```

## Core Concepts

### Policy Registry

The `PolicyRegistry` manages policies from multiple providers and maintains an
immutable snapshot for lock-free evaluation:

```rust
let registry = PolicyRegistry::new();

// Subscribe to a file-based provider (auto-reloads on changes)
let provider = FileProvider::new("policies.json");
registry.subscribe(&provider)?;

// Or register a custom provider
let handle = registry.register_provider();
handle.update(vec![policy1, policy2]);

// Get immutable snapshot for evaluation
let snapshot = registry.snapshot();
```

### Policy Engine

The `PolicyEngine` evaluates logs against compiled policies using Hyperscan for
pattern matching:

```rust
let engine = PolicyEngine::new();
let snapshot = registry.snapshot();

// Read-only evaluation
let result = engine.evaluate(&snapshot, &log).await?;

// Evaluation with transformations applied
let result = engine.evaluate_and_transform(&snapshot, &mut log).await?;
```

### Evaluation Results

```rust
pub enum EvaluateResult {
    /// No policies matched - pass through unchanged
    NoMatch,
    /// Matched policy says keep
    Keep { policy_id: String, transformed: bool },
    /// Matched policy says drop
    Drop { policy_id: String },
    /// Matched policy says sample (percentage-based)
    Sample { policy_id: String, percentage: f64, keep: bool, transformed: bool },
    /// Matched policy says rate limit (count-based)
    RateLimit { policy_id: String, allowed: bool, transformed: bool },
}
```

## Implementing the Traits

To evaluate your log types, implement the `Matchable` trait. For transformation
support, also implement `Transformable`.

### Matchable Trait

The `Matchable` trait provides zero-allocation field access for pattern
matching:

```rust
use policy_rs::{Matchable, LogFieldSelector};
use policy_rs::proto::tero::policy::v1::LogField;

struct MyLogRecord {
    body: String,
    severity: String,
    attributes: HashMap<String, String>,
}

impl Matchable for MyLogRecord {
    fn get_field(&self, field: &LogFieldSelector) -> Option<&str> {
        match field {
            LogFieldSelector::Simple(log_field) => match log_field {
                LogField::Body => Some(&self.body),
                LogField::SeverityText => Some(&self.severity),
                _ => None,
            },
            LogFieldSelector::LogAttribute(key) => {
                self.attributes.get(key).map(|s| s.as_str())
            },
            LogFieldSelector::ResourceAttribute(key) => None,
            LogFieldSelector::ScopeAttribute(key) => None,
        }
    }
}
```

### Transformable Trait

The `Transformable` trait enables field mutations when using
`evaluate_and_transform`:

```rust
use policy_rs::{Transformable, LogFieldSelector};

impl Transformable for MyLogRecord {
    fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => {
                self.attributes.remove(key).is_some()
            },
            _ => false,
        }
    }

    fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => {
                if self.attributes.contains_key(key) {
                    self.attributes.insert(key.clone(), replacement.to_string());
                    true
                } else {
                    false
                }
            },
            _ => false,
        }
    }

    fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
        if let LogFieldSelector::LogAttribute(key) = from {
            if let Some(value) = self.attributes.remove(key) {
                if upsert || !self.attributes.contains_key(to) {
                    self.attributes.insert(to.to_string(), value);
                    return true;
                }
            }
        }
        false
    }

    fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
        match field {
            LogFieldSelector::LogAttribute(key) => {
                if upsert || !self.attributes.contains_key(key) {
                    self.attributes.insert(key.clone(), value.to_string());
                    true
                } else {
                    false
                }
            },
            _ => false,
        }
    }
}
```

## Advanced Usage

### Custom Policy Providers

Implement `PolicyProvider` to load policies from custom sources:

```rust
use policy_rs::{PolicyProvider, PolicyCallback, Policy, PolicyError};

struct MyProvider {
    // Your state here
}

impl PolicyProvider for MyProvider {
    fn load(&self, callback: &PolicyCallback) -> Result<(), PolicyError> {
        let policies = self.fetch_policies()?;
        callback.update(policies);
        Ok(())
    }
}

// Use with the registry
let registry = PolicyRegistry::new();
let provider = MyProvider::new();
registry.subscribe(&provider)?;
```

### Policy Statistics

Track policy hit/miss rates and transform statistics:

```rust
let snapshot = registry.snapshot();

for entry in snapshot.iter() {
    let stats = entry.stats.snapshot();

    println!("Policy: {}", entry.policy.id());
    println!("  Matches: {} hits, {} misses", stats.match_hits, stats.match_misses);
    println!("  Remove: {} hits, {} misses", stats.remove.0, stats.remove.1);
    println!("  Redact: {} hits, {} misses", stats.redact.0, stats.redact.1);
    println!("  Rename: {} hits, {} misses", stats.rename.0, stats.rename.1);
    println!("  Add: {} hits, {} misses", stats.add.0, stats.add.1);
}
```

### Multiple Providers

Combine policies from multiple sources:

```rust
let registry = PolicyRegistry::new();

// File-based policies
let file_provider = FileProvider::new("local-policies.json");
registry.subscribe(&file_provider)?;

// Programmatic policies
let handle = registry.register_provider();
handle.update(vec![
    create_emergency_drop_policy(),
    create_rate_limit_policy(),
]);

// All policies are merged in the snapshot
let snapshot = registry.snapshot();
```

### Transform Order

When using `evaluate_and_transform`, transformations are applied in a fixed
order:

1. **Remove** - Delete fields
2. **Redact** - Replace field values with placeholders
3. **Rename** - Rename fields to new keys
4. **Add** - Add new fields

Transforms from all matching policies are applied, not just the winning policy.

## Policy Format

Policies are defined using the
[Tero Policy protobuf schema](https://github.com/usetero/policy). Example JSON:

```json
{
  "id": "drop-debug-logs",
  "name": "Drop Debug Logs",
  "enabled": true,
  "target": {
    "log": {
      "match": [
        {
          "logField": "SEVERITY_TEXT",
          "regex": "DEBUG|TRACE"
        }
      ],
      "keep": "none"
    }
  }
}
```

### Keep Values

- `"all"` - Keep all matching logs
- `"none"` - Drop all matching logs
- `"50%"` - Sample 50% of matching logs
- `"100/s"` - Rate limit to 100 logs per second
- `"1000/m"` - Rate limit to 1000 logs per minute

### Match Fields

- `logField` - Simple fields: `BODY`, `SEVERITY_TEXT`, `TRACE_ID`, `SPAN_ID`,
  etc.
- `logAttribute` - Log attributes by key
- `resourceAttribute` - Resource attributes by key
- `scopeAttribute` - Scope attributes by key

### Match Types

- `exact` - Exact string match
- `regex` - Regular expression match
- `exists` - Field existence check

## Examples

See the `examples/` directory:

- `basic_usage.rs` - Load policies and evaluate logs
- `transforms.rs` - Apply log transformations
- `multiple_providers.rs` - Combine multiple policy sources
- `custom_provider.rs` - Implement a custom provider

Run examples with:

```sh
cargo run --example basic_usage
cargo run --example transforms
```

## License

Apache-2.0
