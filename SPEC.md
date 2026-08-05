# Policy Engine Specification

This document describes the matching, transform, and sampling semantics of
`policy-rs`. It is the authoritative reference for integrators writing
`Matchable`/`Transformable` adapters and for authors of the cross-language
conformance test suite.

> **Canonical source of truth:** the `policy-conformance` fixture suite. Where
> this document and the fixtures disagree, the fixtures win. File an issue to
> bring this document in sync.

---

## 1. Concepts

### 1.1 Policy

A **policy** consists of:

- A unique string `id` and human-readable `name`.
- An `enabled` flag. Disabled policies are compiled but never matched.
- A `target`: exactly one of `log`, `metric`, or `trace`.

Each target contains:

- A list of **matchers** (AND logic — all must match).
- A **keep** action.
- Optional transforms (logs only).
- Optional sampling config (traces only).

### 1.2 Snapshot

A **snapshot** is an immutable, compiled view of all policies. The registry
produces a new snapshot whenever providers push updates. Snapshots are lock-free
to read and safe to share across threads.

---

## 2. Matching

### 2.1 AND logic

A policy matches a record if and only if **all** of its matchers match. An empty
matcher list never matches (a policy with no matchers is a no-op).

### 2.2 Matcher types

| Matcher         | Behaviour                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `exact`         | Full-value equality. Must equal the entire field value.                                                                               |
| `regex`         | RE2/Hyperscan regex anchored nowhere — matches if the pattern appears anywhere in the value. Wrap with `^...$` for full-string match. |
| `starts_with`   | Value starts with the given prefix.                                                                                                   |
| `ends_with`     | Value ends with the given suffix.                                                                                                     |
| `contains`      | Value contains the given substring.                                                                                                   |
| `exists: true`  | Field is present (regardless of whether it has a string value).                                                                       |
| `exists: false` | Field is absent.                                                                                                                      |

All matchers except `exists` operate on the string value returned by
`Matchable::get_field`. If `get_field` returns `None`, only an `exists: false`
matcher can fire.

### 2.3 `case_insensitive`

When `case_insensitive: true`, the pattern is compiled with Hyperscan's
`HS_FLAG_CASELESS`. Both the pattern and the value are treated
case-insensitively. Does not affect `exists` matchers.

### 2.4 `negate`

When `negate: true`, the matcher fires only when the underlying condition is
false. A negated match that fires **disqualifies** the policy entirely (it
cannot match).

### 2.5 Winning policy

When multiple policies match the same record, the **most restrictive keep
action** wins:

```
none (drop) > rate_limit > percentage > all (keep)
```

On a tie at the same restrictiveness level, the policy that sorts first
**alphanumerically by ID** wins.

### 2.6 Stats

Per-policy match counters follow these rules:

- **If the record is kept**: every matching policy gets a **hit**.
- **If the record is dropped**: the winning policy gets a **hit**; all other
  matching policies get a **miss**.
- Non-matching policies: no counter change.

### 2.7 Volume tracking

Match counters only cover records a policy matched. `PolicyRegistry::volume()`
returns a `VolumeTracker` for the denominator — everything that entered
evaluation — reported as `SyncRequest.volume` by the HTTP and gRPC providers.

**Record counts are automatic.** `PolicyEngine::evaluate`,
`evaluate_and_transform`, and `evaluate_trace` each count one record of their
signal, before any early return — so records that match nothing, and records
evaluated with no policies loaded for their signal, are all counted. Counting
happens before the keep and transform stages, so dropped, sampled-out, and
redacted records are included at their pre-policy size.

| Counter              | Source                                                       |
| -------------------- | ------------------------------------------------------------ |
| `log_records`        | One per `evaluate`/`evaluate_and_transform` on a log.         |
| `metric_data_points` | One per `evaluate` on a metric data point (not per stream).   |
| `spans`              | One per `evaluate_trace`.                                    |
| `*_bytes`            | Opt-in: `volume().add_log_bytes(n)` and its metric/span kin.  |

**Byte counts are opt-in.** The engine cannot measure serialized size through
the `Matchable` trait, so the integrator adds them. When reported they must be
the uncompressed OTLP protobuf size of the records as received; an estimate is
fine, but a size in any other encoding (JSON, post-compression) must never be
reported — leave it at `0`. Because `0` is both "not measured" and "measured as
zero", consumers must not read `0` as an observation.

`volume().collect()` drains the counters and returns the delta since the last
call, or `None` when nothing was observed — providers omit `volume` from the sync
request rather than sending zeroes. Overlapping syncs each drain a disjoint
delta, so no volume is reported twice; a sync that fails hands its delta back via
`add()`, so the next attempt reports it.

---

## 3. Keep Actions

### 3.1 Log keep actions

| Syntax   | Meaning                                                      |
| -------- | ------------------------------------------------------------ |
| `"all"`  | Always keep.                                                 |
| `"none"` | Always drop.                                                 |
| `"N%"`   | Keep N% using consistent probability sampling (see §5).      |
| `"N/s"`  | Keep at most N records per second (token-bucket rate limit). |
| `"N/m"`  | Keep at most N records per minute.                           |

### 3.2 Metric keep actions

| Value   | Meaning |
| ------- | ------- |
| `true`  | Keep.   |
| `false` | Drop.   |

Metrics have no sampling or rate-limiting.

### 3.3 Trace keep actions

See §6 (Consistent Probability Sampling for Traces).

---

## 4. Transforms (Logs only)

Transforms are applied **only when the record is kept**, and only from **all
matching policies** (not just the winner). Transforms run in alphanumeric
policy-ID order.

### 4.1 Operations

| Operation | Behaviour                                                                                                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `remove`  | Delete the field. No-op if absent.                                                                                                                                                |
| `redact`  | Replace the field value. Without `regex`: replace the whole value. With `regex`: replace all non-overlapping matches of the regex within the value. No-op if the field is absent. |
| `rename`  | Move a field to a new name. `upsert: false` (default): no-op if the target already exists. `upsert: true`: delete the target first, then move. No-op if the source is absent.     |
| `add`     | Set a field to a constant value. `upsert: false` (default): no-op if the field already exists. `upsert: true`: overwrite.                                                         |

### 4.2 Field targeting

Transforms can target:

- Simple log fields (`body`, `severity_text`, etc.)
- Log record attributes (`log_attribute`)
- Resource attributes (`resource_attribute`)
- Scope attributes (`scope_attribute`)

---

## 5. Consistent Probability Sampling (Logs)

When a log policy has a `%` keep action, the sampling decision is made once per
record using a deterministic function of the record's **sample key value**.

### 5.1 Sample key

The `sample_key` field names a log record field whose value drives the sampling
decision. Sampling is **consistent**: the same key value always produces the
same keep/drop decision at a given percentage.

### 5.2 Fallback rules

1. **No sample key configured**, or **sample key field is absent**, or **sample
   key value is empty**: fall back to **keep** (no sampling applied, record
   always passes).
2. **Sample key value looks like a 32-char hex trace ID**: use the OTel
   consistent probability algorithm directly (last 14 hex chars as the 56-bit
   randomness value).
3. **Any other value**: hash with FNV-1a (64-bit) and use the result as the
   56-bit randomness value.

### 5.3 Threshold comparison

```
threshold T = (1 - percentage/100) × 2^56
keep if randomness ≥ T
```

- 100% → T=0, always keep.
- 0% → T=2^56, never keep.

---

## 6. Consistent Probability Sampling (Traces)

Trace sampling uses the
[OTel Consistent Probability Sampling](https://opentelemetry.io/docs/specs/otel/trace/tracestate-probability-sampling/)
algorithm.

### 6.1 Modes

| Mode           | Behaviour                                                                    |
| -------------- | ---------------------------------------------------------------------------- |
| `HASH_SEED`    | Compute randomness from `trace_id` (and optional `hash_seed`).               |
| `PROPORTIONAL` | Downstream sampler: outbound threshold = `ThresholdToProbability(T_in) × p`. |
| `EQUALIZING`   | Prefer already-rare spans; apply target threshold to others.                 |

The default mode when unspecified is `HASH_SEED`.

### 6.2 Randomness extraction

Order of preference:

1. `rv` sub-key from OTel tracestate (`ot=rv:...`). Ignored in `HASH_SEED` mode
   with a non-zero seed.
2. Least-significant 56 bits of the `trace_id` hex string.
3. If neither is available: apply `fail_closed` (default: keep).

### 6.3 Threshold propagation

When a span is sampled, the engine writes the outbound threshold to
`TraceFieldSelector::SamplingThreshold`. The `Transformable` implementation must
persist this as the `th` sub-key in the tracestate `ot` entry:

```
ot=th:<hex-threshold>
```

### 6.4 Consistency check

If both `rv` and `th` are present in the upstream tracestate and `rv < th`
(inconsistent), the engine keeps the span but erases the threshold (does not
propagate).

---

## 7. Adapter Implementation Rules

These rules are required for correct conformance. See also `policy_rs::adapter`
for reference implementations and `policy_rs::Matchable` for annotated trait
docs.

### 7.1 `get_field` rules

| Condition                                                            | Return                   |
| -------------------------------------------------------------------- | ------------------------ |
| Field is a **string** value                                          | `Some(Cow::Borrowed(s))` |
| Field is a **non-string** OTel value (`intValue`, `boolValue`, etc.) | `None`                   |
| Field is **absent**                                                  | `None`                   |

### 7.2 `field_exists` rules

| Condition                                      | Return  |
| ---------------------------------------------- | ------- |
| Field has **any** value (string or non-string) | `true`  |
| Field is absent                                | `false` |

The default `field_exists` body returns `get_field(...).is_some()` which
conflates "absent" with "present but non-string". Override it when your records
carry non-string values.

### 7.3 Enum fields

Fields whose values are proto enum types must use `policy_rs::canonical`:

| Field                   | Helper                                       |
| ----------------------- | -------------------------------------------- |
| Metric type             | `canonical::metric_type_str(mt)`             |
| Aggregation temporality | `canonical::aggregation_temporality_str(at)` |
| Span status             | `canonical::span_status_code_str(sc)`        |
| Span kind               | `canonical::span_kind_str(sk)`               |

### 7.4 Special cases

- **`trace_id` / `span_id`**: must be lowercase hex. `trace_id` is 32 chars
  (128-bit); `span_id` is 16 chars (64-bit). Non-hex values cause sampling to
  fall back to the `fail_closed` policy, not panic.
- **SpanStatus Unset**: OTel's "Unset" status code is proto3's default zero
  value (`SpanStatusCode::Unspecified`). Proto3 omits default values during
  serialization, but the status is logically **present**. Return
  `"SPAN_STATUS_CODE_UNSPECIFIED"` (not `None`) for a span with an unset or
  default status.
- **Empty string attributes**: `get_field` may return `Some("")` for a
  present-but-empty string field. `field_exists` must still return `true`.
  Sampling treats an empty sample key value as absent (falls back to keep).
