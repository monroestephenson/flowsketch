# Accuracy contracts

Every FlowSketch estimate is explicitly approximate. Exported samples carry
`algorithm` and `error_kind` labels; `SketchEstimate` carries per-row
`lower_bound` / `upper_bound` / `confidence`; and `flowsketch explain`
prints the contract before anything runs. This document defines what those
contracts mean. The Count-Min failure-rate and HyperLogLog interval-coverage
claims below are empirically verified in
[`benchmarks/current-results.md`](../benchmarks/current-results.md)
("Accuracy contract verification").

## Error kinds

### `additive-overestimate` (Count-Min: `count`, `sum`)

Estimates **never underestimate**. With width `w = ceil(e/epsilon)` and
depth `d = ceil(ln(1/(delta - 2^-64)))`, the overestimate exceeds
`epsilon * N` (N = total weight in the window) with probability at most
`delta` under the seeded row-hash model. The reported failure probability is
`e^-d + 2^-64`; requests at or below the finite-hash floor are rejected.
Emitted bounds: `upper = estimate`, `lower = max(estimate - epsilon*N, 0)`,
`confidence = 1 - delta`. Conservative update is enabled by default, which
only reduces overestimation.

Hash-family version 2 replaced arithmetic double hashing with nonlinear,
domain-separated row mixing. This removes the all-row signature aliases that
made additional depth ineffective. The probability is over the configured
hash family/seed model, not a cryptographic guarantee against an attacker who
knows a fixed seed; rotate to an unpredictable common seed when keys are
adversarial, and keep the same seed on every node that must merge.

Enumeration caveat: groups are enumerated through a SpaceSaving key tracker
sized at 4x `export.maxSeries`; only the heaviest tracked groups are
exported. The counts themselves come from Count-Min.

### `candidate-upper-bound` (SpaceSaving: `heavy_hitters`)

Tracked counts are **upper bounds**. Each entry records its maximum
possible overestimation; `lower_bound` is the guaranteed count
(`count - error`). With capacity `c`, any group whose true weight exceeds
`N/c` is guaranteed to be tracked. Capacity is chosen as
`max(ceil(1/epsilon), 4*limit)`.

Merging across nodes/buckets uses the mergeable-summaries construction:
counts of shared keys add; keys missing from one summary absorb that
summary's minimum count as extra error. Upper/lower bound semantics are
preserved (verified by tests).

### `relative` (HyperLogLog / HLLMap: `distinct_count`)

Relative standard error is `1.04 / sqrt(2^precision)` (~1.6% at the
default precision 12). Emitted bounds are ±2 standard errors
(`confidence = 0.95`, using the normal approximation). `epsilon` in the query
is interpreted as this relative standard error, and the planner picks the
smallest precision that meets it. Small cardinalities stay in an exact sparse
hash set; dense sketches use Ertl's improved raw estimator, including through
the former linear-counting transition. Transition-range coverage is tested
across independent seeds.

HLLMap (grouped distinct counts) adds a second approximation: key
retention is bounded by `max_keys`. The planner prefers 4x
`export.maxSeries` (clamped to [1024, 65536]) but reduces that headroom when
the declared resident-memory budget requires it, never below the export cap.
When full, the key with the smallest estimated cardinality is evicted using a
stable key tie-break, so identical streams and merges retain identical sets.
Therefore **low-fan-out groups may be dropped under pressure**;
high-fan-out groups — the ones fan-out queries exist to find — are
strongly favored. Evictions are counted and exposed.

### `rank-error` (KLL: `quantile`)

The returned value's true rank is within `~2.3/k * n` of the requested
quantile with high probability, where `k` is chosen from the query's
`epsilon` (interpreted as a normalized rank error). Emitted bounds are the
values at the neighboring quantiles `q - eps` and `q + eps`, translating
rank uncertainty into value units.

### `heuristic` (SpaceSaving + HLL: `entropy`)

Entropy (bits) is estimated from the guaranteed counts of the SpaceSaving
head plus a uniform-tail correction whose support size comes from an HLL
distinct count. There is no formal single-number bound: the head terms are
exact-ish, the tail assumption is uniformity. The planner and every
exported sample label this `error_kind="heuristic"`; validate against your
own traffic shape before alerting on absolute values (trends and shifts
are the intended use).

## Merge compatibility

Sketches merge only if algorithm, version, hash family, seed, and all
parameters match. This is enforced by `SketchCompatibility` on every merge
and covered by tests; incompatible merges return errors rather than silently
producing garbage. The `FSK1` snapshot format carries all of this metadata
so merges across processes/nodes are validated the same way. The current wire
format is FSK1 version 2 with hash-family version 2; it requires a coordinated
agent/gateway rollout and intentionally rejects version-1 snapshots.

## Verifying the contracts

- unit tests per algorithm assert bound behavior on uniform/Zipf-ish streams
  (`crates/flowsketch-algos/src/*.rs`)
- `crates/flowsketch-runtime/tests/accuracy.rs` runs the full engine and
  checks every emitted estimate against exact ground truth
- `flowsketch bench --algo <a> --dist zipf` reports measured ARE and
  precision@k against an exact counter on your own machine
