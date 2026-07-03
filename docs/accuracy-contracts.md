# Accuracy contracts

Every FlowSketch estimate is explicitly approximate. Exported samples carry
`algorithm` and `error_kind` labels; `SketchEstimate` carries per-row
`lower_bound` / `upper_bound` / `confidence`; and `flowsketch explain`
prints the contract before anything runs. This document defines what those
contracts mean.

## Error kinds

### `additive-overestimate` (Count-Min: `count`, `sum`)

Estimates **never underestimate**. With width `w = ceil(e/epsilon)` and
depth `d = ceil(ln(1/delta))`, the overestimate exceeds `epsilon * N`
(N = total weight in the window) with probability at most `delta`.
Emitted bounds: `upper = estimate`, `lower = max(estimate - epsilon*N, 0)`,
`confidence = 1 - delta`. Conservative update is enabled by default, which
only reduces overestimation.

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
(`confidence = 0.95`). `epsilon` in the query is interpreted as this
relative standard error, and the planner picks the smallest precision that
meets it.

HLLMap (grouped distinct counts) adds a second approximation: key
retention is bounded by `max_keys` (4x `export.maxSeries`, clamped to
[1024, 65536]). When full, the key with the smallest estimated cardinality
is evicted, so **low-fan-out groups may be dropped under pressure**;
high-fan-out groups — the ones fan-out queries exist to find — are
strongly favored. Evictions are counted and exposed.

## Merge compatibility

Sketches merge only if algorithm, version, hash family, seed, and all
parameters match. This is enforced by `SketchCompatibility` on every merge
and covered by tests; incompatible merges return errors rather than silently
producing garbage. The `FSK1` snapshot format carries all of this metadata
so merges across processes/nodes are validated the same way.

## Verifying the contracts

- unit tests per algorithm assert bound behavior on uniform/Zipf-ish streams
  (`crates/flowsketch-algos/src/*.rs`)
- `crates/flowsketch-runtime/tests/accuracy.rs` runs the full engine and
  checks every emitted estimate against exact ground truth
- `flowsketch bench --algo <a> --dist zipf` reports measured ARE and
  precision@k against an exact counter on your own machine
