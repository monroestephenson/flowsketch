# Algorithm notes

Implementation notes for the sketches in `flowsketch-algos`. See
`accuracy-contracts.md` for the operator-facing error semantics.

## Hashing (`flowsketch-core::hash`)

All sketches hash through the named, versioned `fsk1` family: seeded
FNV-1a with a SplitMix64 finalizer. Hash-family version 2 derives multi-row
indexes and signs with nonlinear, domain-separated mixing of a two-word base
digest; it does not use the arithmetic `h1 + i*h2` sequence whose signature
aliases made deep sketches ineffective. Seeds are
explicit: same seed ⇒ mergeable across nodes; different seed ⇒ merge
rejected. `HASH_VERSION` is baked into snapshots and compatibility checks;
golden tests pin the function's output.

## Count-Min (`count_min.rs`)

`d` rows × `w` columns of u64. Point estimate = min over rows; never
underestimates. Optional conservative update raises each row only to the
new point estimate — strictly less overestimation on skewed traffic, still
mergeable (merged conservative sketches may exceed a single-node sketch of
the same stream, but remain upper bounds). Sizing: `w = ceil(e/eps)`,
`d = ceil(ln(1/(delta - 2^-64)))`; the finite base-digest confidence floor is
included in the reported delta.

## CountSketch (`count_sketch.rs`)

Signed counters with a per-row ±1 sign hash; estimate = median of rows.
Unbiased, supports turnstile (signed) updates, error bounded in the L2
norm — the tool for change detection between windows (planned measure).
Signed estimates remain signed through the generic `Sketch` interface; a
negative estimate is not clamped to zero.

## HyperLogLog (`hll.rs`)

Small cardinalities use a sorted exact set of 64-bit hashes and convert before
its allocation reaches one quarter of the dense representation. Dense mode
uses `2^p` 1-byte registers: index = top `p` bits, rho = leading zeros of the
rest + 1, and Ertl's improved raw estimator for bias correction across the
full range. No large-range correction is needed with 64-bit hashes. Sparse
and dense forms have a versioned snapshot encoding; merge remains the exact
union sketch operation and is tested across representations.

## HLLMap (`hll_map.rs`)

Bounded map key → HLL for grouped distinct counts. Eviction picks the
smallest estimated cardinality with a stable key tie-break. Estimates are
cached per key and refreshed lazily through a deterministic min-heap. The
sparse HLL form avoids allocating a dense register array for singleton and
low-fanout churn. Eviction count is exposed as a health signal, and
`flowsketch bench --algo hll-map` measures both saturated and steady-state
workloads directly.

## SpaceSaving (`space_saving.rs`)

Classic stream-summary: a capacity-bounded stable-slot arena of
`(key, count, error)` entries plus an exact digest index and an indexed binary
min-heap. On overflow, the minimum entry is replaced in place and its count is
inherited as the new key's error. Counts are upper bounds;
`count - error` is guaranteed. Lookup is expected O(1), updates/evictions are
O(log capacity), keys are owned once, digest collisions are resolved by exact
byte comparison, and deterministic count/digest/key ordering makes tied
evictions reproducible.

## Misra-Gries (`misra_gries.rs`)

Deterministic k-counter summary; decrement-all on overflow. Counts
underestimate by at most `N/(k+1)`; every key above that is guaranteed
present. Merge = add summaries, then trim back to capacity by subtracting
the (excess+1)-smallest count — the standard mergeable-summaries result.

## KLL (`kll.rs`)

Quantile sketch (Karnin-Lang-Liberty): levels of buffers where level `l`
holds weight-`2^l` items; overflow sorts the level and promotes a random
parity half. Capacities decay by 2/3 from `k` at the top (floor 8), giving
~3k stored items total. Normalized rank error ~ `2.3/k`. Compaction parity
comes from a seeded SplitMix64 stream, so equal-seed sketches are
byte-deterministic (golden-tested). Merge concatenates levels and
recompresses.

## Entropy estimator (runtime composite)

Not a single sketch: the runtime combines a SpaceSaving head (guaranteed
counts give exact-ish `-p log2 p` terms) with an HLL that sizes the tail's
support, treating residual mass as uniform over it. Labeled `heuristic` in
every export. Grouped entropy needs a bounded keyed distribution sketch
and is deliberately deferred.

## Exact counter (`exact.rs`)

Unbounded hash-map counter and distinct-set tracker. Never planned for
production queries; exists so benchmarks and tests have ground truth.

## Snapshots

Every sketch serializes to FSK1 version 2 (`flowsketch-core::snapshot`):
magic, version, algorithm id, full hash spec, window bounds, params,
payload, checksum. Snapshot payloads are written in deterministic (sorted)
key order so identical state produces identical bytes. Version 2 accompanies
hash-family version 2 and the sparse/dense HLL encoding; mixed-version state
fails closed.
