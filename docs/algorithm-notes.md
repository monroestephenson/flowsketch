# Algorithm notes

Implementation notes for the sketches in `flowsketch-algos`. See
`accuracy-contracts.md` for the operator-facing error semantics.

## Hashing (`flowsketch-core::hash`)

All sketches hash through the named, versioned `fsk1` family: seeded
FNV-1a with a SplitMix64 finalizer. Multi-row sketches derive per-row
hashes with the Kirsch–Mitzenmacher construction `h_i = h1 + i*h2` (h2
forced odd), so one pass over the key bytes serves every row. Seeds are
explicit: same seed ⇒ mergeable across nodes; different seed ⇒ merge
rejected. `HASH_VERSION` is baked into snapshots and compatibility checks;
golden tests pin the function's output.

## Count-Min (`count_min.rs`)

`d` rows × `w` columns of u64. Point estimate = min over rows; never
underestimates. Optional conservative update raises each row only to the
new point estimate — strictly less overestimation on skewed traffic, still
mergeable (merged conservative sketches may exceed a single-node sketch of
the same stream, but remain upper bounds). Sizing: `w = ceil(e/eps)`,
`d = ceil(ln(1/delta))`.

## CountSketch (`count_sketch.rs`)

Signed counters with a per-row ±1 sign hash; estimate = median of rows.
Unbiased, supports turnstile (signed) updates, error bounded in the L2
norm — the tool for change detection between windows (planned measure).

## HyperLogLog (`hll.rs`)

`2^p` 1-byte registers, 64-bit hashes: index = top `p` bits, rho = leading
zeros of the rest + 1. Standard alpha bias correction plus small-range
linear counting; no large-range correction is needed with 64-bit hashes.
Merge = register-wise max (exactly the union sketch — tested).

## HLLMap (`hll_map.rs`)

Bounded map key → HLL for grouped distinct counts. Eviction picks the
smallest estimated cardinality. Estimates are cached per key and refreshed
lazily (dirty flag) during eviction scans — naive rescoring of every key on
every eviction made replay ~60x slower before this was fixed. Eviction
count is exposed as a health signal.

## SpaceSaving (`space_saving.rs`)

Classic stream-summary: capacity-bounded map of (count, error). On
overflow, the minimum entry is evicted and its count inherited as the new
key's error. Counts are upper bounds; `count - error` is guaranteed.
The v0 min-search is an O(capacity) scan on eviction — correct and simple;
a linked "buckets of equal count" structure is the known optimization if
eviction-heavy workloads show up in profiles.

## Misra-Gries (`misra_gries.rs`)

Deterministic k-counter summary; decrement-all on overflow. Counts
underestimate by at most `N/(k+1)`; every key above that is guaranteed
present. Merge = add summaries, then trim back to capacity by subtracting
the (excess+1)-smallest count — the standard mergeable-summaries result.

## Exact counter (`exact.rs`)

Unbounded hash-map counter and distinct-set tracker. Never planned for
production queries; exists so benchmarks and tests have ground truth.

## Snapshots

Every sketch serializes to the `FSK1` format (`flowsketch-core::snapshot`):
magic, version, algorithm id, full hash spec, window bounds, params,
payload, checksum. Snapshot payloads are written in deterministic (sorted)
key order so identical state produces identical bytes.
