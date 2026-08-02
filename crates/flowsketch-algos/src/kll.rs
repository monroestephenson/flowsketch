//! KLL quantile sketch (Karnin, Lang, Liberty 2016) over u64 values.
//!
//! Levels of buffers where level `l` holds items of weight `2^l`. When a
//! level overflows its capacity, it is sorted and every other item (random
//! parity) is promoted to the next level. Capacities decay geometrically
//! from the top level (`k`) down (factor 2/3, floor 8), which is what
//! separates KLL from the older uniform-capacity samplers.
//!
//! Error model: normalized rank error is ~ `2.3 / k` with high probability
//! (constant per the KLL analysis for c = 2/3). Queries return a value
//! whose true rank is within `epsilon * n` of the requested rank.
//!
//! Compaction parity comes from a deterministic SplitMix64 stream seeded by
//! the sketch's `HashSpec`, so identically configured sketches fed the same
//! stream are byte-identical (golden tests rely on this).

use flowsketch_core::hash::{hash64, splitmix64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "kll";
const CAPACITY_DECAY_NUM: usize = 2;
const CAPACITY_DECAY_DEN: usize = 3;
const MIN_LEVEL_CAPACITY: usize = 8;
const MAX_LEVELS: usize = u64::BITS as usize;

#[derive(Debug, Clone)]
pub struct KllSketch {
    k: usize,
    hash: HashSpec,
    /// `levels[l]` holds items of weight `2^l`; kept unsorted until
    /// compaction/query time.
    levels: Vec<Vec<u64>>,
    n: u64,
    rng_state: u64,
    updates: u64,
}

impl KllSketch {
    pub fn new(k: usize, hash: HashSpec) -> Result<Self, SketchError> {
        if k < MIN_LEVEL_CAPACITY {
            return Err(SketchError::InvalidParam(format!(
                "kll k must be >= {MIN_LEVEL_CAPACITY}, got {k}"
            )));
        }
        Ok(KllSketch {
            k,
            hash,
            levels: vec![Vec::new()],
            n: 0,
            rng_state: splitmix64(hash.seed ^ 0x6B6C_6C00), // "kll" tag
            updates: 0,
        })
    }

    /// Smallest `k` whose normalized rank error is <= `epsilon`.
    pub fn k_for_error(epsilon: f64) -> usize {
        ((2.3 / epsilon).ceil() as usize).clamp(MIN_LEVEL_CAPACITY, 1 << 16)
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    /// Normalized rank error bound of this sketch.
    pub fn rank_error(&self) -> f64 {
        2.3 / self.k as f64
    }

    /// Capacity of `level` given the current number of levels: `k` at the
    /// top, decaying by 2/3 per level below, floored at 8.
    fn capacity(&self, level: usize) -> usize {
        let depth = self.levels.len() - 1 - level;
        let mut cap = self.k;
        for _ in 0..depth {
            cap = cap * CAPACITY_DECAY_NUM / CAPACITY_DECAY_DEN;
        }
        cap.max(MIN_LEVEL_CAPACITY)
    }

    fn next_bit(&mut self) -> bool {
        self.rng_state = splitmix64(self.rng_state);
        self.rng_state & 1 == 1
    }

    pub fn insert(&mut self, value: u64) {
        self.n += 1;
        self.updates += 1;
        self.levels[0].push(value);
        self.compress();
    }

    fn compress(&mut self) {
        let mut level = 0;
        while level < self.levels.len() {
            if self.levels[level].len() <= self.capacity(level) {
                level += 1;
                continue;
            }
            if level + 1 == self.levels.len() {
                self.levels.push(Vec::new());
            }
            let mut buf = std::mem::take(&mut self.levels[level]);
            buf.sort_unstable();
            let offset = usize::from(self.next_bit());
            let promoted: Vec<u64> = buf.iter().skip(offset).step_by(2).copied().collect();
            self.levels[level + 1].extend_from_slice(&promoted);
            // Items not promoted are discarded; their weight is represented
            // by the promoted half at double weight.
            level += 1;
        }
    }

    /// Value at quantile `q` in [0, 1], or `None` if empty.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.n == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        let mut weighted: Vec<(u64, u64)> = Vec::new();
        for (level, items) in self.levels.iter().enumerate() {
            let w = 1u64 << level;
            weighted.extend(items.iter().map(|&v| (v, w)));
        }
        weighted.sort_unstable_by_key(|&(v, _)| v);
        let total: u64 = weighted.iter().map(|&(_, w)| w).sum();
        let target = (q * total as f64).ceil().max(1.0) as u64;
        let mut acc = 0u64;
        for (v, w) in &weighted {
            acc += w;
            if acc >= target {
                return Some(*v);
            }
        }
        weighted.last().map(|&(v, _)| v)
    }

    /// Estimated rank (fraction of items <= `value`).
    pub fn rank(&self, value: u64) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        let mut le = 0u64;
        let mut total = 0u64;
        for (level, items) in self.levels.iter().enumerate() {
            let w = 1u64 << level;
            for &v in items {
                total += w;
                if v <= value {
                    le += w;
                }
            }
        }
        le as f64 / total as f64
    }

    fn params_hash(&self) -> u64 {
        hash64(&(self.k as u64).to_le_bytes(), 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u64(self.k as u64);
        let mut payload = Writer::new();
        payload.u64(self.n);
        payload.u64(self.rng_state);
        payload.u64(self.updates);
        payload.u32(self.levels.len() as u32);
        for level in &self.levels {
            payload.u32(level.len() as u32);
            for &v in level {
                payload.u64(v);
            }
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::KLL,
                hash: self.hash,
                window_start_nanos,
                window_end_nanos,
            },
            &params.buf,
            &payload.buf,
        )
    }

    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, SketchError> {
        let (header, params, payload) = read_snapshot(bytes)?;
        if header.algorithm_id != algorithm_id::KLL {
            return Err(SketchError::Snapshot("not a kll snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let encoded_k = p.u64()?;
        let k = usize::try_from(encoded_k).map_err(|_| {
            SketchError::Snapshot(format!(
                "kll snapshot k {encoded_k} does not fit this platform"
            ))
        })?;
        if k < MIN_LEVEL_CAPACITY {
            return Err(SketchError::Snapshot(format!(
                "kll snapshot k must be >= {MIN_LEVEL_CAPACITY}, got {k}"
            )));
        }
        let mut r = Reader::new(&payload);
        let n = r.u64()?;
        let rng_state = r.u64()?;
        let updates = r.u64()?;
        let num_levels = r.u32()? as usize;
        if num_levels > MAX_LEVELS {
            return Err(SketchError::Snapshot(format!(
                "kll snapshot has {num_levels} levels, maximum is {MAX_LEVELS}"
            )));
        }
        // Each level needs at least its u32 length prefix; each item is a
        // u64. Bounding declared counts by the remaining payload keeps a
        // hostile snapshot from forcing huge preallocations.
        r.check_count(num_levels, 4)?;
        let mut levels = Vec::with_capacity(num_levels);
        for _ in 0..num_levels {
            let len = r.u32()? as usize;
            r.check_count(len, 8)?;
            let mut level = Vec::with_capacity(len);
            for _ in 0..len {
                level.push(r.u64()?);
            }
            levels.push(level);
        }
        if levels.is_empty() {
            levels.push(Vec::new());
        }
        Ok(KllSketch {
            k,
            hash: header.hash,
            levels,
            n,
            rng_state,
            updates,
        })
    }
}

impl Sketch for KllSketch {
    fn update(&mut self, _key: &[u8], value: u64) {
        self.insert(value);
    }

    /// For the generic interface, `estimate` returns the median.
    fn estimate(&self, _key: &[u8]) -> f64 {
        self.quantile(0.5).map(|v| v as f64).unwrap_or(0.0)
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility()
            .ensure_matches(&other.compatibility())?;
        while self.levels.len() < other.levels.len() {
            self.levels.push(Vec::new());
        }
        for (level, items) in other.levels.iter().enumerate() {
            self.levels[level].extend_from_slice(items);
        }
        self.n += other.n;
        self.updates += other.updates;
        // Mix the RNG streams so merged sketches do not correlate parities.
        self.rng_state = splitmix64(self.rng_state ^ other.rng_state);
        self.compress();
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let items: usize = self.levels.iter().map(|l| l.capacity() * 8 + 24).sum();
        items + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.levels = vec![Vec::new()];
        self.n = 0;
        self.updates = 0;
    }

    fn update_count(&self) -> u64 {
        self.updates
    }

    fn compatibility(&self) -> SketchCompatibility {
        SketchCompatibility {
            algorithm: ALGORITHM.to_string(),
            version: 1,
            hash: self.hash,
            params_hash: self.params_hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shuffled(n: u64, seed: u64) -> Vec<u64> {
        // Deterministic shuffle of 0..n via sort-by-hash.
        let mut v: Vec<u64> = (0..n).collect();
        v.sort_by_key(|&x| splitmix64(x ^ seed));
        v
    }

    #[test]
    fn quantiles_within_rank_error_on_uniform_stream() {
        let mut s = KllSketch::new(256, HashSpec::new(1)).unwrap();
        let n = 100_000u64;
        for v in shuffled(n, 7) {
            s.insert(v);
        }
        assert_eq!(s.n(), n);
        // With values 0..n the true rank of value v is (v+1)/n.
        let eps = s.rank_error();
        for q in [0.01, 0.25, 0.5, 0.75, 0.99] {
            let v = s.quantile(q).unwrap() as f64;
            let true_rank = (v + 1.0) / n as f64;
            assert!(
                (true_rank - q).abs() <= eps,
                "q={q}: got value {v} (rank {true_rank}), eps {eps}"
            );
        }
    }

    #[test]
    fn bounded_memory_on_large_streams() {
        let mut s = KllSketch::new(200, HashSpec::new(2)).unwrap();
        for v in shuffled(500_000, 3) {
            s.insert(v);
        }
        let stored: usize = (0..s.levels.len()).map(|l| s.levels[l].len()).sum();
        // Geometric capacities sum to ~3k.
        assert!(stored < 6 * 200, "stored {stored} items");
    }

    #[test]
    fn merge_matches_single_stream_error_contract() {
        let mut a = KllSketch::new(256, HashSpec::new(5)).unwrap();
        let mut b = KllSketch::new(256, HashSpec::new(5)).unwrap();
        let n = 60_000u64;
        for (i, v) in shuffled(n, 11).into_iter().enumerate() {
            if i % 2 == 0 {
                a.insert(v);
            } else {
                b.insert(v);
            }
        }
        a.merge_from(&b).unwrap();
        assert_eq!(a.n(), n);
        let eps = a.rank_error();
        for q in [0.1, 0.5, 0.9] {
            let v = a.quantile(q).unwrap() as f64;
            let true_rank = (v + 1.0) / n as f64;
            assert!(
                (true_rank - q).abs() <= eps,
                "merged q={q}: value {v} rank {true_rank}"
            );
        }
    }

    #[test]
    fn incompatible_merge_rejected() {
        let mut a = KllSketch::new(128, HashSpec::new(1)).unwrap();
        let b = KllSketch::new(256, HashSpec::new(1)).unwrap();
        assert!(a.merge_from(&b).is_err());
        let c = KllSketch::new(128, HashSpec::new(9)).unwrap();
        assert!(a.merge_from(&c).is_err());
    }

    #[test]
    fn snapshot_round_trips_exactly() {
        let mut s = KllSketch::new(64, HashSpec::new(4)).unwrap();
        for v in shuffled(10_000, 13) {
            s.insert(v);
        }
        let s2 = KllSketch::from_snapshot(&s.to_snapshot(5, 6)).unwrap();
        for q in [0.0, 0.25, 0.5, 0.75, 1.0] {
            assert_eq!(s.quantile(q), s2.quantile(q));
        }
        assert_eq!(s.n(), s2.n());
    }

    #[test]
    fn hostile_snapshot_counts_are_rejected() {
        let craft = |k: u64, num_levels: u32, level_len: u32| {
            let mut params = Writer::new();
            params.u64(k);
            let mut payload = Writer::new();
            payload.u64(0); // n
            payload.u64(0); // rng_state
            payload.u64(0); // updates
            payload.u32(num_levels);
            payload.u32(level_len);
            write_snapshot(
                &SnapshotHeader {
                    version: SNAPSHOT_VERSION,
                    algorithm_id: algorithm_id::KLL,
                    hash: HashSpec::new(1),
                    window_start_nanos: 0,
                    window_end_nanos: 0,
                },
                &params.buf,
                &payload.buf,
            )
        };
        // k below the constructor's floor, a level count and an item count
        // the payload cannot back: all rejected before allocation.
        assert!(KllSketch::from_snapshot(&craft(1, 1, 0)).is_err());
        #[cfg(target_pointer_width = "32")]
        assert!(KllSketch::from_snapshot(&craft(u64::MAX, 1, 0)).is_err());
        let err = KllSketch::from_snapshot(&craft(64, (MAX_LEVELS + 1) as u32, 0)).unwrap_err();
        assert!(err.to_string().contains("levels"), "{err}");
        assert!(KllSketch::from_snapshot(&craft(64, u32::MAX, 0)).is_err());
        assert!(KllSketch::from_snapshot(&craft(64, 1, u32::MAX)).is_err());
    }

    #[test]
    fn deterministic_with_fixed_seed() {
        let build = || {
            let mut s = KllSketch::new(64, HashSpec::new(42)).unwrap();
            for v in shuffled(20_000, 21) {
                s.insert(v);
            }
            s.to_snapshot(0, 0)
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn rank_and_quantile_are_consistent() {
        let mut s = KllSketch::new(256, HashSpec::new(6)).unwrap();
        for v in shuffled(50_000, 17) {
            s.insert(v);
        }
        let median = s.quantile(0.5).unwrap();
        let r = s.rank(median);
        assert!((r - 0.5).abs() < s.rank_error(), "rank of median {r}");
    }
}
