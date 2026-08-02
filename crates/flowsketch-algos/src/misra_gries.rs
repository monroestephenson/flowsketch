//! Misra-Gries frequent-items summary: deterministic heavy-hitter candidate
//! generation with `k` counters.
//!
//! Error model: every reported count underestimates the true count by at
//! most `total_weight / (k + 1)`; any key with true count above that bound
//! is guaranteed to be present. Merging adds summaries then re-trims,
//! preserving the (summed) error bound.

use std::collections::HashMap;

use flowsketch_core::hash::{hash64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "misra-gries";

#[derive(Debug, Clone)]
pub struct MisraGries {
    capacity: usize,
    hash: HashSpec, // merge-compatibility metadata only
    counters: HashMap<Vec<u8>, u64>,
    total_weight: u64,
    updates: u64,
}

impl MisraGries {
    pub fn new(capacity: usize, hash: HashSpec) -> Result<Self, SketchError> {
        if capacity == 0 {
            return Err(SketchError::InvalidParam(
                "misra-gries capacity must be positive".into(),
            ));
        }
        Ok(MisraGries {
            capacity,
            hash,
            counters: HashMap::with_capacity(capacity + 1),
            total_weight: 0,
            updates: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }
    pub fn len(&self) -> usize {
        self.counters.len()
    }
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// Maximum undercount of any reported key.
    pub fn epsilon(&self) -> f64 {
        1.0 / (self.capacity as f64 + 1.0)
    }

    pub fn add(&mut self, key: &[u8], weight: u64) {
        self.total_weight += weight;
        self.updates += 1;
        if let Some(c) = self.counters.get_mut(key) {
            *c += weight;
            return;
        }
        if self.counters.len() < self.capacity {
            self.counters.insert(key.to_vec(), weight);
            return;
        }
        // Decrement-all by the largest amount that keeps the invariant:
        // min(weight, current minimum counter).
        let min = *self.counters.values().min().expect("capacity > 0");
        let dec = min.min(weight);
        self.counters.retain(|_, c| {
            *c -= dec;
            *c > 0
        });
        let leftover = weight - dec;
        if leftover > 0 && self.counters.len() < self.capacity {
            self.counters.insert(key.to_vec(), leftover);
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<u64> {
        self.counters.get(key).copied()
    }

    /// Candidates sorted by (under)count descending.
    pub fn candidates(&self) -> Vec<(Vec<u8>, u64)> {
        let mut all: Vec<(Vec<u8>, u64)> =
            self.counters.iter().map(|(k, &c)| (k.clone(), c)).collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        all
    }

    fn trim_to_capacity(&mut self) {
        while self.counters.len() > self.capacity {
            let excess = self.counters.len() - self.capacity;
            // Remove at least `excess` counters by subtracting the
            // `excess`-th smallest count from everything.
            let mut counts: Vec<u64> = self.counters.values().copied().collect();
            counts.sort_unstable();
            let dec = counts[excess - 1];
            self.counters.retain(|_, c| {
                let d = (*c).min(dec);
                *c -= d;
                *c > 0
            });
        }
    }

    fn params_hash(&self) -> u64 {
        hash64(&(self.capacity as u64).to_le_bytes(), 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u64(self.capacity as u64);
        let mut payload = Writer::new();
        payload.u64(self.total_weight);
        payload.u64(self.updates);
        payload.u32(self.counters.len() as u32);
        let mut keys: Vec<&Vec<u8>> = self.counters.keys().collect();
        keys.sort();
        for k in keys {
            payload.lp_bytes(k);
            payload.u64(self.counters[k]);
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::MISRA_GRIES,
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
        if header.algorithm_id != algorithm_id::MISRA_GRIES {
            return Err(SketchError::Snapshot("not a misra-gries snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let encoded_capacity = p.u64()?;
        let capacity = usize::try_from(encoded_capacity).map_err(|_| {
            SketchError::Snapshot(format!(
                "misra-gries snapshot capacity {encoded_capacity} does not fit this platform"
            ))
        })?;
        if capacity == 0 {
            return Err(SketchError::Snapshot(
                "misra-gries snapshot capacity must be positive".into(),
            ));
        }
        let mut r = Reader::new(&payload);
        let total_weight = r.u64()?;
        let updates = r.u64()?;
        let n = r.u32()? as usize;
        if n > capacity {
            return Err(SketchError::Snapshot(format!(
                "misra-gries snapshot counter count {n} exceeds capacity {capacity}"
            )));
        }
        // Each counter encodes at least a u32 key length + u64 count.
        r.check_count(n, 4 + 8)?;
        let mut counters = HashMap::with_capacity(n);
        for _ in 0..n {
            let key = r.lp_bytes()?.to_vec();
            let count = r.u64()?;
            counters.insert(key, count);
        }
        Ok(MisraGries {
            capacity,
            hash: header.hash,
            counters,
            total_weight,
            updates,
        })
    }
}

impl Sketch for MisraGries {
    fn update(&mut self, key: &[u8], value: u64) {
        self.add(key, value);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.get(key).unwrap_or(0) as f64
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility()
            .ensure_matches(&other.compatibility())?;
        for (k, &c) in &other.counters {
            *self.counters.entry(k.clone()).or_insert(0) += c;
        }
        self.trim_to_capacity();
        self.total_weight += other.total_weight;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let entry_bytes: usize = self.counters.keys().map(|k| k.len() + 8 + 32).sum();
        entry_bytes + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.counters.clear();
        self.total_weight = 0;
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

    #[test]
    fn counts_underestimate_by_bounded_amount() {
        let mut s = MisraGries::new(10, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        for i in 1..=100u64 {
            let reps = 1_000 / i;
            for _ in 0..reps {
                let key = format!("k{i}");
                s.add(key.as_bytes(), 1);
                *exact.entry(key).or_insert(0) += 1;
            }
        }
        let bound = (s.total_weight() as f64 * s.epsilon()).ceil() as u64;
        for (key, c) in s.candidates() {
            let k = String::from_utf8(key).unwrap();
            let truth = exact[&k];
            assert!(c <= truth, "{k}: count {c} > truth {truth}");
            assert!(truth - c <= bound, "{k}: undercount exceeds bound");
        }
        // Guaranteed detection: keys with truth > N/(k+1) must be present.
        for (k, &truth) in &exact {
            if truth > bound {
                assert!(s.get(k.as_bytes()).is_some(), "{k} missing");
            }
        }
    }

    #[test]
    fn merge_keeps_capacity_and_underestimate() {
        let mut a = MisraGries::new(8, HashSpec::new(1)).unwrap();
        let mut b = MisraGries::new(8, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        for i in 1..=50u64 {
            let reps = 600 / i;
            for r in 0..reps {
                let key = format!("k{i}");
                *exact.entry(key.clone()).or_insert(0) += 1;
                if r % 2 == 0 {
                    a.add(key.as_bytes(), 1);
                } else {
                    b.add(key.as_bytes(), 1);
                }
            }
        }
        a.merge_from(&b).unwrap();
        assert!(a.len() <= 8);
        for (key, c) in a.candidates() {
            let k = String::from_utf8(key).unwrap();
            assert!(c <= exact[&k], "{k}: merged count exceeds truth");
        }
    }

    #[test]
    fn merge_trim_does_not_discard_an_extra_counter() {
        let hash = HashSpec::new(1);
        let mut a = MisraGries::new(4, hash).unwrap();
        for (key, count) in [(b"a", 1), (b"b", 2), (b"c", 3), (b"d", 4)] {
            a.counters.insert(key.to_vec(), count);
            a.total_weight += count;
        }
        let mut b = MisraGries::new(4, hash).unwrap();
        b.counters.insert(b"e".to_vec(), 100);
        b.total_weight = 100;

        a.merge_from(&b).unwrap();

        assert_eq!(a.len(), 4);
        assert_eq!(a.get(b"a"), None);
        assert_eq!(a.get(b"b"), Some(1));
        assert_eq!(a.get(b"c"), Some(2));
        assert_eq!(a.get(b"d"), Some(3));
        assert_eq!(a.get(b"e"), Some(99));
    }

    #[test]
    fn hostile_snapshot_params_are_rejected() {
        let craft = |capacity: u64, n: u32| {
            let mut params = Writer::new();
            params.u64(capacity);
            let mut payload = Writer::new();
            payload.u64(0); // total_weight
            payload.u64(0); // updates
            payload.u32(n);
            write_snapshot(
                &SnapshotHeader {
                    version: SNAPSHOT_VERSION,
                    algorithm_id: algorithm_id::MISRA_GRIES,
                    hash: HashSpec::new(1),
                    window_start_nanos: 0,
                    window_end_nanos: 0,
                },
                &params.buf,
                &payload.buf,
            )
        };
        assert!(MisraGries::from_snapshot(&craft(0, 0)).is_err());
        #[cfg(target_pointer_width = "32")]
        assert!(MisraGries::from_snapshot(&craft(u64::MAX, 0)).is_err());
        let err = MisraGries::from_snapshot(&craft(1, 2)).unwrap_err();
        assert!(err.to_string().contains("exceeds capacity"), "{err}");
        assert!(MisraGries::from_snapshot(&craft(10, u32::MAX)).is_err());
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s = MisraGries::new(5, HashSpec::new(3)).unwrap();
        for i in 0..200u32 {
            s.add(format!("k{}", i % 9).as_bytes(), 1);
        }
        let s2 = MisraGries::from_snapshot(&s.to_snapshot(0, 1)).unwrap();
        assert_eq!(s.candidates(), s2.candidates());
    }
}
