//! SpaceSaving (Metwally, Agrawal, El Abbadi): top-k / heavy hitters with a
//! bounded set of tracked candidates.
//!
//! Error model: for capacity `c`, every tracked key's count is an upper
//! bound on its true count, overestimated by at most its recorded `error`;
//! any key with true count > N/c is guaranteed to be tracked.
//!
//! Merging follows the mergeable-summaries construction: counts of shared
//! keys add; a key present in only one summary is charged the other
//! summary's minimum count as additional potential error; the union is then
//! trimmed back to capacity.

use std::collections::HashMap;

use flowsketch_core::hash::{hash64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "spacesaving";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Upper-bound count for this key.
    pub count: u64,
    /// Maximum possible overestimation of `count`.
    pub error: u64,
}

impl Entry {
    /// Guaranteed (lower-bound) count.
    pub fn guaranteed(&self) -> u64 {
        self.count - self.error
    }
}

#[derive(Debug, Clone)]
pub struct SpaceSaving {
    capacity: usize,
    hash: HashSpec, // kept for merge-compatibility metadata; keys are exact
    entries: HashMap<Vec<u8>, Entry>,
    total_weight: u64,
    updates: u64,
}

impl SpaceSaving {
    pub fn new(capacity: usize, hash: HashSpec) -> Result<Self, SketchError> {
        if capacity == 0 {
            return Err(SketchError::InvalidParam(
                "spacesaving capacity must be positive".into(),
            ));
        }
        Ok(SpaceSaving {
            capacity,
            hash,
            entries: HashMap::with_capacity(capacity + 1),
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
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Additive error bound: any tracked count overestimates by at most
    /// `total_weight / capacity`.
    pub fn epsilon(&self) -> f64 {
        1.0 / self.capacity as f64
    }

    fn min_entry_key(&self) -> Option<Vec<u8>> {
        self.entries
            .iter()
            .min_by_key(|(_, e)| e.count)
            .map(|(k, _)| k.clone())
    }

    pub fn add(&mut self, key: &[u8], weight: u64) {
        self.total_weight += weight;
        self.updates += 1;
        if let Some(e) = self.entries.get_mut(key) {
            e.count += weight;
            return;
        }
        if self.entries.len() < self.capacity {
            self.entries.insert(
                key.to_vec(),
                Entry {
                    count: weight,
                    error: 0,
                },
            );
            return;
        }
        // Evict the current minimum and inherit its count as error.
        let min_key = self.min_entry_key().expect("capacity > 0");
        let min = self.entries.remove(&min_key).unwrap();
        self.entries.insert(
            key.to_vec(),
            Entry {
                count: min.count + weight,
                error: min.count,
            },
        );
    }

    pub fn get(&self, key: &[u8]) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Tracked keys sorted by count descending, trimmed to `limit`.
    pub fn top_k(&self, limit: usize) -> Vec<(Vec<u8>, Entry)> {
        let mut all: Vec<(Vec<u8>, Entry)> = self
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        all.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        all.truncate(limit);
        all
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
        payload.u32(self.entries.len() as u32);
        // Deterministic order for byte-stable snapshots.
        let mut keys: Vec<&Vec<u8>> = self.entries.keys().collect();
        keys.sort();
        for k in keys {
            let e = &self.entries[k];
            payload.lp_bytes(k);
            payload.u64(e.count);
            payload.u64(e.error);
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::SPACE_SAVING,
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
        if header.algorithm_id != algorithm_id::SPACE_SAVING {
            return Err(SketchError::Snapshot("not a spacesaving snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let capacity = p.u64()? as usize;
        let mut r = Reader::new(&payload);
        let total_weight = r.u64()?;
        let updates = r.u64()?;
        let n = r.u32()? as usize;
        let mut entries = HashMap::with_capacity(n);
        for _ in 0..n {
            let key = r.lp_bytes()?.to_vec();
            let count = r.u64()?;
            let error = r.u64()?;
            entries.insert(key, Entry { count, error });
        }
        Ok(SpaceSaving {
            capacity,
            hash: header.hash,
            entries,
            total_weight,
            updates,
        })
    }
}

impl Sketch for SpaceSaving {
    fn update(&mut self, key: &[u8], value: u64) {
        self.add(key, value);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.entries.get(key).map(|e| e.count as f64).unwrap_or(0.0)
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility().ensure_matches(&other.compatibility())?;
        let self_min = if self.entries.len() >= self.capacity {
            self.entries.values().map(|e| e.count).min().unwrap_or(0)
        } else {
            0
        };
        let other_min = if other.entries.len() >= other.capacity {
            other.entries.values().map(|e| e.count).min().unwrap_or(0)
        } else {
            0
        };

        let mut merged: HashMap<Vec<u8>, Entry> = HashMap::new();
        for (k, e) in &self.entries {
            let (oc, oe) = match other.entries.get(k) {
                Some(o) => (o.count, o.error),
                None => (other_min, other_min),
            };
            merged.insert(
                k.clone(),
                Entry {
                    count: e.count + oc,
                    error: e.error + oe,
                },
            );
        }
        for (k, o) in &other.entries {
            if !merged.contains_key(k) {
                merged.insert(
                    k.clone(),
                    Entry {
                        count: o.count + self_min,
                        error: o.error + self_min,
                    },
                );
            }
        }
        // Trim back to capacity, keeping the largest counts.
        if merged.len() > self.capacity {
            let mut all: Vec<(Vec<u8>, Entry)> = merged.into_iter().collect();
            all.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
            all.truncate(self.capacity);
            merged = all.into_iter().collect();
        }
        self.entries = merged;
        self.total_weight += other.total_weight;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let entry_bytes: usize = self
            .entries
            .keys()
            .map(|k| k.len() + std::mem::size_of::<Entry>() + 32)
            .sum();
        entry_bytes + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.entries.clear();
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
    fn tracks_heavy_hitters_exactly_when_under_capacity() {
        let mut s = SpaceSaving::new(100, HashSpec::new(1)).unwrap();
        for i in 0..50u32 {
            for _ in 0..=i {
                s.add(format!("k{i}").as_bytes(), 1);
            }
        }
        let top = s.top_k(3);
        assert_eq!(top[0].0, b"k49".to_vec());
        assert_eq!(top[0].1.count, 50);
        assert_eq!(top[0].1.error, 0);
    }

    #[test]
    fn count_is_upper_bound_and_guarantee_holds() {
        let mut s = SpaceSaving::new(50, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        // Zipf-ish: key i gets ~ 10000/i updates.
        for i in 1..=500u64 {
            let reps = 10_000 / i;
            for _ in 0..reps {
                s.add(format!("k{i}").as_bytes(), 1);
                *exact.entry(format!("k{i}")).or_insert(0) += 1;
            }
        }
        for (key, e) in s.top_k(50) {
            let k = String::from_utf8(key).unwrap();
            let truth = exact.get(&k).copied().unwrap_or(0);
            assert!(e.count >= truth, "{k}: count {} < truth {truth}", e.count);
            assert!(e.guaranteed() <= truth, "{k}: guaranteed too high");
        }
        // The heaviest keys must be present.
        for i in 1..=5u64 {
            assert!(s.get(format!("k{i}").as_bytes()).is_some());
        }
    }

    #[test]
    fn merge_preserves_upper_bound_property() {
        let mut a = SpaceSaving::new(20, HashSpec::new(1)).unwrap();
        let mut b = SpaceSaving::new(20, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        for i in 1..=100u64 {
            let reps = 2_000 / i;
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
        assert!(a.len() <= 20);
        for (key, e) in a.top_k(20) {
            let k = String::from_utf8(key).unwrap();
            let truth = exact.get(&k).copied().unwrap_or(0);
            assert!(e.count >= truth, "{k}: merged count {} < truth {truth}", e.count);
        }
        assert_eq!(a.total_weight(), exact.values().sum::<u64>());
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s = SpaceSaving::new(10, HashSpec::new(2)).unwrap();
        for i in 0..100u32 {
            s.add(format!("k{}", i % 15).as_bytes(), (i % 3 + 1) as u64);
        }
        let s2 = SpaceSaving::from_snapshot(&s.to_snapshot(0, 1)).unwrap();
        assert_eq!(s.top_k(10), s2.top_k(10));
        assert_eq!(s.total_weight(), s2.total_weight());
    }
}
