//! HLLMap: bounded keyed cardinality — a fixed-capacity map from group key
//! to a HyperLogLog, for queries like `distinct_count(dst.ip) by src.ip`.
//!
//! Both dimensions are approximate: per-key cardinalities carry HLL error,
//! and key retention is approximate once the map is full (the key with the
//! smallest estimated cardinality is evicted, so low-fan-out keys may be
//! dropped). High-fan-out keys — the ones scanner/fan-out queries care
//! about — are strongly favored for retention.

use std::collections::HashMap;

use flowsketch_core::hash::{hash64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

use crate::hll::HyperLogLog;

pub const ALGORITHM: &str = "hllmap";

#[derive(Debug, Clone)]
pub struct HllMap {
    max_keys: usize,
    precision: u8,
    hash: HashSpec,
    map: HashMap<Vec<u8>, HyperLogLog>,
    evicted_keys: u64,
    updates: u64,
}

impl HllMap {
    pub fn new(max_keys: usize, precision: u8, hash: HashSpec) -> Result<Self, SketchError> {
        if max_keys == 0 {
            return Err(SketchError::InvalidParam(
                "hllmap max_keys must be positive".into(),
            ));
        }
        // Validate precision eagerly.
        HyperLogLog::new(precision, hash)?;
        Ok(HllMap {
            max_keys,
            precision,
            hash,
            map: HashMap::new(),
            evicted_keys: 0,
            updates: 0,
        })
    }

    pub fn max_keys(&self) -> usize {
        self.max_keys
    }
    pub fn precision(&self) -> u8 {
        self.precision
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Keys dropped due to the max_keys bound (a visible accuracy signal).
    pub fn evicted_keys(&self) -> u64 {
        self.evicted_keys
    }
    pub fn relative_error(&self) -> f64 {
        1.04 / ((1u64 << self.precision) as f64).sqrt()
    }

    /// Record that `key` saw distinct `item`.
    pub fn insert(&mut self, key: &[u8], item: &[u8]) {
        self.updates += 1;
        if let Some(h) = self.map.get_mut(key) {
            h.insert(item);
            return;
        }
        if self.map.len() >= self.max_keys {
            // Evict the key with the smallest estimated cardinality.
            if let Some(evict) = self
                .map
                .iter()
                .min_by(|a, b| {
                    a.1.cardinality()
                        .partial_cmp(&b.1.cardinality())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(k, _)| k.clone())
            {
                self.map.remove(&evict);
                self.evicted_keys += 1;
            }
        }
        let mut h = HyperLogLog::new(self.precision, self.hash).expect("validated params");
        h.insert(item);
        self.map.insert(key.to_vec(), h);
    }

    pub fn cardinality(&self, key: &[u8]) -> Option<f64> {
        self.map.get(key).map(|h| h.cardinality())
    }

    /// All tracked keys with estimated cardinality, sorted descending.
    pub fn entries(&self) -> Vec<(Vec<u8>, f64)> {
        let mut all: Vec<(Vec<u8>, f64)> = self
            .map
            .iter()
            .map(|(k, h)| (k.clone(), h.cardinality()))
            .collect();
        all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0)));
        all
    }

    fn params_hash(&self) -> u64 {
        let mut w = Writer::new();
        w.u64(self.max_keys as u64);
        w.u8(self.precision);
        hash64(&w.buf, 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u64(self.max_keys as u64);
        params.u8(self.precision);
        let mut payload = Writer::new();
        payload.u64(self.updates);
        payload.u64(self.evicted_keys);
        payload.u32(self.map.len() as u32);
        let mut keys: Vec<&Vec<u8>> = self.map.keys().collect();
        keys.sort();
        for k in keys {
            payload.lp_bytes(k);
            let inner = self.map[k].to_snapshot(window_start_nanos, window_end_nanos);
            payload.lp_bytes(&inner);
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::HLL_MAP,
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
        if header.algorithm_id != algorithm_id::HLL_MAP {
            return Err(SketchError::Snapshot("not an hllmap snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let max_keys = p.u64()? as usize;
        let precision = p.u8()?;
        let mut r = Reader::new(&payload);
        let updates = r.u64()?;
        let evicted_keys = r.u64()?;
        let n = r.u32()? as usize;
        let mut map = HashMap::with_capacity(n);
        for _ in 0..n {
            let key = r.lp_bytes()?.to_vec();
            let inner = HyperLogLog::from_snapshot(r.lp_bytes()?)?;
            map.insert(key, inner);
        }
        Ok(HllMap {
            max_keys,
            precision,
            hash: header.hash,
            map,
            evicted_keys,
            updates,
        })
    }
}

impl Sketch for HllMap {
    /// `Sketch::update` treats `value` as unusable for a two-argument
    /// structure; callers should use `insert(key, item)`. Updating through
    /// the generic interface counts the key itself as the distinct item.
    fn update(&mut self, key: &[u8], _value: u64) {
        let key_owned = key.to_vec();
        self.insert(&key_owned, key);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.cardinality(key).unwrap_or(0.0)
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility().ensure_matches(&other.compatibility())?;
        for (k, h) in &other.map {
            match self.map.get_mut(k) {
                Some(mine) => mine.merge_from(h)?,
                None => {
                    self.map.insert(k.clone(), h.clone());
                }
            }
        }
        // Trim back to max_keys, dropping the smallest cardinalities.
        if self.map.len() > self.max_keys {
            let mut all: Vec<(Vec<u8>, f64)> = self
                .map
                .iter()
                .map(|(k, h)| (k.clone(), h.cardinality()))
                .collect();
            all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (k, _) in all.into_iter().skip(self.max_keys) {
                self.map.remove(&k);
                self.evicted_keys += 1;
            }
        }
        self.evicted_keys += other.evicted_keys;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let inner: usize = self
            .map
            .iter()
            .map(|(k, h)| k.len() + h.memory_bytes() + 32)
            .sum();
        inner + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.map.clear();
        self.evicted_keys = 0;
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
    fn per_key_cardinalities_are_accurate() {
        let mut m = HllMap::new(100, 12, HashSpec::new(1)).unwrap();
        for src in 0..10u32 {
            let fanout = (src + 1) * 100;
            for dst in 0..fanout {
                m.insert(format!("10.0.0.{src}").as_bytes(), format!("d{dst}").as_bytes());
            }
        }
        for src in 0..10u32 {
            let truth = ((src + 1) * 100) as f64;
            let est = m.cardinality(format!("10.0.0.{src}").as_bytes()).unwrap();
            let rel = (est - truth).abs() / truth;
            assert!(rel < 0.1, "src {src}: est {est}, truth {truth}");
        }
    }

    #[test]
    fn high_fanout_keys_survive_eviction() {
        let mut m = HllMap::new(10, 10, HashSpec::new(2)).unwrap();
        // One scanner with high fan-out among many low-fan-out keys.
        for dst in 0..5_000u32 {
            m.insert(b"scanner", format!("d{dst}").as_bytes());
        }
        for src in 0..200u32 {
            m.insert(format!("normal-{src}").as_bytes(), b"single-dst");
        }
        assert!(m.len() <= 10);
        assert!(m.evicted_keys() > 0);
        let card = m.cardinality(b"scanner").expect("scanner retained");
        assert!(card > 4_000.0, "scanner cardinality {card}");
    }

    #[test]
    fn merge_unions_per_key() {
        let mut a = HllMap::new(50, 12, HashSpec::new(3)).unwrap();
        let mut b = HllMap::new(50, 12, HashSpec::new(3)).unwrap();
        for dst in 0..1_000u32 {
            if dst % 2 == 0 {
                a.insert(b"k", format!("d{dst}").as_bytes());
            } else {
                b.insert(b"k", format!("d{dst}").as_bytes());
            }
            b.insert(b"only-b", format!("x{dst}").as_bytes());
        }
        a.merge_from(&b).unwrap();
        let k = a.cardinality(b"k").unwrap();
        assert!((k - 1_000.0).abs() / 1_000.0 < 0.1, "union cardinality {k}");
        assert!(a.cardinality(b"only-b").is_some());
    }

    #[test]
    fn snapshot_round_trips() {
        let mut m = HllMap::new(20, 10, HashSpec::new(4)).unwrap();
        for src in 0..15u32 {
            for dst in 0..(src + 1) * 10 {
                m.insert(format!("s{src}").as_bytes(), format!("d{dst}").as_bytes());
            }
        }
        let m2 = HllMap::from_snapshot(&m.to_snapshot(0, 1)).unwrap();
        assert_eq!(m.entries(), m2.entries());
        assert_eq!(m.evicted_keys(), m2.evicted_keys());
    }
}
