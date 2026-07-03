//! Count-Min Sketch (Cormode & Muthukrishnan): a sublinear-space frequency
//! table for nonnegative updates.
//!
//! Error model: point estimates never underestimate; with width `w` and
//! depth `d`, the overestimate exceeds `(e / w) * N` (N = total weight) with
//! probability at most `e^-d`. Optional conservative update reduces
//! overestimation for skewed streams at the cost of losing linearity
//! (conservative sketches still merge, but merged estimates may be slightly
//! larger than a single-node sketch over the same stream).

use flowsketch_core::hash::{hash64, HashSpec, RowHashes};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "count-min";

#[derive(Debug, Clone)]
pub struct CountMinSketch {
    width: usize,
    depth: usize,
    conservative: bool,
    hash: HashSpec,
    table: Vec<u64>, // depth rows of width columns, row-major
    total_weight: u64,
    updates: u64,
}

impl CountMinSketch {
    pub fn new(
        width: usize,
        depth: usize,
        conservative: bool,
        hash: HashSpec,
    ) -> Result<Self, SketchError> {
        if width == 0 || depth == 0 {
            return Err(SketchError::InvalidParam(
                "count-min width and depth must be positive".into(),
            ));
        }
        Ok(CountMinSketch {
            width,
            depth,
            conservative,
            hash,
            table: vec![0; width * depth],
            total_weight: 0,
            updates: 0,
        })
    }

    /// Width/depth for a target additive error `epsilon * N` with failure
    /// probability `delta`.
    pub fn for_error(
        epsilon: f64,
        delta: f64,
        conservative: bool,
        hash: HashSpec,
    ) -> Result<Self, SketchError> {
        let (width, depth) = Self::dimensions_for_error(epsilon, delta)?;
        Self::new(width, depth, conservative, hash)
    }

    pub fn dimensions_for_error(epsilon: f64, delta: f64) -> Result<(usize, usize), SketchError> {
        if !(epsilon > 0.0 && epsilon < 1.0) || !(delta > 0.0 && delta < 1.0) {
            return Err(SketchError::InvalidParam(
                "epsilon and delta must be in (0, 1)".into(),
            ));
        }
        let width = (std::f64::consts::E / epsilon).ceil() as usize;
        let depth = (1.0 / delta).ln().ceil().max(1.0) as usize;
        Ok((width, depth))
    }

    pub fn width(&self) -> usize {
        self.width
    }
    pub fn depth(&self) -> usize {
        self.depth
    }
    pub fn conservative(&self) -> bool {
        self.conservative
    }
    /// Additive error factor: estimates exceed truth by more than
    /// `epsilon() * total_weight()` with probability at most `delta()`.
    pub fn epsilon(&self) -> f64 {
        std::f64::consts::E / self.width as f64
    }
    pub fn delta(&self) -> f64 {
        (-(self.depth as f64)).exp()
    }
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn estimate_u64(&self, key: &[u8]) -> u64 {
        let rh = RowHashes::new(&self.hash, key);
        let mut min = u64::MAX;
        for row in 0..self.depth {
            let idx = row * self.width + rh.index(row, self.width);
            min = min.min(self.table[idx]);
        }
        min
    }

    fn params_hash(&self) -> u64 {
        let mut w = Writer::new();
        w.u64(self.width as u64);
        w.u64(self.depth as u64);
        w.u8(self.conservative as u8);
        hash64(&w.buf, 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u32(self.width as u32);
        params.u32(self.depth as u32);
        params.u8(self.conservative as u8);

        let mut payload = Writer::with_capacity(self.table.len() * 8 + 16);
        payload.u64(self.total_weight);
        payload.u64(self.updates);
        for &c in &self.table {
            payload.u64(c);
        }

        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::COUNT_MIN,
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
        if header.algorithm_id != algorithm_id::COUNT_MIN {
            return Err(SketchError::Snapshot("not a count-min snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let width = p.u32()? as usize;
        let depth = p.u32()? as usize;
        let conservative = p.u8()? != 0;

        let mut r = Reader::new(&payload);
        let total_weight = r.u64()?;
        let updates = r.u64()?;
        let mut table = Vec::with_capacity(width * depth);
        for _ in 0..width * depth {
            table.push(r.u64()?);
        }
        Ok(CountMinSketch {
            width,
            depth,
            conservative,
            hash: header.hash,
            table,
            total_weight,
            updates,
        })
    }
}

impl Sketch for CountMinSketch {
    fn update(&mut self, key: &[u8], value: u64) {
        let rh = RowHashes::new(&self.hash, key);
        self.total_weight += value;
        self.updates += 1;
        if self.conservative {
            // Conservative update: raise each row only up to the new point
            // estimate, never past it.
            let mut min = u64::MAX;
            let mut idxs = [0usize; 64];
            let depth = self.depth.min(64);
            for row in 0..depth {
                let idx = row * self.width + rh.index(row, self.width);
                idxs[row] = idx;
                min = min.min(self.table[idx]);
            }
            let target = min + value;
            for &idx in &idxs[..depth] {
                if self.table[idx] < target {
                    self.table[idx] = target;
                }
            }
        } else {
            for row in 0..self.depth {
                let idx = row * self.width + rh.index(row, self.width);
                self.table[idx] += value;
            }
        }
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.estimate_u64(key) as f64
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility().ensure_matches(&other.compatibility())?;
        for (a, b) in self.table.iter_mut().zip(other.table.iter()) {
            *a += *b;
        }
        self.total_weight += other.total_weight;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        self.table.len() * 8 + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.table.fill(0);
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

    fn cm(conservative: bool) -> CountMinSketch {
        CountMinSketch::new(2048, 4, conservative, HashSpec::new(1)).unwrap()
    }

    #[test]
    fn never_underestimates() {
        let mut s = cm(false);
        for i in 0..1000u32 {
            let key = format!("key-{}", i % 50);
            s.update(key.as_bytes(), (i % 7 + 1) as u64);
        }
        let mut exact = std::collections::HashMap::new();
        for i in 0..1000u32 {
            let key = format!("key-{}", i % 50);
            *exact.entry(key).or_insert(0u64) += (i % 7 + 1) as u64;
        }
        for (k, v) in exact {
            assert!(s.estimate_u64(k.as_bytes()) >= v);
        }
    }

    #[test]
    fn conservative_update_is_at_most_plain() {
        let mut plain = cm(false);
        let mut cons = cm(true);
        for i in 0..20_000u32 {
            let key = format!("k{}", i % 3000);
            plain.update(key.as_bytes(), 1);
            cons.update(key.as_bytes(), 1);
        }
        for i in 0..3000u32 {
            let key = format!("k{i}");
            assert!(cons.estimate_u64(key.as_bytes()) <= plain.estimate_u64(key.as_bytes()));
        }
    }

    #[test]
    fn merge_equals_single_stream() {
        let mut a = cm(false);
        let mut b = cm(false);
        let mut whole = cm(false);
        for i in 0..5000u32 {
            let key = format!("k{}", i % 700);
            whole.update(key.as_bytes(), 3);
            if i % 2 == 0 {
                a.update(key.as_bytes(), 3);
            } else {
                b.update(key.as_bytes(), 3);
            }
        }
        a.merge_from(&b).unwrap();
        for i in 0..700u32 {
            let key = format!("k{i}");
            assert_eq!(a.estimate_u64(key.as_bytes()), whole.estimate_u64(key.as_bytes()));
        }
    }

    #[test]
    fn incompatible_merge_rejected() {
        let mut a = CountMinSketch::new(1024, 4, false, HashSpec::new(1)).unwrap();
        let b = CountMinSketch::new(2048, 4, false, HashSpec::new(1)).unwrap();
        assert!(a.merge_from(&b).is_err());
        let c = CountMinSketch::new(1024, 4, false, HashSpec::new(2)).unwrap();
        assert!(a.merge_from(&c).is_err());
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s = cm(true);
        for i in 0..1000u32 {
            s.update(format!("k{}", i % 100).as_bytes(), 2);
        }
        let bytes = s.to_snapshot(10, 20);
        let s2 = CountMinSketch::from_snapshot(&bytes).unwrap();
        for i in 0..100u32 {
            let key = format!("k{i}");
            assert_eq!(s.estimate_u64(key.as_bytes()), s2.estimate_u64(key.as_bytes()));
        }
        assert_eq!(s.update_count(), s2.update_count());
    }

    #[test]
    fn error_bound_holds_on_uniform_stream() {
        let mut s = CountMinSketch::for_error(0.001, 0.01, false, HashSpec::new(7)).unwrap();
        let n_keys = 10_000u32;
        for i in 0..n_keys {
            s.update(format!("key-{i}").as_bytes(), 1);
        }
        let eps_n = (s.epsilon() * s.total_weight() as f64).ceil() as u64;
        let mut violations = 0;
        for i in 0..n_keys {
            let est = s.estimate_u64(format!("key-{i}").as_bytes());
            if est > 1 + eps_n {
                violations += 1;
            }
        }
        // Expected violation rate <= delta (1%); allow slack for test stability.
        assert!(violations as f64 <= n_keys as f64 * 0.05);
    }
}
