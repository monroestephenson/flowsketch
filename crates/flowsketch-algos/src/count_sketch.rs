//! CountSketch (Charikar, Chen, Farach-Colton): frequency estimation with
//! signed counters and median-of-rows estimates.
//!
//! Compared to Count-Min, CountSketch supports signed/turnstile updates and
//! gives unbiased estimates with error bounded in the L2 norm of the
//! frequency vector — better on heavy-tailed traffic and usable for change
//! detection between windows.

use flowsketch_core::hash::{hash64, HashSpec, RowHashes};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "count-sketch";

#[derive(Debug, Clone)]
pub struct CountSketch {
    width: usize,
    depth: usize,
    hash: HashSpec,
    table: Vec<i64>, // depth rows of width columns, row-major
    updates: u64,
}

impl CountSketch {
    pub fn new(width: usize, depth: usize, hash: HashSpec) -> Result<Self, SketchError> {
        if width == 0 || depth == 0 {
            return Err(SketchError::InvalidParam(
                "count-sketch width and depth must be positive".into(),
            ));
        }
        Ok(CountSketch {
            width,
            depth,
            hash,
            table: vec![0; width * depth],
            updates: 0,
        })
    }

    pub fn width(&self) -> usize {
        self.width
    }
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Signed update (turnstile model).
    pub fn update_signed(&mut self, key: &[u8], value: i64) {
        let rh = RowHashes::new(&self.hash, key);
        self.updates += 1;
        for row in 0..self.depth {
            let idx = row * self.width + rh.index(row, self.width);
            self.table[idx] += rh.sign(row) * value;
        }
    }

    /// Median-of-rows signed estimate.
    pub fn estimate_signed(&self, key: &[u8]) -> i64 {
        let rh = RowHashes::new(&self.hash, key);
        let mut ests: Vec<i64> = (0..self.depth)
            .map(|row| rh.sign(row) * self.table[row * self.width + rh.index(row, self.width)])
            .collect();
        ests.sort_unstable();
        let mid = ests.len() / 2;
        if ests.len() % 2 == 1 {
            ests[mid]
        } else {
            // Round toward zero on even depth.
            (ests[mid - 1] + ests[mid]) / 2
        }
    }

    fn params_hash(&self) -> u64 {
        let mut w = Writer::new();
        w.u64(self.width as u64);
        w.u64(self.depth as u64);
        hash64(&w.buf, 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u32(self.width as u32);
        params.u32(self.depth as u32);
        let mut payload = Writer::with_capacity(self.table.len() * 8 + 8);
        payload.u64(self.updates);
        for &c in &self.table {
            payload.i64(c);
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::COUNT_SKETCH,
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
        if header.algorithm_id != algorithm_id::COUNT_SKETCH {
            return Err(SketchError::Snapshot("not a count-sketch snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let width = p.u32()? as usize;
        let depth = p.u32()? as usize;
        let mut r = Reader::new(&payload);
        let updates = r.u64()?;
        let mut table = Vec::with_capacity(width * depth);
        for _ in 0..width * depth {
            table.push(r.i64()?);
        }
        Ok(CountSketch {
            width,
            depth,
            hash: header.hash,
            table,
            updates,
        })
    }
}

impl Sketch for CountSketch {
    fn update(&mut self, key: &[u8], value: u64) {
        self.update_signed(key, value as i64);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.estimate_signed(key).max(0) as f64
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility()
            .ensure_matches(&other.compatibility())?;
        for (a, b) in self.table.iter_mut().zip(other.table.iter()) {
            *a += *b;
        }
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        self.table.len() * 8 + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.table.fill(0);
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
    fn heavy_keys_are_recovered_accurately() {
        let mut s = CountSketch::new(4096, 5, HashSpec::new(3)).unwrap();
        // Background noise
        for i in 0..20_000u32 {
            s.update_signed(format!("noise-{i}").as_bytes(), 1);
        }
        // Heavy keys
        for _ in 0..5_000 {
            s.update_signed(b"elephant-a", 1);
            s.update_signed(b"elephant-b", 2);
        }
        let ea = s.estimate_signed(b"elephant-a");
        let eb = s.estimate_signed(b"elephant-b");
        assert!((ea - 5_000).abs() < 500, "elephant-a estimate {ea}");
        assert!((eb - 10_000).abs() < 500, "elephant-b estimate {eb}");
    }

    #[test]
    fn signed_updates_cancel() {
        let mut s = CountSketch::new(1024, 5, HashSpec::new(3)).unwrap();
        s.update_signed(b"k", 100);
        s.update_signed(b"k", -100);
        assert_eq!(s.estimate_signed(b"k"), 0);
    }

    #[test]
    fn merge_equals_single_stream() {
        let mut a = CountSketch::new(2048, 5, HashSpec::new(9)).unwrap();
        let mut b = CountSketch::new(2048, 5, HashSpec::new(9)).unwrap();
        let mut whole = CountSketch::new(2048, 5, HashSpec::new(9)).unwrap();
        for i in 0..10_000u32 {
            let key = format!("k{}", i % 500);
            whole.update_signed(key.as_bytes(), 1);
            if i % 2 == 0 {
                a.update_signed(key.as_bytes(), 1);
            } else {
                b.update_signed(key.as_bytes(), 1);
            }
        }
        a.merge_from(&b).unwrap();
        for i in 0..500u32 {
            let key = format!("k{i}");
            assert_eq!(
                a.estimate_signed(key.as_bytes()),
                whole.estimate_signed(key.as_bytes())
            );
        }
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s = CountSketch::new(512, 3, HashSpec::new(4)).unwrap();
        for i in 0..500u32 {
            s.update_signed(format!("k{}", i % 40).as_bytes(), 5);
        }
        let s2 = CountSketch::from_snapshot(&s.to_snapshot(0, 1)).unwrap();
        for i in 0..40u32 {
            let key = format!("k{i}");
            assert_eq!(
                s.estimate_signed(key.as_bytes()),
                s2.estimate_signed(key.as_bytes())
            );
        }
    }
}
