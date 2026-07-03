//! HyperLogLog (Flajolet et al. 2007) cardinality estimation with 64-bit
//! hashes and small-range linear counting.
//!
//! Error model: relative standard error ~ `1.04 / sqrt(2^precision)`.
//! With 64-bit hashes there is no practical large-range correction needed.

use flowsketch_core::hash::{hash64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "hll";
pub const MIN_PRECISION: u8 = 4;
pub const MAX_PRECISION: u8 = 18;

#[derive(Debug, Clone)]
pub struct HyperLogLog {
    precision: u8,
    hash: HashSpec,
    registers: Vec<u8>, // 2^precision registers
    updates: u64,
}

impl HyperLogLog {
    pub fn new(precision: u8, hash: HashSpec) -> Result<Self, SketchError> {
        if !(MIN_PRECISION..=MAX_PRECISION).contains(&precision) {
            return Err(SketchError::InvalidParam(format!(
                "hll precision must be in [{MIN_PRECISION}, {MAX_PRECISION}], got {precision}"
            )));
        }
        Ok(HyperLogLog {
            precision,
            hash,
            registers: vec![0; 1 << precision],
            updates: 0,
        })
    }

    /// Smallest precision whose relative standard error is <= `epsilon`.
    pub fn precision_for_error(epsilon: f64) -> u8 {
        let m = (1.04 / epsilon).powi(2);
        let p = m.log2().ceil() as i64;
        p.clamp(MIN_PRECISION as i64, MAX_PRECISION as i64) as u8
    }

    pub fn precision(&self) -> u8 {
        self.precision
    }

    /// Relative standard error of estimates from this sketch.
    pub fn relative_error(&self) -> f64 {
        1.04 / ((1u64 << self.precision) as f64).sqrt()
    }

    pub fn insert(&mut self, key: &[u8]) {
        self.updates += 1;
        let h = hash64(key, self.hash.seed);
        let idx = (h >> (64 - self.precision)) as usize;
        // rho: position of the leftmost 1-bit in the remaining bits.
        let remaining = h << self.precision;
        let rho = (remaining.leading_zeros() + 1).min(64 - self.precision as u32 + 1) as u8;
        if rho > self.registers[idx] {
            self.registers[idx] = rho;
        }
    }

    pub fn cardinality(&self) -> f64 {
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            n => 0.7213 / (1.0 + 1.079 / n as f64),
        };
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in &self.registers {
            sum += 1.0 / (1u64 << r) as f64;
            if r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m && zeros > 0 {
            // Small-range correction: linear counting.
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }

    fn params_hash(&self) -> u64 {
        hash64(&[self.precision], 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u8(self.precision);
        let mut payload = Writer::with_capacity(self.registers.len() + 8);
        payload.u64(self.updates);
        payload.bytes(&self.registers);
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::HYPER_LOG_LOG,
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
        if header.algorithm_id != algorithm_id::HYPER_LOG_LOG {
            return Err(SketchError::Snapshot("not an hll snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let precision = p.u8()?;
        let mut r = Reader::new(&payload);
        let updates = r.u64()?;
        let registers = r.take(1usize << precision)?.to_vec();
        Ok(HyperLogLog {
            precision,
            hash: header.hash,
            registers,
            updates,
        })
    }
}

impl Sketch for HyperLogLog {
    fn update(&mut self, key: &[u8], _value: u64) {
        self.insert(key);
    }

    fn estimate(&self, _key: &[u8]) -> f64 {
        self.cardinality()
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility().ensure_matches(&other.compatibility())?;
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        self.registers.len() + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.registers.fill(0);
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
    fn small_cardinalities_are_near_exact() {
        let mut h = HyperLogLog::new(12, HashSpec::new(5)).unwrap();
        for i in 0..100u32 {
            h.insert(format!("item-{i}").as_bytes());
            h.insert(format!("item-{i}").as_bytes()); // duplicates ignored
        }
        let est = h.cardinality();
        assert!((est - 100.0).abs() < 5.0, "estimate {est}");
    }

    #[test]
    fn large_cardinalities_within_relative_error() {
        let mut h = HyperLogLog::new(12, HashSpec::new(5)).unwrap();
        let n = 1_000_000u64;
        for i in 0..n {
            h.insert(&i.to_le_bytes());
        }
        let est = h.cardinality();
        let rel = (est - n as f64).abs() / n as f64;
        // 1.04/sqrt(4096) ~ 1.6%; allow 3 sigma.
        assert!(rel < 3.0 * h.relative_error(), "relative error {rel}");
    }

    #[test]
    fn merge_equals_union() {
        let mut a = HyperLogLog::new(12, HashSpec::new(6)).unwrap();
        let mut b = HyperLogLog::new(12, HashSpec::new(6)).unwrap();
        let mut union = HyperLogLog::new(12, HashSpec::new(6)).unwrap();
        for i in 0..50_000u64 {
            if i % 2 == 0 {
                a.insert(&i.to_le_bytes());
                union.insert(&i.to_le_bytes());
            }
            if i % 3 == 0 {
                b.insert(&i.to_le_bytes());
                union.insert(&i.to_le_bytes());
            }
        }
        a.merge_from(&b).unwrap();
        assert_eq!(a.registers, union.registers);
    }

    #[test]
    fn different_seeds_do_not_merge() {
        let mut a = HyperLogLog::new(12, HashSpec::new(1)).unwrap();
        let b = HyperLogLog::new(12, HashSpec::new(2)).unwrap();
        assert!(a.merge_from(&b).is_err());
    }

    #[test]
    fn snapshot_round_trips() {
        let mut h = HyperLogLog::new(10, HashSpec::new(7)).unwrap();
        for i in 0..10_000u64 {
            h.insert(&i.to_le_bytes());
        }
        let h2 = HyperLogLog::from_snapshot(&h.to_snapshot(0, 1)).unwrap();
        assert_eq!(h.cardinality(), h2.cardinality());
        assert_eq!(h.update_count(), h2.update_count());
    }

    #[test]
    fn precision_for_error_is_sane() {
        assert_eq!(HyperLogLog::precision_for_error(0.0163), 12);
        assert!(HyperLogLog::precision_for_error(0.5) >= MIN_PRECISION);
        assert!(HyperLogLog::precision_for_error(1e-9) <= MAX_PRECISION);
    }
}
