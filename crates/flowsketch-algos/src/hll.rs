//! HyperLogLog (Flajolet et al. 2007) cardinality estimation with 64-bit
//! hashes and Ertl's bias-corrected improved raw estimator.
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
const STORAGE_SPARSE: u8 = 0;
const STORAGE_DENSE: u8 = 1;
const SPARSE_MEMORY_FRACTION: usize = 4;

#[derive(Debug, Clone)]
pub struct HyperLogLog {
    precision: u8,
    hash: HashSpec,
    storage: RegisterStorage,
    updates: u64,
}

/// Keep small cardinalities as an exact, sorted set of 64-bit hashes. This
/// avoids allocating and clearing a dense register array for every low-fanout
/// HLLMap key. The sparse representation converts before its allocation can
/// exceed the dense array's byte count, so the planner's worst-case memory
/// contract remains valid.
#[derive(Debug, Clone)]
enum RegisterStorage {
    Empty,
    Singleton(u64),
    Sparse(Vec<u64>),
    Dense(Vec<u8>),
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
            storage: RegisterStorage::Empty,
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
        self.insert_hash(h);
    }

    fn insert_hash(&mut self, hash: u64) {
        let precision = self.precision;
        let sparse_limit = sparse_limit(precision);
        match &mut self.storage {
            RegisterStorage::Empty => {
                self.storage = RegisterStorage::Singleton(hash);
                return;
            }
            RegisterStorage::Singleton(existing) if *existing == hash => return,
            RegisterStorage::Singleton(existing) if sparse_limit > 1 => {
                let mut hashes = vec![*existing, hash];
                hashes.sort_unstable();
                self.storage = RegisterStorage::Sparse(hashes);
                return;
            }
            RegisterStorage::Singleton(_) => {}
            RegisterStorage::Sparse(hashes) => match hashes.binary_search(&hash) {
                Ok(_) => return,
                Err(position) if hashes.len() < sparse_limit => {
                    hashes.insert(position, hash);
                    return;
                }
                Err(_) => {}
            },
            RegisterStorage::Dense(registers) => {
                update_register(registers, precision, hash);
                return;
            }
        }

        self.ensure_dense();
        let RegisterStorage::Dense(registers) = &mut self.storage else {
            unreachable!("ensure_dense always creates dense storage");
        };
        update_register(registers, precision, hash);
    }

    fn ensure_dense(&mut self) {
        if matches!(self.storage, RegisterStorage::Dense(_)) {
            return;
        }
        let sparse = match std::mem::replace(
            &mut self.storage,
            RegisterStorage::Dense(vec![0; 1 << self.precision]),
        ) {
            RegisterStorage::Empty => Vec::new(),
            RegisterStorage::Singleton(hash) => vec![hash],
            RegisterStorage::Sparse(hashes) => hashes,
            RegisterStorage::Dense(_) => unreachable!(),
        };
        let RegisterStorage::Dense(registers) = &mut self.storage else {
            unreachable!();
        };
        for hash in sparse {
            update_register(registers, self.precision, hash);
        }
    }

    #[cfg(test)]
    fn dense_registers(&self) -> Vec<u8> {
        match &self.storage {
            RegisterStorage::Dense(registers) => registers.clone(),
            RegisterStorage::Empty => vec![0; 1 << self.precision],
            RegisterStorage::Singleton(hash) => {
                let mut registers = vec![0; 1 << self.precision];
                update_register(&mut registers, self.precision, *hash);
                registers
            }
            RegisterStorage::Sparse(hashes) => {
                let mut registers = vec![0; 1 << self.precision];
                for &hash in hashes {
                    update_register(&mut registers, self.precision, hash);
                }
                registers
            }
        }
    }

    pub fn cardinality(&self) -> f64 {
        let registers = match &self.storage {
            RegisterStorage::Empty => return 0.0,
            RegisterStorage::Singleton(_) => return 1.0,
            RegisterStorage::Sparse(hashes) => return hashes.len() as f64,
            RegisterStorage::Dense(registers) => registers,
        };
        let m = registers.len() as f64;
        let q = 64usize - self.precision as usize;
        let mut counts = [0usize; 66];
        for &register in registers {
            counts[register as usize] += 1;
        }

        // Ertl's improved raw estimator corrects both the empty-register and
        // saturated-register ranges without empirical bias tables. This also
        // removes the severe bias discontinuity around the old 2.5*m switch
        // from linear counting to the original raw estimator.
        let mut denominator = m * ertl_tau(1.0 - counts[q + 1] as f64 / m);
        for rank in (1..=q).rev() {
            denominator = 0.5 * (denominator + counts[rank] as f64);
        }
        denominator += m * ertl_sigma(counts[0] as f64 / m);
        const ALPHA_INFINITY: f64 = 0.721_347_520_444_481_7;
        ALPHA_INFINITY * m * m / denominator
    }

    fn params_hash(&self) -> u64 {
        hash64(&[self.precision], 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u8(self.precision);
        let mut payload = Writer::new();
        payload.u64(self.updates);
        match &self.storage {
            RegisterStorage::Empty => {
                payload.u8(STORAGE_SPARSE);
                payload.u32(0);
            }
            RegisterStorage::Singleton(hash) => {
                payload.u8(STORAGE_SPARSE);
                payload.u32(1);
                payload.u64(*hash);
            }
            RegisterStorage::Sparse(hashes) => {
                payload.u8(STORAGE_SPARSE);
                payload.u32(hashes.len() as u32);
                for &hash in hashes {
                    payload.u64(hash);
                }
            }
            RegisterStorage::Dense(registers) => {
                payload.u8(STORAGE_DENSE);
                payload.bytes(registers);
            }
        }
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
        // Re-establish the constructor's invariant: an out-of-range
        // precision from a hostile snapshot would otherwise drive the
        // `1 << precision` register math out of `usize`.
        if !(MIN_PRECISION..=MAX_PRECISION).contains(&precision) {
            return Err(SketchError::Snapshot(format!(
                "hll snapshot precision must be in [{MIN_PRECISION}, {MAX_PRECISION}], \
                 got {precision}"
            )));
        }
        let mut r = Reader::new(&payload);
        let updates = r.u64()?;
        let storage = match r.u8()? {
            STORAGE_SPARSE => {
                let count = r.u32()? as usize;
                let sparse_limit = sparse_limit(precision);
                if count > sparse_limit {
                    return Err(SketchError::Snapshot(format!(
                        "hll sparse hash count {count} exceeds limit {sparse_limit}"
                    )));
                }
                r.check_count(count, std::mem::size_of::<u64>())?;
                let mut hashes = Vec::with_capacity(count);
                for _ in 0..count {
                    let hash = r.u64()?;
                    if hashes.last().is_some_and(|previous| *previous >= hash) {
                        return Err(SketchError::Snapshot(
                            "hll sparse hashes must be strictly sorted and unique".into(),
                        ));
                    }
                    hashes.push(hash);
                }
                match hashes.as_slice() {
                    [] => RegisterStorage::Empty,
                    [hash] => RegisterStorage::Singleton(*hash),
                    _ => RegisterStorage::Sparse(hashes),
                }
            }
            STORAGE_DENSE => {
                let registers = r.take(1usize << precision)?.to_vec();
                let max_register = 64 - precision + 1;
                if let Some(&register) = registers.iter().find(|&&register| register > max_register)
                {
                    return Err(SketchError::Snapshot(format!(
                        "hll snapshot register must be <= {max_register} for precision \
                         {precision}, got {register}"
                    )));
                }
                RegisterStorage::Dense(registers)
            }
            encoding => {
                return Err(SketchError::Snapshot(format!(
                    "unknown hll storage encoding {encoding}"
                )))
            }
        };
        if r.remaining() != 0 {
            return Err(SketchError::Snapshot(
                "trailing bytes in hll snapshot payload".into(),
            ));
        }
        Ok(HyperLogLog {
            precision,
            hash: header.hash,
            storage,
            updates,
        })
    }
}

fn sparse_limit(precision: u8) -> usize {
    ((1usize << precision) / (SPARSE_MEMORY_FRACTION * std::mem::size_of::<u64>())).max(1)
}

fn update_register(registers: &mut [u8], precision: u8, hash: u64) {
    let idx = (hash >> (64 - precision)) as usize;
    // rho: position of the leftmost 1-bit in the remaining bits.
    let remaining = hash << precision;
    let rho = (remaining.leading_zeros() + 1).min(64 - precision as u32 + 1) as u8;
    if rho > registers[idx] {
        registers[idx] = rho;
    }
}

/// Small-cardinality correction from Ertl's improved raw estimator.
fn ertl_sigma(mut x: f64) -> f64 {
    if x == 1.0 {
        return f64::INFINITY;
    }
    let mut z = x;
    let mut scale = 1.0;
    loop {
        x *= x;
        let previous = z;
        z += x * scale;
        scale += scale;
        if z == previous {
            return z;
        }
    }
}

/// Saturated-register correction from Ertl's improved raw estimator.
fn ertl_tau(mut x: f64) -> f64 {
    if x == 0.0 || x == 1.0 {
        return 0.0;
    }
    let mut z = 1.0 - x;
    let mut scale = 1.0;
    loop {
        x = x.sqrt();
        let previous = z;
        scale *= 0.5;
        z -= (1.0 - x).powi(2) * scale;
        if z == previous {
            return z / 3.0;
        }
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
        self.compatibility()
            .ensure_matches(&other.compatibility())?;
        match &other.storage {
            RegisterStorage::Empty => {}
            RegisterStorage::Singleton(hash) => self.insert_hash(*hash),
            RegisterStorage::Sparse(hashes) => {
                for &hash in hashes {
                    self.insert_hash(hash);
                }
            }
            RegisterStorage::Dense(theirs) => {
                self.ensure_dense();
                let RegisterStorage::Dense(mine) = &mut self.storage else {
                    unreachable!();
                };
                for (a, b) in mine.iter_mut().zip(theirs) {
                    if *b > *a {
                        *a = *b;
                    }
                }
            }
        }
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let storage = match &self.storage {
            RegisterStorage::Empty | RegisterStorage::Singleton(_) => 0,
            RegisterStorage::Sparse(hashes) => hashes.capacity() * std::mem::size_of::<u64>(),
            RegisterStorage::Dense(registers) => registers.capacity(),
        };
        storage + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        match &mut self.storage {
            RegisterStorage::Empty => {}
            RegisterStorage::Singleton(_) => self.storage = RegisterStorage::Empty,
            RegisterStorage::Sparse(hashes) => hashes.clear(),
            RegisterStorage::Dense(registers) => registers.fill(0),
        }
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
        let relative = (est - 100.0).abs() / 100.0;
        assert!(
            relative <= 2.0 * h.relative_error(),
            "estimate {est}, relative error {relative}"
        );
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
        assert!(rel <= 2.0 * h.relative_error(), "relative error {rel}");
    }

    #[test]
    fn transition_range_intervals_are_not_systematically_biased() {
        const TRIALS: u64 = 64;
        const TRUTH: u64 = 41_000;
        let mut covered = 0u64;
        let mut signed_relative_error = 0.0;
        for seed in 0..TRIALS {
            let mut h = HyperLogLog::new(14, HashSpec::new(seed)).unwrap();
            for item in 0..TRUTH {
                h.insert(&item.to_le_bytes());
            }
            let estimate = h.cardinality();
            let relative = (estimate - TRUTH as f64) / TRUTH as f64;
            signed_relative_error += relative;
            if relative.abs() <= 2.0 * h.relative_error() {
                covered += 1;
            }
        }

        let mean_bias = signed_relative_error / TRIALS as f64;
        assert!(
            mean_bias.abs()
                < 0.5
                    * HyperLogLog::new(14, HashSpec::new(0))
                        .unwrap()
                        .relative_error(),
            "transition-range mean relative bias {mean_bias}"
        );
        assert!(
            covered >= 58,
            "only {covered}/{TRIALS} nominal 95% intervals covered truth"
        );
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
        assert_eq!(a.dense_registers(), union.dense_registers());
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
    fn sparse_snapshot_round_trips_exact_cardinality() {
        let mut h = HyperLogLog::new(14, HashSpec::new(17)).unwrap();
        for i in 0..500u64 {
            h.insert(&i.to_le_bytes());
        }
        assert!(matches!(h.storage, RegisterStorage::Sparse(_)));
        assert_eq!(h.cardinality(), 500.0);
        assert!(h.memory_bytes() <= (1 << h.precision()) + std::mem::size_of::<HyperLogLog>());

        let restored = HyperLogLog::from_snapshot(&h.to_snapshot(0, 1)).unwrap();
        assert!(matches!(restored.storage, RegisterStorage::Sparse(_)));
        assert_eq!(restored.cardinality(), 500.0);
    }

    #[test]
    fn out_of_range_snapshot_precision_is_rejected() {
        let mut params = Writer::new();
        params.u8(200);
        let mut payload = Writer::new();
        payload.u64(0);
        let bytes = write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::HYPER_LOG_LOG,
                hash: HashSpec::new(1),
                window_start_nanos: 0,
                window_end_nanos: 0,
            },
            &params.buf,
            &payload.buf,
        );
        let err = HyperLogLog::from_snapshot(&bytes).unwrap_err();
        assert!(err.to_string().contains("precision"), "{err}");
    }

    #[test]
    fn out_of_range_snapshot_register_is_rejected() {
        let mut params = Writer::new();
        params.u8(MIN_PRECISION);
        let mut payload = Writer::new();
        payload.u64(0);
        payload.u8(STORAGE_DENSE);
        payload.bytes(&[u8::MAX; 1 << MIN_PRECISION]);
        let bytes = write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::HYPER_LOG_LOG,
                hash: HashSpec::new(1),
                window_start_nanos: 0,
                window_end_nanos: 0,
            },
            &params.buf,
            &payload.buf,
        );
        let err = HyperLogLog::from_snapshot(&bytes).unwrap_err();
        assert!(err.to_string().contains("register"), "{err}");
    }

    #[test]
    fn precision_for_error_is_sane() {
        assert_eq!(HyperLogLog::precision_for_error(0.0163), 12);
        assert!(HyperLogLog::precision_for_error(0.5) >= MIN_PRECISION);
        assert!(HyperLogLog::precision_for_error(1e-9) <= MAX_PRECISION);
    }
}
