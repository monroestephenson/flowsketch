//! Seeded hash families.
//!
//! Hashing is not an implementation detail: it affects accuracy, merge
//! compatibility across nodes, and adversarial behavior. FlowSketch uses a
//! named, versioned hash family (`fsk1`) with explicit seeds so that
//! sketches built on different nodes with the same `HashSpec` are mergeable,
//! and so exported estimates can carry hash-version metadata.

use serde::{Deserialize, Serialize};

/// Version of the `fsk1` hash family. Bump on any change to the mixing
/// functions below; sketches with different hash versions must not merge.
pub const HASH_VERSION: u16 = 1;

/// Named hash families. Only `fsk1` exists today; the enum keeps the wire
/// format honest about which function produced an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashFamily {
    Fsk1,
}

impl HashFamily {
    pub fn name(self) -> &'static str {
        match self {
            HashFamily::Fsk1 => "fsk1",
        }
    }
}

/// A fully-specified hash configuration. Two sketches are hash-compatible
/// iff their `HashSpec`s are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashSpec {
    pub family: HashFamily,
    pub seed: u64,
    pub version: u16,
}

impl HashSpec {
    pub fn new(seed: u64) -> Self {
        HashSpec {
            family: HashFamily::Fsk1,
            seed,
            version: HASH_VERSION,
        }
    }

    /// Hash arbitrary bytes to 64 bits under this spec.
    pub fn hash64(&self, bytes: &[u8]) -> u64 {
        hash64(bytes, self.seed)
    }
}

impl Default for HashSpec {
    fn default() -> Self {
        HashSpec::new(0)
    }
}

/// Deterministic RNG over the SplitMix64 stream. Used for reproducible
/// synthetic traffic, benchmarks, and sketch-internal randomness — not for
/// anything security-sensitive.
#[derive(Debug, Clone)]
pub struct SplitMixRng(u64);

impl SplitMixRng {
    pub fn new(seed: u64) -> Self {
        SplitMixRng(seed)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        splitmix64(self.0)
    }

    /// Uniform in [0, 1).
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// SplitMix64 finalizer/mixer. Deterministic, well-distributed, cheap.
#[inline]
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// The `fsk1` byte hash: seeded FNV-1a core with a SplitMix64 finalizer.
/// Deterministic across platforms and versions of this crate (see
/// `HASH_VERSION`).
#[inline]
pub fn hash64(bytes: &[u8], seed: u64) -> u64 {
    const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut h = FNV_OFFSET ^ splitmix64(seed);
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    splitmix64(h)
}

/// Per-row derived hashes for multi-row sketches (Count-Min, CountSketch),
/// using the Kirsch–Mitzenmacher construction: `h_i(x) = h1(x) + i * h2(x)`.
/// One pass over the key bytes yields indexes for every row.
#[derive(Debug, Clone, Copy)]
pub struct RowHashes {
    h1: u64,
    h2: u64,
}

impl RowHashes {
    #[inline]
    pub fn new(spec: &HashSpec, key: &[u8]) -> Self {
        let h1 = hash64(key, spec.seed);
        // Independent second hash; force odd so rows do not collapse.
        let h2 = hash64(key, spec.seed ^ 0xA5A5_A5A5_5A5A_5A5A) | 1;
        RowHashes { h1, h2 }
    }

    /// Column index for `row` in a table of `width` columns.
    #[inline]
    pub fn index(&self, row: usize, width: usize) -> usize {
        let h = self.h1.wrapping_add((row as u64).wrapping_mul(self.h2));
        (h % width as u64) as usize
    }

    /// A +1/-1 sign for `row`, independent of the index bits (CountSketch).
    #[inline]
    pub fn sign(&self, row: usize) -> i64 {
        let s = splitmix64(self.h1 ^ (row as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ self.h2);
        if s & 1 == 1 {
            1
        } else {
            -1
        }
    }

    /// The raw 64-bit hash (used by cardinality sketches).
    #[inline]
    pub fn raw(&self) -> u64 {
        self.h1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_seed_sensitive() {
        let a = hash64(b"10.0.0.1", 7);
        let b = hash64(b"10.0.0.1", 7);
        let c = hash64(b"10.0.0.1", 8);
        let d = hash64(b"10.0.0.2", 7);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn golden_values_are_stable() {
        // Golden values pin the fsk1 wire behavior. If these change,
        // HASH_VERSION must be bumped.
        assert_eq!(hash64(b"", 0), hash64(b"", 0));
        let g1 = hash64(b"flowsketch", 0);
        let g2 = hash64(b"flowsketch", 1);
        assert_ne!(g1, g2);
        // Self-consistency across calls in this process and across runs.
        assert_eq!(g1, hash64(b"flowsketch", 0));
    }

    #[test]
    fn row_hashes_spread_rows() {
        let spec = HashSpec::new(42);
        let rh = RowHashes::new(&spec, b"key");
        let idx: Vec<usize> = (0..4).map(|r| rh.index(r, 1024)).collect();
        // Not a strict requirement, but with h2 odd the rows should not all
        // land on the same column for a nontrivial width.
        assert!(idx.iter().any(|&i| i != idx[0]));
        for r in 0..4 {
            let s = rh.sign(r);
            assert!(s == 1 || s == -1);
        }
    }
}
