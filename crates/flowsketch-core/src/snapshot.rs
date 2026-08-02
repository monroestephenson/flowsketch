//! The `FSK1` versioned binary snapshot format.
//!
//! Layout:
//!
//! ```text
//! magic:        "FSK1" (4 bytes)
//! version:      u16
//! algorithm_id: u16
//! hash_family:  u8   (0 = fsk1)
//! hash_seed:    u64
//! hash_version: u16
//! window_start: u64
//! window_end:   u64
//! params_len:   u32
//! params:       [u8; params_len]
//! payload_len:  u32
//! payload:      [u8; payload_len]
//! checksum:     u64 (fsk1 hash of everything before it, seed 0)
//! ```
//!
//! All integers are little-endian. Stable serialization is what makes
//! distributed merge, golden tests, and future language bindings possible.

use crate::error::SketchError;
use crate::hash::{hash64, HashFamily, HashSpec};

pub const MAGIC: [u8; 4] = *b"FSK1";
/// Version 2 accompanies hash family version 2 and the sparse/dense HLL
/// payload. Version 1 readers reject it at the header instead of silently
/// interpreting a changed algorithm payload.
pub const SNAPSHOT_VERSION: u16 = 2;

/// Stable algorithm identifiers for the snapshot header.
pub mod algorithm_id {
    pub const COUNT_MIN: u16 = 1;
    pub const COUNT_SKETCH: u16 = 2;
    pub const HYPER_LOG_LOG: u16 = 3;
    pub const SPACE_SAVING: u16 = 4;
    pub const MISRA_GRIES: u16 = 5;
    pub const HLL_MAP: u16 = 6;
    pub const EXACT: u16 = 7;
    pub const KLL: u16 = 8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub version: u16,
    pub algorithm_id: u16,
    pub hash: HashSpec,
    pub window_start_nanos: u64,
    pub window_end_nanos: u64,
}

/// Serialize a snapshot with header, algorithm params, and payload.
pub fn write_snapshot(header: &SnapshotHeader, params: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(4 + 2 + 2 + 11 + 16 + 8 + params.len() + payload.len() + 8);
    w.bytes(&MAGIC);
    w.u16(header.version);
    w.u16(header.algorithm_id);
    w.u8(match header.hash.family {
        HashFamily::Fsk1 => 0,
    });
    w.u64(header.hash.seed);
    w.u16(header.hash.version);
    w.u64(header.window_start_nanos);
    w.u64(header.window_end_nanos);
    w.u32(params.len() as u32);
    w.bytes(params);
    w.u32(payload.len() as u32);
    w.bytes(payload);
    let checksum = hash64(&w.buf, 0);
    w.u64(checksum);
    w.buf
}

/// Parse and checksum-verify a snapshot, returning header, params, payload.
pub fn read_snapshot(bytes: &[u8]) -> Result<(SnapshotHeader, Vec<u8>, Vec<u8>), SketchError> {
    if bytes.len() < 4 + 2 + 2 + 11 + 16 + 8 + 8 {
        return Err(SketchError::Snapshot("snapshot too short".into()));
    }
    let (body, tail) = bytes.split_at(bytes.len() - 8);
    let expected = u64::from_le_bytes(tail.try_into().unwrap());
    if hash64(body, 0) != expected {
        return Err(SketchError::Snapshot("checksum mismatch".into()));
    }

    let mut r = Reader::new(body);
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(SketchError::Snapshot("bad magic (expected FSK1)".into()));
    }
    let version = r.u16()?;
    if version != SNAPSHOT_VERSION {
        return Err(SketchError::Snapshot(format!(
            "unsupported snapshot version {version}"
        )));
    }
    let algorithm_id = r.u16()?;
    let family = match r.u8()? {
        0 => HashFamily::Fsk1,
        other => {
            return Err(SketchError::Snapshot(format!(
                "unknown hash family id {other}"
            )))
        }
    };
    let seed = r.u64()?;
    let hash_version = r.u16()?;
    let window_start_nanos = r.u64()?;
    let window_end_nanos = r.u64()?;
    let params_len = r.u32()? as usize;
    let params = r.take(params_len)?.to_vec();
    let payload_len = r.u32()? as usize;
    let payload = r.take(payload_len)?.to_vec();

    Ok((
        SnapshotHeader {
            version,
            algorithm_id,
            hash: HashSpec {
                family,
                seed,
                version: hash_version,
            },
            window_start_nanos,
            window_end_nanos,
        },
        params,
        payload,
    ))
}

/// Little-endian byte writer for snapshot params/payloads.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }
    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// Length-prefixed byte string (u32 length).
    pub fn lp_bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.bytes(v);
    }
}

/// Little-endian byte reader for snapshot params/payloads.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], SketchError> {
        if self.remaining() < n {
            return Err(SketchError::Snapshot("unexpected end of snapshot".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, SketchError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, SketchError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, SketchError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, SketchError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64, SketchError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn lp_bytes(&mut self) -> Result<&'a [u8], SketchError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// Validate a declared element count against the bytes actually left,
    /// given the smallest possible encoding of one element. Snapshots come
    /// from untrusted peers, so a count must never be trusted to size an
    /// allocation the payload cannot back.
    pub fn check_count(&self, count: usize, min_bytes_each: usize) -> Result<(), SketchError> {
        if count > self.remaining() / min_bytes_each.max(1) {
            return Err(SketchError::Snapshot(format!(
                "declared count {count} cannot fit in the {} bytes remaining",
                self.remaining()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips() {
        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            algorithm_id: algorithm_id::COUNT_MIN,
            hash: HashSpec::new(99),
            window_start_nanos: 1_000,
            window_end_nanos: 61_000,
        };
        let params = vec![1u8, 2, 3];
        let payload = vec![9u8; 100];
        let bytes = write_snapshot(&header, &params, &payload);
        let (h2, p2, pl2) = read_snapshot(&bytes).unwrap();
        assert_eq!(h2, header);
        assert_eq!(p2, params);
        assert_eq!(pl2, payload);
    }

    #[test]
    fn check_count_bounds_declared_counts() {
        let buf = [0u8; 40];
        let r = Reader::new(&buf);
        assert!(r.check_count(5, 8).is_ok());
        assert!(r.check_count(6, 8).is_err());
        assert!(r.check_count(usize::MAX, 8).is_err());
        // A zero minimum must not divide by zero (treated as 1 byte each).
        assert!(r.check_count(40, 0).is_ok());
        assert!(r.check_count(41, 0).is_err());
    }

    #[test]
    fn corrupt_snapshot_is_rejected() {
        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            algorithm_id: algorithm_id::HYPER_LOG_LOG,
            hash: HashSpec::new(0),
            window_start_nanos: 0,
            window_end_nanos: 0,
        };
        let mut bytes = write_snapshot(&header, &[], &[1, 2, 3]);
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(read_snapshot(&bytes).is_err());
    }
}
