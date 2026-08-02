//! The `FSKB` push-batch envelope: one round of FSK1 component snapshots
//! shipped from an agent to the gateway in a single POST body.
//!
//! Layout:
//!
//! ```text
//! magic:       "FSKB" (4 bytes)
//! version:     u16
//! node:        length-prefixed UTF-8 (the pushing agent's nodeName)
//! entry_count: u32
//! entries:     query_name lp, component lp, snapshot lp   (repeated)
//! checksum:    u64 (fsk1 hash of everything before it, seed 0)
//! ```
//!
//! All integers are little-endian, matching the FSK1 snapshot format. The
//! inner snapshots stay opaque bytes here; the gateway hands them to
//! `flowsketch_runtime::WindowState` for parsing and compatibility
//! validation.

use flowsketch_core::hash::hash64;
use flowsketch_core::snapshot::{Reader, Writer};
use flowsketch_core::SketchError;

pub const MAGIC: [u8; 4] = *b"FSKB";
pub const BATCH_VERSION: u16 = 1;

/// Hard cap on entries per batch: an agent pushes at most a handful of
/// component snapshots per query, so anything huge is a corrupt or hostile
/// payload, not a bigger deployment.
pub const MAX_ENTRIES: usize = 4_096;
/// Kubernetes node names are DNS subdomains and therefore at most 253 bytes.
/// Applying the same bound to every gateway client prevents identity strings
/// from becoming an independent memory-amplification path.
pub const MAX_NODE_NAME_BYTES: usize = 253;
/// Query and component identifiers come from local plans and are never
/// expected to be remotely supplied blobs.
pub use flowsketch_ir::MAX_QUERY_NAME_BYTES;
pub const MAX_COMPONENT_NAME_BYTES: usize = 128;

/// One component snapshot inside a push batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEntry {
    pub query_name: String,
    pub component: String,
    pub snapshot: Vec<u8>,
}

/// Everything one agent pushes in one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushBatch {
    pub node: String,
    pub entries: Vec<PushEntry>,
}

impl PushBatch {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&MAGIC);
        w.u16(BATCH_VERSION);
        w.lp_bytes(self.node.as_bytes());
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w.lp_bytes(e.query_name.as_bytes());
            w.lp_bytes(e.component.as_bytes());
            w.lp_bytes(&e.snapshot);
        }
        let checksum = hash64(&w.buf, 0);
        w.u64(checksum);
        w.buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SketchError> {
        if bytes.len() < 4 + 2 + 4 + 4 + 8 {
            return Err(SketchError::Snapshot("push batch too short".into()));
        }
        let (body, tail) = bytes.split_at(bytes.len() - 8);
        let expected = u64::from_le_bytes(tail.try_into().unwrap());
        if hash64(body, 0) != expected {
            return Err(SketchError::Snapshot("push batch checksum mismatch".into()));
        }

        let mut r = Reader::new(body);
        if r.take(4)? != MAGIC {
            return Err(SketchError::Snapshot("bad magic (expected FSKB)".into()));
        }
        let version = r.u16()?;
        if version != BATCH_VERSION {
            return Err(SketchError::Snapshot(format!(
                "unsupported push batch version {version}"
            )));
        }
        let node = utf8_bounded(r.lp_bytes()?, "node", MAX_NODE_NAME_BYTES)?;
        let count = r.u32()? as usize;
        if count > MAX_ENTRIES {
            return Err(SketchError::Snapshot(format!(
                "push batch declares {count} entries (max {MAX_ENTRIES})"
            )));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(PushEntry {
                query_name: utf8_bounded(r.lp_bytes()?, "query name", MAX_QUERY_NAME_BYTES)?,
                component: utf8_bounded(r.lp_bytes()?, "component", MAX_COMPONENT_NAME_BYTES)?,
                snapshot: r.lp_bytes()?.to_vec(),
            });
        }
        if r.remaining() != 0 {
            return Err(SketchError::Snapshot(
                "trailing bytes after push batch entries".into(),
            ));
        }
        Ok(PushBatch { node, entries })
    }
}

fn utf8_bounded(bytes: &[u8], what: &str, max_bytes: usize) -> Result<String, SketchError> {
    if bytes.is_empty() {
        return Err(SketchError::Snapshot(format!(
            "push batch {what} must not be empty"
        )));
    }
    if bytes.len() > max_bytes {
        return Err(SketchError::Snapshot(format!(
            "push batch {what} is {} bytes (max {max_bytes})",
            bytes.len()
        )));
    }
    let value = String::from_utf8(bytes.to_vec())
        .map_err(|_| SketchError::Snapshot(format!("push batch {what} is not UTF-8")))?;
    if value.trim().is_empty() {
        return Err(SketchError::Snapshot(format!(
            "push batch {what} must not be blank"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PushBatch {
        PushBatch {
            node: "node-a".into(),
            entries: vec![
                PushEntry {
                    query_name: "top_talkers".into(),
                    component: "spacesaving".into(),
                    snapshot: vec![1, 2, 3, 4],
                },
                PushEntry {
                    query_name: "scanners".into(),
                    component: "hllmap".into(),
                    snapshot: vec![9; 300],
                },
            ],
        }
    }

    #[test]
    fn batch_round_trips() {
        let batch = sample();
        let decoded = PushBatch::decode(&batch.encode()).unwrap();
        assert_eq!(decoded, batch);
    }

    #[test]
    fn empty_batch_round_trips() {
        let batch = PushBatch {
            node: "n".into(),
            entries: vec![],
        };
        assert_eq!(PushBatch::decode(&batch.encode()).unwrap(), batch);
    }

    #[test]
    fn corruption_is_rejected() {
        let mut bytes = sample().encode();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(PushBatch::decode(&bytes).is_err());
    }

    #[test]
    fn truncation_is_rejected() {
        let bytes = sample().encode();
        assert!(PushBatch::decode(&bytes[..bytes.len() - 3]).is_err());
        assert!(PushBatch::decode(&[]).is_err());
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        // Checksum fails first; rewriting it exposes the magic check.
        let n = bytes.len();
        let sum = flowsketch_core::hash::hash64(&bytes[..n - 8], 0);
        bytes[n - 8..].copy_from_slice(&sum.to_le_bytes());
        let err = PushBatch::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("FSKB"), "{err}");
    }

    #[test]
    fn oversized_or_blank_wire_identifiers_are_rejected() {
        let mut batch = sample();
        batch.node = "n".repeat(MAX_NODE_NAME_BYTES + 1);
        let error = PushBatch::decode(&batch.encode()).unwrap_err();
        assert!(error.to_string().contains("node"), "{error}");

        batch = sample();
        batch.node = "   ".into();
        assert!(PushBatch::decode(&batch.encode()).is_err());

        batch = sample();
        batch.entries[0].query_name = "q".repeat(MAX_QUERY_NAME_BYTES + 1);
        assert!(PushBatch::decode(&batch.encode()).is_err());

        batch = sample();
        batch.entries[0].component = "c".repeat(MAX_COMPONENT_NAME_BYTES + 1);
        assert!(PushBatch::decode(&batch.encode()).is_err());
    }
}
