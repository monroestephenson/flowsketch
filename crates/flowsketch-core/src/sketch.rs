//! The common sketch interface and merge-compatibility metadata.

use serde::{Deserialize, Serialize};

use crate::error::SketchError;
use crate::hash::HashSpec;

/// Object-safe sketch interface over byte keys and unsigned weights.
///
/// All FlowSketch sketches speak this interface so the runtime can shard,
/// window, and merge them uniformly. Keys are canonical byte encodings (see
/// `field::group_key`); values are nonnegative weights (1 for counting).
pub trait Sketch {
    /// Add `value` weight for `key`.
    fn update(&mut self, key: &[u8], value: u64);

    /// Point estimate for `key`.
    fn estimate(&self, key: &[u8]) -> f64;

    /// Merge `other` into `self`. Fails unless the two sketches are
    /// compatible (same algorithm, parameters, and hash spec).
    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError>
    where
        Self: Sized;

    /// Bytes of memory currently held.
    fn memory_bytes(&self) -> usize;

    /// Clear all state, keeping configuration.
    fn reset(&mut self);

    /// Total updates applied since creation/reset.
    fn update_count(&self) -> u64;

    /// Compatibility descriptor used to validate merges across nodes.
    fn compatibility(&self) -> SketchCompatibility;
}

/// Everything that must match for two sketch instances to merge:
/// same algorithm, version, hash family/seed, and parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SketchCompatibility {
    pub algorithm: String,
    pub version: u16,
    pub hash: HashSpec,
    /// Hash of the parameter tuple (width/depth/precision/capacity...).
    pub params_hash: u64,
}

impl SketchCompatibility {
    pub fn ensure_matches(&self, other: &SketchCompatibility) -> Result<(), SketchError> {
        if self != other {
            return Err(SketchError::IncompatibleMerge(format!(
                "sketches are not merge-compatible: {self:?} vs {other:?}"
            )));
        }
        Ok(())
    }
}
