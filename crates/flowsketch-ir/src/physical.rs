//! Physical IR: the sketch configuration the planner chose.

use serde::{Deserialize, Serialize};

/// A physical sketch configuration. `Composite` combines stages (e.g. a
/// key tracker plus a counting sketch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhysicalSketch {
    CountMin {
        width: usize,
        depth: usize,
        conservative_update: bool,
    },
    CountSketch {
        width: usize,
        depth: usize,
    },
    SpaceSaving {
        capacity: usize,
    },
    MisraGries {
        capacity: usize,
    },
    HyperLogLog {
        precision: u8,
    },
    HllMap {
        max_keys: usize,
        precision: u8,
    },
    Composite {
        stages: Vec<PhysicalSketch>,
    },
}

impl PhysicalSketch {
    /// Short algorithm name for labels and explain output.
    pub fn algorithm_name(&self) -> String {
        match self {
            PhysicalSketch::CountMin { .. } => "count-min".to_string(),
            PhysicalSketch::CountSketch { .. } => "count-sketch".to_string(),
            PhysicalSketch::SpaceSaving { .. } => "spacesaving".to_string(),
            PhysicalSketch::MisraGries { .. } => "misra-gries".to_string(),
            PhysicalSketch::HyperLogLog { .. } => "hll".to_string(),
            PhysicalSketch::HllMap { .. } => "hllmap".to_string(),
            PhysicalSketch::Composite { stages } => stages
                .iter()
                .map(|s| s.algorithm_name())
                .collect::<Vec<_>>()
                .join("+"),
        }
    }

    /// Estimated steady-state memory for one instance of this sketch, in
    /// bytes. Keyed structures assume an average key of `avg_key_bytes`.
    pub fn estimated_memory_bytes(&self, avg_key_bytes: usize) -> u64 {
        const HASH_ENTRY_OVERHEAD: u64 = 48;
        match self {
            PhysicalSketch::CountMin { width, depth, .. } => (width * depth) as u64 * 8 + 64,
            PhysicalSketch::CountSketch { width, depth } => (width * depth) as u64 * 8 + 64,
            PhysicalSketch::SpaceSaving { capacity } | PhysicalSketch::MisraGries { capacity } => {
                *capacity as u64 * (avg_key_bytes as u64 + 16 + HASH_ENTRY_OVERHEAD) + 64
            }
            PhysicalSketch::HyperLogLog { precision } => (1u64 << precision) + 64,
            PhysicalSketch::HllMap {
                max_keys,
                precision,
            } => {
                *max_keys as u64
                    * ((1u64 << precision) + avg_key_bytes as u64 + HASH_ENTRY_OVERHEAD)
                    + 64
            }
            PhysicalSketch::Composite { stages } => stages
                .iter()
                .map(|s| s.estimated_memory_bytes(avg_key_bytes))
                .sum(),
        }
    }

    /// Render the configuration for explain output.
    pub fn describe(&self) -> String {
        match self {
            PhysicalSketch::CountMin {
                width,
                depth,
                conservative_update,
            } => format!(
                "CountMin(width={width}, depth={depth}, conservative={conservative_update})"
            ),
            PhysicalSketch::CountSketch { width, depth } => {
                format!("CountSketch(width={width}, depth={depth})")
            }
            PhysicalSketch::SpaceSaving { capacity } => {
                format!("SpaceSaving(capacity={capacity})")
            }
            PhysicalSketch::MisraGries { capacity } => {
                format!("MisraGries(capacity={capacity})")
            }
            PhysicalSketch::HyperLogLog { precision } => {
                format!("HyperLogLog(precision={precision})")
            }
            PhysicalSketch::HllMap {
                max_keys,
                precision,
            } => format!("HLLMap(max_keys={max_keys}, precision={precision})"),
            PhysicalSketch::Composite { stages } => {
                let inner: Vec<String> = stages.iter().map(|s| s.describe()).collect();
                format!("Composite[{}]", inner.join(" + "))
            }
        }
    }
}
