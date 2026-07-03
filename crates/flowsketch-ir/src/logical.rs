//! Logical IR: what the operator asked for, independent of any sketch.

use serde::{Deserialize, Serialize};

use flowsketch_core::event::FlowEvent;
use flowsketch_core::Field;

/// Time window specification. `slide == size` means a tumbling window;
/// `slide < size` is a sliding window realized as a ring of
/// `size / slide` tumbling buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSpec {
    pub size_nanos: u64,
    pub slide_nanos: u64,
}

impl WindowSpec {
    pub fn tumbling(size_nanos: u64) -> Self {
        WindowSpec {
            size_nanos,
            slide_nanos: size_nanos,
        }
    }

    pub fn bucket_count(&self) -> usize {
        (self.size_nanos / self.slide_nanos).max(1) as usize
    }

    pub fn describe(&self) -> String {
        humanize_nanos(self.size_nanos).to_string()
    }
}

/// Human-friendly duration rendering for labels/explain output.
pub fn humanize_nanos(nanos: u64) -> String {
    const SEC: u64 = 1_000_000_000;
    // Prefer seconds below two minutes so common windows render as "60s",
    // matching how operators write them.
    if nanos % 3_600_000_000_000 == 0 && nanos >= 3_600_000_000_000 {
        format!("{}h", nanos / 3_600_000_000_000)
    } else if nanos % 60_000_000_000 == 0 && nanos >= 120_000_000_000 {
        format!("{}m", nanos / 60_000_000_000)
    } else if nanos % SEC == 0 {
        format!("{}s", nanos / SEC)
    } else if nanos % 1_000_000 == 0 {
        format!("{}ms", nanos / 1_000_000)
    } else {
        format!("{nanos}ns")
    }
}

/// Requested error contract. Interpretation depends on the measure family:
/// additive `epsilon * N` for counting sketches, relative standard error
/// for cardinality sketches.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ErrorSpec {
    pub epsilon: f64,
    pub delta: f64,
}

impl Default for ErrorSpec {
    fn default() -> Self {
        ErrorSpec {
            epsilon: 0.001,
            delta: 0.01,
        }
    }
}

/// The measure the query estimates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Measure {
    /// Event count per group.
    Count,
    /// Sum of a numeric field per group.
    Sum { value: Field },
    /// Top-`limit` groups by summed value.
    HeavyHitters { value: Field, limit: usize },
    /// Approximate number of distinct `field` values per group.
    DistinctCount { field: Field },
    /// Empirical entropy of `field`'s distribution (not yet planned in v0).
    Entropy { field: Field },
    /// Quantile of a numeric field (not yet planned in v0).
    Quantile { field: Field, q: f64 },
}

impl Measure {
    pub fn name(&self) -> &'static str {
        match self {
            Measure::Count => "count",
            Measure::Sum { .. } => "sum",
            Measure::HeavyHitters { .. } => "heavy_hitters",
            Measure::DistinctCount { .. } => "distinct_count",
            Measure::Entropy { .. } => "entropy",
            Measure::Quantile { .. } => "quantile",
        }
    }
}

/// Conjunctive filter over flow events.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// IANA protocol number, if filtering by protocol.
    pub protocol: Option<u8>,
    /// Match any of these destination ports (empty = no constraint).
    #[serde(default)]
    pub dst_ports: Vec<u16>,
    /// Match any of these source ports (empty = no constraint).
    #[serde(default)]
    pub src_ports: Vec<u16>,
    /// Match any of these interface indexes (empty = no constraint).
    #[serde(default)]
    pub interfaces: Vec<u32>,
}

impl Predicate {
    pub fn matches(&self, e: &FlowEvent) -> bool {
        if let Some(p) = self.protocol {
            if e.protocol != p {
                return false;
            }
        }
        if !self.dst_ports.is_empty() && !self.dst_ports.contains(&e.dst_port) {
            return false;
        }
        if !self.src_ports.is_empty() && !self.src_ports.contains(&e.src_port) {
            return false;
        }
        if !self.interfaces.is_empty() && !self.interfaces.contains(&e.interface_index) {
            return false;
        }
        true
    }

    pub fn is_empty(&self) -> bool {
        self.protocol.is_none()
            && self.dst_ports.is_empty()
            && self.src_ports.is_empty()
            && self.interfaces.is_empty()
    }
}

/// Threshold that turns estimates into alerts/events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct AlertSpec {
    pub gt: Option<f64>,
    pub lt: Option<f64>,
}

impl AlertSpec {
    pub fn fires(&self, value: f64) -> bool {
        self.gt.map(|t| value > t).unwrap_or(false) || self.lt.map(|t| value < t).unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.gt.is_none() && self.lt.is_none()
    }
}

/// Export settings, including the cardinality guardrails that keep an
/// approximate high-cardinality tool from creating a high-cardinality
/// metrics disaster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportSpec {
    pub prometheus: bool,
    /// Hard cap on exported series per query per window.
    pub max_series: usize,
}

impl Default for ExportSpec {
    fn default() -> Self {
        ExportSpec {
            prometheus: true,
            max_series: 1000,
        }
    }
}

/// A fully validated logical query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicalQuery {
    pub name: String,
    pub filter: Predicate,
    pub group_by: Vec<Field>,
    pub measure: Measure,
    pub window: WindowSpec,
    pub error: ErrorSpec,
    pub alert: AlertSpec,
    pub export: ExportSpec,
    /// Memory budget for this query's sketches, in bytes.
    pub max_memory_bytes: u64,
}
