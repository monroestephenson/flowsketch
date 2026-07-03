//! Estimate output. The `algorithm`, `sketch_bytes`, and error/confidence
//! fields make the approximation visible instead of hiding it.

use serde::{Deserialize, Serialize};

/// One approximate answer for one group within one window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SketchEstimate {
    pub query_name: String,
    pub window_start_nanos: u64,
    pub window_end_nanos: u64,

    /// Group-by labels as `(field name, value)` pairs, in query order.
    pub group: Vec<(String, String)>,

    pub estimate: f64,
    pub lower_bound: Option<f64>,
    pub upper_bound: Option<f64>,
    pub confidence: Option<f64>,

    /// Which physical algorithm produced this number.
    pub algorithm: String,
    /// Memory held by the sketch(es) that produced this estimate.
    pub sketch_bytes: u64,
    /// Number of updates observed in the window.
    pub update_count: u64,
}
