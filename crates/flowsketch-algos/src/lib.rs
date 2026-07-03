//! FlowSketch sketch algorithm implementations.
//!
//! Every sketch here is:
//! - bounded-memory with documented error behavior,
//! - mergeable when built with identical parameters and `HashSpec`,
//! - serializable to the versioned `FSK1` snapshot format.

pub mod count_min;
pub mod count_sketch;
pub mod exact;
pub mod hll;
pub mod hll_map;
pub mod misra_gries;
pub mod space_saving;

pub use count_min::CountMinSketch;
pub use count_sketch::CountSketch;
pub use exact::ExactCounter;
pub use hll::HyperLogLog;
pub use hll_map::HllMap;
pub use misra_gries::MisraGries;
pub use space_saving::SpaceSaving;
