//! FlowSketch core types: the flow event model, logical fields, seeded hash
//! families, the `Sketch` trait, estimate output, and the versioned `FSK1`
//! snapshot format used for serialization and distributed merge.

pub mod error;
pub mod estimate;
pub mod event;
pub mod field;
pub mod hash;
pub mod sketch;
pub mod snapshot;

pub use error::SketchError;
pub use estimate::SketchEstimate;
pub use event::{Direction, FlowEvent};
pub use field::{Field, FieldValue};
pub use hash::{hash64, splitmix64, HashFamily, HashSpec, RowHashes};
pub use sketch::{Sketch, SketchCompatibility};
