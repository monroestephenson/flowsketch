//! FlowSketch query IR.
//!
//! Queries enter as YAML (the MVP DSL), are validated into a `LogicalQuery`
//! (what the operator asked), and are compiled by the planner into a
//! `PhysicalPlan` (which sketches will run). SQL comes later, if ever.

pub mod logical;
pub mod physical;
pub mod yaml;

pub use logical::{AlertSpec, ErrorSpec, ExportSpec, LogicalQuery, Measure, Predicate, WindowSpec};
pub use physical::PhysicalSketch;
pub use yaml::{parse_query_yaml, QueryParseError};
