use thiserror::Error;

/// Errors produced by sketch construction, merging, and serialization.
#[derive(Debug, Error)]
pub enum SketchError {
    #[error("invalid sketch parameter: {0}")]
    InvalidParam(String),

    #[error("incompatible merge: {0}")]
    IncompatibleMerge(String),

    #[error("snapshot decode error: {0}")]
    Snapshot(String),
}
