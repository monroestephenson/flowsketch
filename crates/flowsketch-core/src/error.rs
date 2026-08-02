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

    /// A runtime consumer has not drained completed windows quickly enough
    /// to stay inside the planned resident-memory bound. The operation that
    /// returned this error has not consumed the triggering event, so callers
    /// may drain output and retry it.
    #[error("runtime output backpressure: {0}")]
    Backpressure(String),
}
