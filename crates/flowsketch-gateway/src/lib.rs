//! The FlowSketch cluster gateway.
//!
//! ```text
//! agent on node A ─┐  POST /v1/snapshots (FSKB batch of FSK1 snapshots)
//! agent on node B ─┼─> gateway: validate compatibility, keep newest
//! agent on node C ─┘   window per (query, node), merge across nodes
//!                          │
//!                          └─> GET /metrics: cluster-level estimates
//! ```
//!
//! The gateway is configured with the same query files (and hash seed) as
//! the agents pushing to it. That is what makes validation possible:
//! every pushed sketch is checked against the locally planned algorithm,
//! parameters, and hash spec before it may merge — incompatible snapshots
//! are rejected and counted, never blended.
//!
//! Memory is bounded by design: one window state per configured query per
//! live node, each bounded by the planner's budget, with stale nodes
//! evicted after `staleAfterMs`.

pub mod batch;
pub mod client;
pub mod config;
pub mod http;
pub mod state;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use thiserror::Error;

use flowsketch_core::hash::HashSpec;

pub use batch::{PushBatch, PushEntry};
pub use client::{push_batch, PushClientError, PushConfig};
pub use config::GatewayConfig;
pub use state::GatewayState;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("config error: {0}")]
    Config(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the gateway until the process is terminated. Reports the bound
/// address via callback as soon as the listener is up (used by tests and
/// logged for operators).
pub fn run(
    config: GatewayConfig,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> Result<(), GatewayError> {
    run_until(config, Arc::new(AtomicBool::new(false)), on_ready)
}

/// Run until the supplied flag is set. This is the process-facing entry
/// point used for SIGINT/SIGTERM so Kubernetes termination closes the
/// listener cleanly instead of relying on an unconditional process kill.
pub fn run_until(
    config: GatewayConfig,
    shutdown: Arc<AtomicBool>,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> Result<(), GatewayError> {
    let plans = config.load_plans()?;
    let state = Arc::new(GatewayState::new(
        plans,
        HashSpec::new(config.seed),
        config.stale_after(),
        config.max_nodes,
    ));
    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| GatewayError::Http(format!("cannot bind {}: {e}", config.listen)))?;
    on_ready(listener.local_addr()?);
    http::serve_until(listener, state, shutdown)
        .map_err(|e| GatewayError::Http(format!("gateway HTTP server stopped: {e}")))
}
