//! The FlowSketch live agent (README Phase 3).
//!
//! Architecture:
//!
//! ```text
//! capture thread (af_packet | pcap replay)
//!     -> bounded channel (drops counted, never blocks capture)
//! engine thread (QueryEngine: filter, window, sketch)
//!     -> shared PublishedState (latest estimates + health counters)
//! http threads (GET /metrics /healthz /readyz /v1/queries)
//! ```
//!
//! Failure posture: a capture error stops the source and is reported via
//! `/healthz`; the HTTP server keeps serving the last good state. Memory is
//! bounded by the planner's per-query budgets plus the channel capacity.

pub mod config;
pub mod http;
pub mod source;
pub mod state;

use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use flowsketch_core::hash::HashSpec;
use flowsketch_core::FlowEvent;
use flowsketch_runtime::QueryEngine;

pub use config::AgentConfig;
pub use state::PublishedState;

/// Channel capacity between capture and engine. Sized for bursts; when the
/// engine falls behind, capture drops (and counts) rather than blocking.
const EVENT_CHANNEL_CAPACITY: usize = 65_536;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("config error: {0}")]
    Config(String),
    #[error("source error: {0}")]
    Source(String),
    #[error("engine error: {0}")]
    Engine(#[from] flowsketch_core::SketchError),
    #[error("http error: {0}")]
    Http(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the agent until the source is exhausted (pcap mode) or the process
/// is terminated (live mode). Returns the bound HTTP address via callback
/// as soon as the listener is up (used by tests and logged for operators).
pub fn run(
    config: AgentConfig,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> Result<(), AgentError> {
    let plans = config.load_plans()?;
    let hash = HashSpec::new(config.seed);
    let engine = QueryEngine::new(plans.clone(), hash)?;

    let published = Arc::new(PublishedState::new(&plans));
    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| AgentError::Http(format!("cannot bind {}: {e}", config.listen)))?;
    let addr = listener.local_addr()?;
    http::serve_in_background(listener, Arc::clone(&published));
    if let Some(otlp) = config.otlp.clone() {
        spawn_otlp_exporter(otlp, Arc::clone(&published), config.node_name.clone());
    }
    if let Some(gateway) = config.gateway.clone() {
        published.enable_snapshot_export(Duration::from_millis(gateway.interval_ms));
        spawn_gateway_pusher(gateway, Arc::clone(&published), config.node_name.clone());
    }
    on_ready(addr);

    let (tx, rx) = std::sync::mpsc::sync_channel::<FlowEvent>(EVENT_CHANNEL_CAPACITY);
    let capture_state = Arc::clone(&published);
    let source_cfg = config.source.clone();
    let capture = std::thread::Builder::new()
        .name("fs-capture".into())
        .spawn(move || source::capture_loop(source_cfg, tx, capture_state))
        .expect("spawn capture thread");

    engine_loop(engine, rx, Arc::clone(&published), config.flush_interval())?;

    match capture.join() {
        Ok(Ok(())) => {
            // Finite source (pcap replay) completed. Keep serving the final
            // results over HTTP until the process is terminated — the agent
            // is an observability endpoint, not a batch job.
            eprintln!("capture source complete; continuing to serve HTTP endpoints");
            loop {
                std::thread::park();
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AgentError::Source("capture thread panicked".into())),
    }
}

/// Periodically export the latest window's estimates over OTLP/HTTP.
/// Windows already exported are skipped, so an idle agent goes quiet
/// instead of resending stale gauges.
fn spawn_otlp_exporter(
    cfg: flowsketch_otel::OtlpConfig,
    state: Arc<PublishedState>,
    node_name: String,
) {
    use flowsketch_otel::encode::{EncodeOptions, QueryMeta};

    let opts = EncodeOptions {
        service_name: "flowsketch-agent".to_string(),
        host_name: node_name,
        queries: state
            .queries
            .iter()
            .map(|q| {
                (
                    q.name.clone(),
                    QueryMeta {
                        unit: q.otlp_unit.clone(),
                        window: q.window.clone(),
                        error_kind: q.error_kind.clone(),
                    },
                )
            })
            .collect(),
    };
    let url = cfg.metrics_url();
    let interval = Duration::from_millis(cfg.interval_ms);

    std::thread::Builder::new()
        .name("fs-otlp".into())
        .spawn(move || {
            let mut last_end: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            loop {
                std::thread::sleep(interval);
                let estimates: Vec<_> = state
                    .latest_estimates()
                    .into_iter()
                    .filter(|e| {
                        last_end
                            .get(&e.query_name)
                            .is_none_or(|&t| e.window_end_nanos > t)
                    })
                    .collect();
                let Some(doc) = flowsketch_otel::encode_estimates(&estimates, &opts) else {
                    continue;
                };
                match flowsketch_otel::post_metrics(&url, &doc) {
                    Ok(()) => {
                        for e in &estimates {
                            let entry = last_end.entry(e.query_name.clone()).or_insert(0);
                            *entry = (*entry).max(e.window_end_nanos);
                        }
                        state.otlp_exports.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        state.otlp_failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!("otlp export failed: {err}");
                    }
                }
            }
        })
        .expect("spawn otlp thread");
}

/// Periodically push the engine's current window snapshots to the cluster
/// gateway (Phase 7 distributed merge). The engine thread refreshes the
/// snapshot set on its own cadence; this thread just ships the latest one.
/// Re-pushing an unchanged window is harmless — the gateway replaces the
/// node's entry and refreshes its liveness.
fn spawn_gateway_pusher(
    cfg: flowsketch_gateway::PushConfig,
    state: Arc<PublishedState>,
    node_name: String,
) {
    let url = cfg.snapshots_url();
    let interval = Duration::from_millis(cfg.interval_ms);
    std::thread::Builder::new()
        .name("fs-gateway".into())
        .spawn(move || loop {
            std::thread::sleep(interval);
            let snapshots = state.latest_snapshots();
            if snapshots.is_empty() {
                continue;
            }
            let batch = flowsketch_gateway::PushBatch {
                node: node_name.clone(),
                entries: snapshots
                    .into_iter()
                    .map(|s| flowsketch_gateway::PushEntry {
                        query_name: s.query_name,
                        component: s.component,
                        snapshot: s.bytes,
                    })
                    .collect(),
            };
            match flowsketch_gateway::push_batch(&url, &batch.encode()) {
                Ok(()) => {
                    state.gateway_pushes.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    state.gateway_push_failures.fetch_add(1, Ordering::Relaxed);
                    eprintln!("gateway push failed: {err}");
                }
            }
        })
        .expect("spawn gateway push thread");
}

/// Push events into the channel, counting drops instead of blocking.
pub(crate) fn offer_event(
    tx: &SyncSender<FlowEvent>,
    event: FlowEvent,
    state: &PublishedState,
) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            state.dropped_events.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn engine_loop(
    mut engine: QueryEngine,
    rx: Receiver<FlowEvent>,
    published: Arc<PublishedState>,
    flush_interval: Duration,
) -> Result<(), AgentError> {
    published.ready.store(true, Ordering::Release);
    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(event) => {
                engine.process(&event)?;
                published.events_processed.fetch_add(1, Ordering::Relaxed);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Idle: publish whatever windows have closed so far.
                published.publish(&mut engine);
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Cheap periodic publish: every 4096 events.
        if published.events_processed.load(Ordering::Relaxed) % 4096 == 0 {
            published.publish(&mut engine);
        }
    }
    // Source finished: flush trailing windows and publish the final state.
    // The trailing window's snapshots export unconditionally so the
    // gateway pusher ships the final state regardless of gate timing.
    engine.finish()?;
    published.publish(&mut engine);
    published.export_snapshots_now(&engine);
    published.source_done.store(true, Ordering::Release);
    Ok(())
}
