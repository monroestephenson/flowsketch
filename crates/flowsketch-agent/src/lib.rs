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

#[cfg(target_os = "linux")]
mod affinity;

use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use flowsketch_core::hash::HashSpec;
use flowsketch_core::FlowEvent;
use flowsketch_runtime::ShardedQueryEngine;

pub use config::AgentConfig;
pub use state::PublishedState;

/// Channel capacity between capture and engine. Sized for bursts; when the
/// engine falls behind, capture drops (and counts) rather than blocking.
const EVENT_CHANNEL_CAPACITY: usize = 65_536;

/// A parsed event plus an optional kernel-selected AF_PACKET lane. Fan-out
/// lanes map one-to-one to runtime shards, so carrying the lane through the
/// bounded channel avoids hashing the directional tuple a second time.
pub(crate) struct CapturedEvent {
    pub(crate) event: FlowEvent,
    pub(crate) lane: Option<usize>,
}

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
    let engine = if let Some(affinity) = &config.cpu_affinity {
        ShardedQueryEngine::new_with_cpu_affinity(
            plans.clone(),
            hash,
            config.runtime_shards,
            &affinity.runtime_cpus,
        )?
    } else {
        ShardedQueryEngine::new(plans.clone(), hash, config.runtime_shards)?
    };

    let fanout_lanes = config.source.af_packet_fanout_lanes(config.runtime_shards);
    let published = Arc::new(PublishedState::new(
        &plans,
        config.runtime_shards,
        config.cpu_affinity.as_ref(),
        fanout_lanes,
    ));
    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| AgentError::Http(format!("cannot bind {}: {e}", config.listen)))?;
    let addr = listener.local_addr()?;
    http::serve_in_background(listener, Arc::clone(&published))
        .map_err(|e| AgentError::Http(format!("cannot spawn HTTP server: {e}")))?;
    if let Some(otlp) = config.otlp.clone() {
        spawn_otlp_exporter(otlp, Arc::clone(&published), config.node_name.clone())?;
    }
    if let Some(gateway) = config.gateway.clone() {
        published.enable_snapshot_export(Duration::from_millis(gateway.interval_ms));
        spawn_gateway_pusher(gateway, Arc::clone(&published), config.node_name.clone())?;
    }
    on_ready(addr);

    let (tx, rx) = std::sync::mpsc::sync_channel::<CapturedEvent>(EVENT_CHANNEL_CAPACITY);
    let capture_state = Arc::clone(&published);
    let source_cfg = config.source.clone();
    let capture_runtime_shards = config.runtime_shards;
    let capture_cpus = config
        .cpu_affinity
        .as_ref()
        .map(|affinity| affinity.capture_cpus.clone())
        .unwrap_or_default();
    let capture = std::thread::Builder::new()
        .name("fs-capture".into())
        .spawn(move || {
            source::capture_loop(
                source_cfg,
                tx,
                capture_state,
                capture_cpus,
                capture_runtime_shards,
            )
        })
        .map_err(AgentError::Io)?;

    engine_loop(
        engine,
        rx,
        Arc::clone(&published),
        config.flush_interval(),
        config.runtime_batch_size,
        config.runtime_shard_strategy,
    )?;

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
) -> Result<(), AgentError> {
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
        .map(|_| ())
        .map_err(AgentError::Io)
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
) -> Result<(), AgentError> {
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
        .map(|_| ())
        .map_err(AgentError::Io)
}

/// Push events into the channel, counting drops instead of blocking.
#[cfg(target_os = "linux")]
pub(crate) fn offer_event(
    tx: &SyncSender<CapturedEvent>,
    event: FlowEvent,
    state: &PublishedState,
    lane: Option<usize>,
) -> bool {
    match tx.try_send(CapturedEvent { event, lane }) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            state.dropped_events.fetch_add(1, Ordering::Relaxed);
            if let Some(lane) = lane {
                state.record_capture_lane_userspace_drop(lane);
            }
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn engine_loop(
    mut engine: ShardedQueryEngine,
    rx: Receiver<CapturedEvent>,
    published: Arc<PublishedState>,
    flush_interval: Duration,
    batch_size: usize,
    shard_strategy: config::RuntimeShardStrategy,
) -> Result<(), AgentError> {
    published.ready.store(true, Ordering::Release);
    let mut batch = Vec::with_capacity(batch_size);
    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(event) => {
                batch.push(event);
                while batch.len() < batch_size {
                    match rx.try_recv() {
                        Ok(event) => batch.push(event),
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    }
                }
                let event_count = batch.len();
                process_captured_batch(&mut engine, &mut batch, shard_strategy, &published)?;
                published
                    .events_processed
                    .fetch_add(event_count as u64, Ordering::Relaxed);
                published.runtime_batches.fetch_add(1, Ordering::Relaxed);
                batch.clear();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Idle: publish whatever windows have closed so far.
                published.publish(&mut engine)?;
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        published.publish(&mut engine)?;
    }
    // Source finished: flush trailing windows and publish the final state.
    // The trailing window's snapshots export unconditionally so the
    // gateway pusher ships the final state regardless of gate timing.
    engine.finish()?;
    published.publish(&mut engine)?;
    published.export_snapshots_now(&engine);
    published.source_done.store(true, Ordering::Release);
    Ok(())
}

fn process_captured_batch(
    engine: &mut ShardedQueryEngine,
    batch: &mut Vec<CapturedEvent>,
    shard_strategy: config::RuntimeShardStrategy,
    published: &PublishedState,
) -> Result<(), AgentError> {
    let kernel_partitioned = batch.first().is_some_and(|event| event.lane.is_some());
    if kernel_partitioned {
        let mut shard_batches = (0..engine.shard_count())
            .map(|_| Vec::new())
            .collect::<Vec<_>>();
        let mut lane_counts = vec![0u64; engine.shard_count()];
        for captured in batch.drain(..) {
            let lane = captured.lane.ok_or_else(|| {
                AgentError::Source(
                    "capture batch mixed kernel-partitioned and unpartitioned events".into(),
                )
            })?;
            let shard = shard_batches.get_mut(lane).ok_or_else(|| {
                AgentError::Source(format!("capture lane {lane} has no matching runtime shard"))
            })?;
            shard.push(captured.event);
            lane_counts[lane] += 1;
        }
        engine.process_shard_batches(&shard_batches)?;
        for (lane, events) in lane_counts.into_iter().enumerate() {
            if events != 0 {
                published.record_capture_lane_events_processed(lane, events);
            }
        }
    } else {
        let mut events = Vec::with_capacity(batch.len());
        for captured in batch.drain(..) {
            if captured.lane.is_some() {
                return Err(AgentError::Source(
                    "capture batch mixed unpartitioned and kernel-partitioned events".into(),
                ));
            }
            events.push(captured.event);
        }
        let strategy = match shard_strategy {
            config::RuntimeShardStrategy::Flow => flowsketch_runtime::ShardStrategy::Flow,
            config::RuntimeShardStrategy::RoundRobin => {
                flowsketch_runtime::ShardStrategy::RoundRobin
            }
        };
        engine.process_batch_with_strategy(&events, strategy)?;
    }
    Ok(())
}
