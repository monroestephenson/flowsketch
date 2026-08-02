//! The FlowSketch live agent.
//!
//! Architecture:
//!
//! ```text
//! capture thread (af_packet | pcap replay)
//!     -> bounded channel (drops counted, never blocks live capture)
//! engine thread (QueryEngine: filter, window, sketch)
//!     -> shared PublishedState (latest estimates + health counters)
//! http threads (GET /metrics /healthz /readyz /v1/queries)
//! ```
//!
//! AF_PACKET HASH/RX_QUEUE fan-out uses a stronger form of this topology:
//! each capture lane feeds one bounded queue owned by the same-numbered
//! runtime worker. A low-frequency barrier merges window states for export;
//! packet events never traverse a shared receiver or dispatch coordinator.
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
mod direct_runtime;

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::TrySendError;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use thiserror::Error;

use flowsketch_core::hash::HashSpec;
use flowsketch_core::FlowEvent;
use flowsketch_runtime::ShardedQueryEngine;

pub use config::AgentConfig;
pub use state::PublishedState;

/// Channel capacity between capture and engine. Sized for bursts; when the
/// engine falls behind, capture drops (and counts) rather than blocking.
const EVENT_CHANNEL_CAPACITY: usize = 65_536;

#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum CaptureEventSender {
    Shared(SyncSender<FlowEvent>),
    Direct(direct_runtime::LaneEventSender),
}

enum RuntimePath {
    Shared {
        engine: ShardedQueryEngine,
        receiver: Receiver<FlowEvent>,
    },
    Direct(direct_runtime::DirectRuntime),
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
    run_until(config, Arc::new(AtomicBool::new(false)), on_ready)
}

/// Run until `shutdown` is set. Capture stops first, runtime queues drain,
/// trailing windows and snapshots are published, exporters make one final
/// attempt, and only then are background services joined.
pub fn run_until(
    config: AgentConfig,
    shutdown: Arc<AtomicBool>,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> Result<(), AgentError> {
    let plans = config.load_plans()?;
    let hash = HashSpec::new(config.seed);
    let fanout_lanes = config.source.af_packet_fanout_lanes(config.runtime_shards);
    let published = Arc::new(PublishedState::new(
        &plans,
        config.runtime_shards,
        config.max_sketch_memory_bytes,
        config.cpu_affinity.as_ref(),
        fanout_lanes,
    ));
    let (runtime, capture_senders) = if fanout_lanes != 0 {
        let worker_cpus = config
            .cpu_affinity
            .as_ref()
            .map(|affinity| affinity.runtime_cpus.as_slice());
        let (runtime, senders) = direct_runtime::DirectRuntime::new(
            &plans,
            hash,
            fanout_lanes,
            config.runtime_batch_size,
            worker_cpus,
            EVENT_CHANNEL_CAPACITY,
            Arc::clone(&published),
        )?;
        (
            RuntimePath::Direct(runtime),
            senders
                .into_iter()
                .map(CaptureEventSender::Direct)
                .collect(),
        )
    } else {
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
        let (tx, rx) = std::sync::mpsc::sync_channel::<FlowEvent>(EVENT_CHANNEL_CAPACITY);
        (
            RuntimePath::Shared {
                engine,
                receiver: rx,
            },
            vec![CaptureEventSender::Shared(tx)],
        )
    };

    let listener = std::net::TcpListener::bind(&config.listen)
        .map_err(|e| AgentError::Http(format!("cannot bind {}: {e}", config.listen)))?;
    let addr = listener.local_addr()?;
    let services_shutdown = Arc::new(AtomicBool::new(false));
    let http = http::serve_in_background(
        listener,
        Arc::clone(&published),
        Arc::clone(&services_shutdown),
    )
    .map_err(|e| AgentError::Http(format!("cannot spawn HTTP server: {e}")))?;
    let mut exporters = Vec::new();
    if let Some(otlp) = config.otlp.clone() {
        match spawn_otlp_exporter(
            otlp,
            Arc::clone(&published),
            config.node_name.clone(),
            Arc::clone(&services_shutdown),
        ) {
            Ok(handle) => exporters.push(handle),
            Err(error) => {
                services_shutdown.store(true, Ordering::Release);
                let _ = http.join();
                return Err(error);
            }
        }
    }
    if let Some(gateway) = config.gateway.clone() {
        published.enable_snapshot_export(Duration::from_millis(gateway.interval_ms));
        match spawn_gateway_pusher(
            gateway,
            Arc::clone(&published),
            config.node_name.clone(),
            Arc::clone(&services_shutdown),
        ) {
            Ok(handle) => exporters.push(handle),
            Err(error) => {
                services_shutdown.store(true, Ordering::Release);
                let _ = http.join();
                for exporter in exporters {
                    let _ = exporter.join();
                }
                return Err(error);
            }
        }
    }
    on_ready(addr);

    let (capture_done_tx, capture_done_rx) = std::sync::mpsc::sync_channel(1);
    let capture_state = Arc::clone(&published);
    let source_cfg = config.source.clone();
    let capture_runtime_shards = config.runtime_shards;
    let capture_shutdown = Arc::clone(&shutdown);
    let capture_cpus = config
        .cpu_affinity
        .as_ref()
        .map(|affinity| affinity.capture_cpus.clone())
        .unwrap_or_default();
    let capture = match std::thread::Builder::new()
        .name("fs-capture".into())
        .spawn(move || {
            let result = source::capture_loop(
                source_cfg,
                capture_senders,
                capture_state,
                capture_cpus,
                capture_runtime_shards,
                capture_shutdown,
            );
            let _ = capture_done_tx.send(());
            result
        }) {
        Ok(capture) => capture,
        Err(error) => {
            services_shutdown.store(true, Ordering::Release);
            let _ = http.join();
            for exporter in exporters {
                let _ = exporter.join();
            }
            return Err(AgentError::Io(error));
        }
    };

    let runtime_result = match runtime {
        RuntimePath::Shared { engine, receiver } => engine_loop(
            engine,
            receiver,
            Arc::clone(&published),
            config.flush_interval(),
            config.runtime_batch_size,
            config.runtime_shard_strategy,
        ),
        RuntimePath::Direct(mut runtime) => queue_local_engine_loop(
            &mut runtime,
            capture_done_rx,
            Arc::clone(&published),
            config.flush_interval(),
        ),
    };

    let capture_result = capture
        .join()
        .map_err(|_| AgentError::Source("capture thread panicked".into()))
        .and_then(|result| result);
    let mut result = runtime_result.and(capture_result);

    if result.is_ok() && !shutdown.load(Ordering::Acquire) {
        // Finite source (pcap replay) completed. Keep serving the final
        // results over HTTP until shutdown — the agent is an
        // observability endpoint, not a batch job.
        eprintln!("capture source complete; continuing to serve HTTP endpoints");
        while !shutdown.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    published.ready.store(false, Ordering::Release);
    services_shutdown.store(true, Ordering::Release);
    match http.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) if result.is_ok() => {
            result = Err(AgentError::Http(format!(
                "agent HTTP shutdown failed: {error}"
            )));
        }
        Err(_) if result.is_ok() => {
            result = Err(AgentError::Http("agent HTTP thread panicked".into()));
        }
        Ok(Err(_)) | Err(_) => {}
    }
    for exporter in exporters {
        if exporter.join().is_err() && result.is_ok() {
            result = Err(AgentError::Source("agent exporter thread panicked".into()));
        }
    }
    if result.is_ok() && shutdown.load(Ordering::Acquire) {
        eprintln!("flowsketch agent graceful shutdown complete");
    }
    result
}

/// Periodically export the latest window's estimates over OTLP/HTTP.
/// Windows already exported are skipped, so an idle agent goes quiet
/// instead of resending stale gauges.
fn spawn_otlp_exporter(
    cfg: flowsketch_otel::OtlpConfig,
    state: Arc<PublishedState>,
    node_name: String,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, AgentError> {
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
                let stopping = wait_for_interval_or_shutdown(interval, &shutdown);
                let estimates: Vec<_> = state
                    .latest_estimates()
                    .into_iter()
                    .filter(|e| {
                        last_end
                            .get(&e.query_name)
                            .is_none_or(|&t| e.window_end_nanos > t)
                    })
                    .collect();
                if let Some(doc) = flowsketch_otel::encode_estimates(&estimates, &opts) {
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
                if stopping {
                    break;
                }
            }
        })
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
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, AgentError> {
    let url = cfg.snapshots_url();
    let interval = Duration::from_millis(cfg.interval_ms);
    std::thread::Builder::new()
        .name("fs-gateway".into())
        .spawn(move || loop {
            let stopping = wait_for_interval_or_shutdown(interval, &shutdown);
            let snapshots = state.latest_snapshots();
            if !snapshots.is_empty() {
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
            }
            if stopping {
                break;
            }
        })
        .map_err(AgentError::Io)
}

fn wait_for_interval_or_shutdown(interval: Duration, shutdown: &AtomicBool) -> bool {
    let started = Instant::now();
    loop {
        if shutdown.load(Ordering::Acquire) {
            return true;
        }
        let elapsed = started.elapsed();
        if elapsed >= interval {
            return false;
        }
        std::thread::sleep((interval - elapsed).min(Duration::from_millis(100)));
    }
}

/// Push events into the channel, counting drops instead of blocking.
#[cfg(target_os = "linux")]
pub(crate) fn offer_event(
    sender: &CaptureEventSender,
    event: FlowEvent,
    state: &PublishedState,
) -> bool {
    let (result, lane) = match sender {
        CaptureEventSender::Shared(tx) => (tx.try_send(event), None),
        CaptureEventSender::Direct(sender) => (sender.tx.try_send(event), Some(sender.lane)),
    };
    match result {
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
    rx: Receiver<FlowEvent>,
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
                let strategy = match shard_strategy {
                    config::RuntimeShardStrategy::Flow => flowsketch_runtime::ShardStrategy::Flow,
                    config::RuntimeShardStrategy::RoundRobin => {
                        flowsketch_runtime::ShardStrategy::RoundRobin
                    }
                };
                engine.process_batch_with_strategy(&batch, strategy)?;
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

fn queue_local_engine_loop(
    runtime: &mut direct_runtime::DirectRuntime,
    capture_done: Receiver<()>,
    published: Arc<PublishedState>,
    flush_interval: Duration,
) -> Result<(), AgentError> {
    published.ready.store(true, Ordering::Release);
    loop {
        match capture_done.recv_timeout(flush_interval) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                runtime.checkpoint(true)?;
                published.source_done.store(true, Ordering::Release);
                return Ok(());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                runtime.checkpoint(false)?;
            }
        }
    }
}
