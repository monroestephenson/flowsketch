//! Shared state between the engine thread and the HTTP server: the latest
//! window's estimates per query, plus agent health counters.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use flowsketch_core::SketchEstimate;
use flowsketch_ir::logical::Measure;
use flowsketch_planner::Plan;
use flowsketch_prometheus::QueryExportInfo;
use flowsketch_runtime::{ShardedQueryEngine, SnapshotExport};

use crate::config::CpuAffinityConfig;

/// Plan metadata the HTTP layer serves on /v1/queries and uses for
/// /metrics labels.
#[derive(Debug, Clone)]
pub struct QueryInfo {
    pub name: String,
    pub algorithm: String,
    pub window: String,
    pub error_kind: String,
    pub error_contract: String,
    pub estimated_memory_bytes: u64,
    pub max_series: usize,
    pub window_size_nanos: u64,
    /// Which `network.flowsketch.<unit>.estimated` OTLP metric this query
    /// feeds.
    pub otlp_unit: String,
}

/// OTLP unit for a measure: what the estimated number counts.
fn otlp_unit(measure: &Measure) -> String {
    match measure {
        Measure::Count => "count".to_string(),
        Measure::Sum { value } | Measure::HeavyHitters { value, .. } => value.label_name(),
        Measure::DistinctCount { .. } => "distinct".to_string(),
        Measure::Entropy { .. } => "entropy".to_string(),
        Measure::Quantile { .. } => "quantile".to_string(),
    }
}

pub struct PublishedState {
    pub queries: Vec<QueryInfo>,
    /// Latest completed-window estimates, keyed by query name.
    pub estimates: Mutex<BTreeMap<String, Vec<SketchEstimate>>>,

    pub started: Instant,
    pub ready: AtomicBool,
    pub source_done: AtomicBool,
    pub source_error: Mutex<Option<String>>,

    pub events_processed: AtomicU64,
    pub packets_seen: AtomicU64,
    pub packets_parsed: AtomicU64,
    pub packets_unparsed: AtomicU64,
    pub kernel_packets: AtomicU64,
    pub kernel_dropped_packets: AtomicU64,
    pub kernel_queue_freezes: AtomicU64,
    pub dropped_events: AtomicU64,
    pub capture_ring_bytes: AtomicU64,
    pub capture_ring_blocks: AtomicU64,
    pub capture_block_size_bytes: AtomicU64,
    pub ebpf_packets: AtomicU64,
    pub ebpf_events_emitted: AtomicU64,
    pub ebpf_ring_dropped_events: AtomicU64,
    pub ebpf_parse_errors: AtomicU64,
    pub ebpf_unsupported_packets: AtomicU64,
    pub ebpf_fallbacks: AtomicU64,
    pub ebpf_ring_bytes: AtomicU64,
    pub sketch_memory_bytes: AtomicU64,
    pub late_events: AtomicU64,
    pub otlp_exports: AtomicU64,
    pub otlp_failures: AtomicU64,
    pub gateway_pushes: AtomicU64,
    pub gateway_push_failures: AtomicU64,
    pub runtime_batches: AtomicU64,
    pub runtime_shards: usize,
    capture_cpu_affinity: Option<usize>,
    runtime_cpu_affinity: Vec<usize>,

    /// Latest exported window snapshots for the gateway pusher, refreshed
    /// by the engine thread at most once per `interval` (serializing
    /// sketches on every publish would be wasted work under load).
    /// `None` gate = no gateway configured, snapshots never exported.
    snapshot_gate: Mutex<Option<SnapshotGate>>,
    snapshots: Mutex<Vec<SnapshotExport>>,
}

struct SnapshotGate {
    interval: Duration,
    last_export: Option<Instant>,
}

impl PublishedState {
    pub fn new(
        plans: &[Plan],
        runtime_shards: usize,
        cpu_affinity: Option<&CpuAffinityConfig>,
    ) -> Self {
        let queries = plans
            .iter()
            .map(|p| QueryInfo {
                name: p.query.name.clone(),
                algorithm: p.physical.sketch.algorithm_name(),
                window: flowsketch_ir::logical::humanize_nanos(p.query.window.size_nanos),
                error_kind: p.physical.error_kind.name().to_string(),
                error_contract: p.physical.error_contract.clone(),
                estimated_memory_bytes: p.physical.estimated_memory_bytes,
                max_series: p.query.export.max_series,
                window_size_nanos: p.query.window.size_nanos,
                otlp_unit: otlp_unit(&p.query.measure),
            })
            .collect();
        PublishedState {
            queries,
            estimates: Mutex::new(BTreeMap::new()),
            started: Instant::now(),
            ready: AtomicBool::new(false),
            source_done: AtomicBool::new(false),
            source_error: Mutex::new(None),
            events_processed: AtomicU64::new(0),
            packets_seen: AtomicU64::new(0),
            packets_parsed: AtomicU64::new(0),
            packets_unparsed: AtomicU64::new(0),
            kernel_packets: AtomicU64::new(0),
            kernel_dropped_packets: AtomicU64::new(0),
            kernel_queue_freezes: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            capture_ring_bytes: AtomicU64::new(0),
            capture_ring_blocks: AtomicU64::new(0),
            capture_block_size_bytes: AtomicU64::new(0),
            ebpf_packets: AtomicU64::new(0),
            ebpf_events_emitted: AtomicU64::new(0),
            ebpf_ring_dropped_events: AtomicU64::new(0),
            ebpf_parse_errors: AtomicU64::new(0),
            ebpf_unsupported_packets: AtomicU64::new(0),
            ebpf_fallbacks: AtomicU64::new(0),
            ebpf_ring_bytes: AtomicU64::new(0),
            sketch_memory_bytes: AtomicU64::new(0),
            late_events: AtomicU64::new(0),
            otlp_exports: AtomicU64::new(0),
            otlp_failures: AtomicU64::new(0),
            gateway_pushes: AtomicU64::new(0),
            gateway_push_failures: AtomicU64::new(0),
            runtime_batches: AtomicU64::new(0),
            runtime_shards,
            capture_cpu_affinity: cpu_affinity.map(|affinity| affinity.capture_cpu),
            runtime_cpu_affinity: cpu_affinity
                .map(|affinity| affinity.runtime_cpus.clone())
                .unwrap_or_default(),
            snapshot_gate: Mutex::new(None),
            snapshots: Mutex::new(Vec::new()),
        }
    }

    /// Turn on periodic snapshot export (called before the engine starts
    /// when a gateway push is configured).
    pub fn enable_snapshot_export(&self, interval: Duration) {
        *self.snapshot_gate.lock().unwrap() = Some(SnapshotGate {
            interval,
            last_export: None,
        });
    }

    /// The most recently exported window snapshots (empty until the first
    /// export, or when no gateway is configured).
    pub fn latest_snapshots(&self) -> Vec<SnapshotExport> {
        self.snapshots.lock().unwrap().clone()
    }

    /// Export snapshots now, ignoring the rate gate — used for the final
    /// publish when a finite source completes, so the trailing window is
    /// available to push regardless of timing.
    pub fn export_snapshots_now(&self, engine: &ShardedQueryEngine) {
        if self.snapshot_gate.lock().unwrap().is_none() {
            return;
        }
        if let Ok(snaps) = engine.export_snapshots() {
            *self.snapshots.lock().unwrap() = snaps;
        }
    }

    fn maybe_export_snapshots(&self, engine: &ShardedQueryEngine) {
        let mut gate = self.snapshot_gate.lock().unwrap();
        let Some(gate) = gate.as_mut() else { return };
        if gate
            .last_export
            .is_some_and(|last| last.elapsed() < gate.interval)
        {
            return;
        }
        if let Ok(snaps) = engine.export_snapshots() {
            *self.snapshots.lock().unwrap() = snaps;
            gate.last_export = Some(Instant::now());
        }
    }

    /// Drain newly emitted estimates from the engine and retain, per query,
    /// only the most recent window.
    pub fn publish(
        &self,
        engine: &mut ShardedQueryEngine,
    ) -> Result<(), flowsketch_core::SketchError> {
        let drained = engine.take_estimates()?;
        self.sketch_memory_bytes
            .store(engine.sketch_memory_bytes() as u64, Ordering::Relaxed);
        self.late_events
            .store(engine.late_events(), Ordering::Relaxed);
        self.maybe_export_snapshots(engine);
        if drained.is_empty() {
            return Ok(());
        }
        let mut map = self.estimates.lock().unwrap();
        for e in drained {
            let per_query = map.entry(e.query_name.clone()).or_default();
            match per_query.first() {
                Some(existing) if existing.window_end_nanos < e.window_end_nanos => {
                    per_query.clear();
                    per_query.push(e);
                }
                Some(existing) if existing.window_end_nanos == e.window_end_nanos => {
                    per_query.push(e);
                }
                Some(_) => {} // older window: ignore
                None => per_query.push(e),
            }
        }
        Ok(())
    }

    /// Estimates of the latest window across all queries.
    pub fn latest_estimates(&self) -> Vec<SketchEstimate> {
        self.estimates
            .lock()
            .unwrap()
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }

    pub fn export_info(&self) -> BTreeMap<String, QueryExportInfo> {
        self.queries
            .iter()
            .map(|q| {
                (
                    q.name.clone(),
                    QueryExportInfo {
                        error_kind: q.error_kind.clone(),
                        max_series: q.max_series,
                        window_size_nanos: q.window_size_nanos,
                    },
                )
            })
            .collect()
    }

    /// Agent health block appended to /metrics.
    pub fn render_health_metrics(&self) -> String {
        let mut out = String::new();
        let counters: [(&str, &str, u64); 21] = [
            (
                "flowsketch_agent_events_processed_total",
                "Flow events processed by the sketch engine.",
                self.events_processed.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_packets_seen_total",
                "Packets observed by the capture source.",
                self.packets_seen.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_packets_parsed_total",
                "Captured packets successfully converted into flow events.",
                self.packets_parsed.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_packets_unparsed_total",
                "Captured packets skipped because they are unsupported or malformed.",
                self.packets_unparsed.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_kernel_packets_total",
                "Packets accepted by the Linux AF_PACKET socket, including packets later dropped from the receive ring.",
                self.kernel_packets.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_kernel_dropped_packets_total",
                "Packets dropped by the Linux AF_PACKET receive ring before userspace consumed them.",
                self.kernel_dropped_packets.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_kernel_queue_freezes_total",
                "Times the Linux TPACKET_V3 receive queue froze because no ring block was available.",
                self.kernel_queue_freezes.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_packets_total",
                "Packets presented to the FlowSketch tc eBPF program.",
                self.ebpf_packets.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_events_emitted_total",
                "Flow events successfully submitted to the eBPF ring buffer.",
                self.ebpf_events_emitted.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_ring_dropped_events_total",
                "Flow events dropped because the eBPF ring buffer had no space.",
                self.ebpf_ring_dropped_events.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_parse_errors_total",
                "Malformed or truncated packets rejected by the tc eBPF parser.",
                self.ebpf_parse_errors.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_unsupported_packets_total",
                "Packets intentionally skipped by the tc eBPF parser.",
                self.ebpf_unsupported_packets.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_ebpf_fallbacks_total",
                "Explicit transitions from failed eBPF capture to AF_PACKET fallback.",
                self.ebpf_fallbacks.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_dropped_events_total",
                "Parsed events dropped in userspace because the engine channel was full.",
                self.dropped_events.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_late_events_total",
                "Events older than the earliest open window bucket.",
                self.late_events.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_sketch_memory_bytes",
                "Bytes held by sketches across all queries and buckets.",
                self.sketch_memory_bytes.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_otlp_exports_total",
                "Successful OTLP metric exports.",
                self.otlp_exports.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_otlp_export_failures_total",
                "OTLP exports that failed after retries.",
                self.otlp_failures.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_gateway_pushes_total",
                "Successful snapshot pushes to the gateway.",
                self.gateway_pushes.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_gateway_push_failures_total",
                "Snapshot pushes that failed after retries.",
                self.gateway_push_failures.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_agent_runtime_batches_total",
                "Event batches dispatched to runtime shards.",
                self.runtime_batches.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in counters {
            let kind = if name.ends_with("_total") {
                "counter"
            } else {
                "gauge"
            };
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
            ));
        }
        out.push_str(&format!(
            "# HELP flowsketch_agent_capture_ring_bytes Bytes configured for the Linux TPACKET_V3 receive ring.\n\
             # TYPE flowsketch_agent_capture_ring_bytes gauge\n\
             flowsketch_agent_capture_ring_bytes {}\n",
            self.capture_ring_bytes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_capture_ring_blocks Blocks configured in the Linux TPACKET_V3 receive ring.\n\
             # TYPE flowsketch_agent_capture_ring_blocks gauge\n\
             flowsketch_agent_capture_ring_blocks {}\n",
            self.capture_ring_blocks.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_capture_block_size_bytes Bytes in each Linux TPACKET_V3 receive-ring block.\n\
             # TYPE flowsketch_agent_capture_block_size_bytes gauge\n\
             flowsketch_agent_capture_block_size_bytes {}\n",
            self.capture_block_size_bytes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_ebpf_ring_bytes Bytes configured for the tc eBPF event ring buffer.\n\
             # TYPE flowsketch_agent_ebpf_ring_bytes gauge\n\
             flowsketch_agent_ebpf_ring_bytes {}\n",
            self.ebpf_ring_bytes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_runtime_shards Configured parallel runtime shards.\n\
             # TYPE flowsketch_agent_runtime_shards gauge\n\
             flowsketch_agent_runtime_shards {}\n",
            self.runtime_shards
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_cpu_affinity_enabled Whether explicit Linux capture/runtime CPU affinity is configured.\n\
             # TYPE flowsketch_agent_cpu_affinity_enabled gauge\n\
             flowsketch_agent_cpu_affinity_enabled {}\n",
            u8::from(self.capture_cpu_affinity.is_some())
        ));
        out.push_str(
            "# HELP flowsketch_agent_capture_cpu_affinity Configured Linux logical CPU for the capture thread.\n\
             # TYPE flowsketch_agent_capture_cpu_affinity gauge\n",
        );
        if let Some(cpu) = self.capture_cpu_affinity {
            out.push_str(&format!(
                "flowsketch_agent_capture_cpu_affinity{{cpu=\"{cpu}\"}} 1\n"
            ));
        }
        out.push_str(
            "# HELP flowsketch_agent_runtime_cpu_affinity Configured Linux logical CPU for each runtime worker.\n\
             # TYPE flowsketch_agent_runtime_cpu_affinity gauge\n",
        );
        for (worker, cpu) in self.runtime_cpu_affinity.iter().enumerate() {
            out.push_str(&format!(
                "flowsketch_agent_runtime_cpu_affinity{{worker=\"{worker}\",cpu=\"{cpu}\"}} 1\n"
            ));
        }
        out.push_str(&format!(
            "# HELP flowsketch_agent_queries_active Queries this agent is executing.\n\
             # TYPE flowsketch_agent_queries_active gauge\n\
             flowsketch_agent_queries_active {}\n",
            self.queries.len()
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_ready Whether the agent engine is ready to process events.\n\
             # TYPE flowsketch_agent_ready gauge\n\
             flowsketch_agent_ready {}\n",
            u8::from(self.ready.load(Ordering::Acquire))
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_source_done Whether the configured capture source has completed.\n\
             # TYPE flowsketch_agent_source_done gauge\n\
             flowsketch_agent_source_done {}\n",
            u8::from(self.source_done.load(Ordering::Acquire))
        ));
        out.push_str(&format!(
            "# HELP flowsketch_agent_uptime_seconds Seconds since agent start.\n\
             # TYPE flowsketch_agent_uptime_seconds gauge\n\
             flowsketch_agent_uptime_seconds {}\n",
            self.started.elapsed().as_secs()
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_capture_accounting_and_ring_metrics() {
        let affinity = CpuAffinityConfig {
            capture_cpu: 0,
            runtime_cpus: vec![1, 2, 3, 4],
        };
        let state = PublishedState::new(&[], 4, Some(&affinity));
        state.packets_seen.store(11, Ordering::Relaxed);
        state.packets_parsed.store(9, Ordering::Relaxed);
        state.packets_unparsed.store(2, Ordering::Relaxed);
        state.kernel_packets.store(12, Ordering::Relaxed);
        state.kernel_dropped_packets.store(1, Ordering::Relaxed);
        state.kernel_queue_freezes.store(3, Ordering::Relaxed);
        state
            .capture_ring_bytes
            .store(67_108_864, Ordering::Relaxed);
        state.capture_ring_blocks.store(64, Ordering::Relaxed);
        state
            .capture_block_size_bytes
            .store(1_048_576, Ordering::Relaxed);
        state.ebpf_packets.store(20, Ordering::Relaxed);
        state.ebpf_events_emitted.store(17, Ordering::Relaxed);
        state.ebpf_ring_dropped_events.store(1, Ordering::Relaxed);
        state.ebpf_parse_errors.store(1, Ordering::Relaxed);
        state.ebpf_unsupported_packets.store(1, Ordering::Relaxed);
        state.ebpf_fallbacks.store(2, Ordering::Relaxed);
        state.ebpf_ring_bytes.store(16_777_216, Ordering::Relaxed);

        let metrics = state.render_health_metrics();
        for expected in [
            "flowsketch_agent_packets_seen_total 11\n",
            "flowsketch_agent_packets_parsed_total 9\n",
            "flowsketch_agent_packets_unparsed_total 2\n",
            "flowsketch_agent_kernel_packets_total 12\n",
            "flowsketch_agent_kernel_dropped_packets_total 1\n",
            "flowsketch_agent_kernel_queue_freezes_total 3\n",
            "flowsketch_agent_capture_ring_bytes 67108864\n",
            "flowsketch_agent_capture_ring_blocks 64\n",
            "flowsketch_agent_capture_block_size_bytes 1048576\n",
            "flowsketch_agent_ebpf_packets_total 20\n",
            "flowsketch_agent_ebpf_events_emitted_total 17\n",
            "flowsketch_agent_ebpf_ring_dropped_events_total 1\n",
            "flowsketch_agent_ebpf_parse_errors_total 1\n",
            "flowsketch_agent_ebpf_unsupported_packets_total 1\n",
            "flowsketch_agent_ebpf_fallbacks_total 2\n",
            "flowsketch_agent_ebpf_ring_bytes 16777216\n",
            "flowsketch_agent_runtime_shards 4\n",
            "flowsketch_agent_cpu_affinity_enabled 1\n",
            "flowsketch_agent_capture_cpu_affinity{cpu=\"0\"} 1\n",
            "flowsketch_agent_runtime_cpu_affinity{worker=\"3\",cpu=\"4\"} 1\n",
        ] {
            assert!(metrics.contains(expected), "missing {expected:?}");
        }
    }
}
