//! Shared state between the engine thread and the HTTP server: the latest
//! window's estimates per query, plus agent health counters.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use flowsketch_core::SketchEstimate;
use flowsketch_planner::Plan;
use flowsketch_prometheus::QueryExportInfo;
use flowsketch_runtime::QueryEngine;

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
    pub dropped_events: AtomicU64,
    pub sketch_memory_bytes: AtomicU64,
    pub late_events: AtomicU64,
}

impl PublishedState {
    pub fn new(plans: &[Plan]) -> Self {
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
            dropped_events: AtomicU64::new(0),
            sketch_memory_bytes: AtomicU64::new(0),
            late_events: AtomicU64::new(0),
        }
    }

    /// Drain newly emitted estimates from the engine and retain, per query,
    /// only the most recent window.
    pub fn publish(&self, engine: &mut QueryEngine) {
        let drained = engine.take_estimates();
        self.sketch_memory_bytes
            .store(engine.sketch_memory_bytes() as u64, Ordering::Relaxed);
        self.late_events
            .store(engine.late_events(), Ordering::Relaxed);
        if drained.is_empty() {
            return;
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
        let counters: [(&str, &str, u64); 5] = [
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
                "flowsketch_agent_dropped_events_total",
                "Events dropped because the engine channel was full.",
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
            "# HELP flowsketch_agent_queries_active Queries this agent is executing.\n\
             # TYPE flowsketch_agent_queries_active gauge\n\
             flowsketch_agent_queries_active {}\n",
            self.queries.len()
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
