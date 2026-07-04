//! Gateway state: the latest validated window snapshot per (query, node),
//! cross-node merge, and the health counters served on /metrics.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use flowsketch_core::hash::HashSpec;
use flowsketch_core::SketchEstimate;
use flowsketch_planner::Plan;
use flowsketch_prometheus::QueryExportInfo;
use flowsketch_runtime::WindowState;

use crate::batch::PushBatch;

/// The newest validated snapshot from one node for one query.
struct NodeWindow {
    received: Instant,
    state: WindowState,
}

/// Outcome of applying one push batch.
#[derive(Debug)]
pub struct ApplyResult {
    /// Query states accepted (one per query in the batch that validated).
    pub accepted: usize,
    /// Human-readable reasons for each rejected query state.
    pub rejected: Vec<String>,
}

pub struct GatewayState {
    plans: Vec<Plan>,
    hash: HashSpec,
    stale_after: Duration,
    /// query name -> node name -> latest window.
    nodes: Mutex<BTreeMap<String, BTreeMap<String, NodeWindow>>>,

    pub started: Instant,
    pub pushes_total: AtomicU64,
    pub snapshots_accepted: AtomicU64,
    pub snapshots_rejected: AtomicU64,
}

impl GatewayState {
    pub fn new(plans: Vec<Plan>, hash: HashSpec, stale_after: Duration) -> Self {
        GatewayState {
            plans,
            hash,
            stale_after,
            nodes: Mutex::new(BTreeMap::new()),
            started: Instant::now(),
            pushes_total: AtomicU64::new(0),
            snapshots_accepted: AtomicU64::new(0),
            snapshots_rejected: AtomicU64::new(0),
        }
    }

    pub fn plans(&self) -> &[Plan] {
        &self.plans
    }

    /// Validate a pushed batch against the local plans and store each
    /// query's window state under the pushing node. A node's older or
    /// same-window push replaces its previous entry; a push for an
    /// earlier window than the stored one is ignored (out-of-order
    /// delivery must not roll estimates backwards).
    pub fn apply_batch(&self, batch: &PushBatch) -> ApplyResult {
        self.pushes_total.fetch_add(1, Ordering::Relaxed);

        // Group component snapshots by query, preserving order.
        let mut by_query: BTreeMap<&str, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        for e in &batch.entries {
            by_query
                .entry(e.query_name.as_str())
                .or_default()
                .push((e.component.clone(), e.snapshot.clone()));
        }

        let mut accepted = 0usize;
        let mut rejected = Vec::new();
        for (query, components) in by_query {
            let Some(plan) = self.plans.iter().find(|p| p.query.name == query) else {
                rejected.push(format!("query {query:?} is not configured on this gateway"));
                continue;
            };
            match WindowState::from_components(plan, &self.hash, &components) {
                Ok(state) => {
                    let mut nodes = self.nodes.lock().unwrap();
                    let per_node = nodes.entry(query.to_string()).or_default();
                    let entry = per_node.entry(batch.node.clone());
                    match entry {
                        std::collections::btree_map::Entry::Occupied(mut o)
                            if o.get().state.window_end_nanos() > state.window_end_nanos() =>
                        {
                            // Stale push: keep the newer window but refresh
                            // liveness so the node is not evicted.
                            o.get_mut().received = Instant::now();
                        }
                        std::collections::btree_map::Entry::Occupied(mut o) => {
                            *o.get_mut() = NodeWindow {
                                received: Instant::now(),
                                state,
                            };
                        }
                        std::collections::btree_map::Entry::Vacant(v) => {
                            v.insert(NodeWindow {
                                received: Instant::now(),
                                state,
                            });
                        }
                    }
                    accepted += 1;
                }
                Err(e) => rejected.push(format!("query {query:?} from node {:?}: {e}", batch.node)),
            }
        }
        self.snapshots_accepted
            .fetch_add(accepted as u64, Ordering::Relaxed);
        self.snapshots_rejected
            .fetch_add(rejected.len() as u64, Ordering::Relaxed);
        ApplyResult { accepted, rejected }
    }

    /// Drop nodes that have not pushed within the staleness window, so a
    /// decommissioned agent's last window does not linger forever and
    /// gateway memory stays bounded by live nodes x configured queries.
    fn evict_stale(nodes: &mut BTreeMap<String, BTreeMap<String, NodeWindow>>, cutoff: Duration) {
        for per_node in nodes.values_mut() {
            per_node.retain(|_, nw| nw.received.elapsed() < cutoff);
        }
        nodes.retain(|_, per_node| !per_node.is_empty());
    }

    /// Merge each query's freshest common window across nodes and emit
    /// cluster-level estimates. Only nodes whose snapshot covers exactly
    /// the chosen window bounds participate (README §17.3: same window
    /// boundaries or no merge); stragglers are surfaced via the
    /// `nodes_merged` vs `nodes_known` gauges instead of silently blended.
    pub fn merged(&self) -> Vec<MergedQuery> {
        let mut nodes = self.nodes.lock().unwrap();
        Self::evict_stale(&mut nodes, self.stale_after);

        let mut out = Vec::new();
        for plan in &self.plans {
            let query = plan.query.name.as_str();
            let Some(per_node) = nodes.get(query) else {
                continue;
            };
            if per_node.is_empty() {
                continue;
            }
            // Choose the freshest window any node reports, then merge every
            // node that has exactly that window.
            let target = per_node
                .values()
                .map(|nw| (nw.state.window_end_nanos(), nw.state.window_start_nanos()))
                .max()
                .map(|(end, start)| (start, end))
                .unwrap();
            let mut merged: Option<WindowState> = None;
            let mut nodes_merged = 0usize;
            for nw in per_node.values() {
                if (nw.state.window_start_nanos(), nw.state.window_end_nanos()) != target {
                    continue;
                }
                match &mut merged {
                    None => {
                        merged = Some(nw.state.clone());
                        nodes_merged = 1;
                    }
                    Some(m) => {
                        // Compatibility was validated at push time against
                        // the same plan, so this only fails on internal
                        // inconsistency; skip the node rather than poison
                        // the whole query.
                        if m.merge_from(&nw.state).is_ok() {
                            nodes_merged += 1;
                        }
                    }
                }
            }
            let Some(merged) = merged else { continue };
            out.push(MergedQuery {
                query_name: query.to_string(),
                nodes_known: per_node.len(),
                nodes_merged,
                window_end_nanos: merged.window_end_nanos(),
                estimates: merged.estimates(plan),
            });
        }
        out
    }

    /// Render the full Prometheus exposition: merged estimates plus
    /// gateway health.
    pub fn render_metrics(&self) -> String {
        let merged = self.merged();
        let estimates: Vec<SketchEstimate> = merged
            .iter()
            .flat_map(|m| m.estimates.iter().cloned())
            .collect();
        let info: BTreeMap<String, QueryExportInfo> = self
            .plans
            .iter()
            .map(|p| {
                (
                    p.query.name.clone(),
                    QueryExportInfo {
                        error_kind: p.physical.error_kind.name().to_string(),
                        max_series: p.query.export.max_series,
                        window_size_nanos: p.query.window.size_nanos,
                    },
                )
            })
            .collect();
        let (mut body, _) = flowsketch_prometheus::render(&estimates, &info);

        let counters: [(&str, &str, u64); 3] = [
            (
                "flowsketch_gateway_pushes_total",
                "Snapshot push requests received.",
                self.pushes_total.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_gateway_snapshots_accepted_total",
                "Per-query window states accepted from pushes.",
                self.snapshots_accepted.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_gateway_snapshots_rejected_total",
                "Per-query window states rejected (unknown query or incompatible sketch).",
                self.snapshots_rejected.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in counters {
            body.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        body.push_str(
            "# HELP flowsketch_gateway_nodes_known Nodes with a live snapshot for this query.\n\
             # TYPE flowsketch_gateway_nodes_known gauge\n",
        );
        for m in &merged {
            body.push_str(&format!(
                "flowsketch_gateway_nodes_known{{query=\"{}\"}} {}\n",
                m.query_name, m.nodes_known
            ));
        }
        body.push_str(
            "# HELP flowsketch_gateway_nodes_merged Nodes merged into this query's newest \
             window (nodes on other window boundaries are excluded).\n\
             # TYPE flowsketch_gateway_nodes_merged gauge\n",
        );
        for m in &merged {
            body.push_str(&format!(
                "flowsketch_gateway_nodes_merged{{query=\"{}\"}} {}\n",
                m.query_name, m.nodes_merged
            ));
        }
        body.push_str(&format!(
            "# HELP flowsketch_gateway_queries_active Queries this gateway merges.\n\
             # TYPE flowsketch_gateway_queries_active gauge\n\
             flowsketch_gateway_queries_active {}\n",
            self.plans.len()
        ));
        body.push_str(&format!(
            "# HELP flowsketch_gateway_uptime_seconds Seconds since gateway start.\n\
             # TYPE flowsketch_gateway_uptime_seconds gauge\n\
             flowsketch_gateway_uptime_seconds {}\n",
            self.started.elapsed().as_secs()
        ));
        body
    }

    /// JSON view of known nodes for /v1/nodes.
    pub fn nodes_json(&self) -> serde_json::Value {
        let mut nodes = self.nodes.lock().unwrap();
        Self::evict_stale(&mut nodes, self.stale_after);
        let queries: Vec<serde_json::Value> = nodes
            .iter()
            .map(|(query, per_node)| {
                let entries: Vec<serde_json::Value> = per_node
                    .iter()
                    .map(|(node, nw)| {
                        serde_json::json!({
                            "node": node,
                            "windowStartNanos": nw.state.window_start_nanos(),
                            "windowEndNanos": nw.state.window_end_nanos(),
                            "sketchBytes": nw.state.memory_bytes(),
                            "updateCount": nw.state.update_count(),
                            "ageSeconds": nw.received.elapsed().as_secs(),
                        })
                    })
                    .collect();
                serde_json::json!({ "query": query, "nodes": entries })
            })
            .collect();
        serde_json::Value::Array(queries)
    }

    /// JSON view of configured queries for /v1/queries (same shape as the
    /// agent's endpoint).
    pub fn queries_json(&self) -> serde_json::Value {
        let queries: Vec<serde_json::Value> = self
            .plans
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.query.name,
                    "algorithm": p.physical.sketch.algorithm_name(),
                    "window": flowsketch_ir::logical::humanize_nanos(p.query.window.size_nanos),
                    "errorKind": p.physical.error_kind.name(),
                    "errorContract": p.physical.error_contract,
                    "estimatedMemoryBytes": p.physical.estimated_memory_bytes,
                    "maxSeries": p.query.export.max_series,
                })
            })
            .collect();
        serde_json::Value::Array(queries)
    }
}

/// One query's cluster-level merge result.
#[derive(Debug)]
pub struct MergedQuery {
    pub query_name: String,
    pub nodes_known: usize,
    pub nodes_merged: usize,
    pub window_end_nanos: u64,
    pub estimates: Vec<SketchEstimate>,
}
