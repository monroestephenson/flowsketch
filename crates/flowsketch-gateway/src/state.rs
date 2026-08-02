//! Gateway state: the latest validated window snapshot per (query, node),
//! cross-node merge, and the health counters served on /metrics.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use flowsketch_core::hash::{hash64, HashSpec};
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

const MERGE_CACHE_SHARDS: usize = 16;

#[derive(Default)]
struct QueryMergeCache {
    target: Option<(u64, u64)>,
    shard_states: Vec<Option<WindowState>>,
    shard_nodes: Vec<usize>,
    /// Lazily merged from at most `MERGE_CACHE_SHARDS` shard summaries.
    /// Any node update invalidates it; repeated scrapes do no sketch merge.
    final_state: Option<WindowState>,
}

#[derive(Default)]
struct GatewayData {
    /// query name -> node name -> latest window.
    nodes: BTreeMap<String, BTreeMap<String, NodeWindow>>,
    /// Per-query fixed-shard aggregation cache. Node pushes rebuild only the
    /// affected shard unless the selected cluster window changes.
    merge_cache: BTreeMap<String, QueryMergeCache>,
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
    max_nodes: usize,
    data: Mutex<GatewayData>,

    pub started: Instant,
    pub pushes_total: AtomicU64,
    pub snapshots_accepted: AtomicU64,
    pub snapshots_rejected: AtomicU64,
    pub node_admission_rejections: AtomicU64,
    pub body_budget_rejections: AtomicU64,
    pub merge_cache_shard_rebuilds: AtomicU64,
}

impl GatewayState {
    pub fn new(plans: Vec<Plan>, hash: HashSpec, stale_after: Duration, max_nodes: usize) -> Self {
        assert!(max_nodes > 0, "gateway max_nodes must be positive");
        GatewayState {
            plans,
            hash,
            stale_after,
            max_nodes,
            data: Mutex::new(GatewayData::default()),
            started: Instant::now(),
            pushes_total: AtomicU64::new(0),
            snapshots_accepted: AtomicU64::new(0),
            snapshots_rejected: AtomicU64::new(0),
            node_admission_rejections: AtomicU64::new(0),
            body_budget_rejections: AtomicU64::new(0),
            merge_cache_shard_rebuilds: AtomicU64::new(0),
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

        let mut rejected = Vec::new();
        let mut validated = Vec::new();
        for (query, components) in by_query {
            let Some(plan) = self.plans.iter().find(|p| p.query.name == query) else {
                rejected.push(format!("query {query:?} is not configured on this gateway"));
                continue;
            };
            match WindowState::from_components(plan, &self.hash, &components) {
                Ok(state) => validated.push((query.to_string(), state)),
                Err(e) => rejected.push(format!("query {query:?} from node {:?}: {e}", batch.node)),
            }
        }

        let mut accepted = 0usize;
        let mut cache_rebuilds = 0u64;
        if !validated.is_empty() {
            let mut data = self.data.lock().unwrap();
            let stale_changes = Self::evict_stale(&mut data.nodes, self.stale_after);
            cache_rebuilds += Self::refresh_changed_caches(&mut data, &stale_changes);

            let known_node = data
                .nodes
                .values()
                .any(|per_node| per_node.contains_key(&batch.node));
            let tracked_nodes = Self::unique_node_count(&data.nodes);
            if !known_node && tracked_nodes >= self.max_nodes {
                self.node_admission_rejections
                    .fetch_add(1, Ordering::Relaxed);
                rejected.extend(validated.into_iter().map(|(query, _)| {
                    format!(
                        "query {query:?} from node {:?}: gateway node capacity {} is full",
                        batch.node, self.max_nodes
                    )
                }));
            } else {
                let mut changed: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
                let now = Instant::now();
                for (query, state) in validated {
                    let per_node = data.nodes.entry(query.clone()).or_default();
                    let entry = per_node.entry(batch.node.clone());
                    let state_changed = match entry {
                        std::collections::btree_map::Entry::Occupied(mut occupied)
                            if occupied.get().state.window_end_nanos()
                                > state.window_end_nanos() =>
                        {
                            // Stale push: keep the newer window but refresh
                            // liveness so the node is not evicted.
                            occupied.get_mut().received = now;
                            false
                        }
                        std::collections::btree_map::Entry::Occupied(mut occupied) => {
                            *occupied.get_mut() = NodeWindow {
                                received: now,
                                state,
                            };
                            true
                        }
                        std::collections::btree_map::Entry::Vacant(vacant) => {
                            vacant.insert(NodeWindow {
                                received: now,
                                state,
                            });
                            true
                        }
                    };
                    if state_changed {
                        changed
                            .entry(query)
                            .or_default()
                            .insert(Self::merge_shard(&batch.node));
                    }
                    accepted += 1;
                }
                cache_rebuilds += Self::refresh_changed_caches(&mut data, &changed);
            }
        }
        self.merge_cache_shard_rebuilds
            .fetch_add(cache_rebuilds, Ordering::Relaxed);
        self.snapshots_accepted
            .fetch_add(accepted as u64, Ordering::Relaxed);
        self.snapshots_rejected
            .fetch_add(rejected.len() as u64, Ordering::Relaxed);
        ApplyResult { accepted, rejected }
    }

    /// Drop nodes that have not pushed within the staleness window, so a
    /// decommissioned agent's last window does not linger forever and
    /// gateway memory stays bounded by live nodes x configured queries.
    fn evict_stale(
        nodes: &mut BTreeMap<String, BTreeMap<String, NodeWindow>>,
        cutoff: Duration,
    ) -> BTreeMap<String, BTreeSet<usize>> {
        let mut changed = BTreeMap::new();
        for (query, per_node) in nodes.iter_mut() {
            let stale = per_node
                .iter()
                .filter(|(_, window)| window.received.elapsed() >= cutoff)
                .map(|(node, _)| node.clone())
                .collect::<Vec<_>>();
            for node in stale {
                per_node.remove(&node);
                changed
                    .entry(query.clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(Self::merge_shard(&node));
            }
        }
        nodes.retain(|_, per_node| !per_node.is_empty());
        changed
    }

    fn unique_node_count(nodes: &BTreeMap<String, BTreeMap<String, NodeWindow>>) -> usize {
        nodes
            .values()
            .flat_map(|per_node| per_node.keys().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn merge_shard(node: &str) -> usize {
        hash64(node.as_bytes(), 0) as usize % MERGE_CACHE_SHARDS
    }

    fn selected_window(per_node: &BTreeMap<String, NodeWindow>) -> Option<(u64, u64)> {
        let max_end = per_node
            .values()
            .map(|window| window.state.window_end_nanos())
            .max()?;
        let mut start_votes: BTreeMap<u64, usize> = BTreeMap::new();
        for window in per_node.values() {
            if window.state.window_end_nanos() == max_end {
                *start_votes
                    .entry(window.state.window_start_nanos())
                    .or_default() += 1;
            }
        }
        start_votes
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            .map(|(start, _)| (start, max_end))
    }

    fn merge_cache_shard(
        per_node: &BTreeMap<String, NodeWindow>,
        target: (u64, u64),
        shard: usize,
    ) -> (Option<WindowState>, usize) {
        let mut merged: Option<WindowState> = None;
        let mut nodes_merged = 0usize;
        for (node, window) in per_node {
            if Self::merge_shard(node) != shard
                || (
                    window.state.window_start_nanos(),
                    window.state.window_end_nanos(),
                ) != target
            {
                continue;
            }
            match &mut merged {
                None => {
                    merged = Some(window.state.clone());
                    nodes_merged = 1;
                }
                Some(state) => {
                    if state.merge_from(&window.state).is_ok() {
                        nodes_merged += 1;
                    }
                }
            }
        }
        (merged, nodes_merged)
    }

    fn refresh_query_cache(
        data: &mut GatewayData,
        query: &str,
        changed_shards: &BTreeSet<usize>,
    ) -> u64 {
        let GatewayData { nodes, merge_cache } = data;
        let Some(per_node) = nodes.get(query) else {
            merge_cache.remove(query);
            return 0;
        };
        let Some(target) = Self::selected_window(per_node) else {
            merge_cache.remove(query);
            return 0;
        };
        let cache = merge_cache.entry(query.to_string()).or_default();
        let rebuild_all = cache.target != Some(target)
            || cache.shard_states.len() != MERGE_CACHE_SHARDS
            || cache.shard_nodes.len() != MERGE_CACHE_SHARDS;
        if rebuild_all {
            cache.target = Some(target);
            cache.shard_states = vec![None; MERGE_CACHE_SHARDS];
            cache.shard_nodes = vec![0; MERGE_CACHE_SHARDS];
        }
        let shards: Vec<usize> = if rebuild_all {
            (0..MERGE_CACHE_SHARDS).collect()
        } else {
            changed_shards.iter().copied().collect()
        };
        for shard in &shards {
            let (state, count) = Self::merge_cache_shard(per_node, target, *shard);
            cache.shard_states[*shard] = state;
            cache.shard_nodes[*shard] = count;
        }
        if !shards.is_empty() {
            cache.final_state = None;
        }
        shards.len() as u64
    }

    fn refresh_changed_caches(
        data: &mut GatewayData,
        changed: &BTreeMap<String, BTreeSet<usize>>,
    ) -> u64 {
        changed
            .iter()
            .map(|(query, shards)| Self::refresh_query_cache(data, query, shards))
            .sum()
    }

    /// Merge each query's freshest common window across nodes for diagnostics
    /// and complete-cluster export. Only nodes whose snapshot covers exactly
    /// the chosen window bounds participate (same window boundaries or no
    /// merge); stragglers are surfaced via the
    /// `nodes_merged` vs `nodes_known` gauges instead of silently blended.
    pub fn merged(&self) -> Vec<MergedQuery> {
        let mut data = self.data.lock().unwrap();
        let stale_changes = Self::evict_stale(&mut data.nodes, self.stale_after);
        let cache_rebuilds = Self::refresh_changed_caches(&mut data, &stale_changes);
        self.merge_cache_shard_rebuilds
            .fetch_add(cache_rebuilds, Ordering::Relaxed);

        let mut out = Vec::new();
        for plan in &self.plans {
            let query = plan.query.name.as_str();
            let Some(nodes_known) = data.nodes.get(query).map(BTreeMap::len) else {
                continue;
            };
            let Some(cache) = data.merge_cache.get_mut(query) else {
                continue;
            };
            let Some((_, window_end_nanos)) = cache.target else {
                continue;
            };
            let nodes_merged = cache.shard_nodes.iter().sum();
            // Never merge or estimate a subset. While nodes disagree on the
            // selected window, diagnostics remain available but the ordinary
            // cluster estimate is absent.
            if nodes_merged == nodes_known && cache.final_state.is_none() {
                let mut final_state: Option<WindowState> = None;
                for shard in cache.shard_states.iter().flatten() {
                    match &mut final_state {
                        None => final_state = Some(shard.clone()),
                        Some(state) => {
                            if state.merge_from(shard).is_err() {
                                final_state = None;
                                break;
                            }
                        }
                    }
                }
                cache.final_state = final_state;
            }
            let estimates = if nodes_merged == nodes_known {
                cache
                    .final_state
                    .as_ref()
                    .map(|state| state.estimates(plan))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            out.push(MergedQuery {
                query_name: query.to_string(),
                nodes_known,
                nodes_merged,
                window_end_nanos,
                estimates,
            });
        }
        out
    }

    /// Render the full Prometheus exposition: merged estimates plus
    /// gateway health.
    pub fn render_metrics(&self) -> String {
        let merged = self.merged();
        // Fail closed: a freshest-window subset is useful for diagnosing
        // skew, but publishing it under the ordinary cluster estimate name
        // would silently undercount. Health gauges below expose the partial
        // merge while estimates resume only when every live node agrees.
        let estimates: Vec<SketchEstimate> = merged
            .iter()
            .filter(|m| m.nodes_merged == m.nodes_known)
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

        let tracked_nodes = {
            let data = self.data.lock().unwrap();
            Self::unique_node_count(&data.nodes)
        };
        let counters: [(&str, &str, u64); 6] = [
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
            (
                "flowsketch_gateway_node_admission_rejections_total",
                "New-node push batches rejected because gateway node capacity was full.",
                self.node_admission_rejections.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_gateway_body_budget_rejections_total",
                "Snapshot pushes rejected before allocation by the in-flight HTTP body budget.",
                self.body_budget_rejections.load(Ordering::Relaxed),
            ),
            (
                "flowsketch_gateway_merge_cache_shard_rebuilds_total",
                "Fixed merge-cache shards rebuilt after accepted node updates or expiry.",
                self.merge_cache_shard_rebuilds.load(Ordering::Relaxed),
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
        body.push_str(&format!(
            "# HELP flowsketch_gateway_nodes_tracked Unique live node identities retained by the gateway.\n\
             # TYPE flowsketch_gateway_nodes_tracked gauge\n\
             flowsketch_gateway_nodes_tracked {tracked_nodes}\n\
             # HELP flowsketch_gateway_nodes_capacity Configured hard limit on live node identities.\n\
             # TYPE flowsketch_gateway_nodes_capacity gauge\n\
             flowsketch_gateway_nodes_capacity {}\n\
             # HELP flowsketch_gateway_merge_cache_shards Fixed upper bound on sketch states merged after a cache miss, independent of node count.\n\
             # TYPE flowsketch_gateway_merge_cache_shards gauge\n\
             flowsketch_gateway_merge_cache_shards {MERGE_CACHE_SHARDS}\n",
            self.max_nodes
        ));
        body.push_str(
            "# HELP flowsketch_gateway_merge_complete Whether every live node was included in \
             the exported window; incomplete merges suppress cluster estimates.\n\
             # TYPE flowsketch_gateway_merge_complete gauge\n",
        );
        for m in &merged {
            body.push_str(&format!(
                "flowsketch_gateway_merge_complete{{query=\"{}\"}} {}\n",
                m.query_name,
                usize::from(m.nodes_merged == m.nodes_known)
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
        let mut data = self.data.lock().unwrap();
        let stale_changes = Self::evict_stale(&mut data.nodes, self.stale_after);
        let cache_rebuilds = Self::refresh_changed_caches(&mut data, &stale_changes);
        self.merge_cache_shard_rebuilds
            .fetch_add(cache_rebuilds, Ordering::Relaxed);
        let queries: Vec<serde_json::Value> = data
            .nodes
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use flowsketch_core::FlowEvent;
    use flowsketch_ir::parse_query_yaml;
    use flowsketch_planner::plan;
    use flowsketch_runtime::QueryEngine;

    use crate::batch::PushEntry;

    const YAML: &str = "name: scanners\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
         measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n";

    fn plan_for(seed: u64) -> Plan {
        plan(parse_query_yaml(YAML).unwrap(), &HashSpec::new(seed)).unwrap()
    }

    fn event(ts_s: u64, dst: &str) -> FlowEvent {
        FlowEvent {
            ts_nanos: ts_s * 1_000_000_000,
            src_ip: "10.0.1.50".parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 40_000,
            dst_port: 22,
            protocol: 6,
            bytes: 60,
            ..FlowEvent::default()
        }
    }

    /// A push batch from a node whose engine processed one event at each of
    /// `secs`. Events at 0,10,..,50 fill the 6-bucket ring to the full
    /// `[0s,60s)` window; a lone event at 55 leaves a partial `[50s,60s)`.
    fn batch_for(node: &str, secs: &[u64], seed: u64) -> PushBatch {
        let mut eng = QueryEngine::new(vec![plan_for(seed)], HashSpec::new(seed)).unwrap();
        for (i, &s) in secs.iter().enumerate() {
            eng.process(&event(s, &format!("10.9.{}.{}", i / 256, i % 256)))
                .unwrap();
        }
        PushBatch {
            node: node.to_string(),
            entries: eng
                .export_snapshots()
                .unwrap()
                .into_iter()
                .map(|s| PushEntry {
                    query_name: s.query_name,
                    component: s.component,
                    snapshot: s.bytes,
                })
                .collect(),
        }
    }

    #[test]
    fn merge_prefers_window_shared_by_most_nodes() {
        let state = GatewayState::new(
            vec![plan_for(0)],
            HashSpec::new(0),
            Duration::from_secs(300),
            128,
        );
        // node-a and node-c hold the established full window [0s,60s);
        // node-b just (re)started and only has the partial [50s,60s), which
        // shares the same end time.
        state.apply_batch(&batch_for("node-a", &[0, 10, 20, 30, 40, 50], 0));
        state.apply_batch(&batch_for("node-c", &[0, 10, 20, 30, 40, 50], 0));
        state.apply_batch(&batch_for("node-b", &[55], 0));

        let merged = state.merged();
        assert_eq!(merged.len(), 1);
        let m = &merged[0];
        assert_eq!(m.window_end_nanos, 60_000_000_000);
        assert_eq!(m.nodes_known, 3);
        // The two full-window nodes merge; the lone partial window is
        // excluded rather than evicting the majority.
        assert_eq!(
            m.nodes_merged, 2,
            "partial-window straggler must not displace the established full-window nodes"
        );
        assert!(
            m.estimates.is_empty(),
            "gateway computed a subset estimate that must remain suppressed"
        );

        let metrics = state.render_metrics();
        assert!(metrics.contains("flowsketch_gateway_merge_complete{query=\"scanners\"} 0"));
        assert!(
            !metrics.contains("flowsketch_estimate{query=\"scanners\""),
            "partial cluster estimate was exported: {metrics}"
        );
    }

    #[test]
    fn merge_uses_freshest_end_time() {
        let state = GatewayState::new(
            vec![plan_for(0)],
            HashSpec::new(0),
            Duration::from_secs(300),
            128,
        );
        // node-a is a window behind (ends 60s); node-b advanced to the next
        // window (ends 70s). The gateway reports the freshest window only.
        state.apply_batch(&batch_for("node-a", &[0, 10, 20, 30, 40, 50], 0));
        state.apply_batch(&batch_for("node-b", &[10, 20, 30, 40, 50, 60], 0));

        let merged = state.merged();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].window_end_nanos, 70_000_000_000);
        assert_eq!(merged[0].nodes_merged, 1);
        assert!(merged[0].estimates.is_empty());
        let metrics = state.render_metrics();
        assert!(metrics.contains("flowsketch_gateway_merge_complete{query=\"scanners\"} 0"));
        assert!(!metrics.contains("flowsketch_estimate{query=\"scanners\""));
    }

    #[test]
    fn complete_merge_exports_cluster_estimates() {
        let state = GatewayState::new(
            vec![plan_for(0)],
            HashSpec::new(0),
            Duration::from_secs(300),
            128,
        );
        state.apply_batch(&batch_for("node-a", &[0, 10, 20, 30, 40, 50], 0));
        state.apply_batch(&batch_for("node-b", &[0, 10, 20, 30, 40, 50], 0));

        let metrics = state.render_metrics();
        assert!(metrics.contains("flowsketch_gateway_merge_complete{query=\"scanners\"} 1"));
        assert!(metrics.contains("flowsketch_estimate{query=\"scanners\""));

        let rebuilt_before = state.merge_cache_shard_rebuilds.load(Ordering::Relaxed);
        let _ = state.render_metrics();
        let _ = state.render_metrics();
        assert_eq!(
            state.merge_cache_shard_rebuilds.load(Ordering::Relaxed),
            rebuilt_before,
            "unchanged Prometheus scrapes rebuilt node-level sketch state"
        );
    }

    #[test]
    fn same_window_node_refresh_rebuilds_one_shard_and_scrapes_reuse_cache() {
        let state = GatewayState::new(
            vec![plan_for(0)],
            HashSpec::new(0),
            Duration::from_secs(300),
            128,
        );
        for index in 0..32 {
            state.apply_batch(&batch_for(
                &format!("node-{index}"),
                &[0, 10, 20, 30, 40, 50],
                0,
            ));
        }
        let _ = state.render_metrics();
        assert!(state
            .data
            .lock()
            .unwrap()
            .merge_cache
            .get("scanners")
            .is_some_and(|cache| cache.final_state.is_some()));

        let before_refresh = state.merge_cache_shard_rebuilds.load(Ordering::Relaxed);
        state.apply_batch(&batch_for("node-7", &[0, 10, 20, 30, 40, 50], 0));
        assert_eq!(
            state.merge_cache_shard_rebuilds.load(Ordering::Relaxed) - before_refresh,
            1,
            "one node refresh should rebuild only its deterministic cache shard"
        );

        let after_refresh = state.merge_cache_shard_rebuilds.load(Ordering::Relaxed);
        let _ = state.render_metrics();
        let _ = state.render_metrics();
        assert_eq!(
            state.merge_cache_shard_rebuilds.load(Ordering::Relaxed),
            after_refresh,
            "unchanged scrapes rebuilt node-level sketch state"
        );
    }

    #[test]
    fn new_node_admission_is_bounded_but_existing_nodes_can_refresh() {
        let state = GatewayState::new(
            vec![plan_for(0)],
            HashSpec::new(0),
            Duration::from_secs(300),
            2,
        );
        assert_eq!(
            state
                .apply_batch(&batch_for("node-a", &[0, 10, 20, 30, 40, 50], 0))
                .accepted,
            1
        );
        assert_eq!(
            state
                .apply_batch(&batch_for("node-b", &[0, 10, 20, 30, 40, 50], 0))
                .accepted,
            1
        );

        let rejected = state.apply_batch(&batch_for("node-c", &[0, 10, 20, 30, 40, 50], 0));
        assert_eq!(rejected.accepted, 0);
        assert_eq!(rejected.rejected.len(), 1);
        assert!(rejected.rejected[0].contains("capacity 2 is full"));

        let refresh = state.apply_batch(&batch_for("node-a", &[10, 20, 30, 40, 50, 60], 0));
        assert_eq!(refresh.accepted, 1);
        let metrics = state.render_metrics();
        assert!(metrics.contains("flowsketch_gateway_nodes_tracked 2"));
        assert!(metrics.contains("flowsketch_gateway_nodes_capacity 2"));
        assert!(metrics.contains("flowsketch_gateway_node_admission_rejections_total 1"));
    }
}
