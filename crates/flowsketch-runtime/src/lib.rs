//! The FlowSketch runtime: takes planned queries, maintains per-query
//! window buckets (a sliding window is a ring of tumbling buckets), updates
//! sketches from flow events, and emits `SketchEstimate`s when windows
//! close.

use std::collections::{BTreeMap, VecDeque};

use flowsketch_algos::{CountMinSketch, HllMap, HyperLogLog, KllSketch, SpaceSaving};
use flowsketch_core::field::{field_value_into, group_key_into};
use flowsketch_core::hash::HashSpec;
use flowsketch_core::snapshot::read_snapshot;
use flowsketch_core::{Field, FlowEvent, Sketch, SketchError, SketchEstimate};
use flowsketch_ir::logical::Measure;
use flowsketch_ir::physical::PhysicalSketch;
use flowsketch_planner::{ErrorKind, Plan};
use rayon::prelude::*;

/// Component names tagging each FSK1 blob of a (possibly multi-sketch)
/// query state. Shared by snapshot export and reconstruction so the two
/// sides cannot drift.
pub mod component {
    pub const SPACESAVING: &str = "spacesaving";
    pub const COUNT_MIN: &str = "count-min";
    pub const KEYS_SPACESAVING: &str = "keys-spacesaving";
    pub const HLLMAP: &str = "hllmap";
    pub const HLL: &str = "hll";
    pub const KLL: &str = "kll";
    pub const HEAD_SPACESAVING: &str = "head-spacesaving";
    pub const TAIL_HLL: &str = "tail-hll";
}

/// Sketch state for one window bucket of one query.
#[derive(Debug, Clone)]
enum QueryState {
    /// heavy_hitters: SpaceSaving over group keys weighted by value.
    HeavyHitters { ss: SpaceSaving },
    /// count / sum: Count-Min for estimates plus SpaceSaving key tracker
    /// so groups can be enumerated at export time.
    Counter {
        cm: CountMinSketch,
        keys: SpaceSaving,
    },
    /// distinct_count by group: bounded keyed HLL.
    DistinctPerKey { map: HllMap },
    /// distinct_count without grouping: single HLL.
    DistinctGlobal { hll: HyperLogLog },
    /// quantile (ungrouped): KLL over the measured field's values.
    Quantile { kll: KllSketch },
    /// entropy (ungrouped): SpaceSaving head + HLL tail-support estimator.
    Entropy { ss: SpaceSaving, hll: HyperLogLog },
}

impl QueryState {
    fn build(sketch: &PhysicalSketch, hash: &HashSpec) -> Result<Self, SketchError> {
        match sketch {
            PhysicalSketch::SpaceSaving { capacity } => Ok(QueryState::HeavyHitters {
                ss: SpaceSaving::new(*capacity, *hash)?,
            }),
            PhysicalSketch::HllMap {
                max_keys,
                precision,
            } => Ok(QueryState::DistinctPerKey {
                map: HllMap::new(*max_keys, *precision, *hash)?,
            }),
            PhysicalSketch::HyperLogLog { precision } => Ok(QueryState::DistinctGlobal {
                hll: HyperLogLog::new(*precision, *hash)?,
            }),
            PhysicalSketch::Kll { k } => Ok(QueryState::Quantile {
                kll: KllSketch::new(*k, *hash)?,
            }),
            PhysicalSketch::Composite { stages } => match stages.as_slice() {
                [PhysicalSketch::SpaceSaving { capacity }, PhysicalSketch::CountMin {
                    width,
                    depth,
                    conservative_update,
                }] => Ok(QueryState::Counter {
                    cm: CountMinSketch::new(*width, *depth, *conservative_update, *hash)?,
                    keys: SpaceSaving::new(*capacity, *hash)?,
                }),
                [PhysicalSketch::SpaceSaving { capacity }, PhysicalSketch::HyperLogLog { precision }] => {
                    Ok(QueryState::Entropy {
                        ss: SpaceSaving::new(*capacity, *hash)?,
                        hll: HyperLogLog::new(*precision, *hash)?,
                    })
                }
                other => Err(SketchError::InvalidParam(format!(
                    "runtime cannot execute composite plan {other:?}"
                ))),
            },
            other => Err(SketchError::InvalidParam(format!(
                "runtime cannot execute plan {other:?}"
            ))),
        }
    }

    fn update(&mut self, key: &[u8], weight: u64, distinct_item: &[u8]) {
        match self {
            QueryState::HeavyHitters { ss } => ss.add(key, weight),
            QueryState::Counter { cm, keys } => {
                cm.update(key, weight);
                keys.add(key, weight);
            }
            QueryState::DistinctPerKey { map } => map.insert(key, distinct_item),
            QueryState::DistinctGlobal { hll } => hll.insert(distinct_item),
            QueryState::Quantile { kll } => kll.insert(weight),
            QueryState::Entropy { ss, hll } => {
                ss.add(distinct_item, 1);
                hll.insert(distinct_item);
            }
        }
    }

    fn merge_from(&mut self, other: &QueryState) -> Result<(), SketchError> {
        match (self, other) {
            (QueryState::HeavyHitters { ss: a }, QueryState::HeavyHitters { ss: b }) => {
                a.merge_from(b)
            }
            (QueryState::Counter { cm: a, keys: ka }, QueryState::Counter { cm: b, keys: kb }) => {
                a.merge_from(b)?;
                ka.merge_from(kb)
            }
            (QueryState::DistinctPerKey { map: a }, QueryState::DistinctPerKey { map: b }) => {
                a.merge_from(b)
            }
            (QueryState::DistinctGlobal { hll: a }, QueryState::DistinctGlobal { hll: b }) => {
                a.merge_from(b)
            }
            (QueryState::Quantile { kll: a }, QueryState::Quantile { kll: b }) => a.merge_from(b),
            (QueryState::Entropy { ss: a, hll: ha }, QueryState::Entropy { ss: b, hll: hb }) => {
                a.merge_from(b)?;
                ha.merge_from(hb)
            }
            _ => Err(SketchError::IncompatibleMerge(
                "mismatched query state kinds".into(),
            )),
        }
    }

    fn memory_bytes(&self) -> usize {
        match self {
            QueryState::HeavyHitters { ss } => ss.memory_bytes(),
            QueryState::Counter { cm, keys } => cm.memory_bytes() + keys.memory_bytes(),
            QueryState::DistinctPerKey { map } => map.memory_bytes(),
            QueryState::DistinctGlobal { hll } => hll.memory_bytes(),
            QueryState::Quantile { kll } => kll.memory_bytes(),
            QueryState::Entropy { ss, hll } => ss.memory_bytes() + hll.memory_bytes(),
        }
    }

    fn update_count(&self) -> u64 {
        match self {
            QueryState::HeavyHitters { ss } => ss.update_count(),
            QueryState::Counter { cm, .. } => cm.update_count(),
            QueryState::DistinctPerKey { map } => map.update_count(),
            QueryState::DistinctGlobal { hll } => hll.update_count(),
            QueryState::Quantile { kll } => kll.update_count(),
            QueryState::Entropy { ss, .. } => ss.update_count(),
        }
    }

    /// FSK1 snapshots for every component sketch of this state, tagged
    /// with a component name for multi-sketch states.
    fn to_snapshots(&self, ws: u64, we: u64) -> Vec<(String, Vec<u8>)> {
        match self {
            QueryState::HeavyHitters { ss } => {
                vec![(component::SPACESAVING.into(), ss.to_snapshot(ws, we))]
            }
            QueryState::Counter { cm, keys } => vec![
                (component::COUNT_MIN.into(), cm.to_snapshot(ws, we)),
                (component::KEYS_SPACESAVING.into(), keys.to_snapshot(ws, we)),
            ],
            QueryState::DistinctPerKey { map } => {
                vec![(component::HLLMAP.into(), map.to_snapshot(ws, we))]
            }
            QueryState::DistinctGlobal { hll } => {
                vec![(component::HLL.into(), hll.to_snapshot(ws, we))]
            }
            QueryState::Quantile { kll } => vec![(component::KLL.into(), kll.to_snapshot(ws, we))],
            QueryState::Entropy { ss, hll } => vec![
                (component::HEAD_SPACESAVING.into(), ss.to_snapshot(ws, we)),
                (component::TAIL_HLL.into(), hll.to_snapshot(ws, we)),
            ],
        }
    }

    /// The component names this physical plan's state serializes to.
    fn component_names(sketch: &PhysicalSketch) -> Result<&'static [&'static str], SketchError> {
        match sketch {
            PhysicalSketch::SpaceSaving { .. } => Ok(&[component::SPACESAVING]),
            PhysicalSketch::HllMap { .. } => Ok(&[component::HLLMAP]),
            PhysicalSketch::HyperLogLog { .. } => Ok(&[component::HLL]),
            PhysicalSketch::Kll { .. } => Ok(&[component::KLL]),
            PhysicalSketch::Composite { stages } => match stages.as_slice() {
                [PhysicalSketch::SpaceSaving { .. }, PhysicalSketch::CountMin { .. }] => {
                    Ok(&[component::COUNT_MIN, component::KEYS_SPACESAVING])
                }
                [PhysicalSketch::SpaceSaving { .. }, PhysicalSketch::HyperLogLog { .. }] => {
                    Ok(&[component::HEAD_SPACESAVING, component::TAIL_HLL])
                }
                other => Err(SketchError::InvalidParam(format!(
                    "runtime cannot execute composite plan {other:?}"
                ))),
            },
            other => Err(SketchError::InvalidParam(format!(
                "runtime cannot execute plan {other:?}"
            ))),
        }
    }

    /// Rebuild a state from named component snapshots (the inverse of
    /// `to_snapshots`). Parameters come from the snapshots themselves;
    /// callers validate them against a plan via `WindowState`.
    fn from_snapshots(
        sketch: &PhysicalSketch,
        components: &BTreeMap<&str, &[u8]>,
    ) -> Result<Self, SketchError> {
        let get = |name: &str| -> Result<&[u8], SketchError> {
            components.get(name).copied().ok_or_else(|| {
                SketchError::Snapshot(format!("missing component snapshot {name:?}"))
            })
        };
        match sketch {
            PhysicalSketch::SpaceSaving { .. } => Ok(QueryState::HeavyHitters {
                ss: SpaceSaving::from_snapshot(get(component::SPACESAVING)?)?,
            }),
            PhysicalSketch::HllMap { .. } => Ok(QueryState::DistinctPerKey {
                map: HllMap::from_snapshot(get(component::HLLMAP)?)?,
            }),
            PhysicalSketch::HyperLogLog { .. } => Ok(QueryState::DistinctGlobal {
                hll: HyperLogLog::from_snapshot(get(component::HLL)?)?,
            }),
            PhysicalSketch::Kll { .. } => Ok(QueryState::Quantile {
                kll: KllSketch::from_snapshot(get(component::KLL)?)?,
            }),
            PhysicalSketch::Composite { stages } => match stages.as_slice() {
                [PhysicalSketch::SpaceSaving { .. }, PhysicalSketch::CountMin { .. }] => {
                    Ok(QueryState::Counter {
                        cm: CountMinSketch::from_snapshot(get(component::COUNT_MIN)?)?,
                        keys: SpaceSaving::from_snapshot(get(component::KEYS_SPACESAVING)?)?,
                    })
                }
                [PhysicalSketch::SpaceSaving { .. }, PhysicalSketch::HyperLogLog { .. }] => {
                    Ok(QueryState::Entropy {
                        ss: SpaceSaving::from_snapshot(get(component::HEAD_SPACESAVING)?)?,
                        hll: HyperLogLog::from_snapshot(get(component::TAIL_HLL)?)?,
                    })
                }
                other => Err(SketchError::InvalidParam(format!(
                    "runtime cannot execute composite plan {other:?}"
                ))),
            },
            other => Err(SketchError::InvalidParam(format!(
                "runtime cannot execute plan {other:?}"
            ))),
        }
    }
}

/// One query window's sketch state reconstructed from FSK1 component
/// snapshots — the unit the gateway receives from agents, merges across
/// nodes, and emits cluster-level estimates from.
#[derive(Debug, Clone)]
pub struct WindowState {
    state: QueryState,
    window_start_nanos: u64,
    window_end_nanos: u64,
}

/// One completed query window, retained as mergeable sketch state until an
/// engine consumer drains it. Sharded runtimes merge these states before
/// converting them into estimates.
#[derive(Debug, Clone)]
pub struct QueryWindowState {
    /// Name of the planned query that owns this state.
    pub query_name: String,
    /// Mergeable state for one completed or currently open query window.
    pub state: WindowState,
}

impl WindowState {
    /// Parse component snapshots for one query and validate them against
    /// the local `plan` and `hash`: all components must cover the same
    /// window, the component set must match the plan's physical shape, and
    /// each sketch must be merge-compatible with a freshly built instance
    /// of the plan (same algorithm, parameters, and hash spec) — the exact
    /// checks distributed merge correctness depends on.
    pub fn from_components(
        plan: &Plan,
        hash: &HashSpec,
        components: &[(String, Vec<u8>)],
    ) -> Result<Self, SketchError> {
        let expected = QueryState::component_names(&plan.physical.sketch)?;
        let mut window: Option<(u64, u64)> = None;
        let mut by_name: BTreeMap<&str, &[u8]> = BTreeMap::new();
        for (name, bytes) in components {
            if !expected.contains(&name.as_str()) {
                return Err(SketchError::Snapshot(format!(
                    "unexpected component snapshot {name:?} (plan expects {expected:?})"
                )));
            }
            if by_name.insert(name.as_str(), bytes.as_slice()).is_some() {
                return Err(SketchError::Snapshot(format!(
                    "duplicate component snapshot {name:?}"
                )));
            }
            let (header, _, _) = read_snapshot(bytes)?;
            let w = (header.window_start_nanos, header.window_end_nanos);
            match window {
                None => window = Some(w),
                Some(prev) if prev != w => {
                    return Err(SketchError::IncompatibleMerge(format!(
                        "component {name:?} covers window [{}, {}) but its siblings cover \
                         [{}, {})",
                        w.0, w.1, prev.0, prev.1
                    )))
                }
                Some(_) => {}
            }
        }
        let Some((window_start_nanos, window_end_nanos)) = window else {
            return Err(SketchError::Snapshot("no component snapshots given".into()));
        };

        let parsed = QueryState::from_snapshots(&plan.physical.sketch, &by_name)?;
        // Merging into an empty state built from the plan runs the same
        // compatibility validation (params + hash spec) node merges use.
        let mut state = QueryState::build(&plan.physical.sketch, hash)?;
        state.merge_from(&parsed)?;
        Ok(WindowState {
            state,
            window_start_nanos,
            window_end_nanos,
        })
    }

    /// Merge another node's state for the same query. Sketch compatibility
    /// is validated by the sketches; identical window bounds are enforced
    /// here so different time ranges never blend into one estimate.
    pub fn merge_from(&mut self, other: &WindowState) -> Result<(), SketchError> {
        if (self.window_start_nanos, self.window_end_nanos)
            != (other.window_start_nanos, other.window_end_nanos)
        {
            return Err(SketchError::IncompatibleMerge(format!(
                "window mismatch: [{}, {}) vs [{}, {})",
                self.window_start_nanos,
                self.window_end_nanos,
                other.window_start_nanos,
                other.window_end_nanos
            )));
        }
        self.state.merge_from(&other.state)
    }

    /// Estimates for this (possibly merged) window, using the plan's
    /// measure semantics, export caps, and alert thresholds.
    pub fn estimates(&self, plan: &Plan) -> Vec<SketchEstimate> {
        emit_estimates(
            plan,
            &self.state,
            self.window_start_nanos,
            self.window_end_nanos,
        )
    }

    pub fn window_start_nanos(&self) -> u64 {
        self.window_start_nanos
    }

    pub fn window_end_nanos(&self) -> u64 {
        self.window_end_nanos
    }

    pub fn memory_bytes(&self) -> usize {
        self.state.memory_bytes()
    }

    pub fn update_count(&self) -> u64 {
        self.state.update_count()
    }

    /// Serialize this mergeable window into the same FSK1 component set the
    /// distributed gateway accepts.
    pub fn snapshot_exports(&self, query_name: &str) -> Vec<SnapshotExport> {
        self.state
            .to_snapshots(self.window_start_nanos, self.window_end_nanos)
            .into_iter()
            .map(|(component, bytes)| SnapshotExport {
                query_name: query_name.to_string(),
                component,
                bytes,
            })
            .collect()
    }
}

/// One serialized component sketch exported from a running engine.
#[derive(Debug, Clone)]
pub struct SnapshotExport {
    pub query_name: String,
    pub component: String,
    pub bytes: Vec<u8>,
}

/// Empirical entropy (bits) of a distribution summarized by a SpaceSaving
/// head and an HLL support estimate for the tail.
///
/// The tracked keys' guaranteed counts contribute exact `-p log2 p` terms;
/// the residual mass is treated as uniform over the remaining support
/// (HLL distinct count minus tracked keys). This is a heuristic estimator —
/// the planner labels it `error_kind="heuristic"`.
fn estimate_entropy_bits(ss: &SpaceSaving, hll: &HyperLogLog) -> Option<f64> {
    let n = ss.total_weight() as f64;
    if n <= 0.0 {
        return None;
    }
    let tracked = ss.top_k(ss.capacity());
    let mut head_mass = 0.0f64;
    let mut entropy = 0.0f64;
    for (_, entry) in &tracked {
        let g = entry.guaranteed() as f64;
        if g > 0.0 {
            let p = g / n;
            entropy -= p * p.log2();
            head_mass += g;
        }
    }
    let tail_mass = (n - head_mass).max(0.0);
    if tail_mass > 0.0 {
        let tail_support = (hll.cardinality() - tracked.len() as f64).max(1.0);
        // Uniform tail: support * (m/support/n) * log2(n*support/m).
        let p_each = tail_mass / tail_support / n;
        if p_each > 0.0 {
            entropy -= tail_mass / n * p_each.log2();
        }
    }
    Some(entropy.max(0.0))
}

#[derive(Debug, Clone)]
struct Bucket {
    start_nanos: u64,
    state: QueryState,
}

/// One planned query running inside the engine.
struct RunningQuery {
    plan: Plan,
    group_fields: Vec<Field>,
    distinct_field: Option<Field>,
    value_field: Option<Field>,
    hash: HashSpec,
    buckets: VecDeque<Bucket>,
    /// Mergeable states emitted at each window close. Its capacity is part
    /// of the physical plan; consumers must drain before it fills again.
    emitted: Vec<WindowState>,
    /// Events dropped because they arrived before the earliest open bucket.
    late_events: u64,
    /// Reused hot-path buffers for encoded keys.
    key_buf: Vec<u8>,
    distinct_buf: Vec<u8>,
}

impl RunningQuery {
    fn new(plan: Plan, hash: HashSpec) -> Result<Self, SketchError> {
        let (distinct_field, value_field) = match &plan.query.measure {
            Measure::Count => (None, None),
            Measure::Sum { value } => (None, Some(*value)),
            Measure::HeavyHitters { value, .. } => (None, Some(*value)),
            Measure::DistinctCount { field } => (Some(*field), None),
            // Entropy consumes the field as a distinct item; quantile
            // consumes it as the numeric value fed to KLL.
            Measure::Entropy { field } => (Some(*field), None),
            Measure::Quantile { field, .. } => (None, Some(*field)),
        };
        Ok(RunningQuery {
            group_fields: plan.query.group_by.clone(),
            distinct_field,
            value_field,
            hash,
            buckets: VecDeque::new(),
            emitted: Vec::with_capacity(plan.physical.pending_window_capacity),
            late_events: 0,
            key_buf: Vec::with_capacity(64),
            distinct_buf: Vec::with_capacity(32),
            plan,
        })
    }

    fn slide_nanos(&self) -> u64 {
        self.plan.query.window.slide_nanos
    }

    fn bucket_count(&self) -> usize {
        self.plan.physical.window_buckets
    }

    fn pending_window_capacity(&self) -> usize {
        self.plan.physical.pending_window_capacity
    }

    fn bucket_start_for(&self, ts: u64) -> u64 {
        ts - ts % self.slide_nanos()
    }

    fn new_bucket(&self, start_nanos: u64) -> Result<Bucket, SketchError> {
        Ok(Bucket {
            start_nanos,
            state: QueryState::build(&self.plan.physical.sketch, &self.hash)?,
        })
    }

    fn rebuild_trailing_ring(&mut self, target: u64) -> Result<(), SketchError> {
        self.buckets.clear();
        let slide = self.slide_nanos();
        let ring = self.bucket_count() as u64;
        let first = target - slide * (ring - 1).min(target / slide);
        let mut start = first;
        loop {
            self.buckets.push_back(self.new_bucket(start)?);
            if start == target {
                break;
            }
            start += slide;
        }
        Ok(())
    }

    fn windows_closed_by_advance(&self, target: u64) -> usize {
        let Some(back) = self.buckets.back().map(|bucket| bucket.start_nanos) else {
            return 0;
        };
        if target <= back {
            return 0;
        }
        let slides = ((target - back) / self.slide_nanos()) as usize;
        if slides > self.bucket_count() {
            self.bucket_count()
        } else {
            slides
        }
    }

    fn ensure_emit_capacity(&self, additional: usize) -> Result<(), SketchError> {
        let pending = self.emitted.len();
        let capacity = self.pending_window_capacity();
        if pending.saturating_add(additional) > capacity {
            return Err(SketchError::Backpressure(format!(
                "query {:?} has {pending} completed window(s) pending and needs room for \
                 {additional} more (capacity {capacity}); drain estimates or window states and \
                 retry",
                self.plan.query.name
            )));
        }
        Ok(())
    }

    fn ensure_can_advance(&self, target: u64) -> Result<(), SketchError> {
        self.ensure_emit_capacity(self.windows_closed_by_advance(target))
    }

    fn ensure_can_process(&self, event: &FlowEvent) -> Result<(), SketchError> {
        if self.plan.query.filter.matches(event) {
            self.ensure_can_advance(self.bucket_start_for(event.ts_nanos))?;
        }
        Ok(())
    }

    /// Advance time to `target`, closing any windows that end at or before it.
    fn advance_to_bucket(&mut self, target: u64) -> Result<(), SketchError> {
        self.ensure_can_advance(target)?;
        let slide = self.slide_nanos();
        if self.buckets.is_empty() {
            self.buckets.push_back(self.new_bucket(target)?);
            return Ok(());
        }
        // If the jump exceeds the whole window, every open bucket expires at
        // once: flush what we have and restart at the target time. Without
        // this, a single far-future timestamp (corrupt capture, long-idle
        // live agent) would spin one iteration per slide across the gap.
        let back = self.buckets.back().unwrap().start_nanos;
        if target > back && (target - back) / slide > self.bucket_count() as u64 {
            // Preserve the slow path's decaying trailing windows before
            // skipping the empty middle of a large gap. Each iteration
            // advances one slide and evicts at most one real bucket, so a
            // bounded `bucket_count` iterations are sufficient.
            for _ in 0..self.bucket_count() {
                let next = self.buckets.back().unwrap().start_nanos + slide;
                self.flush_window(next)?;
                self.buckets.push_back(self.new_bucket(next)?);
                while self.buckets.len() > self.bucket_count() {
                    self.buckets.pop_front();
                }
            }
            // Rebuild the full (empty) trailing ring at the target time, not
            // just the target bucket, so slightly out-of-order events that
            // are still inside the new window land in a bucket instead of
            // being counted late.
            self.rebuild_trailing_ring(target)?;
            return Ok(());
        }
        while self.buckets.back().unwrap().start_nanos < target {
            let next = self.buckets.back().unwrap().start_nanos + slide;
            // The bucket that just ended closes a window ending at `next`.
            self.flush_window(next)?;
            self.buckets.push_back(self.new_bucket(next)?);
            while self.buckets.len() > self.bucket_count() {
                self.buckets.pop_front();
            }
        }
        Ok(())
    }

    fn process(&mut self, event: &FlowEvent) -> Result<(), SketchError> {
        if !self.plan.query.filter.matches(event) {
            return Ok(());
        }
        let bucket_start = self.bucket_start_for(event.ts_nanos);
        let bucket_index = if self
            .buckets
            .back()
            .is_some_and(|b| b.start_nanos == bucket_start)
        {
            self.buckets.len() - 1
        } else {
            self.advance_to_bucket(bucket_start)?;
            let Some(index) = self
                .buckets
                .iter()
                .position(|b| b.start_nanos == bucket_start)
            else {
                // Late event older than the earliest open bucket.
                self.late_events += 1;
                return Ok(());
            };
            index
        };

        group_key_into(&self.group_fields, event, &mut self.key_buf);
        let weight = match self.value_field {
            Some(f) => f.extract_value(event),
            None => 1,
        };
        if let Some(f) = self.distinct_field {
            self.distinct_buf.clear();
            field_value_into(f, event, &mut self.distinct_buf);
        }

        let bucket = self
            .buckets
            .get_mut(bucket_index)
            .expect("bucket index was just resolved");
        match &mut bucket.state {
            QueryState::HeavyHitters { ss } => ss.add_key_buf(&mut self.key_buf, weight),
            state => state.update(&self.key_buf, weight, &self.distinct_buf),
        }
        Ok(())
    }

    /// Merge all open buckets and emit estimates for the window ending at
    /// `window_end`.
    fn flush_window(&mut self, window_end: u64) -> Result<(), SketchError> {
        if self.buckets.is_empty() {
            return Ok(());
        }
        self.ensure_emit_capacity(1)?;
        let mut merged = self.buckets[0].state.clone();
        for b in self.buckets.iter().skip(1) {
            merged.merge_from(&b.state)?;
        }
        let window_start = self.buckets.front().unwrap().start_nanos;
        self.emitted.push(WindowState {
            state: merged,
            window_start_nanos: window_start,
            window_end_nanos: window_end,
        });
        Ok(())
    }

    /// Final flush for offline replay: close the trailing partial window.
    fn finish(&mut self) -> Result<(), SketchError> {
        if let Some(last) = self.buckets.back() {
            self.ensure_emit_capacity(1)?;
            let window_end = last.start_nanos + self.slide_nanos();
            self.flush_window(window_end)?;
        }
        Ok(())
    }
}

/// Estimates for one query window state under `plan`'s measure semantics,
/// export caps, and alert thresholds. Shared by the live engine and the
/// gateway's cross-node merge path.
fn emit_estimates(
    plan: &Plan,
    state: &QueryState,
    window_start: u64,
    window_end: u64,
) -> Vec<SketchEstimate> {
    if state.update_count() == 0 {
        return Vec::new();
    }
    let q = &plan.query;
    let p = &plan.physical;
    let algorithm = p.sketch.algorithm_name();
    let sketch_bytes = state.memory_bytes() as u64;
    let update_count = state.update_count();
    let cap = p.export_series_upper_bound.min(q.export.max_series);

    let label_names: Vec<String> = q.group_by.iter().map(|f| f.name().to_string()).collect();
    let make_group = |key: &[u8]| -> Vec<(String, String)> {
        label_names
            .iter()
            .cloned()
            .zip(flowsketch_core::field::split_group_key(key))
            .collect()
    };
    let base = |group: Vec<(String, String)>, estimate: f64| SketchEstimate {
        query_name: q.name.clone(),
        window_start_nanos: window_start,
        window_end_nanos: window_end,
        group,
        estimate,
        lower_bound: None,
        upper_bound: None,
        confidence: None,
        algorithm: algorithm.clone(),
        sketch_bytes,
        update_count,
    };

    let mut out: Vec<SketchEstimate> = match state {
        QueryState::HeavyHitters { ss } => ss
            .top_k(cap)
            .into_iter()
            .map(|(key, entry)| {
                let mut e = base(make_group(&key), entry.count as f64);
                e.upper_bound = Some(entry.count as f64);
                e.lower_bound = Some(entry.guaranteed() as f64);
                e
            })
            .collect(),

        QueryState::Counter { cm, keys } => keys
            .top_k(cap)
            .into_iter()
            .map(|(key, _)| {
                let est = cm.estimate_u64(&key) as f64;
                let slack = cm.epsilon() * cm.total_weight() as f64;
                let mut e = base(make_group(&key), est);
                e.upper_bound = Some(est);
                e.lower_bound = Some((est - slack).max(0.0));
                e.confidence = Some(1.0 - cm.delta());
                e
            })
            .collect(),

        QueryState::DistinctPerKey { map } => {
            let rel = map.relative_error();
            map.entries()
                .into_iter()
                .take(cap)
                .map(|(key, card)| {
                    let mut e = base(make_group(&key), card);
                    e.lower_bound = Some(card * (1.0 - 2.0 * rel));
                    e.upper_bound = Some(card * (1.0 + 2.0 * rel));
                    e.confidence = Some(0.95);
                    e
                })
                .collect()
        }

        QueryState::DistinctGlobal { hll } => {
            let card = hll.cardinality();
            let rel = hll.relative_error();
            let mut e = base(Vec::new(), card);
            e.lower_bound = Some(card * (1.0 - 2.0 * rel));
            e.upper_bound = Some(card * (1.0 + 2.0 * rel));
            e.confidence = Some(0.95);
            vec![e]
        }

        QueryState::Quantile { kll } => {
            let Measure::Quantile { q: quantile, .. } = &q.measure else {
                return Vec::new();
            };
            let Some(value) = kll.quantile(*quantile) else {
                return Vec::new();
            };
            let eps = kll.rank_error();
            let mut e = base(Vec::new(), value as f64);
            // Rank error translates to value bounds by querying the
            // neighboring quantiles.
            e.lower_bound = kll.quantile((quantile - eps).max(0.0)).map(|v| v as f64);
            e.upper_bound = kll.quantile((quantile + eps).min(1.0)).map(|v| v as f64);
            e.confidence = Some(0.99);
            vec![e]
        }

        QueryState::Entropy { ss, hll } => {
            let Some(entropy_bits) = estimate_entropy_bits(ss, hll) else {
                return Vec::new();
            };
            vec![base(Vec::new(), entropy_bits)]
        }
    };

    if !q.alert.is_empty() {
        out.retain(|e| q.alert.fires(e.estimate));
    }
    out
}

/// The engine: a set of running queries fed from one event stream.
pub struct QueryEngine {
    queries: Vec<RunningQuery>,
    events_processed: u64,
}

impl QueryEngine {
    /// Build an engine from planned queries. All sketches share `hash` so
    /// engines on different nodes stay merge-compatible.
    pub fn new(plans: Vec<Plan>, hash: HashSpec) -> Result<Self, SketchError> {
        // Validate every plan is executable up front (fail closed at
        // configuration time, not on the hot path).
        let mut queries = Vec::with_capacity(plans.len());
        for plan in plans {
            QueryState::build(&plan.physical.sketch, &hash)?;
            queries.push(RunningQuery::new(plan, hash)?);
        }
        Ok(QueryEngine {
            queries,
            events_processed: 0,
        })
    }

    pub fn process(&mut self, event: &FlowEvent) -> Result<(), SketchError> {
        // Capacity is preflighted across every query so a backpressure error
        // never leaves a multi-query event partially applied. The caller may
        // drain completed windows and retry this exact event safely.
        for q in &self.queries {
            q.ensure_can_process(event)?;
        }
        self.events_processed += 1;
        for q in &mut self.queries {
            q.process(event)?;
        }
        Ok(())
    }

    /// Advance every query to a shared event-time watermark. This is a no-op
    /// for queries already at or beyond the watermark and is used to keep
    /// independently fed shards on identical window boundaries.
    pub fn advance_to(&mut self, ts_nanos: u64) -> Result<(), SketchError> {
        for q in &self.queries {
            q.ensure_can_advance(q.bucket_start_for(ts_nanos))?;
        }
        for q in &mut self.queries {
            q.advance_to_bucket(q.bucket_start_for(ts_nanos))?;
        }
        Ok(())
    }

    /// Close trailing windows (offline replay end-of-stream).
    pub fn finish(&mut self) -> Result<(), SketchError> {
        for q in &self.queries {
            if !q.buckets.is_empty() {
                q.ensure_emit_capacity(1)?;
            }
        }
        for q in &mut self.queries {
            q.finish()?;
        }
        Ok(())
    }

    /// Drain all estimates emitted so far, in emission order.
    pub fn take_estimates(&mut self) -> Vec<SketchEstimate> {
        let mut out = Vec::new();
        for q in &mut self.queries {
            for state in q.emitted.drain(..) {
                out.extend(state.estimates(&q.plan));
            }
        }
        out
    }

    /// Drain completed windows as mergeable sketch states. This is the
    /// low-frequency handoff used by independently owned runtime lanes.
    pub fn take_window_states(&mut self) -> Vec<QueryWindowState> {
        let mut out = Vec::new();
        for q in &mut self.queries {
            out.extend(q.emitted.drain(..).map(|state| QueryWindowState {
                query_name: q.plan.query.name.clone(),
                state,
            }));
        }
        out
    }

    /// Number of completed mergeable windows currently awaiting a drain.
    pub fn pending_window_count(&self) -> usize {
        self.queries.iter().map(|q| q.emitted.len()).sum()
    }

    /// Whether any query has filled its planned completed-window buffer.
    pub fn pending_windows_full(&self) -> bool {
        self.queries
            .iter()
            .any(|q| q.emitted.len() == q.pending_window_capacity())
    }

    /// Clone each query's current open window into a mergeable sketch state.
    /// Callers should request this only when a snapshot export is due.
    pub fn current_window_states(&self) -> Result<Vec<QueryWindowState>, SketchError> {
        let mut out = Vec::new();
        for q in &self.queries {
            if q.buckets.is_empty() {
                continue;
            }
            let mut state = q.buckets[0].state.clone();
            for bucket in q.buckets.iter().skip(1) {
                state.merge_from(&bucket.state)?;
            }
            out.push(QueryWindowState {
                query_name: q.plan.query.name.clone(),
                state: WindowState {
                    state,
                    window_start_nanos: q.buckets.front().unwrap().start_nanos,
                    window_end_nanos: q.buckets.back().unwrap().start_nanos + q.slide_nanos(),
                },
            });
        }
        Ok(out)
    }

    pub fn events_processed(&self) -> u64 {
        self.events_processed
    }

    /// Total late (dropped) events across queries — a health signal.
    pub fn late_events(&self) -> u64 {
        self.queries.iter().map(|q| q.late_events).sum()
    }

    /// Resident sketch memory across open buckets and completed windows
    /// awaiting a consumer drain.
    pub fn sketch_memory_bytes(&self) -> usize {
        self.queries
            .iter()
            .map(|q| {
                q.buckets
                    .iter()
                    .map(|bucket| bucket.state.memory_bytes())
                    .sum::<usize>()
                    + q.emitted
                        .iter()
                        .map(WindowState::memory_bytes)
                        .sum::<usize>()
            })
            .sum()
    }

    /// Error-kind label per query, for exporters.
    pub fn error_kind(&self, query_name: &str) -> Option<ErrorKind> {
        self.queries
            .iter()
            .find(|q| q.plan.query.name == query_name)
            .map(|q| q.plan.physical.error_kind)
    }

    /// The plans this engine is executing.
    pub fn plans(&self) -> impl Iterator<Item = &Plan> {
        self.queries.iter().map(|q| &q.plan)
    }

    /// Serialize each query's current window state to FSK1 snapshots (one
    /// per component sketch), for cross-process merge. The window covers
    /// all currently open buckets.
    pub fn export_snapshots(&self) -> Result<Vec<SnapshotExport>, SketchError> {
        let mut out = Vec::new();
        for window in self.current_window_states()? {
            out.extend(window.state.snapshot_exports(&window.query_name));
        }
        Ok(out)
    }
}

/// A merge-correct set of query engines for receive-queue or flow sharding.
///
/// Callers with NIC RSS metadata should use `process_shard_batches` so queue
/// affinity is preserved without a userspace dispatch pass. Other callers can
/// use `process_batch`, which hashes the directional 5-tuple deterministically.
pub struct ShardedQueryEngine {
    shards: Vec<QueryEngine>,
    plans: Vec<Plan>,
    hash: HashSpec,
    pool: rayon::ThreadPool,
    next_balanced_shard: usize,
}

/// Userspace dispatch policy for sources that do not already provide one
/// batch per NIC receive queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardStrategy {
    /// Keep a directional 5-tuple on one shard for cache locality.
    Flow,
    /// Spread packets evenly; mergeable sketch states preserve query results.
    RoundRobin,
}

fn build_runtime_pool(
    shard_count: usize,
    worker_cpus: Option<&[usize]>,
) -> Result<rayon::ThreadPool, SketchError> {
    let builder = rayon::ThreadPoolBuilder::new()
        .num_threads(shard_count)
        .thread_name(|index| format!("fs-runtime-{index}"));

    #[cfg(target_os = "linux")]
    let builder = if let Some(worker_cpus) = worker_cpus {
        use std::sync::Arc;

        for &cpu in worker_cpus {
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(SketchError::InvalidParam(format!(
                    "runtime CPU {cpu} is outside Linux CPU_SETSIZE {}",
                    libc::CPU_SETSIZE
                )));
            }
        }
        let worker_cpus: Arc<[usize]> = Arc::from(worker_cpus);
        let builder = builder.spawn_handler(move |thread| {
            let worker = thread.index();
            let cpu = worker_cpus[worker];
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let mut os_thread = std::thread::Builder::new();
            if let Some(name) = thread.name() {
                os_thread = os_thread.name(name.to_string());
            }
            if let Some(stack_size) = thread.stack_size() {
                os_thread = os_thread.stack_size(stack_size);
            }
            os_thread.spawn(move || match pin_current_thread(cpu) {
                Ok(()) => {
                    if ready_tx.send(Ok(())).is_ok() {
                        thread.run();
                    }
                }
                Err(error) => {
                    let detail =
                        format!("cannot pin runtime worker {worker} to CPU {cpu}: {error}");
                    let _ = ready_tx.send(Err(std::io::Error::new(error.kind(), detail)));
                }
            })?;
            ready_rx.recv().map_err(|_| {
                std::io::Error::other(format!(
                    "runtime worker {worker} ended before reporting CPU affinity"
                ))
            })?
        });
        let pool = builder.build().map_err(|error| {
            SketchError::InvalidParam(format!("cannot build runtime pool: {error}"))
        })?;
        return Ok(pool);
    } else {
        builder
    };

    #[cfg(not(target_os = "linux"))]
    if worker_cpus.is_some() {
        return Err(SketchError::InvalidParam(
            "runtime CPU affinity is supported only on Linux".into(),
        ));
    }

    builder
        .build()
        .map_err(|error| SketchError::InvalidParam(format!("cannot build runtime pool: {error}")))
}

#[cfg(target_os = "linux")]
fn pin_current_thread(cpu: usize) -> std::io::Result<()> {
    // SAFETY: cpu_set_t is an integer bitset. CPU_ZERO/CPU_SET initialize and
    // update it within CPU_SETSIZE, checked by the caller. sched_setaffinity
    // reads exactly the supplied initialized structure for the current thread.
    let result = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl ShardedQueryEngine {
    pub fn new(plans: Vec<Plan>, hash: HashSpec, shard_count: usize) -> Result<Self, SketchError> {
        Self::new_inner(plans, hash, shard_count, None)
    }

    /// Build a sharded engine whose Rayon workers are each restricted to one
    /// Linux logical CPU. `worker_cpus[i]` is assigned to worker `i`.
    /// Affinity setup is fail-closed so a mistyped or disallowed CPU cannot
    /// silently leave a supposedly isolated high-rate deployment unpinned.
    pub fn new_with_cpu_affinity(
        plans: Vec<Plan>,
        hash: HashSpec,
        shard_count: usize,
        worker_cpus: &[usize],
    ) -> Result<Self, SketchError> {
        Self::new_inner(plans, hash, shard_count, Some(worker_cpus))
    }

    fn new_inner(
        plans: Vec<Plan>,
        hash: HashSpec,
        shard_count: usize,
        worker_cpus: Option<&[usize]>,
    ) -> Result<Self, SketchError> {
        if shard_count == 0 {
            return Err(SketchError::InvalidParam(
                "runtime shard count must be at least 1".into(),
            ));
        }
        if let Some(cpus) = worker_cpus {
            if cpus.len() != shard_count {
                return Err(SketchError::InvalidParam(format!(
                    "runtime CPU affinity lists {} CPU(s) for {shard_count} shard worker(s)",
                    cpus.len()
                )));
            }
            let unique: std::collections::BTreeSet<_> = cpus.iter().copied().collect();
            if unique.len() != cpus.len() {
                return Err(SketchError::InvalidParam(
                    "runtime CPU affinity must not assign one CPU to multiple workers".into(),
                ));
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for plan in &plans {
            if !names.insert(plan.query.name.as_str()) {
                return Err(SketchError::InvalidParam(format!(
                    "duplicate query name {:?} in sharded runtime",
                    plan.query.name
                )));
            }
        }
        let pool = build_runtime_pool(shard_count, worker_cpus)?;
        let shards = (0..shard_count)
            .map(|_| QueryEngine::new(plans.clone(), hash))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            shards,
            plans,
            hash,
            pool,
            next_balanced_shard: 0,
        })
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Stable directional 5-tuple shard selection for sources without an RSS
    /// queue id. A flow stays on one shard, improving cache locality.
    pub fn shard_for(&self, event: &FlowEvent) -> usize {
        let mut key = [0u8; 38];
        let (src, dst) = match (event.src_ip, event.dst_ip) {
            (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
                key[0] = 4;
                (src.to_ipv6_mapped().octets(), dst.to_ipv6_mapped().octets())
            }
            (src, dst) => {
                key[0] = 6;
                let src = match src {
                    std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(ip) => ip.octets(),
                };
                let dst = match dst {
                    std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(ip) => ip.octets(),
                };
                (src, dst)
            }
        };
        key[1..17].copy_from_slice(&src);
        key[17..33].copy_from_slice(&dst);
        key[33..35].copy_from_slice(&event.src_port.to_be_bytes());
        key[35..37].copy_from_slice(&event.dst_port.to_be_bytes());
        key[37] = event.protocol;
        (self.hash.hash64(&key) % self.shards.len() as u64) as usize
    }

    /// Hash-dispatch and process one batch in parallel. Event order is
    /// preserved within each shard.
    pub fn process_batch(&mut self, events: &[FlowEvent]) -> Result<(), SketchError> {
        self.process_batch_with_strategy(events, ShardStrategy::Flow)
    }

    pub fn process_batch_with_strategy(
        &mut self,
        events: &[FlowEvent],
        strategy: ShardStrategy,
    ) -> Result<(), SketchError> {
        let mut batches = vec![Vec::new(); self.shards.len()];
        for event in events {
            let shard = match strategy {
                ShardStrategy::Flow => self.shard_for(event),
                ShardStrategy::RoundRobin => {
                    let shard = self.next_balanced_shard;
                    self.next_balanced_shard = (shard + 1) % self.shards.len();
                    shard
                }
            };
            batches[shard].push(event);
        }
        self.process_shard_refs(&batches)
    }

    /// Process already partitioned receive-queue batches. `batches[i]` maps
    /// to shard `i`; this models the production RSS fast path.
    pub fn process_shard_batches(&mut self, batches: &[Vec<FlowEvent>]) -> Result<(), SketchError> {
        if batches.len() != self.shards.len() {
            return Err(SketchError::InvalidParam(format!(
                "received {} shard batches for {} runtime shards",
                batches.len(),
                self.shards.len()
            )));
        }
        let refs: Vec<Vec<&FlowEvent>> =
            batches.iter().map(|batch| batch.iter().collect()).collect();
        self.process_shard_refs(&refs)
    }

    fn process_shard_refs(&mut self, batches: &[Vec<&FlowEvent>]) -> Result<(), SketchError> {
        let batch_start = batches
            .iter()
            .flat_map(|batch| batch.iter())
            .map(|event| event.ts_nanos)
            .min();
        let watermark = batches
            .iter()
            .flat_map(|batch| batch.iter())
            .map(|event| event.ts_nanos)
            .max();
        self.pool.install(|| {
            self.shards
                .par_iter_mut()
                .zip(batches.par_iter())
                .try_for_each(|(engine, batch)| {
                    // Seed every shard at the earliest timestamp before any
                    // shard processes its first event. Otherwise a skewed
                    // first batch can give lanes different window starts,
                    // preventing their states from merging at the same end.
                    if let Some(batch_start) = batch_start {
                        engine.advance_to(batch_start)?;
                    }
                    for event in batch {
                        engine.process(event)?;
                    }
                    if let Some(watermark) = watermark {
                        engine.advance_to(watermark)?;
                    }
                    Ok::<_, SketchError>(())
                })
        })
    }

    pub fn finish(&mut self) -> Result<(), SketchError> {
        self.pool
            .install(|| self.shards.par_iter_mut().try_for_each(QueryEngine::finish))
    }

    pub fn take_estimates(&mut self) -> Result<Vec<SketchEstimate>, SketchError> {
        let mut merged: BTreeMap<(String, u64, u64), WindowState> = BTreeMap::new();
        for output in self
            .shards
            .iter_mut()
            .flat_map(QueryEngine::take_window_states)
        {
            let key = (
                output.query_name,
                output.state.window_start_nanos,
                output.state.window_end_nanos,
            );
            match merged.get_mut(&key) {
                Some(state) => state.merge_from(&output.state)?,
                None => {
                    merged.insert(key, output.state);
                }
            }
        }
        let plans: BTreeMap<_, _> = self
            .plans
            .iter()
            .map(|plan| (plan.query.name.as_str(), plan))
            .collect();
        let mut estimates = Vec::new();
        for ((query_name, _, _), state) in merged {
            let plan = plans.get(query_name.as_str()).ok_or_else(|| {
                SketchError::InvalidParam(format!("missing plan for query {query_name:?}"))
            })?;
            estimates.extend(state.estimates(plan));
        }
        Ok(estimates)
    }

    pub fn events_processed(&self) -> u64 {
        self.shards.iter().map(QueryEngine::events_processed).sum()
    }

    pub fn late_events(&self) -> u64 {
        self.shards.iter().map(QueryEngine::late_events).sum()
    }

    pub fn sketch_memory_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(QueryEngine::sketch_memory_bytes)
            .sum()
    }

    pub fn export_snapshots(&self) -> Result<Vec<SnapshotExport>, SketchError> {
        let mut merged: BTreeMap<(String, u64, u64), WindowState> = BTreeMap::new();
        for output in self
            .shards
            .iter()
            .map(QueryEngine::current_window_states)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
        {
            let key = (
                output.query_name,
                output.state.window_start_nanos,
                output.state.window_end_nanos,
            );
            match merged.get_mut(&key) {
                Some(state) => state.merge_from(&output.state)?,
                None => {
                    merged.insert(key, output.state);
                }
            }
        }
        let mut exports = Vec::new();
        for ((query_name, _, _), state) in merged {
            exports.extend(state.snapshot_exports(&query_name));
        }
        Ok(exports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowsketch_ir::parse_query_yaml;
    use flowsketch_planner::plan;
    use std::net::IpAddr;

    fn event(ts_s: u64, src: &str, dst: &str, dport: u16, bytes: u32) -> FlowEvent {
        FlowEvent {
            ts_nanos: ts_s * 1_000_000_000,
            src_ip: src.parse::<IpAddr>().unwrap(),
            dst_ip: dst.parse::<IpAddr>().unwrap(),
            src_port: 40_000,
            dst_port: dport,
            protocol: 6,
            bytes,
            ..FlowEvent::default()
        }
    }

    fn engine_for(yaml: &str) -> QueryEngine {
        let q = parse_query_yaml(yaml).unwrap();
        let p = plan(q, &HashSpec::new(7)).unwrap();
        QueryEngine::new(vec![p], HashSpec::new(7)).unwrap()
    }

    #[test]
    fn top_talkers_end_to_end() {
        let mut eng = engine_for(
            "name: tt\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip, dst.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 5}\n",
        );
        // Heavy pair sends 10x the bytes of background pairs.
        for i in 0..600u64 {
            eng.process(&event(i / 10, "10.0.1.10", "10.0.2.50", 443, 10_000))
                .unwrap();
            eng.process(&event(
                i / 10,
                &format!("10.0.9.{}", i % 200),
                "10.0.2.51",
                443,
                100,
            ))
            .unwrap();
        }
        eng.finish().unwrap();
        let est = eng.take_estimates();
        assert!(!est.is_empty());
        // In every emitted window the heavy pair ranks first.
        let mut windows: std::collections::BTreeMap<u64, Vec<&SketchEstimate>> = Default::default();
        for e in &est {
            windows.entry(e.window_end_nanos).or_default().push(e);
        }
        for (_end, mut es) in windows {
            es.sort_by(|a, b| b.estimate.partial_cmp(&a.estimate).unwrap());
            assert_eq!(
                es[0].group,
                vec![
                    ("src.ip".to_string(), "10.0.1.10".to_string()),
                    ("dst.ip".to_string(), "10.0.2.50".to_string())
                ]
            );
            assert_eq!(es[0].algorithm, "spacesaving");
            assert!(es[0].sketch_bytes > 0);
        }
    }

    #[test]
    fn scanner_detection_with_alert_threshold() {
        let mut eng = engine_for(
            "name: scan\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n\
             alertIf: {gt: 500}\n",
        );
        // Scanner hits 2000 distinct destinations; normal hosts hit 3.
        for i in 0..2_000u32 {
            eng.process(&event(
                (i / 40) as u64,
                "10.0.1.50",
                &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                22,
                60,
            ))
            .unwrap();
        }
        for h in 0..50u32 {
            for d in 0..3u32 {
                eng.process(&event(
                    5,
                    &format!("10.1.0.{h}"),
                    &format!("10.2.0.{d}"),
                    443,
                    500,
                ))
                .unwrap();
            }
        }
        eng.finish().unwrap();
        let est = eng.take_estimates();
        // Only the scanner crosses the alert threshold.
        assert!(!est.is_empty());
        for e in &est {
            assert_eq!(e.group[0].0, "src.ip");
            assert_eq!(e.group[0].1, "10.0.1.50");
            assert!(e.estimate > 500.0);
            assert_eq!(e.algorithm, "hllmap");
        }
    }

    #[test]
    fn sum_by_protocol_is_accurate() {
        let mut eng = engine_for(
            "name: pb\nwindow: {size: 60s}\ngroupBy: [protocol]\nmeasure: {type: sum, value: bytes}\n",
        );
        for i in 0..1_000u64 {
            eng.process(&event(i / 100, "10.0.0.1", "10.0.0.2", 443, 1_000))
                .unwrap();
        }
        eng.finish().unwrap();
        let est = eng.take_estimates();
        assert_eq!(est.len(), 1);
        assert_eq!(
            est[0].group,
            vec![("protocol".to_string(), "tcp".to_string())]
        );
        assert_eq!(est[0].estimate, 1_000_000.0);
    }

    #[test]
    fn sharded_engine_merges_before_emitting_estimates() {
        let yaml =
            "name: pb\nwindow: {size: 60s}\ngroupBy: [protocol]\nmeasure: {type: sum, value: bytes}\n";
        let query = parse_query_yaml(yaml).unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, 4).unwrap();
        let events: Vec<_> = (0..1_000)
            .map(|i| {
                event(
                    5,
                    &format!("10.0.{}.{}", i / 250, i % 250 + 1),
                    "10.9.9.9",
                    443,
                    1_000,
                )
            })
            .collect();

        engine.process_batch(&events).unwrap();
        engine.finish().unwrap();
        let estimates = engine.take_estimates().unwrap();

        assert_eq!(engine.events_processed(), 1_000);
        assert_eq!(estimates.len(), 1, "shards leaked duplicate estimates");
        assert_eq!(estimates[0].estimate, 1_000_000.0);
        assert_eq!(estimates[0].update_count, 1_000);
    }

    #[test]
    fn runtime_cpu_affinity_requires_one_unique_cpu_per_worker() {
        let hash = HashSpec::new(7);
        assert!(ShardedQueryEngine::new_with_cpu_affinity(vec![], hash, 2, &[0]).is_err());
        assert!(ShardedQueryEngine::new_with_cpu_affinity(vec![], hash, 2, &[0, 0]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_worker_is_pinned_to_requested_allowed_cpu() {
        // SAFETY: the zeroed set is initialized by sched_getaffinity, which
        // writes exactly size_of::<cpu_set_t>() bytes for the current thread.
        let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut allowed)
        };
        assert_eq!(result, 0, "sched_getaffinity failed");
        let cpu = (0..libc::CPU_SETSIZE as usize)
            .find(|&candidate| unsafe { libc::CPU_ISSET(candidate, &allowed) })
            .expect("test process has no allowed CPU");

        let engine =
            ShardedQueryEngine::new_with_cpu_affinity(vec![], HashSpec::new(7), 1, &[cpu]).unwrap();
        let observed = engine.pool.broadcast(|_| unsafe { libc::sched_getcpu() });
        assert_eq!(observed, vec![cpu as libc::c_int]);

        if let Some(disallowed) = (0..libc::CPU_SETSIZE as usize)
            .find(|&candidate| unsafe { !libc::CPU_ISSET(candidate, &allowed) })
        {
            let error = ShardedQueryEngine::new_with_cpu_affinity(
                vec![],
                HashSpec::new(7),
                1,
                &[disallowed],
            )
            .err()
            .expect("disallowed CPU was accepted");
            assert!(
                error
                    .to_string()
                    .contains(&format!("cannot pin runtime worker 0 to CPU {disallowed}")),
                "{error}"
            );
        }
    }

    #[test]
    fn sharded_engine_advances_active_shards_on_one_watermark() {
        let yaml =
            "name: c\nwindow: {size: 10s, slide: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n";
        let query = parse_query_yaml(yaml).unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, 2).unwrap();
        let first = vec![
            vec![event(5, "10.0.0.1", "10.0.0.2", 80, 100)],
            vec![event(5, "10.0.0.3", "10.0.0.4", 80, 100)],
        ];
        engine.process_shard_batches(&first).unwrap();
        let second = vec![vec![event(15, "10.0.0.1", "10.0.0.2", 80, 100)], vec![]];
        engine.process_shard_batches(&second).unwrap();

        let estimates = engine.take_estimates().unwrap();
        let first_window = estimates
            .iter()
            .find(|estimate| estimate.window_end_nanos == 10_000_000_000)
            .unwrap();
        assert_eq!(first_window.estimate, 2.0);
        assert_eq!(first_window.update_count, 2);
    }

    #[test]
    fn sharded_sliding_windows_align_when_a_shard_starts_late() {
        let yaml =
            "name: c\nwindow: {size: 20s, slide: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n";
        let query = parse_query_yaml(yaml).unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, 2).unwrap();

        engine
            .process_shard_batches(&[vec![event(5, "10.0.0.1", "10.0.0.2", 80, 100)], vec![]])
            .unwrap();
        engine
            .process_shard_batches(&[vec![], vec![event(15, "10.0.0.3", "10.0.0.4", 80, 100)]])
            .unwrap();
        engine
            .process_shard_batches(&[vec![event(25, "10.0.0.5", "10.0.0.6", 80, 100)], vec![]])
            .unwrap();

        let estimates = engine.take_estimates().unwrap();
        let window = estimates
            .iter()
            .filter(|estimate| estimate.window_end_nanos == 20_000_000_000)
            .collect::<Vec<_>>();
        assert_eq!(
            window.len(),
            1,
            "unaligned shards emitted duplicate windows"
        );
        assert_eq!(window[0].window_start_nanos, 0);
        assert_eq!(window[0].estimate, 2.0);
        assert_eq!(window[0].update_count, 2);
    }

    #[test]
    fn sharded_sliding_windows_align_with_a_skewed_first_batch() {
        let yaml =
            "name: c\nwindow: {size: 60s, slide: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n";
        let query = parse_query_yaml(yaml).unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, 2).unwrap();

        engine
            .process_shard_batches(&[
                vec![event(0, "10.0.0.1", "10.0.0.2", 80, 100)],
                vec![event(30, "10.0.0.3", "10.0.0.4", 80, 100)],
            ])
            .unwrap();
        engine
            .process_shard_batches(&[
                vec![event(40, "10.0.0.1", "10.0.0.2", 80, 100)],
                vec![event(40, "10.0.0.3", "10.0.0.4", 80, 100)],
            ])
            .unwrap();

        let estimates = engine.take_estimates().unwrap();
        let window = estimates
            .iter()
            .filter(|estimate| estimate.window_end_nanos == 40_000_000_000)
            .collect::<Vec<_>>();
        assert_eq!(
            window.len(),
            1,
            "skewed first batch emitted duplicate windows"
        );
        assert_eq!(window[0].window_start_nanos, 0);
        assert_eq!(window[0].estimate, 2.0);
        assert_eq!(window[0].update_count, 2);
    }

    #[test]
    fn sharded_engine_rejects_zero_shards() {
        let query = parse_query_yaml(
            "name: c\nwindow: {size: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n",
        )
        .unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        assert!(ShardedQueryEngine::new(vec![planned], hash, 0).is_err());
    }

    #[test]
    fn round_robin_sharding_balances_across_batches() {
        let query = parse_query_yaml(
            "name: c\nwindow: {size: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n",
        )
        .unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, 4).unwrap();
        let batch: Vec<_> = (0..3)
            .map(|i| event(5, "10.0.0.1", "10.0.0.2", 80 + i, 100))
            .collect();
        engine
            .process_batch_with_strategy(&batch, ShardStrategy::RoundRobin)
            .unwrap();
        engine
            .process_batch_with_strategy(&batch, ShardStrategy::RoundRobin)
            .unwrap();

        let counts: Vec<_> = engine
            .shards
            .iter()
            .map(QueryEngine::events_processed)
            .collect();
        assert_eq!(counts, vec![2, 2, 1, 1]);
        engine.finish().unwrap();
        let estimates = engine.take_estimates().unwrap();
        assert_eq!(estimates.len(), 1);
        assert_eq!(estimates[0].estimate, 6.0);
    }

    #[test]
    fn shard_strategies_match_single_engine_across_sliding_windows() {
        let yaml = "name: counts\nwindow: {size: 30s, slide: 10s}\n\
                    groupBy: [protocol]\nmeasure: {type: count}\n";
        let hash = HashSpec::new(91);
        let planned = plan(parse_query_yaml(yaml).unwrap(), &hash).unwrap();
        let mut events = Vec::new();
        for i in 0..3_000u64 {
            let mut item = event(
                i / 30,
                &format!("10.{}.{}.{}", (i / 65_536) % 256, (i / 256) % 256, i % 256),
                "192.0.2.1",
                1_000 + (i % 100) as u16,
                64 + (i % 1_400) as u32,
            );
            item.protocol = [6, 17, 1][i as usize % 3];
            // Deterministic, bounded disorder spanning some batch boundaries.
            if i > 0 && i % 97 == 0 {
                item.ts_nanos = item.ts_nanos.saturating_sub(1_000_000_000);
            }
            events.push(item);
        }

        let signature = |estimates: Vec<SketchEstimate>| {
            estimates
                .into_iter()
                .map(|estimate| {
                    (
                        (
                            estimate.window_start_nanos,
                            estimate.window_end_nanos,
                            estimate.group,
                        ),
                        (estimate.estimate as u64, estimate.update_count),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };

        let mut single = QueryEngine::new(vec![planned.clone()], hash).unwrap();
        let mut single_estimates = Vec::new();
        for item in &events {
            single.process(item).unwrap();
            if single.pending_windows_full() {
                single_estimates.extend(single.take_estimates());
            }
        }
        single.finish().unwrap();
        single_estimates.extend(single.take_estimates());
        let expected = signature(single_estimates);

        for strategy in [ShardStrategy::Flow, ShardStrategy::RoundRobin] {
            let mut sharded = ShardedQueryEngine::new(vec![planned.clone()], hash, 7).unwrap();
            let mut sharded_estimates = Vec::new();
            for batch in events.chunks(73) {
                sharded
                    .process_batch_with_strategy(batch, strategy)
                    .unwrap();
                sharded_estimates.extend(sharded.take_estimates().unwrap());
            }
            sharded.finish().unwrap();
            sharded_estimates.extend(sharded.take_estimates().unwrap());
            assert_eq!(
                signature(sharded_estimates),
                expected,
                "{strategy:?} sharding changed query results"
            );
            assert_eq!(sharded.late_events(), single.late_events());
        }
    }

    #[test]
    fn long_running_shards_stay_inside_planned_memory_budget() {
        let yaml = "name: bounded\nwindow: {size: 60s, slide: 10s}\n\
                    groupBy: [src.ip]\n\
                    measure: {type: heavy_hitters, value: bytes, limit: 20}\n\
                    resources: {maxMemory: 16MiB}\n";
        let hash = HashSpec::new(17);
        let planned = plan(parse_query_yaml(yaml).unwrap(), &hash).unwrap();
        let shard_count = 4usize;
        let memory_limit = planned.physical.estimated_memory_bytes * shard_count as u64;
        let mut engine = ShardedQueryEngine::new(vec![planned], hash, shard_count).unwrap();
        let events: Vec<_> = (0..20_000u64)
            .map(|i| {
                event(
                    i / 10,
                    &format!("10.0.{}.{}", (i / 250) % 200, i % 250 + 1),
                    "192.0.2.1",
                    443,
                    100 + (i % 1_400) as u32,
                )
            })
            .collect();

        for batch in events.chunks(128) {
            engine
                .process_batch_with_strategy(batch, ShardStrategy::RoundRobin)
                .unwrap();
            let _ = engine.take_estimates().unwrap();
            assert!(
                engine.sketch_memory_bytes() as u64 <= memory_limit,
                "runtime used {} bytes above planned shard budget {memory_limit}",
                engine.sketch_memory_bytes()
            );
        }
        engine.finish().unwrap();
        let _ = engine.take_estimates().unwrap();
        assert_eq!(engine.events_processed(), events.len() as u64);
        assert_eq!(engine.late_events(), 0);
    }

    #[test]
    fn sharded_engine_rejects_duplicate_query_names() {
        let yaml =
            "name: duplicate\nwindow: {size: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n";
        let hash = HashSpec::new(7);
        let planned = plan(parse_query_yaml(yaml).unwrap(), &hash).unwrap();
        assert!(ShardedQueryEngine::new(vec![planned.clone(), planned], hash, 2).is_err());
    }

    #[test]
    fn filter_excludes_non_matching_traffic() {
        let mut eng = engine_for(
            "name: f\nwindow: {size: 60s}\nmatch: {protocol: udp}\ngroupBy: [protocol]\n\
             measure: {type: count}\n",
        );
        for i in 0..100u64 {
            eng.process(&event(i / 10, "10.0.0.1", "10.0.0.2", 443, 100))
                .unwrap(); // tcp: filtered out
        }
        eng.finish().unwrap();
        assert!(eng.take_estimates().is_empty());
    }

    #[test]
    fn quantile_measure_tracks_packet_size_distribution() {
        let mut eng = engine_for(
            "name: psize\nwindow: {size: 60s}\n\
             measure: {type: quantile, field: bytes, q: 0.5, error: {epsilon: 0.01}}\n",
        );
        // Packet sizes 1..=10000 in scrambled order: true median 5000.
        let mut sizes: Vec<u32> = (1..=10_000).collect();
        sizes.sort_by_key(|&v| flowsketch_core::hash::splitmix64(v as u64));
        for (i, bytes) in sizes.into_iter().enumerate() {
            eng.process(&event((i / 200) as u64, "10.0.0.1", "10.0.0.2", 443, bytes))
                .unwrap();
        }
        eng.finish().unwrap();
        let est = eng.take_estimates();
        assert_eq!(est.len(), 1);
        let e = &est[0];
        assert_eq!(e.algorithm, "kll");
        assert!(
            (e.estimate - 5_000.0).abs() < 300.0,
            "median estimate {} too far from 5000",
            e.estimate
        );
        assert!(e.lower_bound.unwrap() <= e.estimate);
        assert!(e.upper_bound.unwrap() >= e.estimate);
    }

    #[test]
    fn entropy_measure_separates_uniform_from_concentrated() {
        let run = |concentrated: bool| -> f64 {
            let mut eng = engine_for(
                "name: ent\nwindow: {size: 60s}\n\
                 measure: {type: entropy, field: src.ip}\n",
            );
            for i in 0..10_000u32 {
                let src = if concentrated {
                    "10.0.0.1".to_string() // all traffic from one host
                } else {
                    format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)
                };
                eng.process(&event((i / 200) as u64, &src, "10.9.9.9", 80, 100))
                    .unwrap();
            }
            eng.finish().unwrap();
            let est = eng.take_estimates();
            assert_eq!(est.len(), 1);
            est[0].estimate
        };
        let concentrated = run(true);
        let uniform = run(false);
        // One host => ~0 bits; 10k uniform hosts => ~log2(10000) ~ 13.3 bits.
        assert!(concentrated < 0.5, "concentrated entropy {concentrated}");
        assert!(
            (uniform - 13.29).abs() < 1.0,
            "uniform entropy {uniform} (expected ~13.3 bits)"
        );
        assert!(uniform > concentrated + 10.0);
    }

    #[test]
    fn far_future_timestamp_does_not_spin() {
        // Regression: a single corrupt/far-future timestamp made advance_to
        // iterate once per slide interval across the whole gap.
        let mut eng = engine_for(
            "name: gap\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 10}\n",
        );
        eng.process(&event(1, "10.0.0.1", "10.0.0.2", 80, 100))
            .unwrap();
        // ~year 2200 in nanos: billions of slides ahead.
        let mut far = event(0, "10.0.0.9", "10.0.0.2", 80, 55);
        far.ts_nanos = 7_300_000_000 * 1_000_000_000;
        let started = std::time::Instant::now();
        eng.process(&far).unwrap();
        let mut est = eng.take_estimates();
        eng.finish().unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "gap advance took {:?}",
            started.elapsed()
        );
        est.extend(eng.take_estimates());
        // The pre-gap window flushed with the old host; the final window
        // contains only the post-gap event.
        let last_end = est.iter().map(|e| e.window_end_nanos).max().unwrap();
        for e in est.iter().filter(|e| e.window_end_nanos == last_end) {
            assert_eq!(e.group[0].1, "10.0.0.9");
        }
        assert!(est.iter().any(|e| e.group[0].1 == "10.0.0.1"));
    }

    #[test]
    fn far_future_gap_emits_every_decaying_trailing_window() {
        let mut engine = engine_for(
            "name: c\nwindow: {size: 60s, slide: 10s}\ngroupBy: [protocol]\nmeasure: {type: count}\n",
        );
        for second in (0..=50).step_by(10) {
            engine
                .process(&event(second, "10.0.0.1", "10.0.0.2", 80, 100))
                .unwrap();
        }
        let _ = engine.take_estimates();

        engine
            .process(&event(1_000, "10.0.0.1", "10.0.0.2", 80, 100))
            .unwrap();
        let trailing = engine.take_estimates();
        let observed = trailing
            .iter()
            .map(|estimate| {
                (
                    estimate.window_end_nanos / 1_000_000_000,
                    estimate.estimate as u64,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            vec![(60, 6), (70, 5), (80, 4), (90, 3), (100, 2), (110, 1)]
        );
    }

    #[test]
    fn out_of_order_event_after_gap_fast_forward_is_not_dropped() {
        // After a fast-forward, an event slightly older than the latest one
        // but still inside the window must land in a (rebuilt) trailing
        // bucket, exactly as the slow path would have handled it.
        let mut eng = engine_for(
            "name: gap2\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 10}\n",
        );
        eng.process(&event(1, "10.0.0.1", "10.0.0.2", 80, 100))
            .unwrap();
        let t = 1_000_000u64; // seconds; far beyond the window
        eng.process(&event(t, "10.0.0.7", "10.0.0.2", 80, 700))
            .unwrap();
        let mut est = eng.take_estimates();
        // One slide earlier than t: out of order but within the 60s window.
        eng.process(&event(t - 10, "10.0.0.8", "10.0.0.2", 80, 800))
            .unwrap();
        eng.finish().unwrap();
        assert_eq!(eng.late_events(), 0, "in-window event counted as late");
        est.extend(eng.take_estimates());
        let last_end = est.iter().map(|e| e.window_end_nanos).max().unwrap();
        let final_hosts: Vec<&str> = est
            .iter()
            .filter(|e| e.window_end_nanos == last_end)
            .map(|e| e.group[0].1.as_str())
            .collect();
        assert!(final_hosts.contains(&"10.0.0.7"), "{final_hosts:?}");
        assert!(final_hosts.contains(&"10.0.0.8"), "{final_hosts:?}");
    }

    #[test]
    fn completed_window_buffer_is_bounded_and_retryable() {
        let yaml = "name: bounded_output\nwindow: {size: 30s, slide: 10s}\n\
                    groupBy: [protocol]\nmeasure: {type: count}\n";
        let query = parse_query_yaml(yaml).unwrap();
        let hash = HashSpec::new(7);
        let planned = plan(query, &hash).unwrap();
        assert_eq!(planned.physical.pending_window_capacity, 3);
        let memory_limit = planned.physical.estimated_memory_bytes;
        let mut engine = QueryEngine::new(vec![planned], hash).unwrap();

        for second in [0, 10, 20, 30] {
            engine
                .process(&event(second, "10.0.0.1", "10.0.0.2", 80, 100))
                .unwrap();
        }
        assert_eq!(engine.pending_window_count(), 3);
        assert!(engine.pending_windows_full());
        assert!(engine.sketch_memory_bytes() as u64 <= memory_limit);

        let before = engine.events_processed();
        let blocked = engine
            .process(&event(40, "10.0.0.1", "10.0.0.2", 80, 100))
            .unwrap_err();
        assert!(matches!(blocked, SketchError::Backpressure(_)), "{blocked}");
        assert_eq!(engine.events_processed(), before);
        assert_eq!(engine.pending_window_count(), 3);

        assert_eq!(engine.take_estimates().len(), 3);
        engine
            .process(&event(40, "10.0.0.1", "10.0.0.2", 80, 100))
            .unwrap();
        assert_eq!(engine.events_processed(), before + 1);
    }

    /// Build a planned query and an engine on `seed` for the WindowState
    /// tests, which need the plan alongside the engine.
    fn plan_and_engine(yaml: &str, seed: u64) -> (Plan, QueryEngine) {
        let q = parse_query_yaml(yaml).unwrap();
        let p = plan(q, &HashSpec::new(seed)).unwrap();
        let eng = QueryEngine::new(vec![p.clone()], HashSpec::new(seed)).unwrap();
        (p, eng)
    }

    fn components_of(engine: &QueryEngine) -> Vec<(String, Vec<u8>)> {
        engine
            .export_snapshots()
            .unwrap()
            .into_iter()
            .map(|s| (s.component, s.bytes))
            .collect()
    }

    const SCANNER_YAML: &str = "name: scan\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
         measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n";

    #[test]
    fn window_state_merges_distinct_counts_across_engines() {
        // Two "nodes" observe the same source scanning disjoint /16s; the
        // merged fan-out must approximate the union, which no single node
        // ever saw.
        let (plan, mut node_a) = plan_and_engine(SCANNER_YAML, 7);
        let (_, mut node_b) = plan_and_engine(SCANNER_YAML, 7);
        for i in 0..1_000u32 {
            let (a, b) = (i / 256, i % 256);
            node_a
                .process(&event(5, "10.0.1.50", &format!("10.1.{a}.{b}"), 22, 60))
                .unwrap();
            node_b
                .process(&event(5, "10.0.1.50", &format!("10.2.{a}.{b}"), 22, 60))
                .unwrap();
        }

        let hash = HashSpec::new(7);
        let mut merged =
            WindowState::from_components(&plan, &hash, &components_of(&node_a)).unwrap();
        let other = WindowState::from_components(&plan, &hash, &components_of(&node_b)).unwrap();
        merged.merge_from(&other).unwrap();

        let est = merged.estimates(&plan);
        assert_eq!(est.len(), 1);
        assert_eq!(est[0].group[0].1, "10.0.1.50");
        assert!(
            (est[0].estimate - 2_000.0).abs() < 200.0,
            "merged fan-out {} should approximate the 2000-destination union",
            est[0].estimate
        );
    }

    #[test]
    fn window_state_rejects_mismatched_hash_seed() {
        let (plan, mut foreign) = plan_and_engine(SCANNER_YAML, 9);
        foreign
            .process(&event(5, "10.0.1.50", "10.9.9.9", 22, 60))
            .unwrap();
        // Snapshots hashed with seed 9 must not merge into a seed-7 plan.
        let err = WindowState::from_components(&plan, &HashSpec::new(7), &components_of(&foreign))
            .unwrap_err();
        assert!(matches!(err, SketchError::IncompatibleMerge(_)), "{err}");
    }

    #[test]
    fn window_state_rejects_mismatched_windows() {
        let (plan, mut early) = plan_and_engine(SCANNER_YAML, 7);
        let (_, mut late) = plan_and_engine(SCANNER_YAML, 7);
        early
            .process(&event(5, "10.0.1.50", "10.9.9.9", 22, 60))
            .unwrap();
        late.process(&event(500, "10.0.1.50", "10.9.9.9", 22, 60))
            .unwrap();

        let hash = HashSpec::new(7);
        let mut a = WindowState::from_components(&plan, &hash, &components_of(&early)).unwrap();
        let b = WindowState::from_components(&plan, &hash, &components_of(&late)).unwrap();
        let err = a.merge_from(&b).unwrap_err();
        assert!(matches!(err, SketchError::IncompatibleMerge(_)), "{err}");
    }

    #[test]
    fn window_state_rejects_wrong_components() {
        // Hand a heavy-hitters plan the scanner query's hllmap snapshot.
        let (hh_plan, _) = plan_and_engine(
            "name: tt\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 5}\n",
            7,
        );
        let (_, mut scanner) = plan_and_engine(SCANNER_YAML, 7);
        scanner
            .process(&event(5, "10.0.1.50", "10.9.9.9", 22, 60))
            .unwrap();
        let err =
            WindowState::from_components(&hh_plan, &HashSpec::new(7), &components_of(&scanner))
                .unwrap_err();
        assert!(err.to_string().contains("unexpected component"), "{err}");
    }

    #[test]
    fn window_state_round_trips_counter_composite() {
        // sum(bytes) uses the two-component Counter state (count-min +
        // key tracker); reconstruction must preserve exact totals.
        let yaml =
            "name: pb\nwindow: {size: 60s}\ngroupBy: [protocol]\nmeasure: {type: sum, value: bytes}\n";
        let (plan, mut eng) = plan_and_engine(yaml, 7);
        for _ in 0..500u32 {
            eng.process(&event(5, "10.0.0.1", "10.0.0.2", 443, 1_000))
                .unwrap();
        }
        let state =
            WindowState::from_components(&plan, &HashSpec::new(7), &components_of(&eng)).unwrap();
        let est = state.estimates(&plan);
        assert_eq!(est.len(), 1);
        assert_eq!(est[0].estimate, 500_000.0);
    }

    #[test]
    fn sliding_window_expires_old_buckets() {
        let mut eng = engine_for(
            "name: w\nwindow: {size: 20s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 10}\n",
        );
        // Burst in [0s, 10s), then silence until [100s, 110s).
        for _ in 0..10 {
            eng.process(&event(1, "10.0.0.1", "10.0.0.2", 80, 1_000))
                .unwrap();
        }
        eng.process(&event(105, "10.0.0.9", "10.0.0.2", 80, 1))
            .unwrap();
        let mut est = eng.take_estimates();
        eng.finish().unwrap();
        est.extend(eng.take_estimates());
        // The final window (ending 110s) must not contain the old burst.
        let last_end = est.iter().map(|e| e.window_end_nanos).max().unwrap();
        for e in est.iter().filter(|e| e.window_end_nanos == last_end) {
            assert_ne!(
                e.group[0].1, "10.0.0.1",
                "expired traffic leaked into final window"
            );
        }
    }
}
