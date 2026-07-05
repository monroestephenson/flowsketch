//! The FlowSketch runtime: takes planned queries, maintains per-query
//! window buckets (a sliding window is a ring of tumbling buckets), updates
//! sketches from flow events, and emits `SketchEstimate`s when windows
//! close.

use std::collections::{BTreeMap, VecDeque};

use flowsketch_algos::{CountMinSketch, HllMap, HyperLogLog, KllSketch, SpaceSaving};
use flowsketch_core::field::{field_value_into, group_key_into};
use flowsketch_core::hash::HashSpec;
use flowsketch_core::snapshot::read_snapshot;
use flowsketch_core::{FlowEvent, Sketch, SketchError, SketchEstimate};
use flowsketch_ir::logical::Measure;
use flowsketch_ir::physical::PhysicalSketch;
use flowsketch_planner::{ErrorKind, Plan};

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
    group_fields: Vec<flowsketch_core::Field>,
    distinct_field: Option<flowsketch_core::Field>,
    value_field: Option<flowsketch_core::Field>,
    hash: HashSpec,
    buckets: VecDeque<Bucket>,
    /// Estimates emitted at each window close.
    emitted: Vec<SketchEstimate>,
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
            emitted: Vec::new(),
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

    fn bucket_start_for(&self, ts: u64) -> u64 {
        ts - ts % self.slide_nanos()
    }

    fn new_bucket(&self, start_nanos: u64) -> Result<Bucket, SketchError> {
        Ok(Bucket {
            start_nanos,
            state: QueryState::build(&self.plan.physical.sketch, &self.hash)?,
        })
    }

    /// Advance time to `ts`, closing any windows that end at or before it.
    fn advance_to(&mut self, ts: u64) -> Result<(), SketchError> {
        let slide = self.slide_nanos();
        let target = self.bucket_start_for(ts);
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
            self.flush_window(back + slide)?;
            self.buckets.clear();
            // Rebuild the full (empty) trailing ring at the target time, not
            // just the target bucket, so slightly out-of-order events that
            // are still inside the new window land in a bucket instead of
            // being counted late — identical to what the slow path leaves.
            let ring = self.bucket_count() as u64;
            let first = target - slide * (ring - 1).min(target / slide);
            let mut start = first;
            while start <= target {
                self.buckets.push_back(self.new_bucket(start)?);
                start += slide;
            }
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
        self.advance_to(event.ts_nanos)?;
        let bucket_start = self.bucket_start_for(event.ts_nanos);
        group_key_into(&self.group_fields, event, &mut self.key_buf);
        let weight = match self.value_field {
            Some(f) => f.extract_value(event),
            None => 1,
        };
        self.distinct_buf.clear();
        if let Some(f) = self.distinct_field {
            field_value_into(f, event, &mut self.distinct_buf);
        }

        let Some(bucket) = self
            .buckets
            .iter_mut()
            .find(|b| b.start_nanos == bucket_start)
        else {
            // Late event older than the earliest open bucket.
            self.late_events += 1;
            return Ok(());
        };

        bucket
            .state
            .update(&self.key_buf, weight, &self.distinct_buf);
        Ok(())
    }

    /// Merge all open buckets and emit estimates for the window ending at
    /// `window_end`.
    fn flush_window(&mut self, window_end: u64) -> Result<(), SketchError> {
        if self.buckets.is_empty() {
            return Ok(());
        }
        let mut merged = self.buckets[0].state.clone();
        for b in self.buckets.iter().skip(1) {
            merged.merge_from(&b.state)?;
        }
        let window_start = self.buckets.front().unwrap().start_nanos;
        let estimates = self.emit(&merged, window_start, window_end);
        self.emitted.extend(estimates);
        Ok(())
    }

    /// Final flush for offline replay: close the trailing partial window.
    fn finish(&mut self) -> Result<(), SketchError> {
        if let Some(last) = self.buckets.back() {
            let window_end = last.start_nanos + self.slide_nanos();
            self.flush_window(window_end)?;
        }
        Ok(())
    }

    fn emit(&self, state: &QueryState, window_start: u64, window_end: u64) -> Vec<SketchEstimate> {
        emit_estimates(&self.plan, state, window_start, window_end)
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
        self.events_processed += 1;
        for q in &mut self.queries {
            q.process(event)?;
        }
        Ok(())
    }

    /// Close trailing windows (offline replay end-of-stream).
    pub fn finish(&mut self) -> Result<(), SketchError> {
        for q in &mut self.queries {
            q.finish()?;
        }
        Ok(())
    }

    /// Drain all estimates emitted so far, in emission order.
    pub fn take_estimates(&mut self) -> Vec<SketchEstimate> {
        let mut out = Vec::new();
        for q in &mut self.queries {
            out.append(&mut q.emitted);
        }
        out
    }

    pub fn events_processed(&self) -> u64 {
        self.events_processed
    }

    /// Total late (dropped) events across queries — a health signal.
    pub fn late_events(&self) -> u64 {
        self.queries.iter().map(|q| q.late_events).sum()
    }

    /// Current sketch memory across all queries and buckets.
    pub fn sketch_memory_bytes(&self) -> usize {
        self.queries
            .iter()
            .flat_map(|q| q.buckets.iter())
            .map(|b| b.state.memory_bytes())
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
        for q in &self.queries {
            if q.buckets.is_empty() {
                continue;
            }
            let mut merged = q.buckets[0].state.clone();
            for b in q.buckets.iter().skip(1) {
                merged.merge_from(&b.state)?;
            }
            let ws = q.buckets.front().unwrap().start_nanos;
            let we = q.buckets.back().unwrap().start_nanos + q.slide_nanos();
            for (component, bytes) in merged.to_snapshots(ws, we) {
                out.push(SnapshotExport {
                    query_name: q.plan.query.name.clone(),
                    component,
                    bytes,
                });
            }
        }
        Ok(out)
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
        eng.finish().unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "gap advance took {:?}",
            started.elapsed()
        );
        let est = eng.take_estimates();
        // The pre-gap window flushed with the old host; the final window
        // contains only the post-gap event.
        let last_end = est.iter().map(|e| e.window_end_nanos).max().unwrap();
        for e in est.iter().filter(|e| e.window_end_nanos == last_end) {
            assert_eq!(e.group[0].1, "10.0.0.9");
        }
        assert!(est.iter().any(|e| e.group[0].1 == "10.0.0.1"));
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
        // One slide earlier than t: out of order but within the 60s window.
        eng.process(&event(t - 10, "10.0.0.8", "10.0.0.2", 80, 800))
            .unwrap();
        eng.finish().unwrap();
        assert_eq!(eng.late_events(), 0, "in-window event counted as late");
        let est = eng.take_estimates();
        let last_end = est.iter().map(|e| e.window_end_nanos).max().unwrap();
        let final_hosts: Vec<&str> = est
            .iter()
            .filter(|e| e.window_end_nanos == last_end)
            .map(|e| e.group[0].1.as_str())
            .collect();
        assert!(final_hosts.contains(&"10.0.0.7"), "{final_hosts:?}");
        assert!(final_hosts.contains(&"10.0.0.8"), "{final_hosts:?}");
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
        eng.finish().unwrap();
        let est = eng.take_estimates();
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
