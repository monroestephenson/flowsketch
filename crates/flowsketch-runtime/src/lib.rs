//! The FlowSketch runtime: takes planned queries, maintains per-query
//! window buckets (a sliding window is a ring of tumbling buckets), updates
//! sketches from flow events, and emits `SketchEstimate`s when windows
//! close.

use std::collections::VecDeque;

use flowsketch_algos::{CountMinSketch, HllMap, HyperLogLog, SpaceSaving};
use flowsketch_core::field::group_key;
use flowsketch_core::hash::HashSpec;
use flowsketch_core::{FlowEvent, Sketch, SketchError, SketchEstimate};
use flowsketch_ir::logical::Measure;
use flowsketch_ir::physical::PhysicalSketch;
use flowsketch_planner::{ErrorKind, Plan};

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
            PhysicalSketch::Composite { stages } => match stages.as_slice() {
                [PhysicalSketch::SpaceSaving { capacity }, PhysicalSketch::CountMin {
                    width,
                    depth,
                    conservative_update,
                }] => Ok(QueryState::Counter {
                    cm: CountMinSketch::new(*width, *depth, *conservative_update, *hash)?,
                    keys: SpaceSaving::new(*capacity, *hash)?,
                }),
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
        }
    }

    fn update_count(&self) -> u64 {
        match self {
            QueryState::HeavyHitters { ss } => ss.update_count(),
            QueryState::Counter { cm, .. } => cm.update_count(),
            QueryState::DistinctPerKey { map } => map.update_count(),
            QueryState::DistinctGlobal { hll } => hll.update_count(),
        }
    }
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
}

impl RunningQuery {
    fn new(plan: Plan, hash: HashSpec) -> Result<Self, SketchError> {
        let (distinct_field, value_field) = match &plan.query.measure {
            Measure::Count => (None, None),
            Measure::Sum { value } => (None, Some(*value)),
            Measure::HeavyHitters { value, .. } => (None, Some(*value)),
            Measure::DistinctCount { field } => (Some(*field), None),
            Measure::Entropy { field } | Measure::Quantile { field, .. } => (Some(*field), None),
        };
        Ok(RunningQuery {
            group_fields: plan.query.group_by.clone(),
            distinct_field,
            value_field,
            hash,
            buckets: VecDeque::new(),
            emitted: Vec::new(),
            late_events: 0,
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
        let Some(bucket) = self
            .buckets
            .iter_mut()
            .find(|b| b.start_nanos == bucket_start)
        else {
            // Late event older than the earliest open bucket.
            self.late_events += 1;
            return Ok(());
        };

        let key = group_key(&self.group_fields, event);
        let weight = match self.value_field {
            Some(f) => f.extract_value(event),
            None => 1,
        };
        let distinct_item = self
            .distinct_field
            .map(|f| f.extract(event).into_bytes())
            .unwrap_or_default();
        bucket.state.update(&key, weight, &distinct_item);
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
        let q = &self.plan.query;
        let p = &self.plan.physical;
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
        };

        if !q.alert.is_empty() {
            out.retain(|e| q.alert.fires(e.estimate));
        }
        out
    }
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
