//! The FlowSketch query planner.
//!
//! Translates operator intent (a `LogicalQuery`) into a bounded-memory
//! `PhysicalPlan`: which sketch to run, with what parameters, how much
//! memory it will hold across window buckets, what the error contract is,
//! and whether the plan should be rejected outright.
//!
//! Decision table (v0):
//!
//! | Query                              | Plan                              |
//! |------------------------------------|-----------------------------------|
//! | `count by G` / `sum(v) by G`       | CountMin + SpaceSaving key tracker|
//! | `heavy_hitters(v) by G`            | SpaceSaving                       |
//! | `distinct_count(f) by G`           | HLLMap                            |
//! | `distinct_count(f)` (no group)     | HyperLogLog                       |
//! | `entropy`, `quantile`              | rejected (not in v0)              |

use thiserror::Error;

use flowsketch_core::hash::HashSpec;
use flowsketch_ir::logical::{humanize_nanos, LogicalQuery, Measure};
use flowsketch_ir::physical::PhysicalSketch;

/// Assumed average encoded group-key size for memory estimation.
const AVG_KEY_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("query {name:?} rejected: {reason}")]
    Rejected { name: String, reason: String },
}

/// How the reported error bound should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Estimate may exceed truth by at most epsilon * total weight.
    AdditiveOverestimate,
    /// Estimate is within a relative factor of truth (standard error).
    Relative,
    /// Counts of tracked keys are upper bounds with per-key error terms.
    CandidateUpperBound,
    /// The returned value's true rank is within epsilon*n of the request.
    RankError,
    /// A composed estimator without a formal single-number bound.
    Heuristic,
}

impl ErrorKind {
    pub fn name(self) -> &'static str {
        match self {
            ErrorKind::AdditiveOverestimate => "additive-overestimate",
            ErrorKind::Relative => "relative",
            ErrorKind::CandidateUpperBound => "candidate-upper-bound",
            ErrorKind::RankError => "rank-error",
            ErrorKind::Heuristic => "heuristic",
        }
    }
}

/// The planner's output for one query.
#[derive(Debug, Clone)]
pub struct PhysicalPlan {
    pub sketch: PhysicalSketch,
    /// Number of tumbling buckets realizing the (sliding) window.
    pub window_buckets: usize,
    /// Maximum completed window states retained until the consumer drains.
    /// Reaching this limit returns explicit runtime backpressure.
    pub pending_window_capacity: usize,
    /// Estimated resident memory across open buckets, bounded completed
    /// windows, and one transient merge scratch copy.
    pub estimated_memory_bytes: u64,
    /// Upper bound on exported series per flush.
    pub export_series_upper_bound: usize,
    pub error_kind: ErrorKind,
    /// Human-readable error contract for explain output and labels.
    pub error_contract: String,
    pub warnings: Vec<String>,
}

/// A planned query: the validated logical query plus its physical plan.
#[derive(Debug, Clone)]
pub struct Plan {
    pub query: LogicalQuery,
    pub physical: PhysicalPlan,
}

/// Compile a logical query into a physical plan, or reject it.
pub fn plan(query: LogicalQuery, hash: &HashSpec) -> Result<Plan, PlanError> {
    let _ = hash; // reserved: future planners may pick per-query seeds
    let mut warnings = Vec::new();
    let buckets = query.window.bucket_count();
    let pending_window_capacity = buckets;
    let resident_sketches = buckets as u64 + pending_window_capacity as u64 + 1;
    let max_series = query.export.max_series;

    let reject = |reason: String| PlanError::Rejected {
        name: query.name.clone(),
        reason,
    };

    if !query.group_by.is_empty() && query.alert.lt.is_some() {
        return Err(reject(
            "alertIf.lt is not sound for grouped queries: bounded top-k/key-retention plans \
             cannot enumerate every low-valued or absent group; use alertIf.gt, remove groupBy, \
             or alert on an explicitly enumerated downstream series"
                .into(),
        ));
    }

    let (sketch, error_kind, error_contract, series_bound) = match &query.measure {
        Measure::Count | Measure::Sum { .. } => {
            let (width, depth) =
                count_min_dimensions(query.error.epsilon, query.error.delta).map_err(reject)?;
            // Track key identities alongside the counter sketch so results
            // can be enumerated; retention capacity scales with the export
            // cap so the guardrail, not the sketch, bounds series.
            let tracker_capacity = (max_series * 4).clamp(256, 65_536);
            let sketch = PhysicalSketch::Composite {
                stages: vec![
                    PhysicalSketch::SpaceSaving {
                        capacity: tracker_capacity,
                    },
                    PhysicalSketch::CountMin {
                        width,
                        depth,
                        conservative_update: true,
                    },
                ],
            };
            let contract = format!(
                "estimates never underestimate; overestimate exceeds {} * N with probability <= {}; \
                 only the top {} groups by weight are enumerated",
                query.error.epsilon, query.error.delta, tracker_capacity
            );
            (
                sketch,
                ErrorKind::AdditiveOverestimate,
                contract,
                max_series,
            )
        }

        Measure::HeavyHitters { limit, .. } => {
            if *limit > max_series {
                warnings.push(format!(
                    "heavy_hitters limit {} exceeds export.maxSeries {}; export cap wins",
                    limit, max_series
                ));
            }
            // Capacity from the accuracy target: any key with share > epsilon
            // of total weight is guaranteed tracked when capacity >= 1/epsilon.
            let capacity = ((1.0 / query.error.epsilon).ceil() as usize)
                .max(limit * 4)
                .clamp(256, 1 << 20);
            let sketch = PhysicalSketch::SpaceSaving { capacity };
            let contract = format!(
                "tracked counts are upper bounds, overestimating by at most N/{capacity}; \
                 every group with weight share > {} of total is guaranteed present",
                1.0 / capacity as f64
            );
            (
                sketch,
                ErrorKind::CandidateUpperBound,
                contract,
                (*limit).min(max_series),
            )
        }

        Measure::DistinctCount { .. } => {
            // Epsilon is a relative standard error here (the YAML layer
            // applies the cardinality-appropriate default). Honor it as
            // written; if it is tighter than the largest supported HLL can
            // deliver, plan at max precision and say so.
            let eps = query.error.epsilon;
            let precision = hll_precision_for_error(eps);
            let rel = 1.04 / ((1u64 << precision) as f64).sqrt();
            if rel > eps {
                warnings.push(format!(
                    "requested epsilon {} is tighter than the best supported HLL precision \
                     ({precision}) can deliver; plan achieves ~{:.3}% relative standard error",
                    eps,
                    rel * 100.0
                ));
            }

            if query.group_by.is_empty() {
                let sketch = PhysicalSketch::HyperLogLog { precision };
                let contract = format!(
                    "relative standard error ~ {:.2}% (precision {precision})",
                    rel * 100.0
                );
                (sketch, ErrorKind::Relative, contract, 1)
            } else {
                let preferred_max_keys = (max_series * 4).clamp(1_024, 65_536);
                // HLLMap is often the largest state in the runtime. Size its
                // bounded key-retention map against the query's declared
                // resident budget, including open buckets, completed-window
                // output, and merge scratch. This keeps the useful default
                // query executable without pretending pending output is free.
                let per_key_bytes = (1u64 << precision)
                    + 2 * AVG_KEY_BYTES as u64
                    + 48 // HashMap entry/allocation allowance
                    + 32; // deterministic eviction-heap entry
                let per_sketch_budget = query.max_memory_bytes / resident_sketches;
                let budgeted_max_keys = per_sketch_budget
                    .saturating_sub(64)
                    .checked_div(per_key_bytes)
                    .unwrap_or(0) as usize;
                let minimum_max_keys = max_series.min(preferred_max_keys);
                if budgeted_max_keys < minimum_max_keys {
                    return Err(reject(format!(
                        "resources.maxMemory can retain only {budgeted_max_keys} grouped HLL \
                         keys across {buckets} window buckets and bounded output, below the \
                         configured export.maxSeries requirement of {minimum_max_keys}"
                    )));
                }
                let max_keys = preferred_max_keys.min(budgeted_max_keys);
                if max_keys < preferred_max_keys {
                    warnings.push(format!(
                        "HLLMap key retention reduced from preferred {preferred_max_keys} to \
                         {max_keys} groups to stay within resources.maxMemory; raise the budget \
                         for more low-cardinality retention headroom"
                    ));
                }
                let sketch = PhysicalSketch::HllMap {
                    max_keys,
                    precision,
                };
                let contract = format!(
                    "per-group relative standard error ~ {:.2}% (precision {precision}); \
                     key retention bounded at {max_keys} groups — low-cardinality groups \
                     may be evicted under pressure (evictions are exported as a health metric)",
                    rel * 100.0
                );
                (
                    sketch,
                    ErrorKind::Relative,
                    contract,
                    max_series.min(max_keys),
                )
            }
        }

        Measure::Entropy { .. } => {
            if !query.group_by.is_empty() {
                return Err(reject(
                    "grouped entropy is not supported yet (it needs a bounded keyed \
                     distribution sketch); drop groupBy to measure the field's global \
                     entropy per window"
                        .into(),
                ));
            }
            // Composite estimator: SpaceSaving captures the head of the
            // distribution exactly-ish; HLL sizes the tail's support so the
            // remaining mass can be treated as uniform over it.
            let capacity = ((1.0 / query.error.epsilon).ceil() as usize).clamp(256, 1 << 16);
            let precision = hll_precision_for_error(0.0163);
            let sketch = PhysicalSketch::Composite {
                stages: vec![
                    PhysicalSketch::SpaceSaving { capacity },
                    PhysicalSketch::HyperLogLog { precision },
                ],
            };
            let contract = format!(
                "heuristic: exact head entropy over the top {capacity} values plus a \
                 uniform-tail correction sized by an HLL distinct count (precision \
                 {precision}); no formal single-number bound — validate against \
                 `flowsketch bench` for your traffic shape"
            );
            (sketch, ErrorKind::Heuristic, contract, 1)
        }

        Measure::Quantile { q, .. } => {
            if !query.group_by.is_empty() {
                return Err(reject(
                    "grouped quantile is not supported yet (it needs a bounded keyed \
                     KLL map); drop groupBy to measure the field's global distribution \
                     per window"
                        .into(),
                ));
            }
            if !(0.0..=1.0).contains(q) {
                return Err(reject(format!("quantile q must be in [0, 1], got {q}")));
            }
            // Epsilon is a normalized rank error here.
            let eps = query.error.epsilon;
            let k = kll_k_for_error(eps);
            let achieved = 2.3 / k as f64;
            if achieved > eps {
                warnings.push(format!(
                    "requested rank error {eps} is tighter than the largest supported \
                     KLL (k={k}) delivers; plan achieves ~{achieved:.5}"
                ));
            }
            let sketch = PhysicalSketch::Kll { k };
            let contract = format!(
                "returned value's true rank is within ~{achieved:.4} * n of the requested \
                 quantile with high probability (KLL, k={k})"
            );
            (sketch, ErrorKind::RankError, contract, 1)
        }
    };

    // A large event-time gap can close one decaying window per open bucket
    // in a single operation. Retain exactly that many completed states so
    // the operation is lossless, then require the consumer to drain before
    // accepting more output. Account for open buckets, pending states, and
    // one transient scratch copy used while merging a window.
    let per_bucket = sketch.estimated_memory_bytes(AVG_KEY_BYTES);
    let estimated_memory_bytes = per_bucket * resident_sketches;
    if estimated_memory_bytes > query.max_memory_bytes {
        return Err(reject(format!(
            "plan needs ~{} across {} window buckets but resources.maxMemory is {}; \
             loosen error.epsilon, shrink the window, or raise the budget",
            format_bytes(estimated_memory_bytes),
            buckets,
            format_bytes(query.max_memory_bytes),
        )));
    }

    if query.group_by.iter().any(|f| {
        matches!(
            f,
            flowsketch_core::Field::SrcIp | flowsketch_core::Field::DstIp
        )
    }) {
        warnings.push(
            "raw IP labels can create high series cardinality in Prometheus; \
             export.maxSeries caps this query's output"
                .to_string(),
        );
    }

    Ok(Plan {
        query,
        physical: PhysicalPlan {
            sketch,
            window_buckets: buckets,
            pending_window_capacity,
            estimated_memory_bytes,
            export_series_upper_bound: series_bound,
            error_kind,
            error_contract,
            warnings,
        },
    })
}

fn count_min_dimensions(epsilon: f64, delta: f64) -> Result<(usize, usize), String> {
    const HASH_FAILURE_FLOOR: f64 = 1.0 / 18_446_744_073_709_551_616.0;
    if !(epsilon > 0.0 && epsilon < 1.0 && delta > 0.0 && delta < 1.0) {
        return Err("epsilon and delta must be in (0, 1)".into());
    }
    if delta <= HASH_FAILURE_FLOOR {
        return Err(format!(
            "delta must exceed the fsk1 hash confidence floor {HASH_FAILURE_FLOOR}"
        ));
    }
    let width = (std::f64::consts::E / epsilon).ceil() as usize;
    let depth = (1.0 / (delta - HASH_FAILURE_FLOOR)).ln().ceil().max(1.0) as usize;
    Ok((width, depth))
}

fn hll_precision_for_error(epsilon: f64) -> u8 {
    let m = (1.04 / epsilon).powi(2);
    (m.log2().ceil() as i64).clamp(4, 18) as u8
}

/// Smallest KLL `k` whose normalized rank error (~2.3/k) is <= `epsilon`.
/// Mirrors `flowsketch_algos::KllSketch::k_for_error`.
fn kll_k_for_error(epsilon: f64) -> usize {
    ((2.3 / epsilon).ceil() as usize).clamp(8, 1 << 16)
}

/// Render a byte count for humans.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Operator-facing explain output for a plan.
pub fn explain(plan: &Plan) -> String {
    let q = &plan.query;
    let p = &plan.physical;
    let mut out = String::new();

    out.push_str("Logical query:\n");
    out.push_str(&format!("  name:     {}\n", q.name));
    if !q.group_by.is_empty() {
        let fields: Vec<String> = q.group_by.iter().map(|f| f.name().to_string()).collect();
        out.push_str(&format!("  group by: {}\n", fields.join(", ")));
    }
    out.push_str(&format!("  measure:  {}", q.measure.name()));
    match &q.measure {
        Measure::Sum { value } => out.push_str(&format!("({value})")),
        Measure::HeavyHitters { value, limit } => {
            out.push_str(&format!("({value}, limit={limit})"))
        }
        Measure::DistinctCount { field }
        | Measure::Entropy { field }
        | Measure::Quantile { field, .. } => out.push_str(&format!("({field})")),
        Measure::Count => {}
    }
    out.push('\n');
    out.push_str(&format!(
        "  window:   {} slide {}\n",
        humanize_nanos(q.window.size_nanos),
        humanize_nanos(q.window.slide_nanos)
    ));
    if !q.filter.is_empty() {
        out.push_str("  filter:   ");
        let mut parts = Vec::new();
        if let Some(p) = q.filter.protocol {
            parts.push(format!(
                "protocol={}",
                flowsketch_core::event::protocol::name(p)
            ));
        }
        if !q.filter.dst_ports.is_empty() {
            parts.push(format!("dst.port in {:?}", q.filter.dst_ports));
        }
        if !q.filter.src_ports.is_empty() {
            parts.push(format!("src.port in {:?}", q.filter.src_ports));
        }
        if !q.filter.interfaces.is_empty() {
            parts.push(format!("interface in {:?}", q.filter.interfaces));
        }
        out.push_str(&parts.join(" and "));
        out.push('\n');
    }
    if !q.alert.is_empty() {
        let mut parts = Vec::new();
        if let Some(t) = q.alert.gt {
            parts.push(format!("estimate > {t}"));
        }
        if let Some(t) = q.alert.lt {
            parts.push(format!("estimate < {t}"));
        }
        out.push_str(&format!("  alert if: {}\n", parts.join(" or ")));
    }

    out.push_str("\nPhysical plan:\n");
    out.push_str(&format!("  {}\n", p.sketch.describe()));
    out.push_str(&format!(
        "  {} window bucket(s) of {}\n",
        p.window_buckets,
        humanize_nanos(q.window.slide_nanos)
    ));
    out.push_str(&format!(
        "  estimated memory: {} (budget {})\n",
        format_bytes(p.estimated_memory_bytes),
        format_bytes(q.max_memory_bytes)
    ));
    out.push_str(&format!(
        "  export series upper bound: {}\n",
        p.export_series_upper_bound
    ));
    out.push_str(&format!(
        "  error model: {} — {}\n",
        p.error_kind.name(),
        p.error_contract
    ));

    if !p.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for w in &p.warnings {
            out.push_str(&format!("  - {w}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowsketch_ir::parse_query_yaml;

    fn plan_yaml(yaml: &str) -> Result<Plan, PlanError> {
        plan(parse_query_yaml(yaml).unwrap(), &HashSpec::new(0))
    }

    #[test]
    fn heavy_hitters_plans_spacesaving() {
        let p = plan_yaml(
            "name: tt\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip, dst.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 100}\n",
        )
        .unwrap();
        assert!(matches!(
            p.physical.sketch,
            PhysicalSketch::SpaceSaving { .. }
        ));
        assert_eq!(p.physical.window_buckets, 6);
        assert_eq!(p.physical.export_series_upper_bound, 100);
    }

    #[test]
    fn grouped_distinct_count_plans_hllmap() {
        let p = plan_yaml(
            "name: sc\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n",
        )
        .unwrap();
        assert!(matches!(p.physical.sketch, PhysicalSketch::HllMap { .. }));
        assert_eq!(p.physical.error_kind, ErrorKind::Relative);
    }

    #[test]
    fn ungrouped_distinct_count_plans_single_hll() {
        let p = plan_yaml(
            "name: d\nwindow: {size: 60s}\nmeasure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n",
        )
        .unwrap();
        assert!(matches!(
            p.physical.sketch,
            PhysicalSketch::HyperLogLog { .. }
        ));
        assert_eq!(p.physical.export_series_upper_bound, 1);
    }

    #[test]
    fn explicit_tight_distinct_epsilon_is_honored() {
        // Regression: an explicit epsilon used to be silently replaced with
        // the default when it was <= 0.001.
        let p = plan_yaml(
            "name: d\nwindow: {size: 60s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.004}}\n\
             resources: {maxMemory: 2GiB}\n",
        )
        .unwrap();
        match p.physical.sketch {
            PhysicalSketch::HllMap { precision, .. } => {
                // 1.04/sqrt(2^17) ~ 0.29% <= 0.4% < 1.04/sqrt(2^16)
                assert_eq!(precision, 17, "explicit epsilon not honored");
            }
            other => panic!("expected hllmap, got {other:?}"),
        }
        assert!(p.physical.warnings.iter().all(|w| !w.contains("tighter")));
    }

    #[test]
    fn unachievable_distinct_epsilon_plans_max_precision_with_warning() {
        let p = plan_yaml(
            "name: d\nwindow: {size: 60s}\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.0005}}\n\
             resources: {maxMemory: 2GiB}\n",
        )
        .unwrap();
        match p.physical.sketch {
            PhysicalSketch::HyperLogLog { precision } => assert_eq!(precision, 18),
            other => panic!("expected hll, got {other:?}"),
        }
        assert!(
            p.physical.warnings.iter().any(|w| w.contains("tighter")),
            "missing achievability warning: {:?}",
            p.physical.warnings
        );
    }

    #[test]
    fn sum_plans_composite_countmin() {
        let p = plan_yaml(
            "name: s\nwindow: {size: 60s}\ngroupBy: [protocol]\nmeasure: {type: sum, value: bytes}\n",
        )
        .unwrap();
        match &p.physical.sketch {
            PhysicalSketch::Composite { stages } => {
                assert!(matches!(stages[0], PhysicalSketch::SpaceSaving { .. }));
                assert!(matches!(stages[1], PhysicalSketch::CountMin { .. }));
            }
            other => panic!("expected composite, got {other:?}"),
        }
    }

    #[test]
    fn over_budget_plan_is_rejected() {
        let err = plan_yaml(
            "name: b\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.005}}\n\
             resources: {maxMemory: 1MiB}\n",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("maxMemory") || msg.contains("budget"), "{msg}");
    }

    #[test]
    fn grouped_entropy_and_quantile_are_rejected_with_direction() {
        let err = plan_yaml(
            "name: e\nwindow: {size: 30s}\ngroupBy: [dst.ip]\nmeasure: {type: entropy, field: src.ip}\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("grouped entropy"));

        let err = plan_yaml(
            "name: q\nwindow: {size: 30s}\ngroupBy: [dst.ip]\nmeasure: {type: quantile, field: bytes, q: 0.99}\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("grouped quantile"));
    }

    #[test]
    fn grouped_low_threshold_alert_is_rejected_as_unenumerable() {
        let err = plan_yaml(
            "name: low\nwindow: {size: 30s}\ngroupBy: [src.ip]\n\
             measure: {type: count}\nalertIf: {lt: 5}\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("alertIf.lt"), "{err}");

        plan_yaml(
            "name: global_low\nwindow: {size: 30s}\nmeasure: {type: count}\n\
             alertIf: {lt: 5}\n",
        )
        .unwrap();
    }

    #[test]
    fn ungrouped_quantile_plans_kll() {
        let p = plan_yaml(
            "name: q\nwindow: {size: 30s}\nmeasure: {type: quantile, field: bytes, q: 0.99, error: {epsilon: 0.01}}\n",
        )
        .unwrap();
        match p.physical.sketch {
            PhysicalSketch::Kll { k } => assert_eq!(k, 230),
            other => panic!("expected kll, got {other:?}"),
        }
        assert_eq!(p.physical.error_kind, ErrorKind::RankError);
        assert_eq!(p.physical.export_series_upper_bound, 1);
    }

    #[test]
    fn ungrouped_entropy_plans_head_tail_composite() {
        let p =
            plan_yaml("name: e\nwindow: {size: 30s}\nmeasure: {type: entropy, field: src.ip}\n")
                .unwrap();
        match &p.physical.sketch {
            PhysicalSketch::Composite { stages } => {
                assert!(matches!(stages[0], PhysicalSketch::SpaceSaving { .. }));
                assert!(matches!(stages[1], PhysicalSketch::HyperLogLog { .. }));
            }
            other => panic!("expected composite, got {other:?}"),
        }
        assert_eq!(p.physical.error_kind, ErrorKind::Heuristic);
    }

    #[test]
    fn explain_mentions_algorithm_memory_and_error() {
        let p = plan_yaml(
            "name: tt\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip, dst.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 50}\n",
        )
        .unwrap();
        let text = explain(&p);
        assert!(text.contains("SpaceSaving"));
        assert!(text.contains("estimated memory"));
        assert!(text.contains("error model"));
        assert!(text.contains("60s slide 10s"));
    }
}
