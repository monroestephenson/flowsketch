//! Accuracy integration tests: run the full engine on a synthetic stream
//! and compare every emitted estimate against exact ground truth computed
//! from the same events.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use flowsketch_core::hash::{HashSpec, SplitMixRng};
use flowsketch_core::FlowEvent;
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::plan;
use flowsketch_runtime::QueryEngine;

fn event(ts_nanos: u64, src: [u8; 4], dst: [u8; 4], bytes: u32) -> FlowEvent {
    FlowEvent {
        ts_nanos,
        src_ip: IpAddr::from(src),
        dst_ip: IpAddr::from(dst),
        src_port: 40_000,
        dst_port: 443,
        protocol: 6,
        bytes,
        ..FlowEvent::default()
    }
}

/// Zipf-ish traffic in one tumbling window; every heavy-hitter estimate
/// must respect its [lower, upper] contract against exact truth, and the
/// true top-10 must all be present (precision@10 = 1 for this skew).
#[test]
fn heavy_hitter_bounds_hold_against_exact_truth() {
    let q = parse_query_yaml(
        "name: hh\nwindow: {size: 60s}\ngroupBy: [src.ip, dst.ip]\n\
         measure: {type: heavy_hitters, value: bytes, limit: 50, error: {epsilon: 0.001}}\n",
    )
    .unwrap();
    let planned = plan(q, &HashSpec::new(3)).unwrap();
    let mut engine = QueryEngine::new(vec![planned], HashSpec::new(3)).unwrap();

    let mut rng = SplitMixRng::new(99);
    let mut exact: HashMap<(String, String), u64> = HashMap::new();
    for i in 0..200_000u64 {
        // Zipf-ish source popularity: key k chosen with weight ~ 1/(k+1).
        let r = rng.next_u64() % 1_000;
        let k = if r < 300 {
            0
        } else if r < 500 {
            1
        } else if r < 650 {
            2
        } else {
            3 + rng.next_u64() % 500
        } as u8;
        let src = [10, 0, (k / 250), k];
        let dst = [10, 1, 0, (k % 7)];
        let bytes = 100 + (rng.next_u64() % 1_400) as u32;
        let ts = 1 + i * 250_000; // all inside one 60s window
        engine.process(&event(ts, src, dst, bytes)).unwrap();

        let key = (IpAddr::from(src).to_string(), IpAddr::from(dst).to_string());
        *exact.entry(key).or_insert(0) += bytes as u64;
    }
    engine.finish().unwrap();
    let estimates = engine.take_estimates();
    assert!(!estimates.is_empty());

    for e in &estimates {
        let key = (e.group[0].1.clone(), e.group[1].1.clone());
        let truth = *exact.get(&key).expect("estimated group must exist") as f64;
        let upper = e.upper_bound.unwrap();
        let lower = e.lower_bound.unwrap();
        assert!(
            truth <= upper,
            "{key:?}: truth {truth} above upper bound {upper}"
        );
        assert!(
            lower <= truth,
            "{key:?}: guaranteed count {lower} above truth {truth}"
        );
    }

    // The truly heaviest 10 pairs must all be reported.
    let mut truth_sorted: Vec<(&(String, String), &u64)> = exact.iter().collect();
    truth_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let reported: HashSet<(String, String)> = estimates
        .iter()
        .map(|e| (e.group[0].1.clone(), e.group[1].1.clone()))
        .collect();
    for (key, _) in truth_sorted.iter().take(10) {
        assert!(reported.contains(*key), "missing true heavy hitter {key:?}");
    }
}

/// Per-source distinct destination counts must land within the HLL error
/// contract for high-fanout sources.
#[test]
fn distinct_count_tracks_exact_fanout() {
    let q = parse_query_yaml(
        "name: fanout\nwindow: {size: 60s}\ngroupBy: [src.ip]\n\
         measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.0163}}\n",
    )
    .unwrap();
    let planned = plan(q, &HashSpec::new(5)).unwrap();
    let mut engine = QueryEngine::new(vec![planned], HashSpec::new(5)).unwrap();

    let mut exact: HashMap<String, HashSet<String>> = HashMap::new();
    // Ten sources with fanout 100..1000; each destination visited twice.
    for round in 0..2 {
        let _ = round;
        for s in 0..10u32 {
            let fanout = (s + 1) * 100;
            for d in 0..fanout {
                let src = [10, 0, 0, s as u8];
                let dst = [10, 2, (d / 256) as u8, (d % 256) as u8];
                let ts = 1 + (s as u64 * 2_000 + d as u64) * 1_000;
                engine.process(&event(ts, src, dst, 60)).unwrap();
                exact
                    .entry(IpAddr::from(src).to_string())
                    .or_default()
                    .insert(IpAddr::from(dst).to_string());
            }
        }
    }
    engine.finish().unwrap();
    let estimates = engine.take_estimates();
    assert_eq!(estimates.len(), 10);

    for e in &estimates {
        let truth = exact[&e.group[0].1].len() as f64;
        let rel = (e.estimate - truth).abs() / truth;
        // precision 12 => ~1.6% std error; assert within 5 sigma.
        assert!(
            rel < 0.082,
            "{}: estimate {} vs truth {} (rel {rel})",
            e.group[0].1,
            e.estimate,
            truth
        );
        assert!(e.lower_bound.unwrap() <= truth * 1.02);
        assert!(e.upper_bound.unwrap() >= truth * 0.98);
    }
}

/// count/sum through the Count-Min path must never underestimate and must
/// respect the additive-overestimate contract.
#[test]
fn counter_estimates_never_underestimate() {
    let q = parse_query_yaml(
        "name: cnt\nwindow: {size: 60s}\ngroupBy: [dst.port]\n\
         measure: {type: count, error: {epsilon: 0.001}}\n",
    )
    .unwrap();
    let planned = plan(q, &HashSpec::new(11)).unwrap();
    let mut engine = QueryEngine::new(vec![planned], HashSpec::new(11)).unwrap();

    let mut rng = SplitMixRng::new(4);
    let mut exact: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;
    for i in 0..100_000u64 {
        let port = (rng.next_u64() % 200) as u16;
        let mut ev = event(1 + i * 500_000, [10, 0, 0, 1], [10, 0, 0, 2], 100);
        ev.dst_port = port;
        engine.process(&ev).unwrap();
        *exact.entry(port.to_string()).or_insert(0) += 1;
        total += 1;
    }
    engine.finish().unwrap();
    let estimates = engine.take_estimates();
    assert!(!estimates.is_empty());

    let slack = 0.001 * total as f64 * std::f64::consts::E; // eps * N with CM width rounding
    for e in &estimates {
        let truth = exact[&e.group[0].1] as f64;
        assert!(e.estimate >= truth, "count-min underestimated");
        assert!(
            e.estimate <= truth + slack,
            "overestimate {} beyond contract (truth {truth}, slack {slack})",
            e.estimate
        );
    }
}
