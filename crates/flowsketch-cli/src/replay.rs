//! `flowsketch replay`: feed a pcap through the query engine and print
//! results as a table, Prometheus exposition text, or JSON.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};

use flowsketch_core::hash::HashSpec;
use flowsketch_core::SketchEstimate;
use flowsketch_ir::logical::humanize_nanos;
use flowsketch_pcap::PcapReader;
use flowsketch_planner::Plan;
use flowsketch_runtime::QueryEngine;

use crate::{export_info, OutputFormat};

pub fn run(
    pcap_path: &Path,
    plans: Vec<Plan>,
    format: OutputFormat,
    seed: u64,
    snapshot_out: Option<&Path>,
) -> Result<()> {
    let info = export_info(&plans);
    let plan_meta: Vec<(String, String, u64)> = plans
        .iter()
        .map(|p| {
            (
                p.query.name.clone(),
                p.physical.sketch.algorithm_name(),
                p.query.window.size_nanos,
            )
        })
        .collect();

    let mut engine =
        QueryEngine::new(plans, HashSpec::new(seed)).context("engine construction failed")?;

    let file = File::open(pcap_path)
        .with_context(|| format!("cannot open pcap {}", pcap_path.display()))?;
    let mut reader = PcapReader::new(BufReader::new(file)).context("cannot read pcap header")?;

    let started = Instant::now();
    let mut events = 0u64;
    while let Some(event) = reader.next_event()? {
        engine.process(&event).context("sketch update failed")?;
        events += 1;
    }
    engine.finish().context("final window flush failed")?;
    let elapsed = started.elapsed();

    if let Some(dir) = snapshot_out {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        for snap in engine
            .export_snapshots()
            .context("snapshot export failed")?
        {
            let file = dir.join(format!("{}.{}.fsk1", snap.query_name, snap.component));
            std::fs::write(&file, &snap.bytes)
                .with_context(|| format!("cannot write {}", file.display()))?;
            eprintln!("wrote snapshot {}", file.display());
        }
    }

    let estimates = engine.take_estimates();

    match format {
        OutputFormat::Prometheus => {
            // A scrape exposes one sample per series: render only each
            // query's final window (earlier windows would duplicate series).
            let finals = latest_window_only(&estimates);
            let (text, _) = flowsketch_prometheus::render(&finals, &info);
            print!("{text}");
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&estimates)?);
        }
        OutputFormat::Table => {
            print_tables(&plan_meta, &estimates);
            eprintln!(
                "\nreplayed {} packets ({} parsed events) in {:.2}s ({:.2}M events/s); \
                 sketch memory {} across open buckets; {} late event(s) dropped",
                reader.packets_read(),
                events,
                elapsed.as_secs_f64(),
                events as f64 / elapsed.as_secs_f64().max(1e-9) / 1e6,
                flowsketch_planner::format_bytes(engine.sketch_memory_bytes() as u64),
                engine.late_events(),
            );
        }
    }
    Ok(())
}

/// Keep only each query's most recent window.
fn latest_window_only(estimates: &[SketchEstimate]) -> Vec<SketchEstimate> {
    let mut last_end: std::collections::BTreeMap<&str, u64> = Default::default();
    for e in estimates {
        let entry = last_end.entry(e.query_name.as_str()).or_insert(0);
        *entry = (*entry).max(e.window_end_nanos);
    }
    estimates
        .iter()
        .filter(|e| last_end[e.query_name.as_str()] == e.window_end_nanos)
        .cloned()
        .collect()
}

fn print_tables(plan_meta: &[(String, String, u64)], estimates: &[SketchEstimate]) {
    for (query_name, algorithm, window_nanos) in plan_meta {
        // Show the final window per query (replay's most useful summary).
        let last_end = estimates
            .iter()
            .filter(|e| &e.query_name == query_name)
            .map(|e| e.window_end_nanos)
            .max();
        let Some(last_end) = last_end else {
            println!(
                "QUERY {query_name} window={} algorithm={algorithm}\n  (no results)\n",
                humanize_nanos(*window_nanos)
            );
            continue;
        };
        let mut rows: Vec<&SketchEstimate> = estimates
            .iter()
            .filter(|e| &e.query_name == query_name && e.window_end_nanos == last_end)
            .collect();
        rows.sort_by(|a, b| {
            b.estimate
                .partial_cmp(&a.estimate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        println!(
            "QUERY {query_name} window={} algorithm={algorithm} (final window, {} series)",
            humanize_nanos(*window_nanos),
            rows.len()
        );
        if rows.is_empty() {
            println!("  (no groups matched)\n");
            continue;
        }
        let label_header = rows[0]
            .group
            .iter()
            .map(|(k, _)| format!("{k:<18}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "rank {label_header} {:>16} {:>16} {:>16}",
            "estimate", "low", "high"
        );
        for (i, e) in rows.iter().take(50).enumerate() {
            let labels = e
                .group
                .iter()
                .map(|(_, v)| format!("{v:<18}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "{:<4} {labels} {:>16.0} {:>16} {:>16}",
                i + 1,
                e.estimate,
                e.lower_bound.map_or("-".to_string(), |v| format!("{v:.0}")),
                e.upper_bound.map_or("-".to_string(), |v| format!("{v:.0}")),
            );
        }
        if rows.len() > 50 {
            println!("... {} more", rows.len() - 50);
        }
        println!();
    }
}
