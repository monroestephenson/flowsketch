//! The `flowsketch` CLI: offline replay, plan explain/validate, algorithm
//! benchmarks, and synthetic trace generation.

mod bench;
mod merge;
mod replay;
mod synth;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use flowsketch_core::hash::HashSpec;
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::{explain, plan, Plan};

#[derive(Parser)]
#[command(
    name = "flowsketch",
    version,
    about = "Approximate network telemetry: bounded-memory sketch queries over traffic",
    long_about = "FlowSketch answers high-cardinality network questions (top talkers, fan-out, \
                  scanners) with fixed memory and explicit error bounds, and exports normal \
                  Prometheus/OpenTelemetry signals."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replay a pcap file against one or more sketch queries
    Replay {
        /// Path to a classic pcap file
        pcap: PathBuf,
        /// Query YAML file(s); repeatable
        #[arg(long = "query", required = true)]
        queries: Vec<PathBuf>,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
        /// Hash seed (must match across nodes for mergeable sketches)
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Also write each query's final sketch state as FSK1 snapshot
        /// files into this directory (for merge-snapshots)
        #[arg(long)]
        snapshot_out: Option<PathBuf>,
    },
    /// Run the live agent: capture packets, serve /metrics, /healthz, /v1/queries
    Agent {
        /// Agent config YAML (see examples/agent.yaml)
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Run the cluster gateway: receive snapshot pushes from agents, merge
    /// them across nodes, serve cluster-level /metrics
    Gateway {
        /// Gateway config YAML (see examples/gateway.yaml)
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Merge FSK1 sketch snapshots from different processes/nodes and print
    /// the combined estimates (merge compatibility is validated)
    MergeSnapshots {
        /// Snapshot files produced by `replay --snapshot-out`
        #[arg(required = true)]
        snapshots: Vec<PathBuf>,
        /// Optionally write the merged snapshot here
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show the physical plan, memory estimate, and error contract for a query
    Explain {
        /// Query YAML file
        query: PathBuf,
    },
    /// Validate a query file (parse + plan) without running it
    Validate {
        /// Query YAML file(s)
        #[arg(required = true)]
        queries: Vec<PathBuf>,
    },
    /// Benchmark sketch update throughput and accuracy against exact counts
    Bench {
        /// Algorithm to benchmark
        #[arg(long, value_enum, default_value_t = bench::Algo::CountMin)]
        algo: bench::Algo,
        /// Number of update events
        #[arg(long, default_value_t = 10_000_000)]
        events: u64,
        /// Number of distinct keys
        #[arg(long, default_value_t = 100_000)]
        keys: u64,
        /// Key-frequency distribution
        #[arg(long, value_enum, default_value_t = bench::Dist::Zipf)]
        dist: bench::Dist,
    },
    /// Generate a synthetic pcap trace (background traffic + heavy talkers + scanners)
    Synth {
        /// Output pcap path
        #[arg(long, short)]
        out: PathBuf,
        /// Number of packets
        #[arg(long, default_value_t = 100_000)]
        packets: u64,
        /// Number of scanning hosts to embed
        #[arg(long, default_value_t = 2)]
        scanners: u32,
        /// Number of heavy-talker flows to embed
        #[arg(long, default_value_t = 3)]
        heavy_talkers: u32,
        /// Trace duration in seconds
        #[arg(long, default_value_t = 120)]
        duration_secs: u64,
        /// RNG seed for reproducible traces
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Table,
    Prometheus,
    Json,
}

fn load_plan(path: &PathBuf, seed: u64) -> Result<Plan> {
    let yaml = fs::read_to_string(path)
        .with_context(|| format!("cannot read query file {}", path.display()))?;
    let query =
        parse_query_yaml(&yaml).with_context(|| format!("invalid query in {}", path.display()))?;
    let planned = plan(query, &HashSpec::new(seed))
        .with_context(|| format!("planning failed for {}", path.display()))?;
    Ok(planned)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Replay {
            pcap,
            queries,
            format,
            seed,
            snapshot_out,
        } => {
            let plans: Vec<Plan> = queries
                .iter()
                .map(|p| load_plan(p, seed))
                .collect::<Result<_>>()?;
            replay::run(&pcap, plans, format, seed, snapshot_out.as_deref())
        }
        Command::Agent { config } => {
            let cfg = flowsketch_agent::AgentConfig::from_file(&config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            eprintln!(
                "flowsketch agent starting: node={} queries={} source={:?}",
                cfg.node_name,
                cfg.query_files.len(),
                cfg.source
            );
            flowsketch_agent::run(cfg, |addr| {
                eprintln!("listening on http://{addr} (/metrics /healthz /readyz /v1/queries)");
            })
            .map_err(|e| anyhow::anyhow!("{e}"))
        }
        Command::Gateway { config } => {
            let cfg = flowsketch_gateway::GatewayConfig::from_file(&config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            eprintln!(
                "flowsketch gateway starting: queries={} staleAfterMs={}",
                cfg.query_files.len(),
                cfg.stale_after_ms
            );
            flowsketch_gateway::run(cfg, |addr| {
                eprintln!(
                    "listening on http://{addr} (POST /v1/snapshots; GET /metrics /healthz \
                     /readyz /v1/queries /v1/nodes)"
                );
            })
            .map_err(|e| anyhow::anyhow!("{e}"))
        }
        Command::MergeSnapshots { snapshots, out } => merge::run(&snapshots, out.as_deref()),
        Command::Explain { query } => {
            let planned = load_plan(&query, 0)?;
            print!("{}", explain(&planned));
            Ok(())
        }
        Command::Validate { queries } => {
            let mut failures = 0usize;
            for path in &queries {
                match load_plan(path, 0) {
                    Ok(planned) => {
                        println!(
                            "OK   {} ({}; ~{} across {} bucket(s))",
                            path.display(),
                            planned.physical.sketch.algorithm_name(),
                            flowsketch_planner::format_bytes(
                                planned.physical.estimated_memory_bytes
                            ),
                            planned.physical.window_buckets,
                        );
                        for w in &planned.physical.warnings {
                            println!("     warning: {w}");
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        println!("FAIL {}: {e:#}", path.display());
                    }
                }
            }
            if failures > 0 {
                anyhow::bail!(
                    "{failures} of {} query file(s) failed validation",
                    queries.len()
                );
            }
            Ok(())
        }
        Command::Bench {
            algo,
            events,
            keys,
            dist,
        } => bench::run(algo, events, keys, dist),
        Command::Synth {
            out,
            packets,
            scanners,
            heavy_talkers,
            duration_secs,
            seed,
        } => synth::run(&out, packets, scanners, heavy_talkers, duration_secs, seed),
    }
}

/// Shared: build per-query export info for the Prometheus renderer.
pub fn export_info(plans: &[Plan]) -> BTreeMap<String, flowsketch_prometheus::QueryExportInfo> {
    plans
        .iter()
        .map(|p| {
            (
                p.query.name.clone(),
                flowsketch_prometheus::QueryExportInfo {
                    error_kind: p.physical.error_kind.name().to_string(),
                    max_series: p.query.export.max_series,
                    window_size_nanos: p.query.window.size_nanos,
                },
            )
        })
        .collect()
}
