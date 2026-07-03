//! `flowsketch merge-snapshots`: combine FSK1 sketch snapshots produced by
//! different processes/nodes (`replay --snapshot-out`) and print the merged
//! estimates. This is the distributed-merge primitive the future gateway
//! builds on: merge compatibility (algorithm, hash spec, parameters) is
//! validated, never assumed.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use flowsketch_algos::{CountMinSketch, HllMap, HyperLogLog, KllSketch, SpaceSaving};
use flowsketch_core::snapshot::{algorithm_id, read_snapshot};
use flowsketch_core::Sketch;

pub fn run(files: &[PathBuf], out: Option<&Path>) -> Result<()> {
    if files.is_empty() {
        bail!("no snapshot files given");
    }
    let mut blobs = Vec::with_capacity(files.len());
    let mut algo_ids = Vec::new();
    for f in files {
        let bytes = std::fs::read(f).with_context(|| format!("cannot read {}", f.display()))?;
        let (header, _, _) =
            read_snapshot(&bytes).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        algo_ids.push(header.algorithm_id);
        blobs.push(bytes);
    }
    let algo = algo_ids[0];
    if algo_ids.iter().any(|&a| a != algo) {
        bail!(
            "snapshots use different algorithms ({algo_ids:?}); only same-algorithm \
             snapshots can merge"
        );
    }

    println!("merging {} snapshot(s)", blobs.len());
    let merged_bytes = match algo {
        algorithm_id::HYPER_LOG_LOG => {
            let merged = merge_all(&blobs, HyperLogLog::from_snapshot)?;
            println!("algorithm: hll");
            println!("merged distinct count: {:.0}", merged.cardinality());
            merged.to_snapshot(0, 0)
        }
        algorithm_id::SPACE_SAVING => {
            let merged = merge_all(&blobs, SpaceSaving::from_snapshot)?;
            println!("algorithm: spacesaving");
            println!("merged total weight: {}", merged.total_weight());
            println!("top 20:");
            for (i, (key, entry)) in merged.top_k(20).into_iter().enumerate() {
                println!(
                    "  {:<3} {:<40} count<= {:<12} guaranteed>= {}",
                    i + 1,
                    String::from_utf8_lossy(&key).replace('\u{1f}', " | "),
                    entry.count,
                    entry.guaranteed()
                );
            }
            merged.to_snapshot(0, 0)
        }
        algorithm_id::HLL_MAP => {
            let merged = merge_all(&blobs, HllMap::from_snapshot)?;
            println!("algorithm: hllmap");
            println!(
                "tracked keys: {} (evictions {})",
                merged.len(),
                merged.evicted_keys()
            );
            println!("top 20 by distinct count:");
            for (i, (key, card)) in merged.entries().into_iter().take(20).enumerate() {
                println!(
                    "  {:<3} {:<40} ~{:.0}",
                    i + 1,
                    String::from_utf8_lossy(&key).replace('\u{1f}', " | "),
                    card
                );
            }
            merged.to_snapshot(0, 0)
        }
        algorithm_id::KLL => {
            let merged = merge_all(&blobs, KllSketch::from_snapshot)?;
            println!("algorithm: kll (n={})", merged.n());
            for q in [0.5, 0.9, 0.99] {
                if let Some(v) = merged.quantile(q) {
                    println!("  p{:<4} {}", (q * 100.0) as u32, v);
                }
            }
            merged.to_snapshot(0, 0)
        }
        algorithm_id::COUNT_MIN => {
            let merged = merge_all(&blobs, CountMinSketch::from_snapshot)?;
            println!("algorithm: count-min");
            println!(
                "merged total weight: {} (epsilon {:.6}, delta {:.6})",
                merged.total_weight(),
                merged.epsilon(),
                merged.delta()
            );
            merged.to_snapshot(0, 0)
        }
        other => bail!("snapshots with algorithm id {other} cannot be merged by this tool"),
    };

    if let Some(path) = out {
        std::fs::write(path, &merged_bytes)
            .with_context(|| format!("cannot write {}", path.display()))?;
        println!("wrote merged snapshot to {}", path.display());
    }
    Ok(())
}

fn merge_all<S: Sketch>(
    blobs: &[Vec<u8>],
    from: impl Fn(&[u8]) -> Result<S, flowsketch_core::SketchError>,
) -> Result<S> {
    let mut iter = blobs.iter();
    let first = iter.next().expect("nonempty");
    let mut merged = from(first).map_err(|e| anyhow::anyhow!("{e}"))?;
    for blob in iter {
        let s = from(blob).map_err(|e| anyhow::anyhow!("{e}"))?;
        merged
            .merge_from(&s)
            .map_err(|e| anyhow::anyhow!("merge rejected: {e}"))?;
    }
    Ok(merged)
}
