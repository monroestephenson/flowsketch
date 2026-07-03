//! `flowsketch bench`: update throughput, memory footprint, and accuracy
//! against an exact ground-truth counter on synthetic distributions.

use std::time::Instant;

use anyhow::Result;
use clap::ValueEnum;

use flowsketch_algos::{
    CountMinSketch, CountSketch, ExactCounter, HyperLogLog, MisraGries, SpaceSaving,
};
use flowsketch_core::hash::{splitmix64, HashSpec};
use flowsketch_core::Sketch;

#[derive(Clone, Copy, ValueEnum)]
pub enum Algo {
    CountMin,
    CountSketch,
    Hll,
    SpaceSaving,
    MisraGries,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Dist {
    Uniform,
    Zipf,
}

/// Deterministic RNG (SplitMix64 stream).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        splitmix64(self.0)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Zipf(s=1) sampler over `n` keys via inverse-CDF on a precomputed table.
struct Zipf {
    cdf: Vec<f64>,
}

impl Zipf {
    fn new(n: u64) -> Self {
        let mut cdf = Vec::with_capacity(n as usize);
        let mut acc = 0.0;
        for i in 1..=n {
            acc += 1.0 / i as f64;
            cdf.push(acc);
        }
        let total = acc;
        for c in &mut cdf {
            *c /= total;
        }
        Zipf { cdf }
    }

    fn sample(&self, rng: &mut Rng) -> u64 {
        let u = rng.next_f64();
        self.cdf.partition_point(|&c| c < u) as u64
    }
}

pub fn run(algo: Algo, events: u64, keys: u64, dist: Dist) -> Result<()> {
    let name = match algo {
        Algo::CountMin => "count-min",
        Algo::CountSketch => "count-sketch",
        Algo::Hll => "hll",
        Algo::SpaceSaving => "spacesaving",
        Algo::MisraGries => "misra-gries",
    };
    let dist_name = match dist {
        Dist::Uniform => "uniform",
        Dist::Zipf => "zipf(s=1)",
    };
    println!("benchmark: algo={name} events={events} keys={keys} dist={dist_name}");

    // Pre-generate the key stream so generation cost is excluded from the
    // measured update loop.
    let zipf = matches!(dist, Dist::Zipf).then(|| Zipf::new(keys));
    let mut rng = Rng(12345);
    let mut key_ids: Vec<u64> = Vec::with_capacity(events as usize);
    for _ in 0..events {
        let id = match &zipf {
            Some(z) => z.sample(&mut rng),
            None => rng.next() % keys,
        };
        key_ids.push(id);
    }
    let key_bytes: Vec<[u8; 8]> = (0..keys).map(|i| i.to_le_bytes()).collect();

    let hash = HashSpec::new(1);
    let mut sketch: Box<dyn Sketch> = match algo {
        Algo::CountMin => Box::new(CountMinSketch::for_error(0.0001, 0.01, false, hash)?),
        Algo::CountSketch => Box::new(CountSketch::new(1 << 15, 5, hash)?),
        Algo::Hll => Box::new(HyperLogLog::new(14, hash)?),
        Algo::SpaceSaving => Box::new(SpaceSaving::new(4096, hash)?),
        Algo::MisraGries => Box::new(MisraGries::new(4096, hash)?),
    };

    let started = Instant::now();
    for &id in &key_ids {
        sketch.update(&key_bytes[id as usize], 1);
    }
    let elapsed = started.elapsed();
    let rate = events as f64 / elapsed.as_secs_f64() / 1e6;
    println!(
        "updates:  {events} in {:.3}s -> {rate:.2}M updates/s/core",
        elapsed.as_secs_f64()
    );
    println!(
        "memory:   {}",
        flowsketch_planner::format_bytes(sketch.memory_bytes() as u64)
    );

    // Accuracy vs exact ground truth.
    let mut exact = ExactCounter::new();
    for &id in &key_ids {
        exact.add(&key_bytes[id as usize], 1);
    }

    match algo {
        Algo::Hll => {
            let distinct = key_ids
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len() as f64;
            let est = sketch.estimate(b"");
            println!(
                "accuracy: distinct truth={distinct:.0} estimate={est:.0} relative_error={:.4}",
                (est - distinct).abs() / distinct
            );
        }
        Algo::SpaceSaving | Algo::MisraGries => {
            let truth_top: Vec<(Vec<u8>, u64)> = exact.top_k(100);
            let hits = truth_top
                .iter()
                .filter(|(k, _)| sketch.estimate(k) > 0.0)
                .count();
            println!(
                "accuracy: precision@100 (truth top-100 tracked) = {}/100",
                hits
            );
            let (are, samples) = avg_relative_error(&*sketch, &exact, &truth_top);
            println!("accuracy: ARE over truth top-{samples} = {are:.4}");
        }
        Algo::CountMin | Algo::CountSketch => {
            let truth_top: Vec<(Vec<u8>, u64)> = exact.top_k(1000);
            let (are, samples) = avg_relative_error(&*sketch, &exact, &truth_top);
            println!("accuracy: ARE over truth top-{samples} = {are:.4}");
        }
    }
    Ok(())
}

fn avg_relative_error(
    sketch: &dyn Sketch,
    _exact: &ExactCounter,
    truth: &[(Vec<u8>, u64)],
) -> (f64, usize) {
    let mut total = 0.0;
    for (k, t) in truth {
        let est = sketch.estimate(k);
        total += (est - *t as f64).abs() / *t as f64;
    }
    (total / truth.len() as f64, truth.len())
}
