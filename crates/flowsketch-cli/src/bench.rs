//! `flowsketch bench`: synthetic sketch throughput/accuracy and real-pcap
//! trace throughput against line-rate profiles.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use flowsketch_algos::{
    CountMinSketch, CountSketch, ExactCounter, HllMap, HyperLogLog, MisraGries, SpaceSaving,
};
use flowsketch_core::hash::{HashSpec, SplitMixRng};
use flowsketch_core::{FlowEvent, Sketch, SketchError};
use flowsketch_ir::parse_query_yaml;
use flowsketch_pcap::PcapReader;
use flowsketch_planner::{plan, Plan};
use flowsketch_runtime::{QueryEngine, ShardedQueryEngine};

#[derive(Clone, Copy, ValueEnum)]
pub enum Algo {
    CountMin,
    CountSketch,
    Hll,
    HllMap,
    SpaceSaving,
    MisraGries,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Dist {
    Uniform,
    Zipf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RuntimeShardStrategy {
    /// Directional 5-tuple affinity, matching normal RSS behavior.
    Flow,
    /// Even packet distribution for mergeable, elephant-heavy workloads.
    RoundRobin,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Profile {
    /// Print projections for every supported line-rate target.
    All,
    #[value(name = "1g")]
    OneG,
    #[value(name = "10g")]
    TenG,
    #[value(name = "25g")]
    TwentyFiveG,
    #[value(name = "40g")]
    FortyG,
    #[value(name = "100g")]
    HundredG,
}

impl Profile {
    fn selected(self) -> &'static [Profile] {
        match self {
            Profile::All => &[
                Profile::OneG,
                Profile::TenG,
                Profile::TwentyFiveG,
                Profile::FortyG,
                Profile::HundredG,
            ],
            Profile::OneG => &[Profile::OneG],
            Profile::TenG => &[Profile::TenG],
            Profile::TwentyFiveG => &[Profile::TwentyFiveG],
            Profile::FortyG => &[Profile::FortyG],
            Profile::HundredG => &[Profile::HundredG],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Profile::All => "all",
            Profile::OneG => "1 Gb/s",
            Profile::TenG => "10 Gb/s",
            Profile::TwentyFiveG => "25 Gb/s",
            Profile::FortyG => "40 Gb/s",
            Profile::HundredG => "100 Gb/s",
        }
    }

    fn gbps(self) -> f64 {
        match self {
            Profile::All => 0.0,
            Profile::OneG => 1.0,
            Profile::TenG => 10.0,
            Profile::TwentyFiveG => 25.0,
            Profile::FortyG => 40.0,
            Profile::HundredG => 100.0,
        }
    }
}

#[derive(Clone)]
pub struct BenchConfig {
    pub algo: Algo,
    pub events: u64,
    pub keys: u64,
    pub dist: Dist,
    pub profile: Option<Profile>,
    /// Average packet size used for synthetic line-rate projection.
    pub avg_packet_bytes: u64,
    /// Real classic-pcap trace to benchmark parser/runtime throughput.
    pub trace: Option<PathBuf>,
    /// Query files to execute while replaying `trace`.
    pub queries: Vec<PathBuf>,
    pub seed: u64,
    /// Optional CPU-core budget for selected line-rate profile projections.
    pub core_budget: Option<f64>,
    /// Process preloaded trace events across this many runtime shards.
    pub runtime_shards: usize,
    /// Rescale event timestamps to this L3 rate for accelerated replay.
    pub normalize_line_rate_gbps: Option<f64>,
    pub runtime_shard_strategy: RuntimeShardStrategy,
    /// Independent sharded runtime samples used for the reported median.
    pub runtime_iterations: usize,
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

    fn sample(&self, rng: &mut SplitMixRng) -> u64 {
        let u = rng.next_f64();
        self.cdf.partition_point(|&c| c < u) as u64
    }
}

pub fn run(cfg: BenchConfig) -> Result<()> {
    if let Some(trace) = &cfg.trace {
        run_trace(cfg.clone(), trace)
    } else {
        run_synthetic(cfg)
    }
}

fn run_synthetic(cfg: BenchConfig) -> Result<()> {
    let BenchConfig {
        algo,
        events,
        keys,
        dist,
        profile,
        avg_packet_bytes,
        core_budget,
        ..
    } = cfg;
    if keys == 0 {
        bail!("--keys must be positive");
    }
    let name = match algo {
        Algo::CountMin => "count-min",
        Algo::CountSketch => "count-sketch",
        Algo::Hll => "hll",
        Algo::HllMap => "hllmap",
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
    let mut rng = SplitMixRng::new(12345);
    let mut key_ids: Vec<u64> = Vec::with_capacity(events as usize);
    for _ in 0..events {
        let id = match &zipf {
            Some(z) => z.sample(&mut rng),
            None => rng.next_u64() % keys,
        };
        key_ids.push(id);
    }
    let key_bytes: Vec<[u8; 8]> = (0..keys).map(|i| i.to_le_bytes()).collect();

    if matches!(algo, Algo::HllMap) {
        return run_synthetic_hllmap(&key_ids, &key_bytes, profile, avg_packet_bytes, core_budget);
    }

    let hash = HashSpec::new(1);
    let mut sketch: Box<dyn Sketch> = match algo {
        Algo::CountMin => Box::new(CountMinSketch::for_error(0.0001, 0.01, false, hash)?),
        Algo::CountSketch => Box::new(CountSketch::new(1 << 15, 5, hash)?),
        Algo::Hll => Box::new(HyperLogLog::new(14, hash)?),
        Algo::HllMap => unreachable!("HLLMap uses its two-dimensional benchmark path"),
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
    print_l3_capacity(
        events as f64 / elapsed.as_secs_f64(),
        avg_packet_bytes as f64,
    );
    let projections = print_profile_projection(
        profile,
        avg_packet_bytes as f64,
        events as f64 / elapsed.as_secs_f64(),
    );
    enforce_core_budget(&projections, core_budget)?;
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
        Algo::HllMap => unreachable!("HLLMap uses its two-dimensional benchmark path"),
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
            let (are, samples) = avg_relative_error(&*sketch, &truth_top);
            println!("accuracy: ARE over truth top-{samples} = {are:.4}");
        }
        Algo::CountMin | Algo::CountSketch => {
            let truth_top: Vec<(Vec<u8>, u64)> = exact.top_k(1000);
            let (are, samples) = avg_relative_error(&*sketch, &truth_top);
            println!("accuracy: ARE over truth top-{samples} = {are:.4}");
        }
    }
    Ok(())
}

fn run_synthetic_hllmap(
    key_ids: &[u64],
    key_bytes: &[[u8; 8]],
    profile: Option<Profile>,
    avg_packet_bytes: u64,
    core_budget: Option<f64>,
) -> Result<()> {
    // Matches the public scanner example: p=12 (~1.6% RSE) and preferred
    // retention headroom of up to 2,000 groups.
    let max_keys = key_bytes.len().clamp(1, 2_000);
    let mut sketch = HllMap::new(max_keys, 12, HashSpec::new(1))?;
    let mut truth = vec![0u64; key_bytes.len()];
    let started = Instant::now();
    for (sequence, &id) in key_ids.iter().enumerate() {
        let item = (sequence as u64).to_le_bytes();
        sketch.insert(&key_bytes[id as usize], &item);
        truth[id as usize] += 1;
    }
    let elapsed = started.elapsed();
    let updates_per_second = key_ids.len() as f64 / elapsed.as_secs_f64().max(1e-9);
    println!(
        "updates:  {} in {:.3}s -> {:.2}M updates/s/core",
        key_ids.len(),
        elapsed.as_secs_f64(),
        updates_per_second / 1e6
    );
    print_l3_capacity(updates_per_second, avg_packet_bytes as f64);
    let projections =
        print_profile_projection(profile, avg_packet_bytes as f64, updates_per_second);
    enforce_core_budget(&projections, core_budget)?;
    println!(
        "memory:   {} (retained_keys={}/{} evictions={})",
        flowsketch_planner::format_bytes(sketch.memory_bytes() as u64),
        sketch.len(),
        max_keys,
        sketch.evicted_keys()
    );

    let entries = sketch.entries();
    let mut relative_error = 0.0;
    for (key, estimate) in &entries {
        let id = u64::from_le_bytes(key.as_slice().try_into().expect("benchmark key is u64"));
        let exact = truth[id as usize] as f64;
        relative_error += (estimate - exact).abs() / exact.max(1.0);
    }
    let average = relative_error / entries.len().max(1) as f64;
    println!(
        "accuracy: retained-group ARE={average:.4}; retention is bounded and low-cardinality groups may be evicted"
    );
    Ok(())
}

fn run_trace(cfg: BenchConfig, trace: &PathBuf) -> Result<()> {
    if cfg.runtime_shards > 1 || cfg.normalize_line_rate_gbps.is_some() {
        return run_trace_sharded_runtime(cfg, trace);
    }
    let hash = HashSpec::new(cfg.seed);
    let plans = load_plans(&cfg.queries, cfg.seed)?;
    let mut engine = if plans.is_empty() {
        None
    } else {
        Some(QueryEngine::new(plans, hash).context("engine construction failed")?)
    };

    let file =
        File::open(trace).with_context(|| format!("cannot open trace {}", trace.display()))?;
    let mut reader = PcapReader::new(BufReader::with_capacity(1024 * 1024, file))
        .context("cannot read pcap header")?;

    let started = Instant::now();
    let mut events = 0u64;
    let mut total_l3_bytes = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;
    let mut packet_buf = Vec::with_capacity(2048);
    let mut estimates_len = 0usize;
    while let Some(event) = reader.next_event_into(&mut packet_buf)? {
        first_ts.get_or_insert(event.ts_nanos);
        last_ts = Some(event.ts_nanos);
        total_l3_bytes += event.bytes as u64;
        events += 1;
        if let Some(engine) = &mut engine {
            loop {
                match engine.process(&event) {
                    Ok(()) => break,
                    Err(SketchError::Backpressure(_)) => {
                        let drained = engine.take_estimates();
                        if drained.is_empty() {
                            bail!(
                                "runtime reported output backpressure without a drainable window"
                            );
                        }
                        estimates_len += drained.len();
                    }
                    Err(error) => return Err(error).context("sketch update failed"),
                }
            }
            if engine.pending_windows_full() {
                estimates_len += engine.take_estimates().len();
            }
        }
    }
    if let Some(engine) = &mut engine {
        loop {
            match engine.finish() {
                Ok(()) => break,
                Err(SketchError::Backpressure(_)) => {
                    let drained = engine.take_estimates();
                    if drained.is_empty() {
                        bail!(
                            "runtime reported final-output backpressure without a drainable window"
                        );
                    }
                    estimates_len += drained.len();
                }
                Err(error) => return Err(error).context("final window flush failed"),
            }
        }
    }
    let elapsed = started.elapsed();
    let wall_eps = events as f64 / elapsed.as_secs_f64().max(1e-9);
    let avg_packet_bytes = if events > 0 {
        total_l3_bytes as f64 / events as f64
    } else {
        cfg.avg_packet_bytes as f64
    };
    let trace_duration = match (first_ts, last_ts) {
        (Some(first), Some(last)) if last > first => (last - first) as f64 / 1e9,
        _ => 0.0,
    };
    let trace_gbps = if trace_duration > 0.0 {
        total_l3_bytes as f64 * 8.0 / trace_duration / 1e9
    } else {
        0.0
    };

    println!(
        "trace benchmark: file={} parsed_events={} packets_read={} queries={}",
        trace.display(),
        events,
        reader.packets_read(),
        cfg.queries.len()
    );
    println!(
        "trace shape: avg_l3_packet_bytes={avg_packet_bytes:.1} duration={trace_duration:.3}s observed_l3_rate={trace_gbps:.3}Gbps"
    );
    println!(
        "throughput: {events} events in {:.3}s -> {:.2}M events/s/core",
        elapsed.as_secs_f64(),
        wall_eps / 1e6
    );
    print_l3_capacity(wall_eps, avg_packet_bytes);
    let projections = print_profile_projection(cfg.profile, avg_packet_bytes, wall_eps);
    enforce_core_budget(&projections, cfg.core_budget)?;
    if let Some(engine) = &mut engine {
        estimates_len += engine.take_estimates().len();
        println!(
            "runtime: estimates={} sketch_memory={} late_events={}",
            estimates_len,
            flowsketch_planner::format_bytes(engine.sketch_memory_bytes() as u64),
            engine.late_events()
        );
    }
    Ok(())
}

struct LoadedTrace {
    events: Vec<FlowEvent>,
    packets_read: u64,
    total_l3_bytes: u64,
    avg_packet_bytes: f64,
    trace_duration: f64,
    trace_gbps: f64,
    elapsed_secs: f64,
}

fn load_trace(trace: &PathBuf, fallback_avg_packet_bytes: u64) -> Result<LoadedTrace> {
    let file =
        File::open(trace).with_context(|| format!("cannot open trace {}", trace.display()))?;
    let mut reader = PcapReader::new(BufReader::with_capacity(1024 * 1024, file))
        .context("cannot read pcap header")?;

    let started = Instant::now();
    let mut events = Vec::new();
    let mut total_l3_bytes = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;
    let mut packet_buf = Vec::with_capacity(2048);
    while let Some(event) = reader.next_event_into(&mut packet_buf)? {
        first_ts.get_or_insert(event.ts_nanos);
        last_ts = Some(event.ts_nanos);
        total_l3_bytes += event.bytes as u64;
        events.push(event);
    }
    let elapsed_secs = started.elapsed().as_secs_f64();
    let avg_packet_bytes = if events.is_empty() {
        fallback_avg_packet_bytes as f64
    } else {
        total_l3_bytes as f64 / events.len() as f64
    };
    let trace_duration = match (first_ts, last_ts) {
        (Some(first), Some(last)) if last > first => (last - first) as f64 / 1e9,
        _ => 0.0,
    };
    let trace_gbps = if trace_duration > 0.0 {
        total_l3_bytes as f64 * 8.0 / trace_duration / 1e9
    } else {
        0.0
    };

    Ok(LoadedTrace {
        events,
        packets_read: reader.packets_read(),
        total_l3_bytes,
        avg_packet_bytes,
        trace_duration,
        trace_gbps,
        elapsed_secs,
    })
}

fn run_trace_sharded_runtime(cfg: BenchConfig, trace: &PathBuf) -> Result<()> {
    let shard_count = cfg.runtime_shards;
    if shard_count == 0 {
        bail!("--runtime-shards must be at least 1");
    }
    if !(1..=100).contains(&cfg.runtime_iterations) {
        bail!("--runtime-iterations must be between 1 and 100");
    }

    let hash = HashSpec::new(cfg.seed);
    let plans = load_plans(&cfg.queries, cfg.seed)?;
    let mut loaded = load_trace(trace, cfg.avg_packet_bytes)?;
    let events = loaded.events.len();
    let effective_shards = shard_count.min(events.max(1));
    if let Some(gbps) = cfg.normalize_line_rate_gbps {
        if !gbps.is_finite() || gbps <= 0.0 {
            bail!("--normalize-line-rate-gbps must be a finite value greater than zero");
        }
        let start = loaded.events.first().map_or(0, |event| event.ts_nanos);
        let mut bytes = 0u64;
        for event in &mut loaded.events {
            event.ts_nanos = start.saturating_add((bytes as f64 * 8.0 / gbps) as u64);
            bytes = bytes.saturating_add(event.bytes as u64);
        }
        println!(
            "event_time: normalized_l3_rate={gbps:.2}Gbps normalized_duration={:.6}s",
            loaded.total_l3_bytes as f64 * 8.0 / gbps / 1e9
        );
    }
    let mut engine = ShardedQueryEngine::new(plans.clone(), hash, effective_shards)
        .context("sharded engine construction failed")?;

    println!(
        "trace benchmark: file={} parsed_events={} packets_read={} queries={}",
        trace.display(),
        events,
        loaded.packets_read,
        cfg.queries.len()
    );
    println!(
        "trace shape: avg_l3_packet_bytes={:.1} duration={:.3}s observed_l3_rate={:.3}Gbps",
        loaded.avg_packet_bytes, loaded.trace_duration, loaded.trace_gbps
    );
    println!(
        "preload: {} events in {:.3}s -> {:.2}M parse events/s/core",
        events,
        loaded.elapsed_secs,
        events as f64 / loaded.elapsed_secs.max(1e-9) / 1e6
    );

    // Partition outside the timed runtime section. This models NIC RSS/RX
    // queues delivering flow-affine batches directly to their CPU shards.
    let partition_started = Instant::now();
    let mut shard_batches: Vec<Vec<FlowEvent>> = (0..effective_shards)
        .map(|_| Vec::with_capacity(events.div_ceil(effective_shards)))
        .collect();
    for (index, event) in std::mem::take(&mut loaded.events).into_iter().enumerate() {
        let shard = match cfg.runtime_shard_strategy {
            RuntimeShardStrategy::Flow => engine.shard_for(&event),
            RuntimeShardStrategy::RoundRobin => index % effective_shards,
        };
        shard_batches[shard].push(event);
    }
    let partition_elapsed = partition_started.elapsed();
    let min_shard_events = shard_batches.iter().map(Vec::len).min().unwrap_or(0);
    let max_shard_events = shard_batches.iter().map(Vec::len).max().unwrap_or(0);
    println!(
        "partition: {events} events in {:.3}s -> {:.2}M flow dispatches/s/core",
        partition_elapsed.as_secs_f64(),
        events as f64 / partition_elapsed.as_secs_f64().max(1e-9) / 1e6
    );
    println!(
        "shard_balance: strategy={:?} min_events={min_shard_events} max_events={max_shard_events} max_to_mean={:.2}",
        cfg.runtime_shard_strategy,
        max_shard_events as f64 / (events as f64 / effective_shards as f64).max(1.0)
    );

    let mut elapsed_samples = Vec::with_capacity(cfg.runtime_iterations);
    let mut estimates_len = 0usize;
    let mut sketch_memory_bytes = 0usize;
    let mut late_events = 0u64;
    for iteration in 0..cfg.runtime_iterations {
        if iteration > 0 {
            engine = ShardedQueryEngine::new(plans.clone(), hash, effective_shards)
                .context("sharded engine construction failed")?;
        }
        let started = Instant::now();
        engine
            .process_shard_batches(&shard_batches)
            .context("sharded sketch update failed")?;
        engine.finish().context("final window flush failed")?;
        estimates_len = engine
            .take_estimates()
            .context("sharded window merge failed")?
            .len();
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "sharded_runtime_sample: iteration={} elapsed={elapsed:.6}s rate={:.2}M events/s",
            iteration + 1,
            events as f64 / elapsed.max(1e-9) / 1e6
        );
        elapsed_samples.push(elapsed);
        sketch_memory_bytes = engine.sketch_memory_bytes();
        late_events = engine.late_events();
    }
    elapsed_samples.sort_by(f64::total_cmp);
    let elapsed_secs = elapsed_samples[elapsed_samples.len() / 2];

    let processed = events as u64;
    let aggregate_eps = processed as f64 / elapsed_secs.max(1e-9);
    let per_core_eps = aggregate_eps / effective_shards as f64;
    println!(
        "sharded_runtime: shards={} events={} in {:.3}s -> aggregate {:.2}M events/s, per_core {:.2}M events/s/core",
        effective_shards,
        processed,
        elapsed_secs,
        aggregate_eps / 1e6,
        per_core_eps / 1e6
    );
    print_l3_capacity(per_core_eps, loaded.avg_packet_bytes);
    println!(
        "capacity: aggregate_l3_capacity={:.2} Gb/s across {} shard(s)",
        measured_l3_gbps(aggregate_eps, loaded.avg_packet_bytes),
        effective_shards
    );
    let projections = print_profile_projection(cfg.profile, loaded.avg_packet_bytes, per_core_eps);
    enforce_core_budget(&projections, cfg.core_budget)?;
    println!(
        "runtime: shards={} estimates={} sketch_memory={} late_events={} total_l3_bytes={}",
        effective_shards,
        estimates_len,
        flowsketch_planner::format_bytes(sketch_memory_bytes as u64),
        late_events,
        loaded.total_l3_bytes
    );
    Ok(())
}

fn load_plans(query_files: &[PathBuf], seed: u64) -> Result<Vec<Plan>> {
    let hash = HashSpec::new(seed);
    query_files
        .iter()
        .map(|path| {
            let yaml = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read query file {}", path.display()))?;
            let query = parse_query_yaml(&yaml)
                .with_context(|| format!("invalid query in {}", path.display()))?;
            plan(query, &hash).with_context(|| format!("planning failed for {}", path.display()))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct LineRateProjection {
    profile: Profile,
    estimated_cores: f64,
}

fn print_profile_projection(
    profile: Option<Profile>,
    avg_packet_bytes: f64,
    measured_eps: f64,
) -> Vec<LineRateProjection> {
    let Some(profile) = profile else {
        return Vec::new();
    };
    let mut projections = Vec::new();
    for profile in profile.selected() {
        let target_eps = target_events_per_sec(*profile, avg_packet_bytes);
        let estimated_cores = target_eps / measured_eps.max(1.0);
        println!(
            "target: profile={} line_rate={:.0} Gb/s avg_packet_bytes={avg_packet_bytes:.1} requires {:.2}M events/s",
            profile.name(),
            profile.gbps(),
            target_eps / 1e6
        );
        println!(
            "projection: measured {:.2}M events/s/core => estimated_cores_for_target={estimated_cores:.2}",
            measured_eps / 1e6
        );
        projections.push(LineRateProjection {
            profile: *profile,
            estimated_cores,
        });
    }
    projections
}

fn enforce_core_budget(projections: &[LineRateProjection], core_budget: Option<f64>) -> Result<()> {
    let Some(core_budget) = core_budget else {
        return Ok(());
    };
    if projections.is_empty() {
        bail!("--core-budget requires --profile so there is a line-rate target to check");
    }
    if !core_budget.is_finite() || core_budget <= 0.0 {
        bail!("--core-budget must be a positive finite number");
    }

    let mut failed = false;
    for projection in projections {
        let passed = projection.estimated_cores <= core_budget;
        println!(
            "readiness: profile={} estimated_cores={:.2} core_budget={core_budget:.2} status={}",
            projection.profile.name(),
            projection.estimated_cores,
            if passed { "pass" } else { "fail" }
        );
        failed |= !passed;
    }
    if failed {
        bail!("line-rate readiness check exceeded --core-budget");
    }
    Ok(())
}

pub fn target_events_per_sec(profile: Profile, avg_packet_bytes: f64) -> f64 {
    profile.gbps() * 1e9 / (avg_packet_bytes.max(1.0) * 8.0)
}

fn print_l3_capacity(measured_eps: f64, avg_packet_bytes: f64) {
    println!(
        "capacity: measured_l3_capacity={:.2} Gb/s/core at avg_packet_bytes={avg_packet_bytes:.1}",
        measured_l3_gbps(measured_eps, avg_packet_bytes)
    );
}

pub fn measured_l3_gbps(events_per_sec: f64, avg_packet_bytes: f64) -> f64 {
    events_per_sec * avg_packet_bytes.max(1.0) * 8.0 / 1e9
}

fn avg_relative_error(sketch: &dyn Sketch, truth: &[(Vec<u8>, u64)]) -> (f64, usize) {
    let mut total = 0.0;
    for (k, t) in truth {
        let est = sketch.estimate(k);
        total += (est - *t as f64).abs() / *t as f64;
    }
    (total / truth.len() as f64, truth.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_rate_profile_math_is_explicit() {
        let pps = target_events_per_sec(Profile::TenG, 1_250.0);
        assert!((pps - 1_000_000.0).abs() < 1.0);

        let pps = target_events_per_sec(Profile::HundredG, 1_250.0);
        assert!((pps - 10_000_000.0).abs() < 1.0);
    }

    #[test]
    fn measured_capacity_math_is_explicit() {
        let gbps = measured_l3_gbps(10_000_000.0, 1_250.0);
        assert!((gbps - 100.0).abs() < 0.001);
    }

    #[test]
    fn all_profile_expands_to_supported_line_rates() {
        let names: Vec<_> = Profile::All
            .selected()
            .iter()
            .map(|profile| profile.name())
            .collect();
        assert_eq!(
            names,
            ["1 Gb/s", "10 Gb/s", "25 Gb/s", "40 Gb/s", "100 Gb/s"]
        );
    }

    #[test]
    fn core_budget_gate_accepts_and_rejects_projections() {
        let projections = [LineRateProjection {
            profile: Profile::TenG,
            estimated_cores: 3.9,
        }];
        enforce_core_budget(&projections, Some(4.0)).unwrap();
        enforce_core_budget(&projections, Some(2.0)).unwrap_err();
        enforce_core_budget(&[], Some(4.0)).unwrap_err();
    }
}
