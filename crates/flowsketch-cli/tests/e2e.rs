//! End-to-end tests that drive the compiled `flowsketch` binary:
//! synth -> validate/explain -> replay (table, prometheus, json).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn flowsketch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_flowsketch"))
}

fn workspace_root() -> PathBuf {
    // crates/flowsketch-cli -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn example(name: &str) -> PathBuf {
    workspace_root().join("examples/queries").join(name)
}

fn run_ok(cmd: &mut Command) -> Output {
    let out = cmd.output().expect("failed to spawn flowsketch");
    assert!(
        out.status.success(),
        "command failed: {:?}\nstdout: {}\nstderr: {}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Generate one shared trace per test process.
fn synth_trace(dir: &Path) -> PathBuf {
    let pcap = dir.join("e2e.pcap");
    run_ok(flowsketch().args([
        "synth",
        "--out",
        pcap.to_str().unwrap(),
        "--packets",
        "50000",
        "--scanners",
        "2",
        "--heavy-talkers",
        "3",
        "--duration-secs",
        "120",
        "--seed",
        "7",
    ]));
    pcap
}

#[test]
fn validate_accepts_shipped_examples() {
    let out = run_ok(flowsketch().arg("validate").args([
        example("top-talkers.yaml"),
        example("suspected-scanners.yaml"),
        example("protocol-bytes.yaml"),
    ]));
    let text = stdout(&out);
    assert_eq!(text.matches("OK   ").count(), 3, "{text}");
    assert!(!text.contains("FAIL"));
}

#[test]
fn validate_rejects_broken_query() {
    let dir = std::env::temp_dir().join("flowsketch-e2e-badquery");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.yaml");
    std::fs::write(
        &bad,
        "name: bad\nwindow: {size: 60s}\ngroupBy: [nonsense.field]\nmeasure: {type: count}\n",
    )
    .unwrap();
    let out = flowsketch().arg("validate").arg(&bad).output().unwrap();
    assert!(!out.status.success());
    let text = stdout(&out);
    assert!(text.contains("FAIL"), "{text}");
    assert!(text.contains("unknown field"), "{text}");
}

#[test]
fn explain_shows_plan_memory_and_error_contract() {
    let out = run_ok(
        flowsketch()
            .arg("explain")
            .arg(example("suspected-scanners.yaml")),
    );
    let text = stdout(&out);
    assert!(text.contains("HLLMap"), "{text}");
    assert!(text.contains("estimated memory"), "{text}");
    assert!(text.contains("error model"), "{text}");
    assert!(text.contains("alert if: estimate > 500"), "{text}");
}

#[test]
fn replay_detects_planted_heavy_talkers_and_scanners() {
    let dir = std::env::temp_dir().join("flowsketch-e2e-replay");
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = synth_trace(&dir);

    // Table output: heavy pairs (10.1.1.x -> 10.2.2.x) must lead top_talkers.
    let out = run_ok(
        flowsketch()
            .arg("replay")
            .arg(&pcap)
            .arg("--query")
            .arg(example("top-talkers.yaml")),
    );
    let text = stdout(&out);
    let first_row = text
        .lines()
        .find(|l| l.starts_with("1 "))
        .unwrap_or_else(|| panic!("no rank-1 row in output:\n{text}"));
    assert!(
        first_row.contains("10.1.1."),
        "top talker wrong: {first_row}"
    );
    assert!(
        first_row.contains("10.2.2."),
        "top talker wrong: {first_row}"
    );

    // Scanner query: only the planted scanners (10.66.0.x) cross the alert.
    let out = run_ok(
        flowsketch()
            .arg("replay")
            .arg(&pcap)
            .arg("--query")
            .arg(example("suspected-scanners.yaml"))
            .args(["--format", "json"]),
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let rows = json.as_array().unwrap();
    assert!(!rows.is_empty(), "scanner query produced no alerts");
    for row in rows {
        let src = row["group"][0][1].as_str().unwrap();
        assert!(src.starts_with("10.66.0."), "false positive scanner: {src}");
        assert!(row["estimate"].as_f64().unwrap() > 500.0);
        assert_eq!(row["algorithm"], "hllmap");
    }
}

#[test]
fn replay_prometheus_output_is_valid_exposition() {
    let dir = std::env::temp_dir().join("flowsketch-e2e-prom");
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = synth_trace(&dir);

    let out = run_ok(
        flowsketch()
            .arg("replay")
            .arg(&pcap)
            .arg("--query")
            .arg(example("top-talkers.yaml"))
            .args(["--format", "prometheus"]),
    );
    let text = stdout(&out);
    assert!(text.contains("# TYPE flowsketch_estimate gauge"));
    assert!(text.contains("algorithm=\"spacesaving\""));
    assert!(text.contains("error_kind=\"candidate-upper-bound\""));
    assert!(text.contains("window=\"60s\""));

    // No duplicate series: every metric line's label set must be unique.
    let mut label_sets = std::collections::HashSet::new();
    for line in text
        .lines()
        .filter(|l| l.starts_with("flowsketch_estimate{"))
    {
        let labels = line.split('}').next().unwrap();
        assert!(
            label_sets.insert(labels.to_string()),
            "duplicate series in exposition: {labels}"
        );
    }
    assert!(!label_sets.is_empty());

    // Series cap respected (top-talkers maxSeries = 100).
    assert!(
        label_sets.len() <= 100,
        "series cap violated: {}",
        label_sets.len()
    );
}

#[test]
fn bench_runs_and_reports_accuracy() {
    let out = run_ok(flowsketch().args([
        "bench",
        "--algo",
        "count-min",
        "--events",
        "200000",
        "--keys",
        "10000",
        "--dist",
        "zipf",
        "--profile",
        "all",
    ]));
    let text = stdout(&out);
    assert!(text.contains("updates/s/core"), "{text}");
    assert!(text.contains("measured_l3_capacity="), "{text}");
    assert!(text.contains("ARE over truth top-"), "{text}");
    assert!(text.contains("target: profile=1 Gb/s"), "{text}");
    assert!(text.contains("target: profile=100 Gb/s"), "{text}");
}

#[test]
fn bench_trace_profile_runs_on_generated_pcap() {
    let dir = std::env::temp_dir().join("flowsketch-e2e-bench-trace");
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = synth_trace(&dir);

    let out = run_ok(
        flowsketch()
            .arg("bench")
            .args(["--trace", pcap.to_str().unwrap()])
            .arg("--query")
            .arg(example("top-talkers.yaml"))
            .args(["--profile", "10g"])
            // This debug-binary smoke test verifies the readiness output path,
            // not runner-dependent performance. The release benchmark gate is
            // documented separately with a real CPU budget.
            .args(["--core-budget", "1000"]),
    );
    let text = stdout(&out);
    assert!(text.contains("trace benchmark:"), "{text}");
    assert!(text.contains("observed_l3_rate="), "{text}");
    assert!(text.contains("measured_l3_capacity="), "{text}");
    assert!(text.contains("target: profile=10 Gb/s"), "{text}");
    assert!(text.contains("estimated_cores_for_target="), "{text}");
    assert!(text.contains("readiness: profile=10 Gb/s"), "{text}");
    assert!(text.contains("status=pass"), "{text}");
    assert!(text.contains("runtime: estimates="), "{text}");

    let out = run_ok(
        flowsketch()
            .arg("bench")
            .args(["--trace", pcap.to_str().unwrap()])
            .arg("--query")
            .arg(example("top-talkers.yaml"))
            .args(["--profile", "10g"])
            .args(["--runtime-shards", "2"])
            .args(["--runtime-shard-strategy", "round-robin"])
            .args(["--normalize-line-rate-gbps", "10"])
            .args(["--core-budget", "1000"]),
    );
    let text = stdout(&out);
    assert!(text.contains("preload:"), "{text}");
    assert!(
        text.contains("event_time: normalized_l3_rate=10.00Gbps"),
        "{text}"
    );
    assert!(text.contains("strategy=RoundRobin"), "{text}");
    assert!(text.contains("sharded_runtime: shards=2"), "{text}");
    assert!(text.contains("aggregate_l3_capacity="), "{text}");
}

#[test]
fn bench_real_trace_if_configured() {
    let Ok(trace) = std::env::var("FLOWSKETCH_REAL_TRACE") else {
        eprintln!(
            "skipping real-trace bench; set FLOWSKETCH_REAL_TRACE=/path/to/caida-or-mawi.pcap"
        );
        return;
    };
    let profile = std::env::var("FLOWSKETCH_REAL_TRACE_PROFILE").unwrap_or_else(|_| "100g".into());
    let out = run_ok(
        flowsketch()
            .arg("bench")
            .args(["--trace", &trace])
            .arg("--query")
            .arg(example("top-talkers.yaml"))
            .args(["--profile", &profile]),
    );
    let text = stdout(&out);
    assert!(text.contains("trace benchmark:"), "{text}");
    assert!(text.contains("projection:"), "{text}");
}
