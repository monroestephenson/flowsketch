//! End-to-end tests for the live agent and distributed snapshot merge:
//! spawn the real binary, hit the real HTTP endpoints, merge real FSK1
//! files across process boundaries.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn flowsketch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_flowsketch"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Minimal HTTP GET against the agent.
fn http_get(addr: &str, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status: u16 = response.split_whitespace().nth(1)?.parse().ok()?;
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((status, body))
}

struct AgentUnderTest {
    child: Child,
    addr: String,
}

impl Drop for AgentUnderTest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the agent on an ephemeral port over a synthetic pcap and wait for
/// readiness.
fn start_agent(dir: &Path) -> AgentUnderTest {
    let pcap = dir.join("agent.pcap");
    let status = flowsketch()
        .args([
            "synth",
            "--out",
            pcap.to_str().unwrap(),
            "--packets",
            "30000",
            "--scanners",
            "2",
            "--heavy-talkers",
            "2",
            "--seed",
            "3",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let examples = workspace_root().join("examples/queries");
    let config = dir.join("agent.yaml");
    std::fs::write(
        &config,
        format!(
            "agent:\n  nodeName: test-node\n  listen: 127.0.0.1:0\n  flushIntervalMs: 50\n  \
             source:\n    kind: pcap\n    path: {}\nqueries:\n  - file: {}\n  - file: {}\n  - file: {}\n",
            pcap.display(),
            examples.join("top-talkers.yaml").display(),
            examples.join("flow-size-quantiles.yaml").display(),
            examples.join("source-entropy.yaml").display(),
        ),
    )
    .unwrap();

    let mut child = flowsketch()
        .args(["agent", "--config", config.to_str().unwrap()])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The agent prints "listening on http://ADDR ..." once bound.
    let stderr = child.stderr.take().unwrap();
    let mut addr = None;
    let reader = std::io::BufReader::new(stderr);
    use std::io::BufRead;
    for line in reader.lines().map_while(Result::ok) {
        if let Some(rest) = line.split("http://").nth(1) {
            addr = Some(rest.split_whitespace().next().unwrap().to_string());
            break;
        }
    }
    let addr = addr.expect("agent did not report a listen address");

    // Wait until ready and until the replay has been fully processed.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((200, _)) = http_get(&addr, "/readyz") {
            if let Some((200, body)) = http_get(&addr, "/metrics") {
                if body.contains("flowsketch_estimate{") {
                    break;
                }
            }
        }
        assert!(Instant::now() < deadline, "agent never became ready");
        std::thread::sleep(Duration::from_millis(100));
    }
    AgentUnderTest { child, addr }
}

/// Mock OTLP collector: accepts POSTs on /v1/metrics until dropped,
/// pushing each JSON body into a channel.
fn mock_otlp_collector() -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::BufRead;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(&stream);
                let mut content_length = 0usize;
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                if std::io::Read::read_exact(&mut reader, &mut body).is_ok() {
                    let mut stream = reader.into_inner();
                    let _ = Write::write_all(
                        &mut stream,
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                    );
                    let _ = tx.send(String::from_utf8_lossy(&body).into_owned());
                }
            });
        }
    });
    (format!("http://{addr}"), rx)
}

#[test]
fn agent_exports_otlp_metrics_to_collector() {
    let dir = std::env::temp_dir().join("flowsketch-otlp-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let (endpoint, bodies) = mock_otlp_collector();

    // Synthetic trace + config with OTLP export at a fast interval.
    let pcap = dir.join("otlp.pcap");
    assert!(flowsketch()
        .args([
            "synth",
            "--out",
            pcap.to_str().unwrap(),
            "--packets",
            "20000",
            "--seed",
            "4"
        ])
        .status()
        .unwrap()
        .success());
    let examples = workspace_root().join("examples/queries");
    let config = dir.join("agent.yaml");
    std::fs::write(
        &config,
        format!(
            "agent:\n  nodeName: otlp-node\n  listen: 127.0.0.1:0\n  flushIntervalMs: 50\n  \
             source:\n    kind: pcap\n    path: {}\nqueries:\n  - file: {}\n\
             export:\n  otlp:\n    endpoint: {}\n    intervalMs: 200\n",
            pcap.display(),
            examples.join("top-talkers.yaml").display(),
            endpoint,
        ),
    )
    .unwrap();
    let mut child = flowsketch()
        .args(["agent", "--config", config.to_str().unwrap()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // The exporter should deliver at least one document.
    let body = bodies
        .recv_timeout(Duration::from_secs(30))
        .expect("no OTLP export received");
    let _ = child.kill();
    let _ = child.wait();

    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let resource = &doc["resourceMetrics"][0]["resource"]["attributes"];
    assert!(resource
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "flowsketch-agent"));
    assert!(resource
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["key"] == "host.name" && a["value"]["stringValue"] == "otlp-node"));

    let metric = &doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
    assert_eq!(metric["name"], "network.flowsketch.bytes.estimated");
    let points = metric["gauge"]["dataPoints"].as_array().unwrap();
    assert!(!points.is_empty());
    let attrs = points[0]["attributes"].as_array().unwrap();
    assert!(
        attrs
            .iter()
            .any(|a| a["key"] == "flowsketch.query.name"
                && a["value"]["stringValue"] == "top_talkers")
    );
    assert!(attrs.iter().any(|a| a["key"] == "source.address"));
    assert!(attrs.iter().any(|a| a["key"] == "flowsketch.error.kind"
        && a["value"]["stringValue"] == "candidate-upper-bound"));
}

#[test]
fn agent_serves_metrics_health_and_query_inventory() {
    let dir = std::env::temp_dir().join("flowsketch-agent-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let agent = start_agent(&dir);

    let (status, body) = http_get(&agent.addr, "/healthz").unwrap();
    assert_eq!(status, 200, "{body}");

    let (status, metrics) = http_get(&agent.addr, "/metrics").unwrap();
    assert_eq!(status, 200);
    // Query estimates from all three queries, including the new measures.
    assert!(metrics.contains("query=\"top_talkers\""), "{metrics}");
    assert!(metrics.contains("query=\"packet_size_p99\""), "{metrics}");
    assert!(metrics.contains("algorithm=\"kll\""), "{metrics}");
    assert!(metrics.contains("error_kind=\"rank-error\""), "{metrics}");
    assert!(metrics.contains("query=\"source_entropy\""), "{metrics}");
    assert!(metrics.contains("error_kind=\"heuristic\""), "{metrics}");
    // Agent health block.
    assert!(metrics.contains("flowsketch_agent_events_processed_total"));
    assert!(metrics.contains("flowsketch_agent_sketch_memory_bytes"));
    assert!(metrics.contains("flowsketch_agent_queries_active 3"));

    let (status, queries) = http_get(&agent.addr, "/v1/queries").unwrap();
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&queries).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert!(arr.iter().any(|q| q["name"] == "packet_size_p99"
        && q["algorithm"] == "kll"
        && q["errorContract"].as_str().unwrap().contains("rank")));

    let (status, _) = http_get(&agent.addr, "/nope").unwrap();
    assert_eq!(status, 404);
}

#[test]
fn snapshots_from_separate_processes_merge() {
    let dir = std::env::temp_dir().join("flowsketch-merge-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let examples = workspace_root().join("examples/queries");
    let query = examples.join("suspected-scanners.yaml");

    // Two different traces, replayed by two separate process invocations,
    // as if on two nodes. Same seed => merge-compatible sketches.
    let mut snapshot_files = Vec::new();
    for (node, synth_seed) in [("a", 5u64), ("b", 6u64)] {
        let pcap = dir.join(format!("node-{node}.pcap"));
        assert!(flowsketch()
            .args([
                "synth",
                "--out",
                pcap.to_str().unwrap(),
                "--packets",
                "20000",
                "--scanners",
                "1",
                "--seed",
                &synth_seed.to_string(),
            ])
            .status()
            .unwrap()
            .success());
        let snap_dir = dir.join(format!("snaps-{node}"));
        assert!(flowsketch()
            .args([
                "replay",
                pcap.to_str().unwrap(),
                "--query",
                query.to_str().unwrap(),
                "--seed",
                "9",
                "--snapshot-out",
                snap_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success());
        let f = snap_dir.join("suspected_scanners.hllmap.fsk1");
        assert!(f.exists(), "snapshot file missing: {}", f.display());
        snapshot_files.push(f);
    }

    let merged_out = dir.join("merged.fsk1");
    let out = flowsketch()
        .arg("merge-snapshots")
        .args(&snapshot_files)
        .args(["--out", merged_out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("algorithm: hllmap"), "{text}");
    assert!(text.contains("top 20 by distinct count"), "{text}");
    // Both nodes' scanners (10.66.0.1) swept thousands of distinct dsts.
    assert!(text.contains("10.66.0.1"), "{text}");
    assert!(merged_out.exists());

    // Snapshots covering different time windows must be rejected: merging
    // them would silently mix time ranges into one estimate.
    let short_pcap = dir.join("short.pcap");
    assert!(flowsketch()
        .args([
            "synth",
            "--out",
            short_pcap.to_str().unwrap(),
            "--packets",
            "5000",
            "--scanners",
            "1",
            "--duration-secs",
            "30",
            "--seed",
            "5",
        ])
        .status()
        .unwrap()
        .success());
    let short_snaps = dir.join("snaps-short");
    assert!(flowsketch()
        .args([
            "replay",
            short_pcap.to_str().unwrap(),
            "--query",
            query.to_str().unwrap(),
            "--seed",
            "9",
            "--snapshot-out",
            short_snaps.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success());
    let out = flowsketch()
        .arg("merge-snapshots")
        .arg(&snapshot_files[0])
        .arg(short_snaps.join("suspected_scanners.hllmap.fsk1"))
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "window-mismatched merge was accepted"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("different time windows"), "{err}");

    // Mismatched seeds must be rejected, not silently merged.
    let snap_dir = dir.join("snaps-badseed");
    let pcap = dir.join("node-a.pcap");
    assert!(flowsketch()
        .args([
            "replay",
            pcap.to_str().unwrap(),
            "--query",
            query.to_str().unwrap(),
            "--seed",
            "1234",
            "--snapshot-out",
            snap_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success());
    let bad = snap_dir.join("suspected_scanners.hllmap.fsk1");
    let out = flowsketch()
        .arg("merge-snapshots")
        .arg(&snapshot_files[0])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success(), "incompatible merge was accepted");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("merge rejected"), "{err}");
}
