//! End-to-end gateway test: two simulated nodes run engines over disjoint
//! traffic, push their snapshots over real HTTP, and the gateway serves
//! merged cluster-level estimates that neither node could produce alone.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;

use flowsketch_core::hash::HashSpec;
use flowsketch_core::FlowEvent;
use flowsketch_gateway::{push_batch, GatewayConfig, PushBatch, PushEntry};
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::plan;
use flowsketch_runtime::QueryEngine;

const SCANNER_YAML: &str = "name: scanners\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
     measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n";

fn event(ts_s: u64, src: &str, dst: &str, bytes: u32) -> FlowEvent {
    FlowEvent {
        ts_nanos: ts_s * 1_000_000_000,
        src_ip: src.parse::<IpAddr>().unwrap(),
        dst_ip: dst.parse::<IpAddr>().unwrap(),
        src_port: 40_000,
        dst_port: 22,
        protocol: 6,
        bytes,
        ..FlowEvent::default()
    }
}

/// Start a gateway on an ephemeral port, returning its address.
fn start_gateway(seed: u64) -> SocketAddr {
    let dir = std::env::temp_dir().join(format!("fsk-gw-e2e-{}-{seed}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let query_file: PathBuf = dir.join("scanners.yaml");
    std::fs::write(&query_file, SCANNER_YAML).unwrap();

    let cfg = GatewayConfig::from_yaml(&format!(
        "gateway:\n  listen: 127.0.0.1:0\n  seed: {seed}\nqueries:\n  - file: {}\n",
        query_file.display()
    ))
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        flowsketch_gateway::run(cfg, move |addr| tx.send(addr).unwrap()).unwrap();
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("gateway did not start")
}

fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: gateway\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status: u16 = response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap();
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// Run an engine over `dst_prefix`-scoped scanning traffic and return its
/// push batch: one node's view of the same scanner.
fn node_batch(node: &str, dst_prefix: u8, seed: u64) -> PushBatch {
    let q = parse_query_yaml(SCANNER_YAML).unwrap();
    let p = plan(q, &HashSpec::new(seed)).unwrap();
    let mut eng = QueryEngine::new(vec![p], HashSpec::new(seed)).unwrap();
    for i in 0..1_000u32 {
        let dst = format!("10.{dst_prefix}.{}.{}", i / 256, i % 256);
        eng.process(&event(5, "10.0.1.50", &dst, 60)).unwrap();
    }
    PushBatch {
        node: node.to_string(),
        entries: eng
            .export_snapshots()
            .unwrap()
            .into_iter()
            .map(|s| PushEntry {
                query_name: s.query_name,
                component: s.component,
                snapshot: s.bytes,
            })
            .collect(),
    }
}

#[test]
fn gateway_merges_pushed_snapshots_into_cluster_estimates() {
    let addr = start_gateway(0);
    let url = format!("http://{addr}/v1/snapshots");

    // Each node sees the scanner hit 1000 destinations in its own /16.
    push_batch(&url, &node_batch("node-a", 1, 0).encode()).unwrap();
    push_batch(&url, &node_batch("node-b", 2, 0).encode()).unwrap();

    let (status, metrics) = http_get(addr, "/metrics");
    assert_eq!(status, 200);

    // The cluster-level estimate approximates the 2000-destination union.
    let estimate: f64 = metrics
        .lines()
        .find(|l| l.starts_with("flowsketch_estimate{") && l.contains("query=\"scanners\""))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .expect("scanners estimate served");
    assert!(
        (estimate - 2_000.0).abs() < 200.0,
        "cluster estimate {estimate} should approximate the union of both nodes"
    );
    assert!(metrics.contains("flowsketch_gateway_nodes_known{query=\"scanners\"} 2"));
    assert!(metrics.contains("flowsketch_gateway_nodes_merged{query=\"scanners\"} 2"));
    assert!(metrics.contains("flowsketch_gateway_pushes_total 2"));
    assert!(metrics.contains("flowsketch_gateway_snapshots_rejected_total 0"));

    // Node inventory is served for operators.
    let (status, nodes) = http_get(addr, "/v1/nodes");
    assert_eq!(status, 200);
    assert!(
        nodes.contains("node-a") && nodes.contains("node-b"),
        "{nodes}"
    );

    // Query metadata mirrors the agent's endpoint.
    let (status, queries) = http_get(addr, "/v1/queries");
    assert_eq!(status, 200);
    assert!(queries.contains("\"scanners\"") && queries.contains("hllmap"));

    let (status, _) = http_get(addr, "/healthz");
    assert_eq!(status, 200);
}

#[test]
fn gateway_rejects_incompatible_and_unknown_snapshots() {
    let addr = start_gateway(0);
    let url = format!("http://{addr}/v1/snapshots");

    // Wrong hash seed: sketches are not mergeable with the gateway's plan.
    let err = push_batch(&url, &node_batch("node-x", 1, 99).encode()).unwrap_err();
    assert!(err.to_string().contains("400"), "{err}");

    // Unknown query name.
    let mut batch = node_batch("node-x", 1, 0);
    for e in &mut batch.entries {
        e.query_name = "no-such-query".into();
    }
    let err = push_batch(&url, &batch.encode()).unwrap_err();
    assert!(err.to_string().contains("400"), "{err}");

    // Garbage body.
    let err = push_batch(&url, b"not a batch").unwrap_err();
    assert!(err.to_string().contains("400"), "{err}");

    let (_, metrics) = http_get(addr, "/metrics");
    assert!(
        metrics.contains("flowsketch_gateway_snapshots_rejected_total 2"),
        "{metrics}"
    );
    // Nothing merged, no estimates served.
    assert!(!metrics.contains("flowsketch_estimate{"));
}
