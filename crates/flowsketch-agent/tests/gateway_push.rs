//! Full-pipeline test: two agents replay pcaps with disjoint scanner
//! targets and push snapshots to a live gateway, whose /metrics must show
//! the cluster-level union estimate.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flowsketch_pcap::writer::PcapWriter;

const SCANNER_YAML: &str = "name: scanners\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
     measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n";

fn test_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fsk-agent-gw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A pcap of one scanner probing 800 destinations inside 10.<prefix>.0.0/16.
fn write_scan_pcap(path: &Path, dst_prefix: u8) {
    let file = std::fs::File::create(path).unwrap();
    let mut w = PcapWriter::new(std::io::BufWriter::new(file)).unwrap();
    let src: IpAddr = "10.0.1.50".parse().unwrap();
    for i in 0..800u32 {
        let dst: IpAddr = format!("10.{dst_prefix}.{}.{}", i / 256, i % 256)
            .parse()
            .unwrap();
        w.write_tcp_packet((i as u64) * 10_000_000, src, dst, 40_000, 22, 0x02, 60)
            .unwrap();
    }
}

fn start_gateway(dir: &Path, query_file: &Path) -> SocketAddr {
    let cfg = flowsketch_gateway::GatewayConfig::from_yaml(&format!(
        "gateway:\n  listen: 127.0.0.1:0\nqueries:\n  - file: {}\n",
        query_file.display()
    ))
    .unwrap();
    let _ = dir;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        flowsketch_gateway::run(cfg, move |addr| tx.send(addr).unwrap()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("gateway did not start")
}

fn start_agent(node: &str, pcap: &Path, query_file: &Path, gateway: SocketAddr) {
    let cfg = flowsketch_agent::AgentConfig::from_yaml(&format!(
        "agent:\n  nodeName: {node}\n  listen: 127.0.0.1:0\n  flushIntervalMs: 50\n\
         \x20 source:\n    kind: pcap\n    path: {}\nqueries:\n  - file: {}\n\
         export:\n  gateway:\n    endpoint: http://{gateway}\n    intervalMs: 100\n",
        pcap.display(),
        query_file.display()
    ))
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The agent parks forever after a finite source; leak the thread.
        let _ = flowsketch_agent::run(cfg, move |addr| tx.send(addr).unwrap());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("agent did not start");
}

fn scrape_metrics(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: gateway\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn agents_push_snapshots_and_gateway_serves_cluster_estimate() {
    let dir = test_dir();
    let query_file = dir.join("scanners.yaml");
    std::fs::write(&query_file, SCANNER_YAML).unwrap();
    let pcap_a = dir.join("node-a.pcap");
    let pcap_b = dir.join("node-b.pcap");
    write_scan_pcap(&pcap_a, 1);
    write_scan_pcap(&pcap_b, 2);

    let gateway = start_gateway(&dir, &query_file);
    start_agent("node-a", &pcap_a, &query_file, gateway);
    start_agent("node-b", &pcap_b, &query_file, gateway);

    // Poll until both nodes' snapshots arrived and merged (agents push
    // every 100ms once replay finishes).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let metrics = scrape_metrics(gateway);
        if metrics.contains("flowsketch_gateway_nodes_merged{query=\"scanners\"} 2") {
            let estimate: f64 = metrics
                .lines()
                .find(|l| l.starts_with("flowsketch_estimate{") && l.contains("query=\"scanners\""))
                .and_then(|l| l.rsplit(' ').next())
                .and_then(|v| v.parse().ok())
                .expect("scanners estimate served");
            assert!(
                (estimate - 1_600.0).abs() < 160.0,
                "cluster estimate {estimate} should approximate the 1600-destination union"
            );
            assert!(metrics.contains("flowsketch_gateway_snapshots_rejected_total 0"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "gateway never merged both nodes; last metrics:\n{metrics}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
