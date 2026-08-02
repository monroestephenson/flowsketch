# FlowSketch

[![CI](https://github.com/monroestephenson/flowsketch/actions/workflows/ci.yml/badge.svg)](https://github.com/monroestephenson/flowsketch/actions/workflows/ci.yml)
[![Linux live](https://github.com/monroestephenson/flowsketch/actions/workflows/linux-live.yml/badge.svg)](https://github.com/monroestephenson/flowsketch/actions/workflows/linux-live.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

FlowSketch is a bounded-memory network telemetry engine written in Rust. It
turns declarative questions such as “who are the top talkers?” or “which hosts
are scanning the most destinations?” into streaming sketches with explicit
error and memory contracts.

It can analyze packet captures offline, run as a Linux node agent, export to
Prometheus or OpenTelemetry, and merge compatible sketch state across nodes.
Packet payloads are never part of the event model.

> **Status:** pre-1.0 controlled beta. The offline engine and Linux functional
> paths are extensively tested. Published throughput numbers are projections
> unless a report explicitly identifies physical NIC hardware.

## Highlights

- YAML query language with plan-time memory limits and error contracts
- Count-Min, CountSketch, HyperLogLog, HLLMap, SpaceSaving, Misra-Gries, and KLL
- Sliding event-time windows and merge-correct parallel execution
- Linux TPACKET_V3, AF_PACKET HASH/RX_QUEUE fan-out, and tc eBPF capture
- Queue-local capture-to-runtime lanes with fail-closed CPU affinity
- Prometheus, OTLP/HTTP, and versioned `FSK1` sketch snapshots
- Cluster gateway for compatible cross-node window merges
- Docker, systemd, Helm, Kustomize, Grafana, and Prometheus alert assets

## Try it

FlowSketch requires Rust 1.85 or newer.

```bash
git clone https://github.com/monroestephenson/flowsketch.git
cd flowsketch
cargo build --locked --release -p flowsketch-cli

# Generate a repeatable trace with planted scanners and heavy talkers.
target/release/flowsketch synth \
  --out demo.pcap \
  --packets 200000 \
  --scanners 2 \
  --heavy-talkers 3

# Inspect the physical plan before running it.
target/release/flowsketch explain examples/queries/top-talkers.yaml

# Run two approximate queries over the trace.
target/release/flowsketch replay demo.pcap \
  --query examples/queries/top-talkers.yaml \
  --query examples/queries/suspected-scanners.yaml
```

To serve the same trace through the agent API:

```bash
target/release/flowsketch agent --config examples/agent.yaml
curl -s http://127.0.0.1:9464/metrics
curl -s http://127.0.0.1:9464/healthz
curl -s http://127.0.0.1:9464/v1/queries
```

## Queries

A query declares a window, grouping dimensions, measure, and export cap:

```yaml
name: top_talkers
window:
  size: 60s
  slide: 10s
groupBy:
  - src.ip
  - dst.ip
measure:
  type: heavy_hitters
  value: bytes
  limit: 100
export:
  prometheus: true
  maxSeries: 100
```

The planner chooses a bounded sketch and exposes its algorithm, estimated
memory, series limit, warnings, and error interpretation before execution.
See the [query language](docs/query-language.md) and
[accuracy contracts](docs/accuracy-contracts.md) for the supported fields and
semantics.

## Linux capture

The agent supports three source modes:

| Source | Use case | Privileges |
| --- | --- | --- |
| `pcap` | repeatable development and offline analysis | none |
| `af_packet` | live TPACKET_V3 capture | `CAP_NET_RAW` |
| `ebpf` | tc ingress capture through a BPF ring buffer | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` |

AF_PACKET selects its parser from the interface hardware type: Ethernet and
loopback use Ethernet framing, while TUN, WireGuard, and raw-IP interfaces use
raw IPv4/IPv6 framing. Unknown link types fail startup instead of remaining
healthy while parsing nothing. `hash` and `rx_queue` modes create one
socket/parser lane and one dedicated bounded runtime queue per shard. The Linux
smoke suite verifies both framing paths, exact aggregate and per-lane
accounting, capture/runtime pinning, and fail-closed affinity behavior. tc eBPF
fallback to AF_PACKET is explicit and counted.

Start with the [operator guide](docs/operator-guide.md) before granting
capabilities or enabling host-network capture.

## Architecture

```text
packet source
    -> bounded capture lane(s)
    -> event-time windows + mergeable sketches
    -> Prometheus / OTLP / FSK1 snapshots
    -> optional cluster merge gateway
```

Live capture never blocks waiting for sketch execution. If a bounded queue is
full, the event is dropped and counted. Kernel, parser, userspace, and per-lane
counters make loss visible and are checked by the Linux integration gates.

The gateway accepts only snapshots compatible with its local query plan, hash
seed, algorithm parameters, and window bounds. The current supported topology
is one in-memory gateway writer; replicated gateway HA is not claimed.

## Deployment

A published container image is not available yet; one will accompany the
first tagged release. Until then, build the container locally:

```bash
docker build -t flowsketch:local .
```

The Helm chart installs against an image you have built and pushed to your
own registry, using an immutable tag or digest:

```bash
helm upgrade --install flowsketch deploy/helm/flowsketch \
  --namespace flowsketch \
  --create-namespace \
  --set image.repository=<your-registry>/flowsketch \
  --set image.tag=0.1.0 \
  --set agent.interface=eth0
```

Review the [chart guide](deploy/helm/flowsketch/README.md),
[production checklist](docs/production-readiness.md), and
[incident runbook](docs/runbook.md) before a rollout.

## Verification

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/validate-deploy.sh
```

Linux live-capture gates require an isolated Linux host or VM and temporary
network namespaces:

```bash
scripts/linux-afpacket-live-smoke.sh target/release/flowsketch
scripts/linux-afpacket-rawip-smoke.sh target/release/flowsketch
scripts/linux-afpacket-fanout-smoke.sh target/release/flowsketch
scripts/linux-cpu-affinity-smoke.sh target/release/flowsketch
scripts/linux-ebpf-live-smoke.sh target/release/flowsketch
scripts/linux-m4-live-validation.sh target/release/flowsketch
```

The virtual M4 gate proves accounting and recovery behavior, not physical
10 Gb/s line rate. See [M4 validation](docs/m4-validation.md) for the hardware
acceptance procedure.

## Current boundaries

- No XDP or AF_XDP source yet
- No Kubernetes metadata enrichment or query operator yet
- No replicated or durable gateway state yet
- Built-in HTTP endpoints are plaintext; use a trusted network and a
  proxy, mesh, or local collector for authentication and TLS
- Physical 10/25/40/100 Gb/s qualification remains external hardware work

## Documentation

- [Operator guide](docs/operator-guide.md)
- [Query language](docs/query-language.md)
- [Accuracy contracts](docs/accuracy-contracts.md)
- [Production readiness](docs/production-readiness.md)
- [Security model](docs/security.md)
- [Runbook](docs/runbook.md)
- [Benchmarks](benchmarks/README.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
