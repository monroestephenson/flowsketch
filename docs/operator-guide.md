# Operator guide

Everything runs from a single static binary: offline replay (README §26),
the live userspace agent (Phase 3), and distributed merge — both the
offline `merge-snapshots` primitive and the live cluster gateway
(Phase 7).

For deployment hardening and rollout gates, see
`docs/production-readiness.md`. For Kubernetes manifests, see
`deploy/kubernetes/`. For the eBPF collector contract and roadmap, see
`docs/ebpf-roadmap.md`.

## Build

```bash
cargo build --release
# binary at target/release/flowsketch
```

## Try it in 60 seconds (no capture files needed)

```bash
# 1. Generate a reproducible synthetic trace with planted anomalies:
flowsketch synth --out demo.pcap --packets 200000 --scanners 2 --heavy-talkers 3

# 2. See what a query will cost before running it:
flowsketch explain examples/queries/suspected-scanners.yaml

# 3. Replay the trace:
flowsketch replay demo.pcap \
  --query examples/queries/top-talkers.yaml \
  --query examples/queries/suspected-scanners.yaml \
  --query examples/queries/protocol-bytes.yaml
```

The planted heavy talkers (`10.1.1.x -> 10.2.2.x`) lead the top-talkers
table; only the planted scanners (`10.66.0.x`) cross the scanner alert.

## Commands

| command | purpose |
| ------- | ------- |
| `flowsketch replay <pcap> --query q.yaml [--format table\|prometheus\|json]` | run queries over a trace |
| `flowsketch explain q.yaml` | physical plan, memory estimate, error contract, warnings |
| `flowsketch validate q.yaml...` | parse + plan check; nonzero exit on failure |
| `flowsketch bench --algo count-min --events 10000000` | throughput + accuracy vs exact |
| `flowsketch synth --out t.pcap ...` | reproducible synthetic traces |
| `flowsketch agent --config agent.yaml` | live agent: capture + HTTP endpoints |
| `flowsketch replay ... --snapshot-out DIR` | dump final sketch state as FSK1 files |
| `flowsketch merge-snapshots a.fsk1 b.fsk1 [--out m.fsk1]` | merge sketches across nodes/processes |
| `flowsketch gateway --config gateway.yaml` | cluster gateway: receive agent pushes, serve merged /metrics |

`--format prometheus` prints text exposition for the final window — the
same rendering the live agent will serve at `/metrics`.

## Live agent

```bash
flowsketch synth --out demo.pcap --packets 200000
flowsketch agent --config examples/agent.yaml   # pcap demo source
curl -s localhost:9464/metrics | head            # estimates + agent health
curl -s localhost:9464/healthz                   # capture-source health
curl -s localhost:9464/v1/queries | jq           # plans, memory, error contracts
```

For live capture on Linux, set `source.kind: af_packet` with an `interface`
— this opens an AF_PACKET raw socket and needs CAP_NET_RAW (or root). On
macOS and other non-Linux platforms, `source.kind: pcap` is supported for
development, demos, and offline analysis; `af_packet` returns a clear
"Linux only" error. The agent is a capture thread feeding a bounded channel
into the engine thread; when the engine falls behind, capture drops events
and counts them in `flowsketch_agent_dropped_events_total` rather than
blocking the NIC path. Linux AF_PACKET socket overflow is reported separately
as `flowsketch_agent_kernel_dropped_packets_total`. A capture failure flips `/healthz` to 503 while
`/metrics` keeps serving the last good state.

Parallel runtime execution is configured under `agent`:

```yaml
runtimeShards: 8
runtimeBatchSize: 8192
runtimeShardStrategy: flow       # flow or round_robin
```

`flow` preserves 5-tuple affinity and models normal RSS. `round_robin`
balances elephant-heavy traffic across mergeable sketch shards. Each shard
owns its window state; completed states are merged before metrics or gateway
snapshots are emitted. Memory grows approximately with the shard count, so
size it from measurements and keep the default of one for small nodes.

In pcap-source mode, the capture source is finite: once the file is fully
processed, the agent marks `flowsketch_agent_source_done` and keeps serving
the final published window until the process is terminated. Thread startup
failures return errors instead of panicking, and the embedded HTTP server
caps concurrent connections, request-line/header sizes, and read/write
timeouts.

## OTLP export

Add an `export.otlp` block to the agent config to push estimates to any
OTLP/HTTP endpoint (OpenTelemetry Collector, Grafana Alloy, the Datadog
OTel path):

```yaml
export:
  otlp:
    endpoint: http://otel-collector:4318   # /v1/metrics appended
    intervalMs: 5000
```

Estimates become `network.flowsketch.<unit>.estimated` gauges with
`service.name`/`host.name` resource attributes and query metadata plus
group labels as attributes (`src.ip` maps to `source.address`, `protocol`
to `network.protocol.name`, and so on). Already-exported windows are
skipped, transient failures retry with exponential backoff, and export
health shows up in `/metrics` as `flowsketch_agent_otlp_exports_total` /
`flowsketch_agent_otlp_export_failures_total`. Plain `http://` only in
v0 — run the collector next to the agent, which is the standard shape.

## Distributed merge (two-node demo)

```bash
# "node A" and "node B" replay different traffic with the SAME --seed:
flowsketch replay a.pcap --query q.yaml --seed 9 --snapshot-out snaps-a
flowsketch replay b.pcap --query q.yaml --seed 9 --snapshot-out snaps-b
# combine into cluster-wide estimates:
flowsketch merge-snapshots snaps-a/*.fsk1 snaps-b/*.fsk1
```

Merges validate algorithm, parameters, hash family, and seed from the
FSK1 headers; mismatches are rejected loudly, never silently merged.

## Cluster gateway (live distributed merge)

The gateway turns the snapshot-merge primitive into a running service:
each agent periodically pushes its current window's sketch snapshots, and
the gateway serves cluster-level estimates no single node could compute
(cluster-wide top-k, distinct destinations across all nodes).

```text
agent on node A ─┐  POST /v1/snapshots (FSK1 snapshots, FSKB batch)
agent on node B ─┼─> flowsketch gateway ──> GET /metrics (merged)
agent on node C ─┘
```

```bash
# Gateway side — same query files and seed as the agents:
flowsketch gateway --config examples/gateway.yaml

# Agent side — add a push block to each agent config:
# export:
#   gateway:
#     endpoint: http://flowsketch-gateway:9465
#     intervalMs: 5000

curl -s localhost:9465/metrics   # merged estimates + gateway health
curl -s localhost:9465/v1/nodes  # per-node windows, freshness, sizes
```

Semantics and safety:

- Every pushed sketch is validated against the gateway's own plan for
  that query (algorithm, parameters, hash family and seed) before it may
  merge; incompatible or unknown pushes are rejected with HTTP 400 and
  counted in `flowsketch_gateway_snapshots_rejected_total`.
- Only nodes covering **exactly the same window boundaries** merge
  (README §17.3). Nodes on other boundaries are excluded from that round
  and visible as the gap between `flowsketch_gateway_nodes_known` and
  `flowsketch_gateway_nodes_merged`.
- Gateway memory is bounded: one window state per (query, live node),
  each within the planner's budget; nodes that stop pushing are evicted
  after `staleAfterMs`.
- The gateway HTTP server caps concurrent connections, request-line/header
  sizes, POST body size, and read/write timeouts. Agent push clients cap
  endpoint length, request body size, response reads, and retry count.
- Estimates keep their error contracts: the merged output carries the
  same `algorithm`/`error_kind` labels and series caps as node-local
  export.

## Cardinality guardrails

Every query has a hard `export.maxSeries` cap (default 1000). When the cap
truncates output, the `flowsketch_export_series_dropped{query=...}` gauge
says so. Raw-IP group-by labels produce an explicit plan warning. The
planner rejects queries whose sketch memory exceeds `resources.maxMemory`.

## Privacy posture

Headers and metadata only: the pcap parser never reads past the TCP/UDP
header, and payload bytes are never retained, hashed, or exported.

See `docs/security.md` for the full security posture, including HTTP
exposure, capture privileges, exporter trust boundaries, and snapshot
handling.

## Supported inputs (v0)

Classic pcap (`.pcap`, both endiannesses, µs/ns timestamps) over Ethernet
(incl. 802.1Q/QinQ), raw-IP, or Linux SLL link types; IPv4/IPv6 (with
extension-header walking); TCP/UDP ports and TCP flags. Linux live capture
is available through AF_PACKET. pcapng, macOS BPF live capture, eBPF, and
Hubble/NetFlow receivers are later phases (README §10).
