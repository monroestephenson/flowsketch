# Operator guide

Everything runs from a single static binary: offline replay (README §26),
the live userspace agent (Phase 3), and distributed merge — both the
offline `merge-snapshots` primitive and the live cluster gateway
(Phase 7).

For deployment hardening and rollout gates, see
`docs/production-readiness.md`. For Kubernetes manifests, see
`deploy/kubernetes/`; use `deploy/helm/flowsketch` for configurable production
installs. For the eBPF collector contract and roadmap, see
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

For simple live capture on Linux, set `source.kind: af_packet` with an
`interface` — this opens a TPACKET_V3 memory-mapped AF_PACKET ring and needs
CAP_NET_RAW (or root). On
macOS and other non-Linux platforms, `source.kind: pcap` is supported for
development, demos, and offline analysis; `af_packet` returns a clear
"Linux only" error. The agent is a capture thread feeding a bounded channel
into the engine thread; when the engine falls behind, capture drops events
and counts them in `flowsketch_agent_dropped_events_total` rather than
blocking the NIC path. Linux AF_PACKET socket overflow is reported separately
as `flowsketch_agent_kernel_dropped_packets_total`; the socket counters are
sampled about once per second even when capture is idle. A capture failure flips
`/healthz` to 503 while `/metrics` keeps serving the last good state.

The default receive ring is 64 blocks of 1 MiB (64 MiB total), with partially
filled blocks retired after 64 ms:

```yaml
source:
  kind: af_packet
  interface: ens5f0
  ringBlockSizeBytes: 1048576
  ringBlockCount: 64
  blockRetireTimeoutMs: 64
  fanoutMode: single
  fanoutGroup: 0
```

Block size must be a power of two from 64 KiB through 16 MiB, timeout must be
1–1000 ms, and all rings combined may not exceed 1 GiB. Watch the ring gauges,
kernel packet/drop/freeze counters, parser dispositions, and userspace drops
when tuning. The dedicated M4 runbook is in `docs/m4-validation.md`.

For multi-queue capture, set `fanoutMode: rx_queue`; the agent creates one
TPACKET_V3 socket and parser lane per runtime shard, and Linux selects the lane
from the skb receive-queue mapping. `fanoutMode: hash` uses the kernel packet
hash and is useful for virtual or single-queue devices. Both modes require at
least two shards and `runtimeShardStrategy: flow`. `fanoutGroup: 0` derives a
process-local group. If a stable explicit nonzero 16-bit group is required, it
must remain unique to that agent/interface; sharing it with another capture
process would split traffic between processes. The kernel-selected lane is
carried through the bounded channel directly to the same-numbered runtime
shard. Per-lane metrics reconcile kernel, parser, engine, and drop totals.

For the tc ingress collector, build the object and select `ebpf`:

```bash
scripts/build-ebpf.sh
```

```yaml
source:
  kind: ebpf
  interface: ens5f0
  objectPath: target/bpf/flowsketch_tc.bpf.o
  ringBufferBytes: 16777216
  fallbackToAfPacket: false
```

The default is fail-closed: a missing object, verifier rejection, attachment
failure, ABI error, or ring read failure makes `/healthz` fail. Set
`fallbackToAfPacket: true` only when a deliberate, counted downgrade is
preferred; it additionally requires CAP_NET_RAW. The eBPF-only process needs
CAP_BPF, CAP_NET_ADMIN, and CAP_PERFMON on the validated Linux 6.8 target.
Watch `flowsketch_agent_ebpf_{packets,events_emitted,ring_dropped_events,
parse_errors,unsupported_packets}_total`; the kernel identity is packets =
emitted + ring drops + parse errors + unsupported. See
`docs/ebpf-roadmap.md` for validation and support boundaries.

For systemd installs, copy
`deploy/systemd/flowsketch-agent-ebpf.conf` into the unit's drop-in directory
and run `systemctl daemon-reload`. If explicit AF_PACKET fallback is enabled,
add CAP_NET_RAW to both capability lines in that drop-in.

Parallel runtime execution is configured under `agent`:

```yaml
runtimeShards: 8
runtimeBatchSize: 8192
runtimeShardStrategy: flow       # flow or round_robin
cpuAffinity:                     # optional; Linux logical CPU IDs
  captureCpus: [0]
  runtimeCpus: [1, 2, 3, 4, 5, 6, 7, 8]
```

`flow` preserves 5-tuple affinity and models normal RSS. `round_robin`
balances elephant-heavy traffic across mergeable sketch shards. Each shard
owns its window state; completed states are merged before metrics or gateway
snapshots are emitted. Memory grows approximately with the shard count, so
size it from measurements and keep the default of one for small nodes.
When `cpuAffinity` is present, `runtimeCpus` must contain one unique CPU per
runtime shard. `captureCpus` contains one CPU for ordinary sources and one per
runtime shard for AF_PACKET `hash`/`rx_queue` fan-out. Startup fails if Linux
rejects any requested CPU instead of silently running unpinned. Capture CPUs
may overlap runtime CPUs, but dedicated CPUs are preferable at high packet
rates. In Kubernetes,
use Guaranteed QoS with integer CPU requests/limits and a node configured with
the static CPU Manager policy; the configured host CPU IDs must belong to the
container's allowed cpuset. The affinity mapping is exported in `/metrics`.

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
