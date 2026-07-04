# Operator guide

Everything runs from a single static binary: offline replay (README §26),
the live userspace agent (Phase 3), and cross-process sketch merge (the
Phase 7 primitive).

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

For live capture, set `source.kind: af_packet` with an `interface` — this
opens an AF_PACKET raw socket and needs CAP_NET_RAW (or root). The agent
is a capture thread feeding a bounded channel into the engine thread;
when the engine falls behind, capture drops events and counts them in
`flowsketch_agent_dropped_events_total` rather than blocking the NIC path.
A capture failure flips `/healthz` to 503 while `/metrics` keeps serving
the last good state.

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

## Cardinality guardrails

Every query has a hard `export.maxSeries` cap (default 1000). When the cap
truncates output, the `flowsketch_export_series_dropped{query=...}` gauge
says so. Raw-IP group-by labels produce an explicit plan warning. The
planner rejects queries whose sketch memory exceeds `resources.maxMemory`.

## Privacy posture

Headers and metadata only: the pcap parser never reads past the TCP/UDP
header, and payload bytes are never retained, hashed, or exported.

## Supported inputs (v0)

Classic pcap (`.pcap`, both endiannesses, µs/ns timestamps) over Ethernet
(incl. 802.1Q/QinQ), raw-IP, or Linux SLL link types; IPv4/IPv6 (with
extension-header walking); TCP/UDP ports and TCP flags. pcapng, live
capture, eBPF, and Hubble/NetFlow receivers are later phases (README §10).
