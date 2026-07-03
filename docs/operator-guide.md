# Operator guide (v0: offline replay)

v0 is the offline/replay milestone from README §26: prove the query model
on traces before shipping a live agent. Everything below runs from a
single static binary.

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

`--format prometheus` prints text exposition for the final window — the
same rendering the live agent will serve at `/metrics`.

## Cardinality guardrails

Every query has a hard `export.maxSeries` cap (default 1000). When the cap
truncates output, `flowsketch_export_series_dropped_total{query=...}` says
so. Raw-IP group-by labels produce an explicit plan warning. The planner
rejects queries whose sketch memory exceeds `resources.maxMemory`.

## Privacy posture

Headers and metadata only: the pcap parser never reads past the TCP/UDP
header, and payload bytes are never retained, hashed, or exported.

## Supported inputs (v0)

Classic pcap (`.pcap`, both endiannesses, µs/ns timestamps) over Ethernet
(incl. 802.1Q/QinQ), raw-IP, or Linux SLL link types; IPv4/IPv6 (with
extension-header walking); TCP/UDP ports and TCP flags. pcapng, live
capture, eBPF, and Hubble/NetFlow receivers are later phases (README §10).
