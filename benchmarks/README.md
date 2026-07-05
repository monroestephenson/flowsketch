# FlowSketch benchmarks

This directory documents benchmark inputs and commands. Large packet
captures are intentionally not checked in; `.gitignore` excludes `*.pcap`.

Current local baseline numbers are recorded in `benchmarks/current-results.md`.

## Real trace benchmarks

Use legally obtained classic pcap traces, for example CAIDA or MAWI traces
where your use is permitted. Put them outside the repository or under this
directory as ignored files.

```bash
cargo build --release -p flowsketch-cli

target/release/flowsketch bench \
  --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --query examples/queries/suspected-scanners.yaml \
  --profile all
```

The `--profile` value is a line-rate projection in gigabits per second
(`Gb/s`); use `1g`, `10g`, `25g`, `40g`, `100g`, or `all`.
It does not create a 100 Gb/s NIC test in CI. The harness reports:

- parsed events and packets read from the pcap
- average L3 packet size and observed timestamp rate in the trace
- measured parser/runtime throughput on the current CPU
- target events/sec for the selected 1/10/25/40/100 Gb/s profile(s) at the
  measured average packet size
- estimated cores needed to meet the selected target
- optional pass/fail readiness when `--core-budget` is provided
- runtime memory, estimate count, and late-event count when queries are run

For example, 100 Gb/s at 1250-byte packets is 10 million packets/events per
second. At 64-byte packets, the packet rate is much higher. Always interpret
the result with the trace's average packet size.

## 10 Gb/s projection gate

Use `--core-budget` when you want a benchmark to fail if the measured path
needs too many cores for a target line rate:

```bash
target/release/flowsketch bench \
  --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 10g \
  --core-budget 5
```

This is the current M3 milestone gate: **10 Gb/s projected mixed-traffic
capacity within a five-core CPU budget**. It is not the M4 milestone, which requires
live Linux capture validation with explicit packet-drop accounting.

## CI-safe benchmark tests

The normal test suite generates small synthetic pcaps and runs:

```bash
flowsketch bench --trace synthetic.pcap --query examples/queries/top-talkers.yaml --profile 10g --core-budget 1000
```

This verifies the real-trace harness and line-rate math without checking in
large or legally restricted traces. The high budget is intentional because
normal test runs use debug binaries on shared CI runners; release benchmark
gates are documented separately.

## Optional real-trace test hook

To run the same integration test against your local real trace:

```bash
FLOWSKETCH_REAL_TRACE=/data/caida-or-mawi.pcap \
FLOWSKETCH_REAL_TRACE_PROFILE=all \
cargo test -p flowsketch-cli bench_real_trace_if_configured -- --nocapture
```

The test is skipped when `FLOWSKETCH_REAL_TRACE` is not set.

## Interpreting 100 Gb/s readiness

Passing a 100 Gb/s projection means the measured code path appears capable
with the reported number of CPU cores for that packet-size distribution.
It is not a substitute for live Linux capture validation with AF_PACKET,
eBPF tc/XDP, NIC RSS configuration, CPU pinning, and packet-drop counters.
