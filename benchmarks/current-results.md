# Current benchmark baseline

Measured on 2026-07-11 from the release binary on a local x86_64 Mac development
machine. These are capacity projections, not live NIC validation results.

## Count-Min hot loop

Command:

```bash
cargo run --release -p flowsketch-cli -- bench \
  --algo count-min \
  --events 5000000 \
  --keys 100000 \
  --dist zipf \
  --profile all \
  --avg-packet-bytes 1250
```

Result:

- throughput: 19.26M updates/s/core
- projected L3 capacity at 1250-byte packets: 192.61 Gb/s/core
- 100 Gb/s target at 1250-byte packets: 10.00M events/s
- projected cores for 100 Gb/s: 0.52
- sketch memory: 1.0 MiB
- ARE over truth top-1000: 0.0192

Interpretation: the sketch update loop itself is not the 100 Gb/s blocker for
large packets.

## Generated pcap plus runtime

Trace command:

```bash
target/release/flowsketch synth \
  --out /tmp/flowsketch-bench-2m.pcap \
  --packets 2000000 \
  --scanners 2 \
  --heavy-talkers 3 \
  --duration-secs 120 \
  --seed 77
```

Benchmark command:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench-2m.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile all
```

Result:

- parsed packets/events: 2000000
- average L3 packet size: 632.4 bytes
- throughput: 1.81M events/s/core
- projected L3 capacity at 632.4-byte packets: 9.13 Gb/s/core
- 100 Gb/s target at 632.4-byte packets: 19.76M events/s
- projected cores for 100 Gb/s: 10.95
- runtime estimates: 1300
- sketch memory: 752.2 KiB
- late events: 0

10 Gb/s projection:

- target at 632.4-byte packets: 1.98M events/s
- projected cores for 10 Gb/s: 1.09
- M3 projection gate: `--profile 10g --core-budget 2`

100 Gb/s projection:

- target at 632.4-byte packets: 19.76M events/s
- projected cores for 100 Gb/s: 10.95
- projection gate: `--profile 100g --core-budget 15`

Interpretation: current pcap parsing plus runtime query execution needs
parallel capture, eBPF or XDP ingestion, and hardware validation before a
credible 100 Gb/s live claim. The M3 two-core 10 Gb/s projection gate passes.

## GitHub-hosted Linux projection

The `linux-live.yml` workflow measured the generated 200,000-packet trace on
a GitHub-hosted Linux runner:

- average L3 packet size: 631.8 bytes
- throughput: 2.39M events/s/core
- projected capacity: 12.10 Gb/s/core
- 10 Gb/s target: 1.98M events/s
- projected cores for 10 Gb/s: 0.83
- runtime estimates: 1300
- late events: 0

This passes the enforced M3 `--core-budget 2` projection gate. It is pcap
replay on shared CI compute, not live 10 Gb/s capture or a stable hardware
performance baseline.

## Sharded runtime projection

The sharded runtime preloads parsed events, normalizes event time to the
candidate 100 Gb/s rate, and processes mergeable window states in parallel:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench-2m.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 100g \
  --runtime-shards 8 \
  --runtime-shard-strategy round-robin \
  --normalize-line-rate-gbps 100
```

Result:

- normalized event-time duration: 0.101191s
- parse preload: 7.63M events/s/core
- balanced partition: 8.21M dispatches/s/core
- shard imbalance: 1.00 max-to-mean
- three runtime samples: 10.87M, 10.93M, and 10.20M events/s
- 8-shard runtime median: 10.87M events/s
- projected aggregate L3 capacity: 54.99 Gb/s across 8 shards
- projected cores for 100 Gb/s from per-core shard rate: 14.55
- merged estimates: 100 (one set, not one duplicate set per shard)
- total sketch memory: 1.2 MiB

Exploratory flow-affine runs showed up to 1.87x max-to-mean shard skew from the
three planted elephant flows. The harness now defaults to three independent
runtime samples and reports the median so one favorable scheduler sample is
not presented as the baseline.

Interpretation: sharding is now production runtime code, not an ad hoc chunk
benchmark. Active shards share a watermark and completed window states merge
before estimates and snapshots are emitted. The runtime still falls short of
100 Gb/s on this host, and serial pcap parsing/dispatch falls short sooner.
The next step is direct parallel RX-queue parsing, CPU affinity, and live
eBPF/XDP hardware replay.

## Real-world comparison

Packet size controls how hard 100 Gb/s is:

| Packet shape | Approximate packet rate for 100 Gb/s | Current pcap/runtime core projection |
| ------------ | ------------------------------------ | ------------------------------------ |
| 1250-byte L3 packets | 10.00M packets/s | depends on the trace/query path |
| 632.4-byte generated trace average | 19.76M packets/s | about 9.1% single-stream; 55.0% aggregate with 8 balanced shards |
| minimum Ethernet frames on wire | about 148.8M packets/s | below 1% of target per core |

The current hot loop is good. The current end-to-end ingest/runtime path is
not yet a production 100 Gb/s design. Treat it as a correctness-focused
userspace baseline that now has measurable distance-to-target numbers.
