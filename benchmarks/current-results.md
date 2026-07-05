# Current benchmark baseline

Measured on 2026-07-05 from the release binary on a local Mac development
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

- throughput: 19.53M updates/s/core
- projected L3 capacity at 1250-byte packets: 195.31 Gb/s/core
- 100 Gb/s target at 1250-byte packets: 10.00M events/s
- projected cores for 100 Gb/s: 0.51
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
- throughput: 1.54M events/s/core
- projected L3 capacity at 632.4-byte packets: 7.77 Gb/s/core
- 100 Gb/s target at 632.4-byte packets: 19.76M events/s
- projected cores for 100 Gb/s: 12.87
- runtime estimates: 1300
- sketch memory: 752.2 KiB
- late events: 0

10 Gb/s projection:

- target at 632.4-byte packets: 1.98M events/s
- projected cores for 10 Gb/s: 1.29
- M3 projection gate: `--profile 10g --core-budget 2`

100 Gb/s projection:

- target at 632.4-byte packets: 19.76M events/s
- projected cores for 100 Gb/s: 12.87
- projection gate: `--profile 100g --core-budget 14`

Interpretation: current pcap parsing plus runtime query execution needs
parallel capture/sharding, eBPF or XDP ingestion, and drop accounting before a
credible 100 Gb/s live claim.

## Sharded runtime projection

The sharded runtime mode preloads parsed events, then processes them across
independent userspace query engines:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench-2m.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 100g \
  --runtime-shards 16
```

Result:

- parse preload: 8.26M events/s/core
- 16-shard runtime aggregate: 7.14M events/s
- projected aggregate L3 capacity: 36.12 Gb/s across 16 shards
- projected cores for 100 Gb/s from per-core shard rate: 44.30

Interpretation: runtime sharding now works as a benchmark mode, but this
naive userspace split is not the production 100 Gb/s answer yet. The next
sharding step needs RSS/RX-queue affinity, fewer duplicated window flushes,
and live ingress paths instead of preloaded pcap events.

## Real-world comparison

Packet size controls how hard 100 Gb/s is:

| Packet shape | Approximate packet rate for 100 Gb/s | Current pcap/runtime core projection |
| ------------ | ------------------------------------ | ------------------------------------ |
| 1250-byte L3 packets | 10.00M packets/s | depends on the trace/query path |
| 632.4-byte generated trace average | 19.76M packets/s | about 7.8% of target per core |
| minimum Ethernet frames on wire | about 148.8M packets/s | below 1% of target per core |

The current hot loop is good. The current end-to-end ingest/runtime path is
not yet a production 100 Gb/s design. Treat it as a correctness-focused
userspace baseline that now has measurable distance-to-target numbers.
