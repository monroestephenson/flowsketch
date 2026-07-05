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
  --out /tmp/flowsketch-bench.pcap \
  --packets 200000 \
  --scanners 2 \
  --heavy-talkers 3 \
  --duration-secs 120 \
  --seed 77
```

Benchmark command:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile all
```

Result:

- parsed packets/events: 200000
- average L3 packet size: 631.8 bytes
- throughput: 0.49M events/s/core
- projected L3 capacity at 631.8-byte packets: 2.45 Gb/s/core
- 100 Gb/s target at 631.8-byte packets: 19.78M events/s
- projected cores for 100 Gb/s: 40.77
- runtime estimates: 1300
- sketch memory: 336.9 KiB
- late events: 0

10 Gb/s projection:

- target at 631.8-byte packets: 1.98M events/s
- projected cores for 10 Gb/s: 4.08
- M3 projection gate: `--profile 10g --core-budget 5`

Interpretation: current pcap parsing plus runtime query execution needs
parallel capture/sharding, eBPF or XDP ingestion, and drop accounting before a
credible 100 Gb/s live claim.

## Real-world comparison

Packet size controls how hard 100 Gb/s is:

| Packet shape | Approximate packet rate for 100 Gb/s | Current pcap/runtime core projection |
| ------------ | ------------------------------------ | ------------------------------------ |
| 1250-byte L3 packets | 10.00M packets/s | about 5.1% of target per core |
| 631.8-byte generated trace average | 19.78M packets/s | about 2.6% of target per core |
| minimum Ethernet frames on wire | about 148.8M packets/s | below 1% of target per core |

The current hot loop is good. The current end-to-end ingest/runtime path is
not yet a production 100 Gb/s design. Treat it as a correctness-focused
userspace baseline that now has measurable distance-to-target numbers.
