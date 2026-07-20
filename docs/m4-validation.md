# M4: live Linux 10 GbE validation

M4 is the hardware acceptance gate for the live Linux capture path. The same
script has two deliberately separate modes:

- The default isolated-veth mode proves deterministic end-to-end accounting,
  least privilege, ring configuration, and failure visibility on Linux/CI.
- Hardware mode proves sustained capture on two real, cabled 10 GbE ports.

A virtual-veth pass is required evidence, but it is not a 10 Gb/s claim.

## Acceptance criteria

A physical M4 report passes only when all of these conditions hold:

1. Capture and replay use different physical interfaces. Both report carrier,
   full duplex, and a negotiated speed of at least 10,000 Mb/s.
2. The agent runs as the invoking non-root user with exactly `CAP_NET_RAW` in
   its effective capability set.
3. Replay-interface TX and capture-interface RX packet deltas both equal the
   packet count reported by `tcpreplay`.
4. NIC TX/RX drop and error deltas are zero.
5. Accounting converges exactly:

   ```text
   offered = replay TX = capture RX = kernel packets
   kernel packets = packets seen + kernel drops
   packets seen = packets parsed + packets unparsed
   packets parsed = events processed + userspace drops
   ```

6. Kernel drops, TPACKET queue freezes, unparsed synthetic packets, and
   userspace drops are all zero.
7. Estimated wire occupancy is at least the configured threshold (9.5 Gb/s by
   default) for at least 10 seconds. The report records agent CPU, total host
   busy CPU, softirq time, softnet pressure, convergence latency, peak RSS, and
   ring settings.
8. If `FLOWSKETCH_M4_MAX_AGENT_CORES` is set, measured agent CPU remains at or
   below that explicit budget.

The deterministic trace contains Ethernet frames of at least 60 bytes.
`tcpreplay` reports captured L2 bytes, so the harness adds 4 bytes of FCS,
8 bytes of preamble/SFD, and 12 bytes of inter-frame gap per packet when it
estimates physical wire occupancy. Both the replayed-L2 and estimated-wire
rates appear in the report.

## Prerequisites

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 libcap2-bin tcpreplay
cargo build --locked --release -p flowsketch-cli
```

The invoking user needs noninteractive `sudo` for temporary network-namespace
setup, file capabilities, and raw replay. The long-running agent itself is not
root and receives only `CAP_NET_RAW`.

## Virtual correctness gate

Run this on any Linux host or VM:

```bash
scripts/linux-m4-live-validation.sh target/release/flowsketch
```

The script creates a private network namespace and veth pair, disables IPv6 on
the test link, generates a seeded full-payload pcap, rewrites its destination
MAC to the capture interface, and cleans up all temporary state. A passing
summary ends with an explicit warning that it is not physical 10 Gb/s
certification.

For a quick development run:

```bash
FLOWSKETCH_M4_PACKETS=10000 \
FLOWSKETCH_M4_LOOPS=1 \
FLOWSKETCH_M4_TARGET_MBPS=1000 \
scripts/linux-m4-live-validation.sh target/release/flowsketch
```

## Physical 10 GbE gate

Use an isolated capture port and replay port joined by a direct cable or an
isolated switch/VLAN. Keep unrelated traffic, address autoconfiguration, and
other capture processes off the two ports. Bring both links up before running
the gate. The harness verifies physical-device sysfs entries, carrier, duplex,
and speed; it will reject its own veth pair in hardware mode.

A 20-million-packet run is long enough to produce a useful CPU sample on a
10 GbE link while reusing a manageable 200,000-packet full-payload pcap:

```bash
FLOWSKETCH_M4_CAPTURE_INTERFACE=ens5f0 \
FLOWSKETCH_M4_REPLAY_INTERFACE=ens5f1 \
FLOWSKETCH_M4_HARDWARE_GATE=1 \
FLOWSKETCH_M4_PACKETS=200000 \
FLOWSKETCH_M4_LOOPS=100 \
FLOWSKETCH_M4_TARGET_MBPS=10000 \
FLOWSKETCH_M4_REPORT=benchmarks/m4-10gbe.md \
scripts/linux-m4-live-validation.sh target/release/flowsketch
```

If the replay port already lives in a network namespace, also set
`FLOWSKETCH_M4_REPLAY_NETNS`. To enforce a project-specific process CPU budget,
set `FLOWSKETCH_M4_MAX_AGENT_CORES` to a positive decimal value.

Do not publish a hardware PASS from a dirty worktree. The generated Markdown
report records the commit and worktree state, kernel, CPU model, tcpreplay
version, binary hash, rewritten trace hash, rate, CPU, memory, and every loss
counter needed to audit the result.

## Tuning controls

The validation defaults match a high-throughput agent profile:

| Environment variable | Default | Meaning |
| --- | ---: | --- |
| `FLOWSKETCH_M4_RING_BLOCK_SIZE_BYTES` | 1048576 | TPACKET_V3 block size |
| `FLOWSKETCH_M4_RING_BLOCK_COUNT` | 64 | Receive-ring blocks (64 MiB total by default) |
| `FLOWSKETCH_M4_BLOCK_RETIRE_TIMEOUT_MS` | 25 | Partial-block retirement timeout |
| `FLOWSKETCH_M4_RUNTIME_SHARDS` | 4 | Mergeable runtime workers |
| `FLOWSKETCH_M4_RUNTIME_BATCH_SIZE` | 8192 | Maximum runtime dispatch batch |
| `FLOWSKETCH_M4_ACCOUNTING_POLLS` | 300 | 100 ms polls allowed for final convergence |
| `FLOWSKETCH_M4_MIN_HARDWARE_GBPS` | 9.5 | Minimum estimated wire rate in hardware mode |
| `FLOWSKETCH_M4_MIN_HARDWARE_SECONDS` | 10 | Minimum sustained replay duration in hardware mode |

Ring blocks must be powers of two from 64 KiB through 16 MiB, the retirement
timeout must be 1–1000 ms, and total ring allocation may not exceed 1 GiB.
Tune only with measurements from the target kernel, NIC, NUMA layout, trace
shape, and query set.

## Reading failures

- Replay TX mismatch or errors point to the generator/interface path.
- Capture RX mismatch or NIC errors point to the cable, switch, driver, queue,
  or NIC configuration before AF_PACKET.
- Kernel drops or queue freezes mean userspace did not recycle TPACKET blocks
  quickly enough; inspect CPU placement and ring sizing.
- Userspace drops mean parsing outpaced the bounded engine channel/runtime;
  inspect shard strategy, query cost, and CPU allocation.
- Nonzero unparsed packets in this seeded trace are a parser regression.
- Exact counts with low rate are a capacity failure, not a correctness failure.
- A large convergence delay or replay-end backlog indicates the runtime kept
  up only after traffic stopped.

Colima and GitHub-hosted runners are valuable for the virtual correctness gate,
but neither exposes a dedicated physical 10 GbE link. Their reports must never
be relabeled as hardware evidence.
