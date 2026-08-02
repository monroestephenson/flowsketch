# tc eBPF collector

FlowSketch has a Linux tc ingress collector baseline. The kernel program only
parses packet headers and emits normalized metadata; sketches, query planning,
windowing, enrichment, and export remain in userspace.

## Support boundary

- BPF ring buffers require Linux 5.8 or newer.
- The current validation target is x86_64 Ubuntu with Linux 6.8. Other kernels
  and architectures are not release-qualified until this repository's live
  gate passes on them.
- The build script supports x86_64, arm64, s390x, ppc64le, and riscv64 header
  layouts, but that is build support rather than runtime validation evidence.
- tc ingress is implemented. XDP and AF_XDP are not.
- IPv6 jumbograms and extension chains longer than six supported headers are
  deliberately classified as unsupported.

The kernel ABI remains the native-endian 56-byte `EbpfFlowEvent` record in
`flowsketch-ebpf`. The loader requires the expected program, maps, ABI symbol,
counter count, and record size; a mismatch fails the source rather than
decoding unknown bytes.

The ABI timestamp is `bpf_ktime_get_ns()` (`CLOCK_MONOTONIC`), not epoch time.
The agent samples `CLOCK_MONOTONIC` and `CLOCK_REALTIME` around every ring poll
and converts records to Unix nanoseconds before they enter windowing or OTLP.
This keeps eBPF and AF_PACKET events in the same clock domain while refreshing
the offset after wall-clock corrections.

## Packet parser

The verifier-safe C program handles:

- Ethernet and up to two 802.1Q/802.1ad VLAN tags;
- IPv4, including options and non-initial fragments;
- IPv6 with a bounded chain of hop-by-hop, routing, destination, fragment,
  and authentication headers;
- TCP ports, header length, and flags;
- UDP ports and length;
- other IP protocols with zero transport ports.

It uses bounded `bpf_skb_load_bytes` reads, never accesses payload content,
always returns `TC_ACT_OK`, and therefore never drops, redirects, or modifies
traffic.

## Build and run

Install Clang and libbpf development headers, then build both artifacts:

```bash
scripts/build-ebpf.sh
cargo build --locked --release -p flowsketch-cli
```

Configure the agent:

```yaml
agent:
  listen: 127.0.0.1:9464
  source:
    kind: ebpf
    interface: ens5f0
    objectPath: target/bpf/flowsketch_tc.bpf.o
    ringBufferBytes: 16777216
    fallbackToAfPacket: false
queries:
  - file: examples/queries/top-talkers.yaml
```

`ringBufferBytes` must be a power of two from 64 KiB through 1 GiB. The
production container includes the object at
`/usr/lib/flowsketch/flowsketch_tc.bpf.o`.

On the validated kernel, a non-root eBPF-only process uses:

```text
CAP_BPF
CAP_NET_ADMIN
CAP_PERFMON
```

It does not need CAP_SYS_ADMIN or CAP_NET_RAW. Legacy kernels and container
runtimes may impose different capability or seccomp constraints; qualify the
actual deployment rather than broadening privileges silently.

## Failure and fallback behavior

The default is fail-closed. Object read errors, ABI mismatch, verifier
rejection, attach failure, map errors, invalid records, and ring polling errors
make the capture source unhealthy. Aya first attempts the modern TCX link and
falls back to a `clsact` netlink attachment where needed. Dropping the loader
detaches either link.

`fallbackToAfPacket: true` explicitly permits a transition to TPACKET_V3 and
increments `flowsketch_agent_ebpf_fallbacks_total`. This mode also needs
CAP_NET_RAW. It is intentionally opt-in so a production deployment cannot
silently claim eBPF while running a different collector.

## Accounting contract

The eBPF program increments `packets` once for every tc invocation and then
exactly one terminal counter:

```text
packets = emitted + ring_drops + parse_errors + unsupported
emitted = userspace_seen
userspace_seen = parsed + unparsed
parsed = engine_processed + userspace_drops
```

The exported metrics are:

```text
flowsketch_agent_ebpf_packets_total
flowsketch_agent_ebpf_events_emitted_total
flowsketch_agent_ebpf_ring_dropped_events_total
flowsketch_agent_ebpf_parse_errors_total
flowsketch_agent_ebpf_unsupported_packets_total
flowsketch_agent_ebpf_fallbacks_total
flowsketch_agent_ebpf_ring_bytes
```

Per-CPU kernel counters are sampled about once per second. During active
traffic, independently read values may be briefly in flight; exact identities
must converge after traffic becomes idle.

## Reproducible Linux gate

Run:

```bash
bash scripts/linux-ebpf-live-smoke.sh target/release/flowsketch
```

The gate:

1. compiles the C object with warnings as errors;
2. loads it through the kernel verifier and attaches tc ingress;
3. runs the agent as a non-root user without CAP_SYS_ADMIN or CAP_NET_RAW;
4. replays mixed IPv4/IPv6 TCP/UDP traffic and requires exact, loss-free
   kernel-to-engine accounting;
5. injects one malformed IP frame and one non-IP frame and checks their
   mutually exclusive rejection counters;
6. stops userspace, overfills the BPF ring, resumes it, and requires every
   packet and both kernel/userspace loss layers to reconcile;
7. terminates the agent and verifies that the kernel program detached; and
8. starts a CAP_NET_RAW-only agent with a missing object and proves the
   explicitly configured AF_PACKET fallback captures the trace.

The Colima x86_64 Linux 6.8 result for the default loss-free phase was 50,000
offered, kernel, emitted, seen, parsed, and processed packets with zero ring or
userspace drops. A forced 300,000-packet overload with userspace stopped
filled the 16 MiB ring at 262,143 emitted records and counted the remaining
37,857 as ring drops. These are VM functional results, not line-rate hardware
performance claims.

## Next phases

1. Qualify the implemented queue-local AF_PACKET path with physical NIC replay
   and publish throughput, loss, CPU, convergence, and p99 evidence.
2. Implement an XDP producer for the same event/accounting contract.
3. Compare AF_PACKET, tc, and XDP on identical real traces and physical NICs.
4. Publish a kernel, architecture, container-runtime, and upgrade validation
   matrix.
