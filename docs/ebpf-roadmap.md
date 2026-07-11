# eBPF collector roadmap

FlowSketch should keep sketches in userspace. The eBPF program should only
parse packets, apply cheap filters, and emit normalized header metadata.

## Contract

The `flowsketch-ebpf` crate defines the versioned, native-endian 56-byte
`EbpfFlowEvent` ring-buffer contract a tc/XDP collector must produce. Its
`#[repr(C)]` layout is padding-free, has explicit direction values, safely
decodes unaligned byte slices, and rejects incompatible record sizes:

- timestamp
- IPv4/IPv6 source and destination
- TCP/UDP ports where available
- IP protocol
- TCP flags
- byte count
- interface index

`EbpfFlowEvent` converts into `flowsketch_core::FlowEvent`, so the existing
planner/runtime/exporter stack stays unchanged.

The ABI is ready for a Linux producer/loader conformance fixture. No kernel
program is loaded by this crate yet.

## Preferred phases

1. **tc ingress prototype**
   - Parse Ethernet, VLAN, IPv4, IPv6, TCP, and UDP.
   - Emit events through a ring buffer.
   - Drop malformed/truncated packets without verifier-risky parsing.

2. **Userspace loader**
   - Attach/detach programs by interface.
   - Feed ring-buffer events into the existing agent channel.
   - Expose dropped/ring-buffer-overrun counters in `/metrics`.

3. **XDP variant**
   - Same event contract.
   - Validate on NICs and kernels used by target deployments.

4. **Production validation**
   - Run `flowsketch bench --trace ... --profile 10g/100g`.
   - Run live packet generators or replay hardware at 1/10/25/40/100 Gb/s.
   - Track kernel drops, ring-buffer drops, agent channel drops, CPU, and
     memory.

## Non-goals for the kernel program

- No sketch state in eBPF maps for v1.
- No YAML query planner in kernel.
- No payload inspection.
- No Kubernetes metadata enrichment in kernel.

Keeping kernel logic small makes verifier behavior, kernel compatibility,
and production support tractable.
