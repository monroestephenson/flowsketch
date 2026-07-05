# Production readiness checklist

FlowSketch is suitable for controlled beta deployments when run with the
current Linux AF_PACKET agent, gateway, and Prometheus/OTLP exports. Treat
the items below as the gate to broad production rollout.

## Build and release

- Build immutable container images from `Dockerfile`.
- Pin image tags in Kubernetes manifests or Helm values.
- Run CI on Linux and macOS.
- Run `cargo fmt --all --check`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Run `cargo test --workspace`.
- Run `cargo build --release -p flowsketch-cli`.

## Linux capture validation

- Validate AF_PACKET on the target kernel and CNI.
- Confirm the capture interface name on each node type.
- Grant only `CAP_NET_RAW` when possible.
- Track:
  - `flowsketch_agent_packets_seen_total`
  - `flowsketch_agent_events_processed_total`
  - `flowsketch_agent_dropped_events_total`
  - `flowsketch_agent_late_events_total`
  - gateway rejected snapshots and merged-node counts

## Capacity testing

Use real traces where legally available:

```bash
flowsketch bench --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --query examples/queries/suspected-scanners.yaml \
  --profile all
```

Interpret `100g` as **100 Gb/s** line-rate projection and `all` as the
1/10/25/40/100 Gb/s sweep. Confirm live capture separately with packet
generation or hardware replay.

For the current 10 Gb/s projection milestone, gate a representative trace with
a CPU budget:

```bash
flowsketch bench --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 10g \
  --core-budget 5
```

Passing this gate means the measured trace path projects to 10 Gb/s within
five cores on that machine and packet-size distribution. It is not a live NIC
claim until validated with packet-drop counters on Linux.

## Kubernetes

- Start from `deploy/kubernetes/`.
- Convert to Helm before multi-environment rollout.
- Start from the optional gateway NetworkPolicy template and add explicit
  allow rules for node CIDRs and monitoring namespace/pod labels.
- Add ServiceMonitor/PodMonitor if using Prometheus Operator.
- Tune resource requests/limits from benchmark data.
- Consider node selectors/tolerations for high-throughput nodes.

## Security

- Bind built-in HTTP endpoints only to trusted networks.
- Use mesh/proxy/collector for TLS and authentication.
- Keep query ConfigMaps under change control.
- Do not merge snapshots from untrusted sources.
- Review `docs/security.md`.

## eBPF

- Treat `flowsketch-ebpf` as the contract crate, not a collector yet.
- Keep eBPF parsing header-only.
- Keep sketches, query planning, and exports in userspace.
- Add ring-buffer drop counters before production use.
