# Production readiness checklist

FlowSketch is suitable for controlled beta deployments when run with the
current Linux AF_PACKET agent, gateway, and Prometheus/OTLP exports. Treat
the items below as the gate to broad production rollout.

## Build and release

- Build immutable container images from `Dockerfile`.
- Pin image tags in Kubernetes manifests or Helm values.
- Run CI on Linux and macOS.
- Run `cargo fmt --all --check`.
- Run `cargo clippy --locked --workspace --all-targets -- -D warnings`.
- Run `cargo test --locked --workspace`.
- Run `cargo build --locked --release -p flowsketch-cli`.
- Run `scripts/validate-deploy.sh` to lint, package, and render all Helm and
  Kustomize deployment profiles.

## Linux capture validation

- Validate AF_PACKET on the target kernel and CNI.
- Confirm the capture interface name on each node type.
- Grant only `CAP_NET_RAW`; `scripts/linux-afpacket-live-smoke.sh` exercises
  this least-privilege mode on a veth pair and network namespace.
- Run `scripts/linux-m4-live-validation.sh` first on an isolated veth pair,
  then with two isolated cabled 10 GbE ports and the hardware gate enabled;
  see `docs/m4-validation.md`.
- Track:
  - `flowsketch_agent_kernel_packets_total`
  - `flowsketch_agent_packets_seen_total`
  - `flowsketch_agent_packets_parsed_total`
  - `flowsketch_agent_packets_unparsed_total`
  - `flowsketch_agent_events_processed_total`
  - `flowsketch_agent_kernel_dropped_packets_total`
  - `flowsketch_agent_kernel_queue_freezes_total`
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
  --core-budget 2
```

Passing this gate means the measured trace path projects to 10 Gb/s within
two cores on that machine and packet-size distribution. It is not a live NIC
claim until validated with packet-drop counters on Linux.

For a runtime-only 100G event-time projection, separate parser, dispatch, and
merge-correct shard costs:

```bash
flowsketch bench --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 100g --runtime-shards 8 \
  --runtime-shard-strategy flow \
  --normalize-line-rate-gbps 100
```

Repeat with `round-robin` to quantify elephant-flow shard skew. Neither mode
is a live-NIC result. Production rollout still requires dedicated hardware
replay, direct RX-queue ingestion, target-host validation of the optional CPU
affinity configuration, and zero unexplained drops.

## Kubernetes

- Start from `deploy/kubernetes/`.
- Use `deploy/helm/flowsketch` for multi-environment rollout and keep image
  tags immutable.
- Start from the optional gateway NetworkPolicy template and add explicit
  allow rules for node CIDRs and monitoring namespace/pod labels.
- Apply `deploy/kubernetes/monitoring` when using Prometheus Operator and
  verify that its monitor/rule selectors include the `app.kubernetes.io/name`
  label.
- Tune resource requests/limits from benchmark data.
- Consider node selectors/tolerations for high-throughput nodes.

## Security

- Bind built-in HTTP endpoints only to trusted networks.
- Use mesh/proxy/collector for TLS and authentication.
- Keep query ConfigMaps under change control.
- Do not merge snapshots from untrusted sources.
- Review `docs/security.md`.

## eBPF

- The tc ingress collector is implemented and remains header-only; sketches,
  planning, windows, and exports stay in userspace.
- Current validation support is x86_64 Linux 6.8; qualify every production
  kernel/runtime combination and preserve verifier logs on failure.
- Alert on ring drops, parse errors, userspace drops, and explicit fallback.
- Keep fallback disabled unless the deployment intentionally grants NET_RAW
  and accepts an AF_PACKET downgrade.
- XDP, queue-local lane-to-worker channels, and physical high-rate comparison
  remain future work. AF_PACKET HASH/RX_QUEUE kernel fan-out and direct
  lane-to-shard mapping are implemented and VM-gated.
