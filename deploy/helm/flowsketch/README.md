# FlowSketch Helm chart

This chart installs the Linux agent as a host-networked DaemonSet and, by
default, one in-memory merge gateway. AF_PACKET is the default; tc eBPF is an
opt-in source. It requires Kubernetes 1.25 or newer.

```bash
helm upgrade --install flowsketch deploy/helm/flowsketch \
  --namespace flowsketch --create-namespace \
  --set image.tag=0.1.0 \
  --set agent.interface=eth0
```

Production installations should use an immutable image digest or release tag,
measure resource settings on their node types, and verify both kernel and
userspace drop counters. The values schema rejects `latest` and gateway
replica counts above one.

## Runtime scaling

```yaml
agent:
  interface: ens5f0
  ringBlockSizeBytes: 1048576
  ringBlockCount: 64
  blockRetireTimeoutMs: 64
  runtimeShards: 8
  runtimeBatchSize: 8192
  runtimeShardStrategy: flow
  cpuAffinity:
    enabled: true
    captureCpu: 0
    runtimeCpus: [1, 2, 3, 4, 5, 6, 7, 8]
```

`flow` preserves directional 5-tuple affinity. `round_robin` balances packets
across mergeable sketch shards when elephant flows overload individual queues.
Sketch memory grows approximately with `runtimeShards`.
CPU affinity is opt-in and fails closed if a requested logical CPU is outside
the container's allowed cpuset. `runtimeCpus` must contain one unique CPU per
runtime shard. For Kubernetes, pair this with Guaranteed QoS and the static
CPU Manager policy; arbitrary host CPU IDs are not portable between nodes.

The three ring values configure the Linux TPACKET_V3 receive ring. Their
defaults allocate 64 MiB per agent. Increase the block count only after
measuring kernel drops and container memory on the target node; the chart and
agent reject rings above 1 GiB. A shorter retire timeout reduces latency for
quiet interfaces, while a longer timeout reduces block turnover.

## tc eBPF source

The production image contains `/usr/lib/flowsketch/flowsketch_tc.bpf.o`.
Select it with:

```yaml
agent:
  source: ebpf
  interface: ens5f0
  ebpf:
    objectPath: /usr/lib/flowsketch/flowsketch_tc.bpf.o
    ringBufferBytes: 16777216
    fallbackToAfPacket: false
```

This renders BPF, NET_ADMIN, and PERFMON capabilities instead of NET_RAW.
Enabling `fallbackToAfPacket` also grants NET_RAW and is rejected unless the
source is `ebpf`. The host kernel must support BPF ring buffers (Linux 5.8+),
the container runtime/seccomp profile must permit the BPF operations, and the
specific kernel/runtime pair should pass `scripts/linux-ebpf-live-smoke.sh`
before rollout. Current validation evidence is x86_64 Linux 6.8.

## Prometheus Operator

```yaml
monitoring:
  enabled: true
  labels:
    release: kube-prometheus-stack
  rules:
    enabled: true
    severity: warning
```

This renders a PodMonitor, ServiceMonitor, and alerts for packet drops, late
events, readiness, gateway push failures, and rejected snapshots. The cluster
must already contain the `monitoring.coreos.com` CRDs.

## Network policy

`networkPolicy.enabled=true` restricts gateway ingress to agents from the same
release. Host-network behavior varies by CNI; use
`networkPolicy.additionalGatewayIngress` for node CIDRs or monitoring
namespace selectors required by the target cluster.

## Gateway limitation

The current gateway keeps merge state in memory and is intentionally limited
to one replica. Its Deployment uses `Recreate` to prevent split state during
upgrades. Gateway HA requires a sharding or replicated-state design, not a
larger replica count.

Validate every deployment surface locally with:

```bash
scripts/validate-deploy.sh
```
