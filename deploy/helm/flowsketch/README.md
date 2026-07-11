# FlowSketch Helm chart

This chart installs the Linux AF_PACKET agent as a host-networked DaemonSet
and, by default, one in-memory merge gateway. It requires Kubernetes 1.25 or
newer.

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
  runtimeShards: 8
  runtimeBatchSize: 8192
  runtimeShardStrategy: flow
```

`flow` preserves directional 5-tuple affinity. `round_robin` balances packets
across mergeable sketch shards when elephant flows overload individual queues.
Sketch memory grows approximately with `runtimeShards`.

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
