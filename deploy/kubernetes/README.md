# Kubernetes deployment

These manifests are a fixed production-prep baseline. For configurable
multi-environment installs, use `deploy/helm/flowsketch`. The baseline runs:

- one `flowsketch-gateway` Deployment
- one `flowsketch-agent` DaemonSet using Linux AF_PACKET capture
- ConfigMaps for query files and service configs
- a gateway PodDisruptionBudget
- an optional gateway NetworkPolicy template

## Build and publish the image

```bash
docker build -t ghcr.io/monroestephenson/flowsketch:0.1.0 .
docker push ghcr.io/monroestephenson/flowsketch:0.1.0
```

Use a pinned immutable tag in production.

## Deploy

```bash
kubectl apply -k deploy/kubernetes
```

Review `deploy/kubernetes/networkpolicy.yaml` before applying it. The agent
uses `hostNetwork: true`, and some CNIs classify that traffic by node IP
rather than by pod labels. Add your node CIDRs and monitoring namespace/pod
labels before enabling strict default-deny policy.

## Capture privileges

The DaemonSet uses `hostNetwork: true` and adds only `NET_RAW`, which is
required for AF_PACKET. The image's AF_PACKET-specific entrypoint carries
`cap_net_raw=ep`; the pod permits that exec-time file-capability transition
inside a `drop: [ALL]` / `add: [NET_RAW]` bounding set. This is why the agent
container has `allowPrivilegeEscalation: true`: setting it to false enables
`no_new_privs`, leaving a non-root process with zero effective capabilities.
The pod remains non-root and is not a privileged container. The gateway keeps
`allowPrivilegeEscalation: false` and drops every capability.

The default interface is `eth0` in `flowsketch-agent-config`. Change it to
the node interface that carries the traffic you want to observe.

The fixed Kustomize baseline intentionally remains AF_PACKET. Use the Helm
chart with `agent.source=ebpf` for the tc collector; it renders BPF,
NET_ADMIN, and PERFMON instead of NET_RAW and points at the object embedded in
the production image. Enabling its explicit AF_PACKET fallback adds NET_RAW.
The image provides separate eBPF-only and eBPF-with-fallback capability
entrypoints so a source never receives capabilities outside its rendered
bounding set.
Qualify the node kernel and container runtime with
`scripts/linux-ebpf-live-smoke.sh` before rollout.

## Metrics

- Agent: `http://<node-ip>:9464/metrics`
- Gateway service: `flowsketch-gateway.flowsketch.svc:9465/metrics`

The agent pushes sketch snapshots to the gateway every 5 seconds. The
gateway merges only nodes with matching query plans, hash seeds, and window
boundaries.

The optional NetworkPolicy template allows labeled agent pods in the
`flowsketch` namespace to push to the gateway. Host-networked agents and
Prometheus scrapes may need additional CNI-specific allow rules.

## Prometheus Operator

Clusters with Prometheus Operator can install the optional monitoring pack:

```bash
kubectl apply -k deploy/kubernetes/monitoring
```

It installs a PodMonitor for host-networked agents, a ServiceMonitor for the
gateway, and PrometheusRule alerts for AF_PACKET/eBPF/userspace packet drops,
eBPF parse errors/fallback, invalid timestamps, late events, readiness, OTLP failures, gateway push
failures, rejected snapshots, and persistent merge gaps. Install the
`monitoring.coreos.com` CRDs before applying this pack. Operator deployments
that select monitors or rules by labels may require an environment-specific
label transformer or Kustomize overlay. Import the canonical Grafana dashboard
from `deploy/helm/flowsketch/dashboards/flowsketch-overview.json`; the
configurable Helm chart can also publish it as a sidecar ConfigMap.

## Production TODOs

- Validate the selected AF_PACKET or eBPF capture path on the target CNI,
  kernel, container runtime, and node OS.
- Pin CPU requests/limits after running `flowsketch bench --trace` on real
  cluster traffic.
- Apply the HTTP trust-boundary and upgrade/recovery procedures in
  `docs/runbook.md`; the built-in endpoints have no TLS or authentication and
  the gateway is a single in-memory writer.
