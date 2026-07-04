# Kubernetes deployment

These manifests are a production-prep baseline, not a Helm chart. They run:

- one `flowsketch-gateway` Deployment
- one `flowsketch-agent` DaemonSet using Linux AF_PACKET capture
- ConfigMaps for query files and service configs
- a gateway PodDisruptionBudget
- an optional gateway NetworkPolicy template

## Build and publish the image

```bash
docker build -t ghcr.io/monroestephenson/flowsketch:latest .
docker push ghcr.io/monroestephenson/flowsketch:latest
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
required for AF_PACKET. It does not run a fully privileged container.

The default interface is `eth0` in `flowsketch-agent-config`. Change it to
the node interface that carries the traffic you want to observe.

## Metrics

- Agent: `http://<node-ip>:9464/metrics`
- Gateway service: `flowsketch-gateway.flowsketch.svc:9465/metrics`

The agent pushes sketch snapshots to the gateway every 5 seconds. The
gateway merges only nodes with matching query plans, hash seeds, and window
boundaries.

The optional NetworkPolicy template allows labeled agent pods in the
`flowsketch` namespace to push to the gateway. Host-networked agents and
Prometheus scrapes may need additional CNI-specific allow rules.

## Production TODOs

- Convert these manifests to a Helm chart with image/tag/resources values.
- Add ServiceMonitor/PodMonitor templates for your Prometheus operator.
- Validate AF_PACKET capture on the target CNI and node OS.
- Pin CPU requests/limits after running `flowsketch bench --trace` on real
  cluster traffic.
