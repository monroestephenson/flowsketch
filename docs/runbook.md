# FlowSketch operations runbook

This runbook covers the supported operational baseline: one agent per Linux
node, one in-memory merge gateway, Prometheus scraping, and optional
agent-to-local-collector OTLP export. It deliberately does not claim gateway
high availability or built-in transport security.

## First five minutes of an incident

Set the release and namespace, then establish whether the problem is capture,
runtime processing, export, or gateway merge:

```bash
export RELEASE=flowsketch
export NAMESPACE=flowsketch

kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/instance="$RELEASE" -o wide
kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp
kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/instance="$RELEASE",app.kubernetes.io/component=agent --tail=200 --prefix
kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/instance="$RELEASE",app.kubernetes.io/component=gateway --tail=200 --prefix
```

Inspect one agent directly in a second terminal:

```bash
AGENT_POD=$(kubectl -n "$NAMESPACE" get pod \
  -l app.kubernetes.io/instance="$RELEASE",app.kubernetes.io/component=agent \
  -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NAMESPACE" port-forward "pod/$AGENT_POD" 19464:9464
```

```bash
curl -fsS http://127.0.0.1:19464/healthz
curl -fsS http://127.0.0.1:19464/readyz
curl -fsS http://127.0.0.1:19464/v1/queries | jq
curl -fsS http://127.0.0.1:19464/metrics
```

Inspect the gateway in another terminal:

```bash
kubectl -n "$NAMESPACE" port-forward "svc/$RELEASE-flowsketch-gateway" 19465:9465
```

```bash
curl -fsS http://127.0.0.1:19465/healthz
curl -fsS http://127.0.0.1:19465/readyz
curl -fsS http://127.0.0.1:19465/v1/nodes | jq
curl -fsS http://127.0.0.1:19465/metrics
```

Custom `fullnameOverride` values change the service name; select the gateway
service by its `app.kubernetes.io/instance` and component labels in that case.

Do not trust estimates while an agent is unready, packet-loss counters are
increasing, accounting does not settle, or the expected gateway nodes are not
merged. Preserve pod logs, the rendered configuration, kernel version,
container runtime, CNI, interface name, CPU allocation, and the relevant
counter values before restarting anything.

## Accounting contracts

Counter samples can be taken during different instructions in a busy process.
Check identities after traffic stops or over a settled interval; a transient
small delta during live capture is not by itself corruption.

For AF_PACKET, including each individual fan-out lane:

```text
kernel packets = packets seen + kernel drops
packets seen = packets parsed + packets unparsed
packets parsed = events processed + userspace drops
```

The sum of every `flowsketch_agent_af_packet_lane_*` counter must equal its
aggregate agent counter once a fan-out run settles. Queue freezes are a
separate kernel-pressure signal and are not added to the packet identity.
For HASH/RX_QUEUE fan-out,
`flowsketch_agent_af_packet_queue_local_handoff` must be 1 and the sum of
`flowsketch_agent_af_packet_lane_channel_capacity` must be 65,536. A missing
lane capacity or a zero handoff gauge means the expected queue-local topology
is not active; stop the rollout and inspect the rendered source mode and
runtime shard count.

For tc eBPF:

```text
eBPF packets = events emitted + ring drops + parse errors + unsupported packets
events emitted = packets seen
packets parsed = events processed + userspace drops
```

The Helm dashboard includes an accounting-invariants panel. The Linux gates
also assert these identities directly:

```bash
scripts/linux-afpacket-live-smoke.sh target/release/flowsketch
scripts/linux-afpacket-fanout-smoke.sh target/release/flowsketch
scripts/linux-ebpf-live-smoke.sh target/release/flowsketch
```

Run privileged live-capture gates only on an isolated test host or VM. The
scripts create interfaces, namespaces, qdiscs, and temporary capabilities and
clean them up on exit.

## Dashboard and alerts

The chart can publish `FlowSketch Operations Overview` as a Grafana sidecar
ConfigMap:

```yaml
monitoring:
  enabled: true
  labels:
    release: kube-prometheus-stack
  dashboards:
    enabled: true
    labels:
      grafana_dashboard: "1"
```

The Grafana installation must have a dashboard sidecar selecting the chosen
label. Without a sidecar, import
`deploy/helm/flowsketch/dashboards/flowsketch-overview.json` directly. The
dashboard uses a Prometheus data-source variable and filters Helm-monitored
series through the `flowsketch_release` scrape label.

### FlowSketchPacketDrops

This alert combines AF_PACKET kernel drops, AF_PACKET queue freezes, eBPF ring
drops, and userspace channel drops. Split the expression by metric and
instance before changing configuration.

- For AF_PACKET kernel drops, inspect NIC/RX-queue counters, per-lane rates,
  receive-ring size, capture CPU saturation, and CNI duplication. Increase
  ring memory only from measured evidence; the agent and chart cap all lane
  rings together at 1 GiB.
- If representative multi-flow traffic leaves fan-out lanes idle, verify NIC
  queue count/RSS and whether `hash` or `rx_queue` matches the environment.
  Confirm each configured capture/runtime CPU belongs to the pod cpuset.
- For queue freezes, inspect host softirq pressure and ring retirement. A
  larger ring can absorb bursts; a shorter retirement timeout reduces delay
  for partially filled blocks. Re-run the target-host fan-out gate after any
  change.
- For eBPF ring drops, inspect consumer CPU, runtime backpressure, and
  `ringBufferBytes`. Increasing the ring only absorbs bursts; sustained drops
  require reducing work or adding processing capacity.
- For userspace drops, inspect runtime CPU, batch rate, query count, window
  overlap, and sketch memory. Increase `runtimeShards` only with sufficient
  CPU and memory and remeasure flow skew.

Treat every sustained nonzero loss rate as incomplete observation. Do not
silence the alert solely because estimates still appear.

### FlowSketchEbpfParseErrors

The tc parser saw a malformed or truncated Ethernet/IP/transport header.
Compare `parse_errors` with `unsupported_packets`; the latter covers traffic
outside the supported parse contract and is not corruption. Capture a small,
authorized external trace at the same hook, identify the header shape, and
reproduce it with `scripts/linux-ebpf-live-smoke.sh`. Preserve the verifier and
agent logs. A sudden change after a kernel, CNI, offload, or encapsulation
upgrade is a rollback signal.

### FlowSketchEbpfFallback

The explicitly enabled AF_PACKET fallback was used after an eBPF load,
verifier, attach, or receive failure. The agent remains observable but is no
longer on the selected source. Check the embedded object, kernel support,
seccomp policy, and BPF/NET_ADMIN/PERFMON capabilities. Either restore eBPF or
formally accept the AF_PACKET capacity envelope; do not leave the downgrade
unexamined. Fallback must remain disabled when NET_RAW is not intentionally
granted.

### FlowSketchAgentNotReady

Read both `/healthz` and `/readyz` and inspect the agent log. Common causes are
an absent/renamed interface, missing capability, invalid CPU affinity, eBPF
verification or attachment failure, and a capture thread that failed after
startup. Compare the pod's node, interface, cpuset, kernel, and config with a
healthy node. A restart without fixing the source is not remediation.

### FlowSketchLateEvents

Events arrived before the earliest retained window. For live sources, verify
host clock synchronization and investigate timestamp discontinuities around
suspend, VM migration, or clock correction. For replay, verify trace ordering
and window settings. Increasing a window only to hide late input changes query
semantics and requires a reviewed query update.

### FlowSketchInvalidTimestamps

A live AF_PACKET timestamp or normalized eBPF monotonic timestamp fell outside
the five-minute realtime trust window and was quarantined before windowing.
Inspect host clock synchronization, suspend/resume or VM migration events,
kernel capture records, and the eBPF clock-conversion path. Do not widen the
trust window merely to silence the alert: a sufficiently future timestamp can
otherwise advance every shard and make subsequent traffic appear late.

### FlowSketchOtlpExportFailures

Confirm the node-local collector is ready and accepting OTLP/HTTP on the
configured endpoint. Check agent-to-collector DNS/network policy, collector
queue/backpressure, and downstream authentication/TLS from the collector.
FlowSketch intentionally accepts only plain `http://` OTLP endpoints; the
supported trust boundary is a local collector that applies TLS and credentials
on outward traffic.

### FlowSketchGatewayPushFailures

Check gateway readiness, service endpoints, DNS, and NetworkPolicy/CNI behavior
from an agent node. Host-networked agents may be classified by node IP rather
than pod labels. Brief failures are expected during the supported Recreate
gateway upgrade; they must stop after the gateway returns.

### FlowSketchGatewayRejectedSnapshots

Rejections are fail-closed compatibility decisions. Compare the agent and
gateway query files, hash seed, image version, and window configuration.
Coordinated query or seed changes can reject old-agent pushes during a rolling
transition; the counter must stop increasing after all agents run the same
configuration. Never work around this alert by accepting incompatible FSK1
state.

### FlowSketchGatewayMergeGap

`nodes_known - nodes_merged` remained positive for one query for five minutes.
While this gap is positive, `flowsketch_gateway_merge_complete` is `0` and the
gateway intentionally suppresses that query's cluster estimate rather than
publishing an undercount from only the freshest subset.
Inspect `/v1/nodes` for window boundaries and snapshot ages. Verify clocks,
query files, flush intervals, stalled agents, and packet timestamps. A brief
gap at a sliding-window boundary is valid; a persistent gap means the cluster
estimate excludes known nodes.

## Supported gateway recovery model

The gateway is an explicit single writer:

- The Helm schema permits exactly one replica.
- The Deployment uses `Recreate`, preventing old and new gateway pods from
  independently serving split in-memory state during an upgrade.
- State is not persisted. A restart temporarily removes merged estimates and
  resets gateway-local counters.
- Running agents continue pushing their latest snapshot. After a compatible
  gateway returns, its node inventory and estimates reconstruct without an
  operator restoring data.
- The PodDisruptionBudget reduces voluntary disruption but does not create
  high availability.

External monitoring must tolerate the bounded restart gap. There is no
zero-downtime gateway or multi-replica failover claim in this release. Validate
the exact recovery and incompatibility behavior with the release binary:

```bash
scripts/gateway-restart-smoke.sh target/release/flowsketch
```

The gate starts two continuously pushing agents, proves the initial merge,
restarts an empty compatible gateway and waits for repopulation, proves a
mismatched seed rejects all snapshots without estimates, then restores the
compatible gateway and proves recovery again.

If a gateway is lost unexpectedly, restore the same image, query files, and
seed. Confirm every expected node appears in `/v1/nodes`, every query's
`nodes_merged` reaches its expected value, rejected snapshots stop increasing,
and estimates return. Historical telemetry lives in Prometheus/OTLP storage,
not in the gateway.

## Upgrade procedure

### Preflight

1. Record the current chart revision, image digest, full values, rendered
   manifest, and query ConfigMaps:

   ```bash
   helm -n "$NAMESPACE" history "$RELEASE"
   helm -n "$NAMESPACE" get values "$RELEASE" --all > "${RELEASE}-values-before.yaml"
   helm -n "$NAMESPACE" get manifest "$RELEASE" > "${RELEASE}-manifest-before.yaml"
   kubectl -n "$NAMESPACE" get configmap \
     -l app.kubernetes.io/instance="$RELEASE" -o yaml > "${RELEASE}-configmaps-before.yaml"
   ```

2. Validate every proposed query with the candidate binary. Review `explain`
   output for memory, algorithm, error, cardinality, and warning changes.
3. Run `scripts/validate-deploy.sh`, the workspace tests, the gateway restart
   smoke, and the applicable Linux capture gates against the candidate.
4. Render the exact production values with `helm template` and review
   capabilities, host networking, interface, CPUs, ring sizes, resources,
   monitoring selectors, NetworkPolicy, image tag, seed, and queries.
5. Qualify the candidate on a dedicated node class or staging release before
   the fleet. A separate canary must use non-conflicting host ports, fan-out
   group, and gateway settings.

### Rollout

Use an immutable image tag or digest and an atomic Helm upgrade:

```bash
helm upgrade --install "$RELEASE" deploy/helm/flowsketch \
  --namespace "$NAMESPACE" \
  --values production-values.yaml \
  --atomic --wait --timeout 10m --history-max 10
```

The gateway is recreated and starts empty. The DaemonSet then rolls with its
configured `maxUnavailable`. During the rollout, watch:

- pod readiness and restarts;
- all capture, parse, and runtime loss counters;
- gateway push failures and rejected snapshots;
- expected `nodes_known` and `nodes_merged` recovery;
- accounting identities after each upgraded node settles;
- sketch memory and exported-series truncation;
- the external Prometheus/OTLP ingest path.

Changing queries, the hash seed, the hash-family version, or the FSK1 version
is a coordinated compatibility change. The current FSK1/hash v2 boundary is
intentionally incompatible with v1 state. Mixed old/new agents can be rejected
by the new gateway until the DaemonSet finishes. Stop and roll back if
rejections persist, expected nodes do not recover, readiness fails, or loss
begins increasing.

### Rollback

Choose the last known-good Helm revision and restore its exact image, values,
queries, and seed:

```bash
helm -n "$NAMESPACE" history "$RELEASE"
helm -n "$NAMESPACE" rollback "$RELEASE" REVISION \
  --wait --timeout 10m --cleanup-on-fail
```

Apply the same post-rollout gates. Because gateway state is ephemeral,
rollback recovery also depends on compatible agents repushing; an old gateway
must not merge snapshots from a still-incompatible agent fleet.

## Transport security and authorization

FlowSketch's HTTP servers have bounded requests but no TLS or authentication.
The supported production topology places them only on a trusted management
network and enforces identity at a service mesh, reverse proxy, or node-local
collector:

```text
agent capture process
  -> local HTTP metrics -> authenticated Prometheus scrape proxy/mesh
  -> local HTTP OTLP -> node-local collector -> TLS/auth -> remote backend
  -> authenticated cluster path -> gateway POST /v1/snapshots

Prometheus -> authenticated cluster path -> agent/gateway GET /metrics
operator   -> restricted management path -> health/query inventory endpoints
```

Required controls:

- Do not publish agent or gateway ports through an internet-facing
  LoadBalancer, ingress, or node firewall rule.
- Require workload identity and mTLS on every non-local hop. Authorize agent
  service accounts to `POST /v1/snapshots`; authorize monitoring identities to
  `GET /metrics`; restrict health and query inventory endpoints to probes and
  operators. Kubernetes NetworkPolicy alone cannot enforce HTTP methods, so
  use a layer-7 proxy or mesh for this separation.
- Verify how the CNI and mesh treat `hostNetwork` agents. If sidecar
  interception is unreliable, use a tested node-local proxy and node-IP
  NetworkPolicy/firewall rules.
- Put OTLP credentials and remote certificates in the collector or secret
  store, never query ConfigMaps, command-line arguments, dashboard JSON, or
  FlowSketch configuration committed to source control.
- Exercise certificate issuance, expiry alerts, rotation, and revocation in
  staging. During rotation, prove snapshot pushes, Prometheus scrapes, and
  collector export continue or recover without disabling verification.
- Treat IP addresses and other exported group labels as sensitive metadata.
  Apply downstream tenancy, retention, access, and deletion policy even though
  FlowSketch does not retain packet payloads.

See `docs/security.md` for the component trust boundaries and
`docs/production-readiness.md` for the release gate.

## Backup and evidence

Back up version-controlled query files, chart values, image digests, alert
configuration, dashboard revisions, and target-host validation reports. There
is no gateway database to back up. Retain test commands, trace provenance,
kernel/NIC/firmware details, traffic generator evidence, packet accounting,
CPU allocation, and raw reports for every physical throughput claim.

Virtual veth and VM passes prove correctness and integration, not physical
10/25/40/100 Gb/s capacity. Follow `docs/m4-validation.md` and
`docs/ebpf-roadmap.md`; do not remove the hardware-evidence caveat from release
notes until the corresponding isolated NIC gate passes.
