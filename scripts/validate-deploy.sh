#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CHART="$ROOT/deploy/helm/flowsketch"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-deploy.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

for command in helm jq kubectl tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 1
  fi
done

jq -e '
  .uid == "flowsketch-overview"
  and .title == "FlowSketch Operations Overview"
  and (.panels | length >= 10)
  and ([.panels[].targets[]?.expr] | any(contains("flowsketch_agent_kernel_dropped_packets_total")))
  and ([.panels[].targets[]?.expr] | any(contains("flowsketch_gateway_nodes_merged")))
' "$CHART/dashboards/flowsketch-overview.json" >/dev/null

kubectl kustomize "$ROOT/deploy/kubernetes" >"$TMP/kustomize.yaml"
kubectl kustomize "$ROOT/deploy/kubernetes/monitoring" >"$TMP/monitoring.yaml"
helm lint "$CHART"
helm template default "$CHART" --namespace flowsketch >"$TMP/helm-default.yaml"
helm template monitored "$CHART" --namespace telemetry \
  --set monitoring.enabled=true \
  --set monitoring.dashboards.enabled=true \
  --set networkPolicy.enabled=true \
  --set agent.runtimeShards=8 \
  --set agent.runtimeBatchSize=8192 >"$TMP/helm-monitored.yaml"
helm template agent-only "$CHART" --namespace flowsketch \
  --set gateway.enabled=false >"$TMP/helm-agent-only.yaml"
helm template ebpf "$CHART" --namespace flowsketch \
  --set agent.source=ebpf >"$TMP/helm-ebpf.yaml"
helm template ebpf-fallback "$CHART" --namespace flowsketch \
  --set agent.source=ebpf \
  --set agent.ebpf.fallbackToAfPacket=true >"$TMP/helm-ebpf-fallback.yaml"
helm template affinity "$CHART" --namespace flowsketch \
  --set agent.cpuAffinity.enabled=true \
  --set agent.runtimeShards=2 \
  --set 'agent.cpuAffinity.runtimeCpus[0]=1' \
  --set 'agent.cpuAffinity.runtimeCpus[1]=2' >"$TMP/helm-affinity.yaml"
helm template fanout "$CHART" --namespace flowsketch \
  --set agent.runtimeShards=2 \
  --set agent.fanoutMode=rx_queue \
  --set agent.cpuAffinity.enabled=true \
  --set 'agent.cpuAffinity.captureCpus[0]=0' \
  --set 'agent.cpuAffinity.captureCpus[1]=1' \
  --set 'agent.cpuAffinity.runtimeCpus[0]=2' \
  --set 'agent.cpuAffinity.runtimeCpus[1]=3' >"$TMP/helm-fanout.yaml"
helm package "$CHART" --destination "$TMP" >/dev/null

grep -q 'kind: DaemonSet' "$TMP/helm-default.yaml"
grep -q 'kind: Deployment' "$TMP/helm-default.yaml"
grep -q 'runAsNonRoot: true' "$TMP/helm-default.yaml"
grep -q 'allowPrivilegeEscalation: true' "$TMP/helm-default.yaml"
grep -q '/usr/local/libexec/flowsketch-agent-afpacket' "$TMP/helm-default.yaml"
grep -q 'add: \["NET_RAW"\]' "$TMP/helm-default.yaml"
grep -q 'kind: ebpf' "$TMP/helm-ebpf.yaml"
grep -q 'objectPath: /usr/lib/flowsketch/flowsketch_tc.bpf.o' "$TMP/helm-ebpf.yaml"
grep -q 'add: \["BPF", "NET_ADMIN", "PERFMON"\]' "$TMP/helm-ebpf.yaml"
grep -q '/usr/local/libexec/flowsketch-agent-ebpf agent' "$TMP/helm-ebpf.yaml"
if grep -q 'add:.*NET_RAW' "$TMP/helm-ebpf.yaml"; then
  echo "eBPF-only render unexpectedly grants NET_RAW" >&2
  exit 1
fi
grep -q 'add: \["BPF", "NET_ADMIN", "PERFMON", "NET_RAW"\]' "$TMP/helm-ebpf-fallback.yaml"
grep -q '/usr/local/libexec/flowsketch-agent-ebpf-fallback' "$TMP/helm-ebpf-fallback.yaml"
grep -q 'captureCpus:' "$TMP/helm-affinity.yaml"
grep -q -- '- 2' "$TMP/helm-affinity.yaml"
grep -q 'fanoutMode: rx_queue' "$TMP/helm-fanout.yaml"
grep -q 'fanoutGroup: 0' "$TMP/helm-fanout.yaml"
grep -q -- '- 3' "$TMP/helm-fanout.yaml"
grep -q 'kind: PodMonitor' "$TMP/helm-monitored.yaml"
grep -q 'kind: ServiceMonitor' "$TMP/helm-monitored.yaml"
grep -q 'kind: PrometheusRule' "$TMP/helm-monitored.yaml"
grep -q 'name: monitored-flowsketch-dashboard' "$TMP/helm-monitored.yaml"
grep -q 'grafana_dashboard: "1"' "$TMP/helm-monitored.yaml"
grep -q 'flowsketch-overview.json: |' "$TMP/helm-monitored.yaml"
grep -q 'FlowSketchGatewayMergeGap' "$TMP/helm-monitored.yaml"
grep -q 'FlowSketchOtlpExportFailures' "$TMP/helm-monitored.yaml"
grep -q 'kind: NetworkPolicy' "$TMP/helm-monitored.yaml"
grep -q 'runAsNonRoot: true' "$TMP/kustomize.yaml"
grep -q 'allowPrivilegeEscalation: true' "$TMP/kustomize.yaml"
grep -q '/usr/local/libexec/flowsketch-agent-afpacket' "$TMP/kustomize.yaml"
grep -q 'ghcr.io/monroestephenson/flowsketch:0.1.0' "$TMP/kustomize.yaml"
grep -q 'kind: PodMonitor' "$TMP/monitoring.yaml"
grep -q 'FlowSketchPacketDrops' "$TMP/monitoring.yaml"
grep -q 'FlowSketchGatewayMergeGap' "$TMP/monitoring.yaml"
test -f "$TMP/flowsketch-0.1.0.tgz"
tar -tzf "$TMP/flowsketch-0.1.0.tgz" |
  grep -q '^flowsketch/dashboards/flowsketch-overview.json$'
if grep -R ':latest' "$ROOT/deploy/kubernetes" "$CHART"; then
  echo "deployment manifests contain a mutable latest image tag" >&2
  exit 1
fi
if grep -q 'kind: Deployment' "$TMP/helm-agent-only.yaml"; then
  echo "agent-only render unexpectedly contains a gateway Deployment" >&2
  exit 1
fi

if helm template invalid "$CHART" --set image.tag=latest >"$TMP/invalid" 2>&1; then
  echo "values schema accepted mutable image tag latest" >&2
  exit 1
fi
if helm template invalid "$CHART" --set gateway.replicas=2 >"$TMP/invalid" 2>&1; then
  echo "values schema accepted multiple in-memory gateway replicas" >&2
  exit 1
fi
if helm template invalid "$CHART" --set gateway.seed=1 >"$TMP/invalid" 2>&1; then
  echo "chart accepted incompatible agent and gateway hash seeds" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set serviceAccounts.agent.create=false >"$TMP/invalid" 2>&1; then
  echo "chart accepted a missing externally managed agent ServiceAccount" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.ebpf.fallbackToAfPacket=true >"$TMP/invalid" 2>&1; then
  echo "chart accepted eBPF fallback while agent.source is AF_PACKET" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.source=ebpf \
  --set agent.ebpf.ringBufferBytes=1000000 >"$TMP/invalid" 2>&1; then
  echo "values schema accepted a non-power-of-two eBPF ring" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.enabled=false --set gateway.enabled=false >"$TMP/invalid" 2>&1; then
  echo "chart accepted a release with no enabled workload" >&2
  exit 1
fi
if helm template invalid "$CHART" --set agent.otlp.enabled=true >"$TMP/invalid" 2>&1; then
  echo "chart accepted enabled OTLP without an endpoint" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.ringBlockSizeBytes=196608 >"$TMP/invalid" 2>&1; then
  echo "values schema accepted a non-power-of-two AF_PACKET ring block" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.ringBlockSizeBytes=16777216 \
  --set agent.ringBlockCount=65 >"$TMP/invalid" 2>&1; then
  echo "chart accepted an AF_PACKET receive ring larger than 1 GiB" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.cpuAffinity.enabled=true \
  --set agent.runtimeShards=2 >"$TMP/invalid" 2>&1; then
  echo "chart accepted CPU affinity without one runtime CPU per shard" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.fanoutMode=hash >"$TMP/invalid" 2>&1; then
  echo "chart accepted AF_PACKET fan-out with only one runtime shard" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.runtimeShards=2 \
  --set agent.runtimeShardStrategy=round_robin \
  --set agent.fanoutMode=hash >"$TMP/invalid" 2>&1; then
  echo "chart accepted AF_PACKET fan-out with round-robin runtime dispatch" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.runtimeShards=4 \
  --set agent.fanoutMode=rx_queue \
  --set agent.ringBlockSizeBytes=16777216 \
  --set agent.ringBlockCount=17 >"$TMP/invalid" 2>&1; then
  echo "chart accepted aggregate AF_PACKET fan-out rings larger than 1 GiB" >&2
  exit 1
fi
if helm template invalid "$CHART" \
  --set agent.source=ebpf \
  --set agent.runtimeShards=2 \
  --set agent.fanoutMode=hash >"$TMP/invalid" 2>&1; then
  echo "chart accepted AF_PACKET fan-out settings for an eBPF source" >&2
  exit 1
fi

echo "deployment validation passed"
