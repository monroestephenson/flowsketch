#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CHART="$ROOT/deploy/helm/flowsketch"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-deploy.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

for command in helm kubectl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 1
  fi
done

kubectl kustomize "$ROOT/deploy/kubernetes" >"$TMP/kustomize.yaml"
kubectl kustomize "$ROOT/deploy/kubernetes/monitoring" >"$TMP/monitoring.yaml"
helm lint "$CHART"
helm template default "$CHART" --namespace flowsketch >"$TMP/helm-default.yaml"
helm template monitored "$CHART" --namespace telemetry \
  --set monitoring.enabled=true \
  --set networkPolicy.enabled=true \
  --set agent.runtimeShards=8 \
  --set agent.runtimeBatchSize=8192 >"$TMP/helm-monitored.yaml"
helm template agent-only "$CHART" --namespace flowsketch \
  --set gateway.enabled=false >"$TMP/helm-agent-only.yaml"
helm package "$CHART" --destination "$TMP" >/dev/null

grep -q 'kind: DaemonSet' "$TMP/helm-default.yaml"
grep -q 'kind: Deployment' "$TMP/helm-default.yaml"
grep -q 'runAsNonRoot: true' "$TMP/helm-default.yaml"
grep -q 'add: \["NET_RAW"\]' "$TMP/helm-default.yaml"
grep -q 'kind: PodMonitor' "$TMP/helm-monitored.yaml"
grep -q 'kind: ServiceMonitor' "$TMP/helm-monitored.yaml"
grep -q 'kind: PrometheusRule' "$TMP/helm-monitored.yaml"
grep -q 'kind: NetworkPolicy' "$TMP/helm-monitored.yaml"
grep -q 'runAsNonRoot: true' "$TMP/kustomize.yaml"
grep -q 'ghcr.io/monroestephenson/flowsketch:0.1.0' "$TMP/kustomize.yaml"
grep -q 'kind: PodMonitor' "$TMP/monitoring.yaml"
grep -q 'FlowSketchPacketDrops' "$TMP/monitoring.yaml"
test -f "$TMP/flowsketch-0.1.0.tgz"
if grep -R ':latest' "$ROOT/deploy/kubernetes" "$CHART" --exclude='validate-deploy.sh'; then
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
  --set agent.enabled=false --set gateway.enabled=false >"$TMP/invalid" 2>&1; then
  echo "chart accepted a release with no enabled workload" >&2
  exit 1
fi
if helm template invalid "$CHART" --set agent.otlp.enabled=true >"$TMP/invalid" 2>&1; then
  echo "chart accepted enabled OTLP without an endpoint" >&2
  exit 1
fi

echo "deployment validation passed"
