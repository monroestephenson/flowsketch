#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-target/release/flowsketch}
case "$BIN" in
  /*) ;;
  *) BIN="$ROOT/$BIN" ;;
esac

PORT=${FLOWSKETCH_GATEWAY_SMOKE_PORT:-19465}
URL="http://127.0.0.1:$PORT"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-gateway-restart.XXXXXX")
GATEWAY_PID=
AGENT_A_PID=
AGENT_B_PID=
GATEWAY_RUN=0
MAX_ATTEMPTS=${FLOWSKETCH_GATEWAY_SMOKE_ATTEMPTS:-100}

cleanup() {
  for pid in ${AGENT_A_PID:-} ${AGENT_B_PID:-} ${GATEWAY_PID:-}; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in ${AGENT_A_PID:-} ${AGENT_B_PID:-} ${GATEWAY_PID:-}; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
}

show_logs() {
  for log in "$TMP"/*.log; do
    if [ -f "$log" ]; then
      echo "--- $log" >&2
      tail -80 "$log" >&2
    fi
  done
}

fail() {
  echo "gateway restart smoke failed: $*" >&2
  show_logs
  exit 1
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for command in curl grep mktemp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    fail "required command not found: $command"
  fi
done
if [ ! -x "$BIN" ]; then
  fail "FlowSketch binary is not executable: $BIN"
fi
case "$PORT" in
  '' | *[!0-9]*) fail "FLOWSKETCH_GATEWAY_SMOKE_PORT must be an integer" ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  fail "FLOWSKETCH_GATEWAY_SMOKE_PORT must be between 1024 and 65535"
fi
case "$MAX_ATTEMPTS" in
  '' | *[!0-9]*) fail "FLOWSKETCH_GATEWAY_SMOKE_ATTEMPTS must be a positive integer" ;;
esac
if [ "$MAX_ATTEMPTS" -lt 1 ]; then
  fail "FLOWSKETCH_GATEWAY_SMOKE_ATTEMPTS must be a positive integer"
fi
if curl -fsS --max-time 1 "$URL/healthz" >/dev/null 2>&1; then
  fail "$URL is already serving HTTP; choose FLOWSKETCH_GATEWAY_SMOKE_PORT"
fi

cp "$ROOT/examples/queries/suspected-scanners.yaml" "$TMP/query.yaml"
"$BIN" synth --out "$TMP/source.pcap" --packets 20000 --scanners 2 --heavy-talkers 2
cp "$TMP/source.pcap" "$TMP/a.pcap"
cp "$TMP/source.pcap" "$TMP/b.pcap"

for node in a b; do
  cat >"$TMP/agent-$node.yaml" <<EOF
agent:
  nodeName: node-$node
  listen: 127.0.0.1:0
  seed: 0
  flushIntervalMs: 100
  source:
    kind: pcap
    path: $node.pcap
queries:
  - file: query.yaml
export:
  gateway:
    endpoint: $URL
    intervalMs: 100
EOF
done

start_gateway() {
  seed=$1
  GATEWAY_RUN=$((GATEWAY_RUN + 1))
  cat >"$TMP/gateway.yaml" <<EOF
gateway:
  listen: 127.0.0.1:$PORT
  seed: $seed
  staleAfterMs: 30000
queries:
  - file: query.yaml
EOF
  "$BIN" gateway --config "$TMP/gateway.yaml" >"$TMP/gateway-$GATEWAY_RUN.log" 2>&1 &
  GATEWAY_PID=$!
}

stop_gateway() {
  if [ -n "$GATEWAY_PID" ]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
    GATEWAY_PID=
  fi
}

assert_processes_alive() {
  if [ -z "$GATEWAY_PID" ] || ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    fail "gateway exited before reaching the expected state"
  fi
  if [ -n "$AGENT_A_PID" ] && ! kill -0 "$AGENT_A_PID" 2>/dev/null; then
    fail "agent node-a exited unexpectedly"
  fi
  if [ -n "$AGENT_B_PID" ] && ! kill -0 "$AGENT_B_PID" 2>/dev/null; then
    fail "agent node-b exited unexpectedly"
  fi
}

wait_for_http() {
  attempts=0
  while [ "$attempts" -lt "$MAX_ATTEMPTS" ]; do
    if curl -fsS --max-time 1 "$URL/readyz" >/dev/null 2>&1; then
      return 0
    fi
    assert_processes_alive
    attempts=$((attempts + 1))
    sleep 0.2
  done
  fail "gateway did not become ready"
}

wait_for_metric() {
  description=$1
  pattern=$2
  attempts=0
  while [ "$attempts" -lt "$MAX_ATTEMPTS" ]; do
    metrics=$(curl -fsS --max-time 1 "$URL/metrics" 2>/dev/null || true)
    if printf '%s\n' "$metrics" | grep -Eq "$pattern"; then
      return 0
    fi
    assert_processes_alive
    attempts=$((attempts + 1))
    sleep 0.2
  done
  fail "timed out waiting for $description"
}

assert_nodes() {
  nodes=$(curl -fsS --max-time 2 "$URL/v1/nodes") || fail "cannot read gateway nodes"
  printf '%s\n' "$nodes" | grep -Eq '"node"[[:space:]]*:[[:space:]]*"node-a"' ||
    fail "node-a is absent"
  printf '%s\n' "$nodes" | grep -Eq '"node"[[:space:]]*:[[:space:]]*"node-b"' ||
    fail "node-b is absent"
}

echo "starting compatible gateway and two continuously pushing agents"
start_gateway 0
wait_for_http
"$BIN" agent --config "$TMP/agent-a.yaml" >"$TMP/agent-a.log" 2>&1 &
AGENT_A_PID=$!
"$BIN" agent --config "$TMP/agent-b.yaml" >"$TMP/agent-b.log" 2>&1 &
AGENT_B_PID=$!
wait_for_metric "the initial two-node merge" 'flowsketch_gateway_nodes_merged\{query="suspected_scanners"\} 2$'
assert_nodes

echo "restarting the empty in-memory gateway and waiting for agent repopulation"
stop_gateway
start_gateway 0
wait_for_http
wait_for_metric "two-node recovery after restart" 'flowsketch_gateway_nodes_merged\{query="suspected_scanners"\} 2$'
assert_nodes

echo "starting an incompatible gateway and checking fail-closed snapshot rejection"
stop_gateway
start_gateway 1
wait_for_http
wait_for_metric "an incompatible snapshot rejection" 'flowsketch_gateway_snapshots_rejected_total [1-9][0-9]*$'
if curl -fsS --max-time 2 "$URL/metrics" | grep -q '^flowsketch_estimate{'; then
  fail "incompatible gateway published an estimate"
fi

echo "restoring the compatible seed and checking recovery again"
stop_gateway
start_gateway 0
wait_for_http
wait_for_metric "two-node recovery after compatibility restore" 'flowsketch_gateway_nodes_merged\{query="suspected_scanners"\} 2$'
assert_nodes

metrics=$(curl -fsS --max-time 2 "$URL/metrics")
printf '%s\n' "$metrics" | grep -E 'flowsketch_gateway_(nodes_merged|pushes_total|snapshots_rejected_total)'
echo "gateway restart smoke passed: compatible state repopulated twice and incompatible state failed closed"
