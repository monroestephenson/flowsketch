#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <flowsketch-image>" >&2
  exit 2
fi

IMAGE=$1
PORT=${FLOWSKETCH_CONTAINER_SMOKE_PORT:-19464}
NAME="flowsketch-cap-smoke-$$"
# The Docker daemon may run inside a VM (for example Colima), where the
# client's private /tmp is not bind-mounted. Keep fixtures below the checkout
# by default so both local and VM-backed daemons can resolve the bind source.
TMP_ROOT=${FLOWSKETCH_CONTAINER_SMOKE_TMPDIR:-"$PWD/target"}
mkdir -p "$TMP_ROOT"
TMP=$(mktemp -d "$TMP_ROOT/flowsketch-container.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ]; then
    docker inspect --format '{{json .State}}' "$NAME" >&2 2>/dev/null || true
    docker logs "$NAME" >&2 2>/dev/null || true
    if [ "${FLOWSKETCH_CONTAINER_SMOKE_KEEP_FAILED:-0}" = 1 ]; then
      echo "preserving failed container $NAME and config $TMP" >&2
      exit "$status"
    fi
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

for command in awk curl docker mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

cat >"$TMP/query.yaml" <<'EOF'
name: container_capture
window: {size: 10s}
groupBy: [protocol]
measure: {type: count}
EOF

cat >"$TMP/agent.yaml" <<EOF
agent:
  nodeName: container-smoke
  listen: 0.0.0.0:$PORT
  flushIntervalMs: 50
  runtimeShards: 1
  source:
    kind: af_packet
    interface: eth0
    ringBlockSizeBytes: 65536
    ringBlockCount: 8
    blockRetireTimeoutMs: 25
queries:
  - file: /config/query.yaml
EOF

docker run -d --name "$NAME" \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --cap-drop ALL \
  --cap-add NET_RAW \
  -p "127.0.0.1:$PORT:$PORT" \
  -v "$TMP:/config:ro" \
  --entrypoint /usr/local/libexec/flowsketch-agent-afpacket \
  "$IMAGE" agent --config /config/agent.yaml >/dev/null

ready=false
for _ in $(seq 1 100); do
  if curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.1
done
[ "$ready" = true ] || {
  echo "container agent did not become ready" >&2
  exit 1
}

cap_eff=$(docker exec "$NAME" sh -c \
  "awk '/^CapEff:/ { print \$2 }' /proc/1/status")
cap_prm=$(docker exec "$NAME" sh -c \
  "awk '/^CapPrm:/ { print \$2 }' /proc/1/status")
[ "$cap_eff" = "0000000000002000" ]
[ "$cap_prm" = "0000000000002000" ]

processed=0
for _ in $(seq 1 100); do
  metrics=$(curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$PORT/metrics")
  processed=$(printf '%s\n' "$metrics" |
    awk '$1 == "flowsketch_agent_events_processed_total" { print int($2); found=1 } END { if (!found) print 0 }')
  [ "$processed" -gt 0 ] && break
  sleep 0.1
done
[ "$processed" -gt 0 ] || {
  echo "container opened AF_PACKET but captured no traffic" >&2
  exit 1
}

docker stop --time 5 "$NAME" >/dev/null
exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$NAME")
[ "$exit_code" -eq 0 ] || {
  echo "container did not exit successfully after SIGTERM: exit=$exit_code" >&2
  exit 1
}
docker logs "$NAME" 2>&1 | grep -q 'graceful shutdown complete' || {
  echo "container did not report a graceful SIGTERM shutdown" >&2
  exit 1
}

echo "container AF_PACKET smoke passed: uid=65532 CapEff=$cap_eff processed=$processed graceful_shutdown=true"
