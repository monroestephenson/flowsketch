#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NS="flowsketch-live-$$"
HOST_IF="fsk0$$"
PEER_IF="fsk1$$"
CONFIG="/tmp/flowsketch-live-agent-$$.yaml"
LOG="/tmp/flowsketch-live-agent-$$.log"
AGENT_PID=""

cleanup() {
  set +e
  if [[ -n "${AGENT_PID:-}" ]]; then
    sudo kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$HOST_IF" 2>/dev/null || true
  rm -f "$CONFIG" "$LOG"
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

need curl
need ip
need ping
need setpriv
need sudo

sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name "$PEER_IF"
sudo ip addr add 10.240.0.1/24 dev "$HOST_IF"
sudo ip link set "$HOST_IF" up
sudo ip link set "$PEER_IF" netns "$NS"
sudo ip netns exec "$NS" ip addr add 10.240.0.2/24 dev "$PEER_IF"
sudo ip netns exec "$NS" ip link set "$PEER_IF" up
sudo ip netns exec "$NS" ip link set lo up

cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-live-ci
  listen: 127.0.0.1:19464
  flushIntervalMs: 100
  source:
    kind: af_packet
    interface: $HOST_IF
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

# Run the agent as the invoking user with only CAP_NET_RAW. Network namespace
# setup still needs sudo, but a successful capture must not depend on a
# long-running root process or unrelated Linux capabilities.
sudo setpriv \
  --reuid="$(id -u)" \
  --regid="$(id -g)" \
  --clear-groups \
  --inh-caps=-all,+net_raw \
  --ambient-caps=-all,+net_raw \
  --bounding-set=-all,+net_raw \
  "$BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:19464/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS http://127.0.0.1:19464/readyz >/dev/null

# Generate real packets across the veth pair. Flood ping can fail on some
# constrained environments, so fall back to regular ping if needed.
sudo ip netns exec "$NS" ping -f -c 2000 10.240.0.1 >/dev/null 2>&1 ||
  sudo ip netns exec "$NS" ping -c 250 10.240.0.1 >/dev/null

metrics=""
processed=0
packets_seen=0
observed_traffic=false
for _ in $(seq 1 100); do
  metrics="$(curl -fsS http://127.0.0.1:19464/metrics)"
  processed="$(awk '$1 == "flowsketch_agent_events_processed_total" { print int($2) }' <<<"$metrics")"
  packets_seen="$(awk '$1 == "flowsketch_agent_packets_seen_total" { print int($2) }' <<<"$metrics")"
  processed="${processed:-0}"
  packets_seen="${packets_seen:-0}"
  if (( processed > 0 && packets_seen > 0 )); then
    observed_traffic=true
    break
  fi
  sleep 0.1
done

if [[ "$observed_traffic" != true ]]; then
  echo "AF_PACKET live smoke failed: packets_seen=$packets_seen events_processed=$processed" >&2
  echo "--- agent log ---" >&2
  cat "$LOG" >&2 || true
  echo "--- metrics ---" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

# Let the socket receive timeout fire while traffic is idle. This exercises
# periodic PACKET_STATISTICS collection rather than only packet reception.
sleep 2
curl -fsS http://127.0.0.1:19464/healthz >/dev/null
metrics="$(curl -fsS http://127.0.0.1:19464/metrics)"
kernel_dropped="$(awk '$1 == "flowsketch_agent_kernel_dropped_packets_total" { print int($2) }' <<<"$metrics")"
userspace_dropped="$(awk '$1 == "flowsketch_agent_dropped_events_total" { print int($2) }' <<<"$metrics")"

if [[ ! "$kernel_dropped" =~ ^[0-9]+$ || ! "$userspace_dropped" =~ ^[0-9]+$ ]]; then
  echo "AF_PACKET live smoke failed: drop counters are missing or invalid" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

echo "AF_PACKET live smoke passed with CAP_NET_RAW only: packets_seen=$packets_seen events_processed=$processed kernel_dropped=$kernel_dropped userspace_dropped=$userspace_dropped"
