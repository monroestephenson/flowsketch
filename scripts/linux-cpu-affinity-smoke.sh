#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${FLOWSKETCH_AFFINITY_PORT:-$((24000 + $$ % 20000))}"
SUFFIX="$$"
NS="flowsketch-affinity-$SUFFIX"
HOST_IF="fsa0$SUFFIX"
PEER_IF="fsa1$SUFFIX"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-affinity.XXXXXX")"
CONFIG="$TMP/agent.yaml"
INVALID_CONFIG="$TMP/invalid.yaml"
LOG="$TMP/agent.log"
INVALID_LOG="$TMP/invalid.log"
AGENT_PID=""
AGENT_LAUNCHER_PID=""

cleanup() {
  set +e
  if [[ -n "${AGENT_PID:-}" ]]; then
    sudo kill "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "${AGENT_LAUNCHER_PID:-}" ]]; then
    if [[ "$AGENT_LAUNCHER_PID" != "$AGENT_PID" ]]; then
      sudo kill "$AGENT_LAUNCHER_PID" 2>/dev/null || true
    fi
    wait "$AGENT_LAUNCHER_PID" 2>/dev/null || true
  fi
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$HOST_IF" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
# shellcheck disable=SC2154
trap 'status=$?; echo "CPU-affinity smoke failed at line $LINENO (exit $status)" >&2' ERR

for command in curl ip setpriv sudo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 127
  }
done
sudo -n true
test -x "$BIN" || {
  echo "FlowSketch binary is not executable: $BIN" >&2
  exit 2
}

allowed_spec="$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)"
[[ -n "$allowed_spec" ]] || {
  echo "cannot read Cpus_allowed_list from /proc/self/status" >&2
  exit 1
}
declare -a ALLOWED_CPUS=()
IFS=',' read -ra ranges <<<"$allowed_spec"
for range in "${ranges[@]}"; do
  if [[ "$range" == *-* ]]; then
    start="${range%-*}"
    end="${range#*-}"
    for ((cpu = start; cpu <= end; cpu++)); do
      ALLOWED_CPUS+=("$cpu")
    done
  else
    ALLOWED_CPUS+=("$range")
  fi
done
(( ${#ALLOWED_CPUS[@]} > 0 )) || {
  echo "allowed CPU set is empty" >&2
  exit 1
}

CAPTURE_CPU="${ALLOWED_CPUS[0]}"
declare -a RUNTIME_CPUS=()
if (( ${#ALLOWED_CPUS[@]} == 1 )); then
  RUNTIME_CPUS+=("${ALLOWED_CPUS[0]}")
else
  for cpu in "${ALLOWED_CPUS[@]:1}"; do
    RUNTIME_CPUS+=("$cpu")
    (( ${#RUNTIME_CPUS[@]} == 3 )) && break
  done
fi
RUNTIME_SHARDS="${#RUNTIME_CPUS[@]}"
runtime_cpu_list="$(IFS=,; echo "[${RUNTIME_CPUS[*]}]")"

declare -A allowed=()
for cpu in "${ALLOWED_CPUS[@]}"; do
  allowed[$cpu]=1
done
DISALLOWED_CPU=""
for ((cpu = 0; cpu < 1024; cpu++)); do
  if [[ -z "${allowed[$cpu]:-}" ]]; then
    DISALLOWED_CPU="$cpu"
    break
  fi
done
[[ -n "$DISALLOWED_CPU" ]] || {
  echo "cannot find a CPU outside this process's allowed set" >&2
  exit 1
}

sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name "$PEER_IF"
sudo ip link set "$HOST_IF" up
sudo ip link set "$PEER_IF" netns "$NS"
sudo ip netns exec "$NS" ip link set "$PEER_IF" up

cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-affinity-smoke
  listen: 127.0.0.1:$PORT
  runtimeShards: $RUNTIME_SHARDS
  runtimeBatchSize: 128
  cpuAffinity:
    captureCpu: $CAPTURE_CPU
    runtimeCpus: $runtime_cpu_list
  source:
    kind: af_packet
    interface: $HOST_IF
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

# The long-running process has only CAP_NET_RAW; setting affinity on its own
# threads does not require privilege beyond access to its allowed cpuset.
# shellcheck disable=SC2024
sudo setpriv \
  --reuid="$(id -u)" \
  --regid="$(id -g)" \
  --clear-groups \
  --inh-caps=-all,+net_raw \
  --ambient-caps=-all,+net_raw \
  --bounding-set=-all,+net_raw \
  "$BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
AGENT_LAUNCHER_PID=$!

for _ in $(seq 1 100); do
  AGENT_PID="$({ ps -o pid= --ppid "$AGENT_LAUNCHER_PID" || true; } |
    awk 'NF { print $1; exit }')"
  [[ -n "$AGENT_PID" ]] && break
  if ! kill -0 "$AGENT_LAUNCHER_PID" 2>/dev/null; then
    break
  fi
  sleep 0.01
done
if [[ -z "$AGENT_PID" ]]; then
  if [[ "$(ps -o comm= -p "$AGENT_LAUNCHER_PID" | xargs)" == flowsketch ]]; then
    AGENT_PID="$AGENT_LAUNCHER_PID"
  else
    echo "cannot identify non-root agent process" >&2
    cat "$LOG" >&2
    exit 1
  fi
fi

for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null || {
  cat "$LOG" >&2
  exit 1
}

thread_cpu() {
  local wanted="$1"
  local task
  for task in "/proc/$AGENT_PID/task/"*; do
    if [[ "$(<"$task/comm")" == "$wanted" ]]; then
      awk '/^Cpus_allowed_list:/ { print $2 }' "$task/status"
      return 0
    fi
  done
  return 1
}

actual_capture="$(thread_cpu fs-capture)" || {
  echo "capture thread not found" >&2
  exit 1
}
[[ "$actual_capture" == "$CAPTURE_CPU" ]] || {
  echo "capture affinity is $actual_capture, expected $CAPTURE_CPU" >&2
  exit 1
}
for ((worker = 0; worker < RUNTIME_SHARDS; worker++)); do
  actual="$(thread_cpu "fs-runtime-$worker")" || {
    echo "runtime worker $worker not found" >&2
    exit 1
  }
  [[ "$actual" == "${RUNTIME_CPUS[$worker]}" ]] || {
    echo "runtime worker $worker affinity is $actual, expected ${RUNTIME_CPUS[$worker]}" >&2
    exit 1
  }
done

metrics="$(curl -fsS "http://127.0.0.1:$PORT/metrics")"
grep -q '^flowsketch_agent_cpu_affinity_enabled 1$' <<<"$metrics"
grep -q "^flowsketch_agent_capture_cpu_affinity{cpu=\"$CAPTURE_CPU\"} 1$" <<<"$metrics"
for ((worker = 0; worker < RUNTIME_SHARDS; worker++)); do
  grep -q "^flowsketch_agent_runtime_cpu_affinity{worker=\"$worker\",cpu=\"${RUNTIME_CPUS[$worker]}\"} 1$" <<<"$metrics"
done

sudo kill "$AGENT_PID"
wait "$AGENT_LAUNCHER_PID" 2>/dev/null || true
AGENT_PID=""
AGENT_LAUNCHER_PID=""

cat >"$INVALID_CONFIG" <<EOF
agent:
  runtimeShards: 1
  cpuAffinity:
    captureCpu: $CAPTURE_CPU
    runtimeCpus: [$DISALLOWED_CPU]
  source: {kind: pcap, path: /does/not/matter.pcap}
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF
if "$BIN" agent --config "$INVALID_CONFIG" >"$INVALID_LOG" 2>&1; then
  echo "agent accepted a runtime CPU outside its allowed cpuset" >&2
  exit 1
fi
grep -q "cannot pin runtime worker 0 to CPU $DISALLOWED_CPU" "$INVALID_LOG" || {
  cat "$INVALID_LOG" >&2
  exit 1
}

echo "Linux CPU-affinity smoke passed: capture_cpu=$CAPTURE_CPU runtime_cpus=$runtime_cpu_list; disallowed_cpu=$DISALLOWED_CPU rejected"
