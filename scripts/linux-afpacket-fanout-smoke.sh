#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Exercise Linux PACKET_FANOUT_HASH and PACKET_FANOUT_QM on a multi-queue
# veth pair. The test proves that capture lanes are independently threaded,
# pinned when requested, handed to permanently paired queue-local runtime
# workers, and exactly accounted at both aggregate and per-lane levels.

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKETS="${FLOWSKETCH_FANOUT_PACKETS:-50000}"
REQUESTED_LANES="${FLOWSKETCH_FANOUT_LANES:-4}"
PORT_BASE="${FLOWSKETCH_FANOUT_PORT_BASE:-$((25000 + $$ % 20000))}"
RING_BLOCK_SIZE_BYTES="${FLOWSKETCH_FANOUT_RING_BLOCK_SIZE_BYTES:-1048576}"
RING_BLOCK_COUNT="${FLOWSKETCH_FANOUT_RING_BLOCK_COUNT:-16}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-fanout.XXXXXX")"
TOKEN="${TMP##*.}"
NS="fskfns$TOKEN"
HOST_IF="fskfh$TOKEN"
PEER_IF="fskfp$TOKEN"
SOURCE_TRACE="$TMP/source.pcap"
TRACE="$TMP/replay.pcap"
CAP_BIN="$TMP/flowsketch"
CONFIG="$TMP/agent.yaml"
LOG="$TMP/agent.log"
AGENT_PID=""

cleanup() {
  set +e
  if [[ -n "${AGENT_PID:-}" ]]; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  sudo -n ip netns del "$NS" 2>/dev/null || true
  sudo -n ip link del "$HOST_IF" 2>/dev/null || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
# shellcheck disable=SC2154
trap 'status=$?; echo "AF_PACKET fan-out smoke failed at line $LINENO (exit $status)" >&2; cat "$LOG" >&2 2>/dev/null || true' ERR

for command in awk curl getcap ip mktemp seq setcap sudo sysctl timeout tcpreplay tcprewrite; do
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
[[ "$PACKETS" =~ ^[1-9][0-9]*$ ]] || {
  echo "FLOWSKETCH_FANOUT_PACKETS must be a positive integer" >&2
  exit 2
}
[[ "$REQUESTED_LANES" =~ ^[1-9][0-9]*$ ]] || {
  echo "FLOWSKETCH_FANOUT_LANES must be a positive integer" >&2
  exit 2
}
[[ "$PORT_BASE" =~ ^[1-9][0-9]*$ ]] || {
  echo "FLOWSKETCH_FANOUT_PORT_BASE must be a positive integer" >&2
  exit 2
}
[[ "$RING_BLOCK_SIZE_BYTES" =~ ^[1-9][0-9]*$ &&
  "$RING_BLOCK_COUNT" =~ ^[1-9][0-9]*$ ]] || {
  echo "fan-out ring settings must be positive integers" >&2
  exit 2
}
if (( REQUESTED_LANES < 2 || REQUESTED_LANES > 16 )); then
  echo "FLOWSKETCH_FANOUT_LANES must be between 2 and 16" >&2
  exit 2
fi
if (( PORT_BASE < 1024 || PORT_BASE > 65532 )); then
  echo "FLOWSKETCH_FANOUT_PORT_BASE must be between 1024 and 65532" >&2
  exit 2
fi

allowed_spec="$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)"
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
if (( ${#ALLOWED_CPUS[@]} < 2 )); then
  echo "AF_PACKET fan-out smoke requires at least two allowed logical CPUs" >&2
  exit 2
fi
LANES="$REQUESTED_LANES"
if (( LANES > ${#ALLOWED_CPUS[@]} )); then
  LANES="${#ALLOWED_CPUS[@]}"
fi
CAPTURE_CPUS=("${ALLOWED_CPUS[@]:0:LANES}")
cpu_list="$(IFS=,; echo "[${CAPTURE_CPUS[*]}]")"
declare -A allowed_cpu=()
for cpu in "${ALLOWED_CPUS[@]}"; do
  allowed_cpu[$cpu]=1
done
DISALLOWED_CPU=""
for ((cpu = 0; cpu < 1024; cpu++)); do
  if [[ -z "${allowed_cpu[$cpu]:-}" ]]; then
    DISALLOWED_CPU="$cpu"
    break
  fi
done
[[ -n "$DISALLOWED_CPU" ]] || {
  echo "cannot find a CPU outside this process's allowed set" >&2
  exit 2
}

sudo -n ip netns add "$NS"
sudo -n ip link add "$HOST_IF" numrxqueues "$LANES" numtxqueues "$LANES" \
  type veth peer name "$PEER_IF" numrxqueues "$LANES" numtxqueues "$LANES"
sudo -n ip link set "$PEER_IF" netns "$NS"
sudo -n ip netns exec "$NS" sysctl -q -w \
  "net.ipv6.conf.$PEER_IF.disable_ipv6=1" >/dev/null
sudo -n sysctl -q -w "net.ipv6.conf.$HOST_IF.disable_ipv6=1" >/dev/null
sudo -n ip link set "$HOST_IF" up
sudo -n ip netns exec "$NS" ip link set "$PEER_IF" up
sudo -n ip netns exec "$NS" ip link set lo up
sleep 1

capture_mac="$(cat "/sys/class/net/$HOST_IF/address")"
"$BIN" synth \
  --out "$SOURCE_TRACE" \
  --packets "$PACKETS" \
  --scanners 8 \
  --heavy-talkers 8 \
  --duration-secs 120 \
  --seed 707 \
  --full-payload >/dev/null
tcprewrite --enet-dmac="$capture_mac" --infile="$SOURCE_TRACE" --outfile="$TRACE"

cp -- "$BIN" "$CAP_BIN"
sudo -n setcap cap_net_raw=ep "$CAP_BIN"
[[ "$(getcap "$CAP_BIN")" == "$CAP_BIN cap_net_raw=ep" ]]

metric_value() {
  local name="$1"
  awk -v metric="$name" '$1 == metric { print int($2); found=1 } END { if (!found) exit 1 }'
}

lane_value() {
  local name="$1"
  local lane="$2"
  awk -v metric="$name{lane=\"$lane\"}" \
    '$1 == metric { print int($2); found=1 } END { if (!found) exit 1 }'
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

run_mode() {
  local mode="$1"
  local port="$2"
  local require_all_lanes="$3"
  local group="$4"
  local metrics=""

  cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-fanout-$mode
  listen: 127.0.0.1:$port
  flushIntervalMs: 100
  runtimeShards: $LANES
  runtimeBatchSize: 1024
  runtimeShardStrategy: flow
  cpuAffinity:
    captureCpus: $cpu_list
    runtimeCpus: $cpu_list
  source:
    kind: af_packet
    interface: $HOST_IF
    ringBlockSizeBytes: $RING_BLOCK_SIZE_BYTES
    ringBlockCount: $RING_BLOCK_COUNT
    blockRetireTimeoutMs: 25
    fanoutMode: $mode
    fanoutGroup: $group
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

  : >"$LOG"
  "$CAP_BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
  AGENT_PID=$!
  for _ in $(seq 1 100); do
    if curl --connect-timeout 1 --max-time 2 -fsS \
      "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
      break
    fi
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.1
  done
  curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$port/readyz" >/dev/null

  capture_threads=0
  runtime_threads=0
  for _ in $(seq 1 200); do
    capture_threads="$({ grep -l '^fs-capture-[0-9][0-9]*$' \
      "/proc/$AGENT_PID/task/"*/comm 2>/dev/null || true; } | wc -l | tr -d ' ')"
    runtime_threads="$({ grep -l '^fs-runtime-[0-9][0-9]*$' \
      "/proc/$AGENT_PID/task/"*/comm 2>/dev/null || true; } | wc -l | tr -d ' ')"
    (( capture_threads == LANES && runtime_threads == LANES )) && break
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.05
  done
  if (( capture_threads != LANES )); then
    echo "$mode started $capture_threads/$LANES capture lane threads" >&2
    cat "$LOG" >&2
    return 1
  fi
  if (( runtime_threads != LANES )); then
    echo "$mode started $runtime_threads/$LANES queue-local runtime threads" >&2
    cat "$LOG" >&2
    return 1
  fi

  for ((lane = 0; lane < LANES; lane++)); do
    expected_cpu="${CAPTURE_CPUS[$lane]}"
    capture_cpu="$(thread_cpu "fs-capture-$lane")"
    [[ "$capture_cpu" == "$expected_cpu" ]] || {
      echo "$mode capture lane $lane affinity is $capture_cpu, expected $expected_cpu" >&2
      return 1
    }
    runtime_cpu="$(thread_cpu "fs-runtime-$lane")"
    [[ "$runtime_cpu" == "$expected_cpu" ]] || {
      echo "$mode runtime lane $lane affinity is $runtime_cpu, expected $expected_cpu" >&2
      return 1
    }
  done

  sudo -n ip netns exec "$NS" tcpreplay \
    --stats=0 --topspeed --intf1="$PEER_IF" "$TRACE" >/dev/null
  sleep 2

  local converged=false
  for _ in $(seq 1 100); do
    metrics="$(curl --connect-timeout 1 --max-time 5 -fsS \
      "http://127.0.0.1:$port/metrics")"
    kernel_packets="$(metric_value flowsketch_agent_kernel_packets_total <<<"$metrics")"
    packets_seen="$(metric_value flowsketch_agent_packets_seen_total <<<"$metrics")"
    packets_parsed="$(metric_value flowsketch_agent_packets_parsed_total <<<"$metrics")"
    packets_unparsed="$(metric_value flowsketch_agent_packets_unparsed_total <<<"$metrics")"
    events_processed="$(metric_value flowsketch_agent_events_processed_total <<<"$metrics")"
    kernel_dropped="$(metric_value flowsketch_agent_kernel_dropped_packets_total <<<"$metrics")"
    queue_freezes="$(metric_value flowsketch_agent_kernel_queue_freezes_total <<<"$metrics")"
    userspace_dropped="$(metric_value flowsketch_agent_dropped_events_total <<<"$metrics")"

    sum_kernel=0
    sum_seen=0
    sum_parsed=0
    sum_unparsed=0
    sum_processed=0
    sum_kernel_dropped=0
    sum_queue_freezes=0
    sum_userspace_dropped=0
    active_lanes=0
    per_lane_exact=true
    for ((lane = 0; lane < LANES; lane++)); do
      lane_kernel="$(lane_value flowsketch_agent_af_packet_lane_kernel_packets_total "$lane" <<<"$metrics")"
      lane_seen="$(lane_value flowsketch_agent_af_packet_lane_packets_seen_total "$lane" <<<"$metrics")"
      lane_parsed="$(lane_value flowsketch_agent_af_packet_lane_packets_parsed_total "$lane" <<<"$metrics")"
      lane_unparsed="$(lane_value flowsketch_agent_af_packet_lane_packets_unparsed_total "$lane" <<<"$metrics")"
      lane_processed="$(lane_value flowsketch_agent_af_packet_lane_events_processed_total "$lane" <<<"$metrics")"
      lane_kernel_dropped="$(lane_value flowsketch_agent_af_packet_lane_kernel_dropped_packets_total "$lane" <<<"$metrics")"
      lane_queue_freezes="$(lane_value flowsketch_agent_af_packet_lane_kernel_queue_freezes_total "$lane" <<<"$metrics")"
      lane_userspace_dropped="$(lane_value flowsketch_agent_af_packet_lane_userspace_dropped_events_total "$lane" <<<"$metrics")"
      ((lane_seen > 0)) && active_lanes=$((active_lanes + 1))
      if (( lane_kernel != lane_seen + lane_kernel_dropped ||
        lane_seen != lane_parsed + lane_unparsed ||
        lane_parsed != lane_processed + lane_userspace_dropped )); then
        per_lane_exact=false
      fi
      sum_kernel=$((sum_kernel + lane_kernel))
      sum_seen=$((sum_seen + lane_seen))
      sum_parsed=$((sum_parsed + lane_parsed))
      sum_unparsed=$((sum_unparsed + lane_unparsed))
      sum_processed=$((sum_processed + lane_processed))
      sum_kernel_dropped=$((sum_kernel_dropped + lane_kernel_dropped))
      sum_queue_freezes=$((sum_queue_freezes + lane_queue_freezes))
      sum_userspace_dropped=$((sum_userspace_dropped + lane_userspace_dropped))
    done

    if [[ "$per_lane_exact" == true ]] &&
      (( kernel_packets == PACKETS &&
        kernel_packets == packets_seen + kernel_dropped &&
        packets_seen == packets_parsed + packets_unparsed &&
        packets_parsed == events_processed + userspace_dropped &&
        sum_kernel == kernel_packets &&
        sum_seen == packets_seen &&
        sum_parsed == packets_parsed &&
        sum_unparsed == packets_unparsed &&
        sum_processed == events_processed &&
        sum_kernel_dropped == kernel_dropped &&
        sum_queue_freezes == queue_freezes &&
        sum_userspace_dropped == userspace_dropped )); then
      converged=true
      break
    fi
    sleep 0.1
  done

  [[ "$converged" == true ]] || {
    echo "$mode accounting did not converge" >&2
    printf '%s\n' "$metrics" >&2
    return 1
  }
  [[ "$(metric_value flowsketch_agent_af_packet_fanout_lanes <<<"$metrics")" == "$LANES" ]]
  [[ "$(metric_value flowsketch_agent_af_packet_queue_local_handoff <<<"$metrics")" == 1 ]]
  [[ "$(metric_value flowsketch_agent_capture_ring_bytes <<<"$metrics")" == \
    "$((RING_BLOCK_SIZE_BYTES * RING_BLOCK_COUNT * LANES))" ]]
  [[ "$(metric_value flowsketch_agent_capture_ring_blocks <<<"$metrics")" == \
    "$((RING_BLOCK_COUNT * LANES))" ]]
  channel_capacity_sum=0
  for ((lane = 0; lane < LANES; lane++)); do
    lane_capacity="$(lane_value flowsketch_agent_af_packet_lane_channel_capacity "$lane" <<<"$metrics")"
    (( lane_capacity > 0 ))
    channel_capacity_sum=$((channel_capacity_sum + lane_capacity))
    grep -Fqx \
      "flowsketch_agent_capture_cpu_affinity{lane=\"$lane\",cpu=\"${CAPTURE_CPUS[$lane]}\"} 1" \
      <<<"$metrics"
    grep -Fqx \
      "flowsketch_agent_runtime_cpu_affinity{worker=\"$lane\",cpu=\"${CAPTURE_CPUS[$lane]}\"} 1" \
      <<<"$metrics"
  done
  [[ "$channel_capacity_sum" == 65536 ]]
  if [[ "$require_all_lanes" == true ]] && (( active_lanes != LANES )); then
    echo "$mode used $active_lanes/$LANES capture lanes" >&2
    return 1
  fi
  if (( active_lanes == 0 )); then
    echo "$mode did not deliver traffic to any capture lane" >&2
    return 1
  fi

  echo "AF_PACKET $mode passed: lanes=$LANES active_lanes=$active_lanes packets=$kernel_packets parsed=$packets_parsed processed=$events_processed kernel_dropped=$kernel_dropped userspace_dropped=$userspace_dropped"
  kill "$AGENT_PID"
  wait "$AGENT_PID" 2>/dev/null || true
  AGENT_PID=""
  sleep 1
}

# Both modes must spread varied synthetic flows over every queue on the
# explicitly multi-queue veth pair.
run_mode hash "$PORT_BASE" true 0
run_mode rx_queue "$((PORT_BASE + 1))" true 47001

INVALID_CAPTURE_CPUS=("${CAPTURE_CPUS[@]}")
INVALID_LANE=$((LANES - 1))
INVALID_CAPTURE_CPUS[INVALID_LANE]="$DISALLOWED_CPU"
invalid_cpu_list="$(IFS=,; echo "[${INVALID_CAPTURE_CPUS[*]}]")"
cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-fanout-invalid-affinity
  listen: 127.0.0.1:$((PORT_BASE + 2))
  runtimeShards: $LANES
  cpuAffinity:
    captureCpus: $invalid_cpu_list
    runtimeCpus: $cpu_list
  source:
    kind: af_packet
    interface: $HOST_IF
    ringBlockSizeBytes: $RING_BLOCK_SIZE_BYTES
    ringBlockCount: $RING_BLOCK_COUNT
    fanoutMode: hash
    fanoutGroup: 47002
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF
: >"$LOG"
if timeout 10 "$CAP_BIN" agent --config "$CONFIG" >"$LOG" 2>&1; then
  invalid_status=0
else
  invalid_status=$?
fi
if (( invalid_status == 0 || invalid_status == 124 )); then
  echo "fan-out capture affinity failure was not fail-closed (status $invalid_status)" >&2
  exit 1
fi
grep -Fq \
  "cannot pin capture lane $INVALID_LANE to CPU $DISALLOWED_CPU" "$LOG" || {
  cat "$LOG" >&2
  exit 1
}

INVALID_RUNTIME_CPUS=("${CAPTURE_CPUS[@]}")
INVALID_RUNTIME_CPUS[INVALID_LANE]="$DISALLOWED_CPU"
invalid_runtime_cpu_list="$(IFS=,; echo "[${INVALID_RUNTIME_CPUS[*]}]")"
cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-fanout-invalid-runtime-affinity
  listen: 127.0.0.1:$((PORT_BASE + 3))
  runtimeShards: $LANES
  cpuAffinity:
    captureCpus: $cpu_list
    runtimeCpus: $invalid_runtime_cpu_list
  source:
    kind: af_packet
    interface: $HOST_IF
    ringBlockSizeBytes: $RING_BLOCK_SIZE_BYTES
    ringBlockCount: $RING_BLOCK_COUNT
    fanoutMode: hash
    fanoutGroup: 47003
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF
: >"$LOG"
if timeout 10 "$CAP_BIN" agent --config "$CONFIG" >"$LOG" 2>&1; then
  invalid_status=0
else
  invalid_status=$?
fi
if (( invalid_status == 0 || invalid_status == 124 )); then
  echo "fan-out runtime affinity failure was not fail-closed (status $invalid_status)" >&2
  exit 1
fi
grep -Fq \
  "cannot pin runtime worker $INVALID_LANE to CPU $DISALLOWED_CPU" "$LOG" || {
  cat "$LOG" >&2
  exit 1
}

echo "Linux AF_PACKET fan-out smoke passed for HASH/RX_QUEUE, queue-local handoff, and fail-closed affinity"
