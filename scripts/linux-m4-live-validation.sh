#!/usr/bin/env bash
set -euo pipefail
umask 077

# Deterministic M4 live-capture validation.
#
# Default mode creates an isolated veth pair and proves packet accounting in a
# Linux VM/CI environment. Set FLOWSKETCH_M4_CAPTURE_INTERFACE and
# FLOWSKETCH_M4_REPLAY_INTERFACE to two cabled physical ports, plus
# FLOWSKETCH_M4_HARDWARE_GATE=1, for the real 10 Gb/s acceptance run.

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKETS="${FLOWSKETCH_M4_PACKETS:-200000}"
LOOPS="${FLOWSKETCH_M4_LOOPS:-10}"
TARGET_MBPS="${FLOWSKETCH_M4_TARGET_MBPS:-10000}"
MIN_HARDWARE_GBPS="${FLOWSKETCH_M4_MIN_HARDWARE_GBPS:-9.5}"
MIN_HARDWARE_SECONDS="${FLOWSKETCH_M4_MIN_HARDWARE_SECONDS:-10}"
MAX_AGENT_CORES="${FLOWSKETCH_M4_MAX_AGENT_CORES:-}"
HARDWARE_GATE="${FLOWSKETCH_M4_HARDWARE_GATE:-0}"
REPORT="${FLOWSKETCH_M4_REPORT:-}"
LISTEN_PORT="${FLOWSKETCH_M4_LISTEN_PORT:-19466}"
ACCOUNTING_POLLS="${FLOWSKETCH_M4_ACCOUNTING_POLLS:-300}"
LINK_SETTLE_SECONDS="${FLOWSKETCH_M4_LINK_SETTLE_SECONDS:-2}"
RING_BLOCK_SIZE_BYTES="${FLOWSKETCH_M4_RING_BLOCK_SIZE_BYTES:-1048576}"
RING_BLOCK_COUNT="${FLOWSKETCH_M4_RING_BLOCK_COUNT:-64}"
BLOCK_RETIRE_TIMEOUT_MS="${FLOWSKETCH_M4_BLOCK_RETIRE_TIMEOUT_MS:-25}"
RUNTIME_SHARDS="${FLOWSKETCH_M4_RUNTIME_SHARDS:-4}"
RUNTIME_BATCH_SIZE="${FLOWSKETCH_M4_RUNTIME_BATCH_SIZE:-8192}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-m4.XXXXXX")"
TOKEN="${TMP##*.}"
NS="flowsketch-m4-$TOKEN"
CREATED_NS=false
CREATED_LINK=false
CAPTURE_IF="${FLOWSKETCH_M4_CAPTURE_INTERFACE:-}"
REPLAY_IF="${FLOWSKETCH_M4_REPLAY_INTERFACE:-}"
REPLAY_NS="${FLOWSKETCH_M4_REPLAY_NETNS:-}"
HOST_IF="fsm4h$TOKEN"
PEER_IF="fsm4p$TOKEN"
CONFIG="$TMP/agent.yaml"
LOG="$TMP/agent.log"
SOURCE_TRACE="$TMP/replay-source.pcap"
TRACE="$TMP/replay.pcap"
REPLAY_LOG="$TMP/tcpreplay.log"
CAP_BIN="$TMP/flowsketch"
AGENT_PID=""
SUDO=(sudo -n)

cleanup() {
  set +e
  if [[ -n "${AGENT_PID:-}" ]]; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ "$CREATED_NS" == true ]]; then
    "${SUDO[@]}" ip netns del "$NS" 2>/dev/null || true
  fi
  if [[ "$CREATED_LINK" == true ]]; then
    "${SUDO[@]}" ip link del "$HOST_IF" 2>/dev/null || true
  fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

positive_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] &&
    awk -v value="$1" 'BEGIN { exit !(value > 0) }'
}

valid_interface_name() {
  [[ "$1" =~ ^[[:alnum:]_.-]{1,15}$ ]]
}

need awk
need curl
need getcap
need getconf
need ip
need cat
need lscpu
need mktemp
need setcap
need sha256sum
need seq
need sudo
need sysctl
need tcpreplay
need tcprewrite

if ! "${SUDO[@]}" true; then
  echo "passwordless sudo is required for isolated interface setup and replay" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "FlowSketch binary is not executable: $BIN" >&2
  exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
if ! positive_integer "$PACKETS" || ! positive_integer "$LOOPS" ||
  ! positive_integer "$TARGET_MBPS" || ! positive_integer "$LISTEN_PORT" ||
  ! positive_integer "$ACCOUNTING_POLLS" ||
  ! positive_integer "$LINK_SETTLE_SECONDS" ||
  ! positive_integer "$RING_BLOCK_SIZE_BYTES" ||
  ! positive_integer "$RING_BLOCK_COUNT" ||
  ! positive_integer "$BLOCK_RETIRE_TIMEOUT_MS" ||
  ! positive_integer "$RUNTIME_SHARDS" ||
  ! positive_integer "$RUNTIME_BATCH_SIZE"; then
  echo "packet, rate, timeout, ring, and runtime settings must be positive integers" >&2
  exit 2
fi
if ! positive_decimal "$MIN_HARDWARE_GBPS"; then
  echo "FLOWSKETCH_M4_MIN_HARDWARE_GBPS must be greater than zero" >&2
  exit 2
fi
if ! positive_decimal "$MIN_HARDWARE_SECONDS"; then
  echo "FLOWSKETCH_M4_MIN_HARDWARE_SECONDS must be greater than zero" >&2
  exit 2
fi
if [[ -n "$MAX_AGENT_CORES" ]] && ! positive_decimal "$MAX_AGENT_CORES"; then
  echo "FLOWSKETCH_M4_MAX_AGENT_CORES must be greater than zero" >&2
  exit 2
fi
if [[ "$HARDWARE_GATE" != 0 && "$HARDWARE_GATE" != 1 ]]; then
  echo "FLOWSKETCH_M4_HARDWARE_GATE must be 0 or 1" >&2
  exit 2
fi
if (( LISTEN_PORT > 65535 )); then
  echo "FLOWSKETCH_M4_LISTEN_PORT must be <= 65535" >&2
  exit 2
fi
if (( RUNTIME_SHARDS > 256 || RUNTIME_BATCH_SIZE > 65536 )); then
  echo "runtime shards must be <= 256 and batch size must be <= 65536" >&2
  exit 2
fi
if (( RING_BLOCK_SIZE_BYTES < 65536 || RING_BLOCK_SIZE_BYTES > 16777216 ||
  (RING_BLOCK_SIZE_BYTES & (RING_BLOCK_SIZE_BYTES - 1)) != 0 )); then
  echo "ring block size must be a power of two from 65536 through 16777216 bytes" >&2
  exit 2
fi
if (( BLOCK_RETIRE_TIMEOUT_MS > 1000 ||
  RING_BLOCK_COUNT > 1073741824 / RING_BLOCK_SIZE_BYTES )); then
  echo "ring timeout must be <= 1000 ms and total ring memory must be <= 1 GiB" >&2
  exit 2
fi
RING_BYTES=$((RING_BLOCK_SIZE_BYTES * RING_BLOCK_COUNT))
if [[ -n "$CAPTURE_IF" || -n "$REPLAY_IF" ]]; then
  if [[ -z "$CAPTURE_IF" || -z "$REPLAY_IF" ]]; then
    echo "set both FLOWSKETCH_M4_CAPTURE_INTERFACE and FLOWSKETCH_M4_REPLAY_INTERFACE" >&2
    exit 2
  fi
  if ! valid_interface_name "$CAPTURE_IF" || ! valid_interface_name "$REPLAY_IF"; then
    echo "capture and replay interfaces must be conventional Linux interface names" >&2
    exit 2
  fi
  if [[ "$CAPTURE_IF" == "$REPLAY_IF" && -z "$REPLAY_NS" ]]; then
    echo "capture and replay interfaces must be different" >&2
    exit 2
  fi
  ip link show "$CAPTURE_IF" >/dev/null
  if [[ -z "$REPLAY_NS" ]]; then
    ip link show "$REPLAY_IF" >/dev/null
  else
    "${SUDO[@]}" ip netns exec "$REPLAY_NS" ip link show "$REPLAY_IF" >/dev/null
  fi
else
  CAPTURE_IF="$HOST_IF"
  REPLAY_IF="$PEER_IF"
  REPLAY_NS="$NS"
  "${SUDO[@]}" ip netns add "$NS"
  CREATED_NS=true
  "${SUDO[@]}" ip link add "$HOST_IF" type veth peer name "$PEER_IF"
  CREATED_LINK=true
  "${SUDO[@]}" ip link set "$PEER_IF" netns "$NS"
  "${SUDO[@]}" sysctl -q -w "net.ipv6.conf.$HOST_IF.disable_ipv6=1" >/dev/null
  "${SUDO[@]}" ip netns exec "$NS" sysctl -q -w "net.ipv6.conf.$PEER_IF.disable_ipv6=1" >/dev/null
  "${SUDO[@]}" ip link set "$HOST_IF" up
  "${SUDO[@]}" ip netns exec "$NS" ip link set "$PEER_IF" up
  "${SUDO[@]}" ip netns exec "$NS" ip link set lo up
fi

read_interface_attr() {
  local netns="$1"
  local interface="$2"
  local attribute="$3"
  local path="/sys/class/net/$interface/$attribute"
  if [[ -n "$netns" ]]; then
    "${SUDO[@]}" ip netns exec "$netns" cat "$path"
  else
    cat "$path"
  fi
}

if [[ "$HARDWARE_GATE" == 1 ]]; then
  if [[ "$CREATED_NS" == true ]]; then
    echo "M4 hardware gate requires two real cabled interfaces, not the default veth pair" >&2
    exit 2
  fi
  if [[ -z "$REPORT" ]]; then
    echo "M4 hardware gate requires FLOWSKETCH_M4_REPORT to preserve the evidence" >&2
    exit 2
  fi
  if ! command -v git >/dev/null 2>&1 ||
    ! git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1 ||
    [[ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]]; then
    echo "M4 hardware gate requires a clean Git worktree at a recorded commit" >&2
    exit 2
  fi
  if ! read_interface_attr "" "$CAPTURE_IF" device/uevent >/dev/null 2>&1; then
    echo "M4 hardware gate requires a physical capture interface: $CAPTURE_IF" >&2
    exit 2
  fi
  if ! read_interface_attr "$REPLAY_NS" "$REPLAY_IF" device/uevent >/dev/null 2>&1; then
    echo "M4 hardware gate requires a physical replay interface: $REPLAY_IF" >&2
    exit 2
  fi
  capture_link_speed_mbps="$(read_interface_attr "" "$CAPTURE_IF" speed)"
  replay_link_speed_mbps="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" speed)"
  capture_carrier="$(read_interface_attr "" "$CAPTURE_IF" carrier)"
  replay_carrier="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" carrier)"
  capture_duplex="$(read_interface_attr "" "$CAPTURE_IF" duplex)"
  replay_duplex="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" duplex)"
  if ! positive_integer "$capture_link_speed_mbps" ||
    ! positive_integer "$replay_link_speed_mbps" ||
    (( capture_link_speed_mbps < 10000 || replay_link_speed_mbps < 10000 )); then
    echo "M4 hardware gate requires both ports to negotiate at least 10000 Mb/s" >&2
    exit 2
  fi
  if [[ "$capture_carrier" != 1 || "$replay_carrier" != 1 ||
    "$capture_duplex" != full || "$replay_duplex" != full ]]; then
    echo "M4 hardware gate requires carrier and full duplex on both ports" >&2
    exit 2
  fi
else
  capture_link_speed_mbps="virtual-or-unverified"
  replay_link_speed_mbps="virtual-or-unverified"
fi

# Link-up can emit a small burst of control traffic. Let it finish before the
# packet socket exists so the replay baseline cannot contain a partially
# retired TPACKET block from validation setup.
sleep "$LINK_SETTLE_SECONDS"

capture_mac="$(read_interface_attr "" "$CAPTURE_IF" address)"
if [[ ! "$capture_mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
  echo "could not read a valid capture-interface MAC address for replay targeting" >&2
  exit 1
fi

if (( PACKETS > 9223372036854775807 / LOOPS )); then
  echo "expected packet count overflowed" >&2
  exit 2
fi
expected_packets=$((PACKETS * LOOPS))

"$BIN" synth \
  --out "$SOURCE_TRACE" \
  --packets "$PACKETS" \
  --scanners 2 \
  --heavy-talkers 3 \
  --duration-secs 120 \
  --seed 77 \
  --full-payload >/dev/null
tcprewrite \
  --enet-dmac="$capture_mac" \
  --infile="$SOURCE_TRACE" \
  --outfile="$TRACE"
trace_sha256="$(sha256sum "$TRACE" | awk '{print $1}')"
binary_sha256="$(sha256sum "$BIN" | awk '{print $1}')"

cp -- "$BIN" "$CAP_BIN"
"${SUDO[@]}" setcap cap_net_raw=ep "$CAP_BIN"
if [[ "$(getcap "$CAP_BIN")" != "$CAP_BIN cap_net_raw=ep" ]]; then
  echo "failed to grant only CAP_NET_RAW to validation binary" >&2
  exit 1
fi

cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-m4-validation
  listen: 127.0.0.1:$LISTEN_PORT
  flushIntervalMs: 100
  runtimeShards: $RUNTIME_SHARDS
  runtimeBatchSize: $RUNTIME_BATCH_SIZE
  runtimeShardStrategy: round_robin
  source:
    kind: af_packet
    interface: $CAPTURE_IF
    ringBlockSizeBytes: $RING_BLOCK_SIZE_BYTES
    ringBlockCount: $RING_BLOCK_COUNT
    blockRetireTimeoutMs: $BLOCK_RETIRE_TIMEOUT_MS
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

"$CAP_BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 100); do
  if curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$LISTEN_PORT/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! curl --connect-timeout 1 --max-time 2 -fsS \
  "http://127.0.0.1:$LISTEN_PORT/readyz" >/dev/null; then
  echo "M4 validation agent did not become ready" >&2
  cat "$LOG" >&2 || true
  exit 1
fi

agent_uid="$(awk '/^Uid:/ {print $2}' "/proc/$AGENT_PID/status")"
agent_effective_uid="$(awk '/^Uid:/ {print $3}' "/proc/$AGENT_PID/status")"
cap_eff="$(awk '/^CapEff:/ {print $2}' "/proc/$AGENT_PID/status")"
cap_eff_value=$((16#$cap_eff))
if [[ "$agent_uid" != "$(id -u)" || "$agent_effective_uid" != "$(id -u)" ]]; then
  echo "M4 validation agent is not running as the invoking non-root user" >&2
  exit 1
fi
if (( cap_eff_value != (1 << 13) )); then
  echo "M4 validation agent effective capabilities are not exactly CAP_NET_RAW: $cap_eff" >&2
  exit 1
fi

metric_value() {
  local name="$1"
  awk -v metric="$name" '$1 == metric { print int($2); found=1 } END { if (!found) exit 1 }'
}

read_metrics() {
  METRICS="$(curl --connect-timeout 1 --max-time 5 -fsS \
    "http://127.0.0.1:$LISTEN_PORT/metrics")"
  EVENTS_PROCESSED="$(metric_value flowsketch_agent_events_processed_total <<<"$METRICS")"
  PACKETS_SEEN="$(metric_value flowsketch_agent_packets_seen_total <<<"$METRICS")"
  PACKETS_PARSED="$(metric_value flowsketch_agent_packets_parsed_total <<<"$METRICS")"
  PACKETS_UNPARSED="$(metric_value flowsketch_agent_packets_unparsed_total <<<"$METRICS")"
  KERNEL_PACKETS="$(metric_value flowsketch_agent_kernel_packets_total <<<"$METRICS")"
  KERNEL_DROPPED="$(metric_value flowsketch_agent_kernel_dropped_packets_total <<<"$METRICS")"
  QUEUE_FREEZES="$(metric_value flowsketch_agent_kernel_queue_freezes_total <<<"$METRICS")"
  USERSPACE_DROPPED="$(metric_value flowsketch_agent_dropped_events_total <<<"$METRICS")"
  CAPTURE_RING_BYTES="$(metric_value flowsketch_agent_capture_ring_bytes <<<"$METRICS")"
  CAPTURE_RING_BLOCKS="$(metric_value flowsketch_agent_capture_ring_blocks <<<"$METRICS")"
  CAPTURE_BLOCK_SIZE_BYTES="$(metric_value flowsketch_agent_capture_block_size_bytes <<<"$METRICS")"
}

metrics_accounted() {
  (( KERNEL_PACKETS == PACKETS_SEEN + KERNEL_DROPPED &&
    PACKETS_SEEN == PACKETS_PARSED + PACKETS_UNPARSED &&
    PACKETS_PARSED == EVENTS_PROCESSED + USERSPACE_DROPPED ))
}

cpu_snapshot() {
  awk '/^cpu / {
    total = 0
    for (i = 2; i <= 9; i++) total += $i
    print total, $5 + $6, $8
    exit
  }' /proc/stat
}

softnet_snapshot() {
  local dropped=0
  local squeezed=0
  local drop_field squeeze_field rest
  while read -r _ drop_field squeeze_field rest; do
    dropped=$((dropped + 16#$drop_field))
    squeezed=$((squeezed + 16#$squeeze_field))
  done </proc/net/softnet_stat
  echo "$dropped $squeezed"
}

baseline_converged=false
sleep 2
for _ in $(seq 1 10); do
  read_metrics
  if metrics_accounted; then
    candidate_events="$EVENTS_PROCESSED"
    candidate_seen="$PACKETS_SEEN"
    candidate_parsed="$PACKETS_PARSED"
    candidate_unparsed="$PACKETS_UNPARSED"
    candidate_kernel="$KERNEL_PACKETS"
    candidate_kernel_dropped="$KERNEL_DROPPED"
    candidate_freezes="$QUEUE_FREEZES"
    candidate_userspace_dropped="$USERSPACE_DROPPED"
    sleep 2
    read_metrics
    if metrics_accounted &&
      [[ "$EVENTS_PROCESSED" == "$candidate_events" &&
         "$PACKETS_SEEN" == "$candidate_seen" &&
         "$PACKETS_PARSED" == "$candidate_parsed" &&
         "$PACKETS_UNPARSED" == "$candidate_unparsed" &&
         "$KERNEL_PACKETS" == "$candidate_kernel" &&
         "$KERNEL_DROPPED" == "$candidate_kernel_dropped" &&
         "$QUEUE_FREEZES" == "$candidate_freezes" &&
         "$USERSPACE_DROPPED" == "$candidate_userspace_dropped" ]]; then
      baseline_converged=true
      break
    fi
  fi
  sleep 0.1
done
if [[ "$baseline_converged" != true ]]; then
  echo "capture counters did not converge before replay" >&2
  printf '%s\n' "$METRICS" >&2
  exit 1
fi
if (( CAPTURE_RING_BYTES != RING_BYTES ||
  CAPTURE_RING_BLOCKS != RING_BLOCK_COUNT ||
  CAPTURE_BLOCK_SIZE_BYTES != RING_BLOCK_SIZE_BYTES )); then
  echo "agent ring gauges do not match the requested receive-ring configuration" >&2
  printf '%s\n' "$METRICS" >&2
  exit 1
fi
BASE_EVENTS_PROCESSED="$EVENTS_PROCESSED"
BASE_PACKETS_SEEN="$PACKETS_SEEN"
BASE_PACKETS_PARSED="$PACKETS_PARSED"
BASE_PACKETS_UNPARSED="$PACKETS_UNPARSED"
BASE_KERNEL_PACKETS="$KERNEL_PACKETS"
BASE_KERNEL_DROPPED="$KERNEL_DROPPED"
BASE_QUEUE_FREEZES="$QUEUE_FREEZES"
BASE_USERSPACE_DROPPED="$USERSPACE_DROPPED"
BASE_INTERFACE_RX_PACKETS="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_packets)"
BASE_CAPTURE_RX_DROPPED="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_dropped)"
BASE_CAPTURE_RX_ERRORS="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_errors)"
BASE_CAPTURE_RX_FIFO_ERRORS="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_fifo_errors)"
BASE_CAPTURE_RX_MISSED_ERRORS="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_missed_errors)"
BASE_REPLAY_TX_PACKETS="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_packets)"
BASE_REPLAY_TX_DROPPED="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_dropped)"
BASE_REPLAY_TX_ERRORS="$(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_errors)"

clock_ticks="$(getconf CLK_TCK)"
cpu_ticks_before="$(awk '{print $14 + $15}' "/proc/$AGENT_PID/stat")"
read -r host_cpu_total_before host_cpu_idle_before host_cpu_softirq_before < <(cpu_snapshot)
read -r softnet_dropped_before softnet_squeezed_before < <(softnet_snapshot)

replay_command=(
  tcpreplay
  --intf1="$REPLAY_IF"
  --preload-pcap
  --mbps="$TARGET_MBPS"
  --loop="$LOOPS"
  "$TRACE"
)
if [[ -n "$REPLAY_NS" ]]; then
  if ! "${SUDO[@]}" ip netns exec "$REPLAY_NS" \
    "${replay_command[@]}" >"$REPLAY_LOG" 2>&1; then
    echo "tcpreplay failed" >&2
    cat "$REPLAY_LOG" >&2 || true
    exit 1
  fi
else
  if ! "${SUDO[@]}" "${replay_command[@]}" >"$REPLAY_LOG" 2>&1; then
    echo "tcpreplay failed" >&2
    cat "$REPLAY_LOG" >&2 || true
    exit 1
  fi
fi

replay_end_ns="$(date +%s%N)"
cpu_ticks_replay_end="$(awk '{print $14 + $15}' "/proc/$AGENT_PID/stat")"
read -r host_cpu_total_after host_cpu_idle_after host_cpu_softirq_after < <(cpu_snapshot)
read -r softnet_dropped_after softnet_squeezed_after < <(softnet_snapshot)
read_metrics
parsed_at_replay_end=$((PACKETS_PARSED - BASE_PACKETS_PARSED))
processed_at_replay_end=$((EVENTS_PROCESSED - BASE_EVENTS_PROCESSED))
userspace_dropped_at_replay_end=$((USERSPACE_DROPPED - BASE_USERSPACE_DROPPED))
backlog_at_replay_end=$((parsed_at_replay_end - processed_at_replay_end - userspace_dropped_at_replay_end))

converged=false
for _ in $(seq 1 "$ACCOUNTING_POLLS"); do
  read_metrics
  kernel_packets_delta=$((KERNEL_PACKETS - BASE_KERNEL_PACKETS))
  packets_seen_delta=$((PACKETS_SEEN - BASE_PACKETS_SEEN))
  packets_parsed_delta=$((PACKETS_PARSED - BASE_PACKETS_PARSED))
  packets_unparsed_delta=$((PACKETS_UNPARSED - BASE_PACKETS_UNPARSED))
  kernel_dropped_delta=$((KERNEL_DROPPED - BASE_KERNEL_DROPPED))
  queue_freezes_delta=$((QUEUE_FREEZES - BASE_QUEUE_FREEZES))
  userspace_dropped_delta=$((USERSPACE_DROPPED - BASE_USERSPACE_DROPPED))
  events_processed_delta=$((EVENTS_PROCESSED - BASE_EVENTS_PROCESSED))
  if (( kernel_packets_delta >= expected_packets &&
        kernel_packets_delta == packets_seen_delta + kernel_dropped_delta &&
        packets_seen_delta == packets_parsed_delta + packets_unparsed_delta &&
        packets_parsed_delta == events_processed_delta + userspace_dropped_delta )); then
    converged=true
    break
  fi
  sleep 0.1
done
converged_ns="$(date +%s%N)"
cpu_ticks_after="$(awk '{print $14 + $15}' "/proc/$AGENT_PID/stat")"
interface_rx_packets="$(read_interface_attr "" "$CAPTURE_IF" statistics/rx_packets)"
interface_rx_packets_delta=$((interface_rx_packets - BASE_INTERFACE_RX_PACKETS))
capture_rx_dropped_delta=$(($(read_interface_attr "" "$CAPTURE_IF" statistics/rx_dropped) - BASE_CAPTURE_RX_DROPPED))
capture_rx_errors_delta=$(($(read_interface_attr "" "$CAPTURE_IF" statistics/rx_errors) - BASE_CAPTURE_RX_ERRORS))
capture_rx_fifo_errors_delta=$(($(read_interface_attr "" "$CAPTURE_IF" statistics/rx_fifo_errors) - BASE_CAPTURE_RX_FIFO_ERRORS))
capture_rx_missed_errors_delta=$(($(read_interface_attr "" "$CAPTURE_IF" statistics/rx_missed_errors) - BASE_CAPTURE_RX_MISSED_ERRORS))
replay_tx_packets_delta=$(($(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_packets) - BASE_REPLAY_TX_PACKETS))
replay_tx_dropped_delta=$(($(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_dropped) - BASE_REPLAY_TX_DROPPED))
replay_tx_errors_delta=$(($(read_interface_attr "$REPLAY_NS" "$REPLAY_IF" statistics/tx_errors) - BASE_REPLAY_TX_ERRORS))
softnet_dropped_delta=$((softnet_dropped_after - softnet_dropped_before))
softnet_squeezed_delta=$((softnet_squeezed_after - softnet_squeezed_before))

actual_packets="$(awk '/^Actual:/ {print $2; exit}' "$REPLAY_LOG")"
actual_bytes="$(awk '/^Actual:/ {gsub(/[()]/, "", $4); print $4; exit}' "$REPLAY_LOG")"
actual_seconds="$(awk '/^Actual:/ {for (i = 2; i <= NF; i++) if ($i == "seconds") {print $(i-1); exit}}' "$REPLAY_LOG")"
if ! positive_integer "${actual_packets:-}" || ! positive_integer "${actual_bytes:-}" ||
  ! positive_decimal "${actual_seconds:-}"; then
  echo "could not parse tcpreplay result" >&2
  cat "$REPLAY_LOG" >&2
  exit 1
fi
if (( actual_packets != expected_packets )); then
  echo "tcpreplay sent $actual_packets packets; expected $expected_packets" >&2
  cat "$REPLAY_LOG" >&2
  exit 1
fi

convergence_ns=$((converged_ns - replay_end_ns))
cpu_ticks_during_replay=$((cpu_ticks_replay_end - cpu_ticks_before))
cpu_ticks_total=$((cpu_ticks_after - cpu_ticks_before))
host_cpu_total_delta=$((host_cpu_total_after - host_cpu_total_before))
host_cpu_idle_delta=$((host_cpu_idle_after - host_cpu_idle_before))
host_cpu_softirq_delta=$((host_cpu_softirq_after - host_cpu_softirq_before))
achieved_gbps="$(awk -v bytes="$actual_bytes" -v seconds="$actual_seconds" 'BEGIN { printf "%.3f", (bytes * 8) / (seconds * 1000000000) }')"
# The deterministic synthetic frames are all at least the Ethernet minimum.
# Add 4-byte FCS, 8-byte preamble/SFD, and 12-byte inter-frame gap to estimate
# physical wire occupancy from tcpreplay's captured-frame byte count.
achieved_wire_gbps="$(awk -v bytes="$actual_bytes" -v packets="$actual_packets" -v seconds="$actual_seconds" \
  'BEGIN { printf "%.3f", ((bytes + packets * 24) * 8) / (seconds * 1000000000) }')"
agent_cores_during_replay="$(awk -v ticks="$cpu_ticks_during_replay" -v hz="$clock_ticks" -v seconds="$actual_seconds" 'BEGIN { printf "%.3f", (ticks / hz) / seconds }')"
host_busy_cores_during_replay="$(awk -v total="$host_cpu_total_delta" -v idle="$host_cpu_idle_delta" -v hz="$clock_ticks" -v seconds="$actual_seconds" \
  'BEGIN { printf "%.3f", ((total - idle) / hz) / seconds }')"
host_softirq_seconds_during_replay="$(awk -v ticks="$host_cpu_softirq_delta" -v hz="$clock_ticks" \
  'BEGIN { printf "%.3f", ticks / hz }')"
agent_cpu_seconds_total="$(awk -v ticks="$cpu_ticks_total" -v hz="$clock_ticks" 'BEGIN { printf "%.3f", ticks / hz }')"
agent_peak_rss_kib="$(awk '/^VmHWM:/ {print $2; found=1} END {if (!found) print 0}' "/proc/$AGENT_PID/status")"
catchup_ms="$(awk -v ns="$convergence_ns" 'BEGIN { printf "%.1f", ns / 1000000 }')"

failed=false
failure_reason=""
if [[ "$converged" != true ]]; then
  failed=true
  failure_reason="metrics did not converge after replay"
elif (( replay_tx_packets_delta != expected_packets )); then
  failed=true
  failure_reason="replay-interface TX packets do not match offered packets"
elif (( interface_rx_packets_delta != expected_packets )); then
  failed=true
  failure_reason="capture-interface RX packets do not match offered packets"
elif (( replay_tx_dropped_delta != 0 || replay_tx_errors_delta != 0 )); then
  failed=true
  failure_reason="replay interface reported transmit drops or errors"
elif (( capture_rx_dropped_delta != 0 || capture_rx_errors_delta != 0 ||
  capture_rx_fifo_errors_delta != 0 || capture_rx_missed_errors_delta != 0 )); then
  failed=true
  failure_reason="capture interface reported receive drops or errors"
elif (( kernel_packets_delta != expected_packets )); then
  failed=true
  failure_reason="kernel packet total does not match offered packets"
elif (( packets_seen_delta + kernel_dropped_delta != expected_packets )); then
  failed=true
  failure_reason="captured plus kernel-dropped packets do not match offered packets"
elif (( packets_seen_delta != packets_parsed_delta + packets_unparsed_delta )); then
  failed=true
  failure_reason="captured packets do not match parser dispositions"
elif (( packets_unparsed_delta != 0 )); then
  failed=true
  failure_reason="synthetic replay contained packets the parser did not accept"
elif (( packets_parsed_delta != events_processed_delta + userspace_dropped_delta )); then
  failed=true
  failure_reason="parsed packets do not match engine dispositions"
elif (( kernel_dropped_delta != 0 || queue_freezes_delta != 0 || userspace_dropped_delta != 0 )); then
  failed=true
  failure_reason="validation observed packet loss or a frozen receive queue"
fi

hardware_result="not-requested"
if [[ "$HARDWARE_GATE" == 1 ]]; then
  hardware_result="passed"
  if ! awk -v actual="$achieved_wire_gbps" -v minimum="$MIN_HARDWARE_GBPS" 'BEGIN { exit !(actual >= minimum) }'; then
    failed=true
    hardware_result="failed"
    if [[ -z "$failure_reason" ]]; then
      failure_reason="estimated wire rate is below the hardware threshold"
    fi
  fi
  if ! awk -v actual="$actual_seconds" -v minimum="$MIN_HARDWARE_SECONDS" \
    'BEGIN { exit !(actual >= minimum) }'; then
    failed=true
    hardware_result="failed"
    if [[ -z "$failure_reason" ]]; then
      failure_reason="replay duration is shorter than the sustained hardware threshold"
    fi
  fi
fi
if [[ -n "$MAX_AGENT_CORES" ]] &&
  ! awk -v actual="$agent_cores_during_replay" -v maximum="$MAX_AGENT_CORES" \
    'BEGIN { exit !(actual <= maximum) }'; then
  failed=true
  if [[ -z "$failure_reason" ]]; then
    failure_reason="agent CPU use exceeds the configured core budget"
  fi
fi
if [[ "$HARDWARE_GATE" == 1 && "$failed" == true ]]; then
  hardware_result="failed"
fi

if [[ "$CREATED_NS" == true ]]; then
  validation_mode="virtual-veth"
elif [[ "$HARDWARE_GATE" == 1 ]]; then
  validation_mode="physical-interfaces"
else
  validation_mode="user-supplied-interfaces-unverified"
fi
cpu_budget="${MAX_AGENT_CORES:-not-set}"

summary=$(cat <<EOF
FlowSketch M4 live validation
mode: $validation_mode
hardware_gate: $hardware_result
minimum_hardware_seconds: $MIN_HARDWARE_SECONDS
capture_interface: $CAPTURE_IF
replay_interface: $REPLAY_IF
capture_mac: $capture_mac
capture_link_mbps: $capture_link_speed_mbps
replay_link_mbps: $replay_link_speed_mbps
target_mbps: $TARGET_MBPS
offered_packets: $actual_packets
offered_bytes: $actual_bytes
offered_duration_seconds: $actual_seconds
achieved_replayed_l2_gbps: $achieved_gbps
achieved_estimated_wire_gbps: $achieved_wire_gbps
replay_tx_packets: $replay_tx_packets_delta
replay_tx_dropped: $replay_tx_dropped_delta
replay_tx_errors: $replay_tx_errors_delta
interface_rx_packets: $interface_rx_packets_delta
interface_rx_dropped: $capture_rx_dropped_delta
interface_rx_errors: $capture_rx_errors_delta
interface_rx_fifo_errors: $capture_rx_fifo_errors_delta
interface_rx_missed_errors: $capture_rx_missed_errors_delta
kernel_packets: $kernel_packets_delta
packets_seen: $packets_seen_delta
packets_parsed: $packets_parsed_delta
packets_unparsed: $packets_unparsed_delta
events_processed: $events_processed_delta
kernel_dropped: $kernel_dropped_delta
kernel_queue_freezes: $queue_freezes_delta
userspace_dropped: $userspace_dropped_delta
engine_backlog_at_replay_end: $backlog_at_replay_end
accounting_convergence_ms: $catchup_ms
agent_cores_during_replay: $agent_cores_during_replay
agent_core_budget: $cpu_budget
host_busy_cores_during_replay: $host_busy_cores_during_replay
host_softirq_seconds_during_replay: $host_softirq_seconds_during_replay
host_softnet_dropped: $softnet_dropped_delta
host_softnet_time_squeezed: $softnet_squeezed_delta
agent_cpu_seconds_through_convergence: $agent_cpu_seconds_total
agent_peak_rss_kib: $agent_peak_rss_kib
ring_block_size_bytes: $RING_BLOCK_SIZE_BYTES
ring_block_count: $RING_BLOCK_COUNT
block_retire_timeout_ms: $BLOCK_RETIRE_TIMEOUT_MS
runtime_shards: $RUNTIME_SHARDS
runtime_batch_size: $RUNTIME_BATCH_SIZE
result: $([[ "$failed" == true ]] && echo FAIL || echo PASS)
EOF
)
printf '%s\n' "$summary"

if [[ -n "$REPORT" ]]; then
  git_commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [[ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null || true)" ]]; then
    git_state="dirty"
  else
    git_state="clean"
  fi
  tcpreplay_version="unknown"
  while IFS= read -r version_line; do
    if [[ "$version_line" == "tcpreplay version:"* ]]; then
      tcpreplay_version="$version_line"
      break
    fi
  done <<<"$(tcpreplay --version 2>&1)"
  {
    echo "# FlowSketch M4 live validation"
    echo
    echo '```text'
    printf '%s\n' "$summary"
    echo '```'
    echo
    echo "Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Kernel: $(uname -srmo)"
    echo "CPU: $(lscpu | awk -F: '/^Model name:/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
    echo "tcpreplay: $tcpreplay_version"
    echo "Commit: $git_commit ($git_state worktree)"
    echo "Binary SHA-256: $binary_sha256"
    echo "Trace SHA-256: $trace_sha256"
  } >"$REPORT"
fi

if [[ "$failed" == true ]]; then
  echo "M4 validation failed: $failure_reason" >&2
  echo "--- agent log ---" >&2
  cat "$LOG" >&2 || true
  echo "--- tcpreplay log ---" >&2
  cat "$REPLAY_LOG" >&2 || true
  exit 1
fi

if [[ "$HARDWARE_GATE" != 1 ]]; then
  echo "Non-hardware validation passed; this is not physical 10 Gb/s certification."
fi
