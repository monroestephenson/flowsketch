#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKETS="${FLOWSKETCH_EBPF_PACKETS:-50000}"
OVERLOAD_LOOPS="${FLOWSKETCH_EBPF_OVERLOAD_LOOPS:-10}"
PORT="${FLOWSKETCH_EBPF_PORT:-$((20000 + $$ % 20000))}"
SUFFIX="$$"
NS="flowsketch-ebpf-$SUFFIX"
HOST_IF="fse0$SUFFIX"
PEER_IF="fse1$SUFFIX"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-ebpf.XXXXXX")"
OBJECT="$TMP/flowsketch_tc.bpf.o"
TRACE="$TMP/source.pcap"
REPLAY="$TMP/replay.pcap"
CONFIG="$TMP/agent.yaml"
LOG="$TMP/agent.log"
AGENT_PID=""
AGENT_LAUNCHER_PID=""
AGENT_STOPPED=false
BASE_PROGRAMS=0

cleanup() {
  set +e
  if [[ -n "${AGENT_PID:-}" ]]; then
    if [[ "$AGENT_STOPPED" == true ]]; then
      sudo kill -CONT "$AGENT_PID" 2>/dev/null || true
      sudo kill -CONT "$AGENT_LAUNCHER_PID" 2>/dev/null || true
    fi
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
trap 'status=$?; echo "eBPF smoke command failed at line $LINENO (exit $status)" >&2' ERR

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

for command in curl ip python3 setpriv sudo tcpreplay tcprewrite; do
  need "$command"
done
sudo -n true
test -x "$BIN" || {
  echo "FlowSketch binary is not executable: $BIN" >&2
  exit 2
}
[[ "$PACKETS" =~ ^[1-9][0-9]*$ ]] || {
  echo "FLOWSKETCH_EBPF_PACKETS must be a positive integer" >&2
  exit 2
}
[[ "$OVERLOAD_LOOPS" =~ ^[1-9][0-9]*$ ]] || {
  echo "FLOWSKETCH_EBPF_OVERLOAD_LOOPS must be a positive integer" >&2
  exit 2
}

BPFOOL=""
if command -v bpftool >/dev/null 2>&1 && sudo bpftool version >/dev/null 2>&1; then
  BPFOOL="$(command -v bpftool)"
else
  for candidate in /usr/lib/linux-tools/*/bpftool; do
    if [[ -x "$candidate" ]]; then
      BPFOOL="$candidate"
    fi
  done
fi
[[ -n "$BPFOOL" ]] || {
  echo "missing working bpftool (needed to verify attach and detach)" >&2
  exit 127
}

program_count() {
  { sudo "$BPFOOL" prog show name flowsketch_tc 2>/dev/null || true; } |
    awk '$1 ~ /^[0-9]+:$/ { count++ } END { print count + 0 }'
}

metric() {
  local name="$1"
  awk -v name="$name" '$1 == name { print int($2); found = 1 } END { if (!found) print 0 }'
}

start_agent() {
  local capabilities="$1"

  AGENT_PID=""
  AGENT_LAUNCHER_PID=""
  AGENT_STOPPED=false
  # The invoking user owns the private log; sudo intentionally does not own
  # the redirection.
  # shellcheck disable=SC2024
  sudo setpriv \
    --reuid="$(id -u)" \
    --regid="$(id -g)" \
    --clear-groups \
    --inh-caps="$capabilities" \
    --ambient-caps="$capabilities" \
    --bounding-set="$capabilities" \
    "$BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
  AGENT_LAUNCHER_PID=$!

  # sudo remains as a supervising parent when changing credentials. Signals
  # used by the overload test must target the actual setpriv/FlowSketch child.
  for _ in $(seq 1 100); do
    AGENT_PID="$({ ps -o pid= --ppid "$AGENT_LAUNCHER_PID" || true; } |
      awk 'NF { print $1; exit }')"
    if [[ -n "$AGENT_PID" ]]; then
      break
    fi
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
      return 1
    fi
  fi
}

"$ROOT/scripts/build-ebpf.sh" "$OBJECT"
"$BIN" synth \
  --out "$TRACE" \
  --packets "$PACKETS" \
  --scanners 2 \
  --heavy-talkers 3 \
  --duration-secs 30 \
  --seed 606 \
  --full-payload \
  --ipv6-percent 25 >/dev/null

sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name "$PEER_IF"
sudo ip link set "$PEER_IF" netns "$NS"
sudo sysctl -qw "net.ipv6.conf.$HOST_IF.disable_ipv6=1"
sudo ip link set "$HOST_IF" up
sudo ip netns exec "$NS" sysctl -qw "net.ipv6.conf.$PEER_IF.disable_ipv6=1"
sudo ip netns exec "$NS" ip link set "$PEER_IF" up
HOST_MAC="$(cat "/sys/class/net/$HOST_IF/address")"
tcprewrite \
  --infile "$TRACE" \
  --outfile "$REPLAY" \
  --enet-dmac "$HOST_MAC" >/dev/null

cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-ebpf-smoke
  listen: 127.0.0.1:$PORT
  flushIntervalMs: 100
  source:
    kind: ebpf
    interface: $HOST_IF
    objectPath: $OBJECT
    ringBufferBytes: 16777216
    fallbackToAfPacket: false
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

BASE_PROGRAMS="$(program_count)"
# Run as the invoking non-root user with only modern BPF attachment
# capabilities. In particular, CAP_SYS_ADMIN and CAP_NET_RAW are absent.
start_agent "-all,+bpf,+net_admin,+perfmon"

for _ in $(seq 1 150); do
  if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$AGENT_LAUNCHER_PID" 2>/dev/null; then
    echo "eBPF agent exited during startup" >&2
    cat "$LOG" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null

attached=false
for _ in $(seq 1 100); do
  if (( $(program_count) > BASE_PROGRAMS )); then
    attached=true
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ "$attached" != true ]]; then
  echo "tc eBPF program is not visible after agent readiness" >&2
  cat "$LOG" >&2
  exit 1
fi

# Let the one-second kernel counter publication interval elapse, then take a
# baseline so unrelated interface lifecycle traffic cannot taint the replay.
sleep 1.2
metrics="$(curl -fsS "http://127.0.0.1:$PORT/metrics")"
base_kernel="$(metric flowsketch_agent_ebpf_packets_total <<<"$metrics")"
base_emitted="$(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics")"
base_ring_drops="$(metric flowsketch_agent_ebpf_ring_dropped_events_total <<<"$metrics")"
base_parse_errors="$(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics")"
base_unsupported="$(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics")"
base_seen="$(metric flowsketch_agent_packets_seen_total <<<"$metrics")"
base_parsed="$(metric flowsketch_agent_packets_parsed_total <<<"$metrics")"
base_processed="$(metric flowsketch_agent_events_processed_total <<<"$metrics")"
base_userspace_drops="$(metric flowsketch_agent_dropped_events_total <<<"$metrics")"

# Exercise terminal parser buckets with one non-IP Ethernet frame and one
# malformed/truncated IPv4 frame. Neither is allowed to appear in userspace.
sudo ip netns exec "$NS" env HOST_MAC="$HOST_MAC" PEER_IF="$PEER_IF" python3 - <<'PY'
import os
import socket

destination = bytes.fromhex(os.environ["HOST_MAC"].replace(":", ""))
source = bytes.fromhex("0200000000fe")
unsupported = destination + source + bytes.fromhex("0806") + bytes(46)
malformed = destination + source + bytes.fromhex("0800") + bytes.fromhex("45000000000000000000")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((os.environ["PEER_IF"], 0))
sock.send(unsupported)
sock.send(malformed)
sock.close()
PY

rejections_converged=false
for _ in $(seq 1 100); do
  metrics="$(curl -fsS "http://127.0.0.1:$PORT/metrics")"
  rejected_kernel=$(( $(metric flowsketch_agent_ebpf_packets_total <<<"$metrics") - base_kernel ))
  rejected_emitted=$(( $(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics") - base_emitted ))
  rejected_parse=$(( $(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics") - base_parse_errors ))
  rejected_unsupported=$(( $(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics") - base_unsupported ))
  rejected_seen=$(( $(metric flowsketch_agent_packets_seen_total <<<"$metrics") - base_seen ))
  if (( rejected_kernel == 2 && rejected_emitted == 0 && rejected_parse == 1 &&
    rejected_unsupported == 1 && rejected_seen == 0 )); then
    rejections_converged=true
    break
  fi
  sleep 0.1
done
if [[ "$rejections_converged" != true ]]; then
  echo "eBPF rejection accounting failed: kernel=$rejected_kernel emitted=$rejected_emitted parse_errors=$rejected_parse unsupported=$rejected_unsupported seen=$rejected_seen" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

# Start the loss-free replay from a fresh baseline after the deliberate
# rejection probes.
base_kernel="$(metric flowsketch_agent_ebpf_packets_total <<<"$metrics")"
base_emitted="$(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics")"
base_ring_drops="$(metric flowsketch_agent_ebpf_ring_dropped_events_total <<<"$metrics")"
base_parse_errors="$(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics")"
base_unsupported="$(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics")"
base_seen="$(metric flowsketch_agent_packets_seen_total <<<"$metrics")"
base_parsed="$(metric flowsketch_agent_packets_parsed_total <<<"$metrics")"
base_processed="$(metric flowsketch_agent_events_processed_total <<<"$metrics")"
base_userspace_drops="$(metric flowsketch_agent_dropped_events_total <<<"$metrics")"

sudo ip netns exec "$NS" tcpreplay \
  --intf1 "$PEER_IF" \
  --topspeed \
  "$REPLAY" >/dev/null

converged=false
for _ in $(seq 1 200); do
  metrics="$(curl -fsS "http://127.0.0.1:$PORT/metrics")"
  kernel=$(( $(metric flowsketch_agent_ebpf_packets_total <<<"$metrics") - base_kernel ))
  emitted=$(( $(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics") - base_emitted ))
  ring_drops=$(( $(metric flowsketch_agent_ebpf_ring_dropped_events_total <<<"$metrics") - base_ring_drops ))
  parse_errors=$(( $(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics") - base_parse_errors ))
  unsupported=$(( $(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics") - base_unsupported ))
  seen=$(( $(metric flowsketch_agent_packets_seen_total <<<"$metrics") - base_seen ))
  parsed=$(( $(metric flowsketch_agent_packets_parsed_total <<<"$metrics") - base_parsed ))
  processed=$(( $(metric flowsketch_agent_events_processed_total <<<"$metrics") - base_processed ))
  userspace_drops=$(( $(metric flowsketch_agent_dropped_events_total <<<"$metrics") - base_userspace_drops ))
  if (( kernel == PACKETS && emitted == PACKETS && ring_drops == 0 &&
    parse_errors == 0 && unsupported == 0 && seen == PACKETS &&
    parsed == PACKETS && processed == PACKETS && userspace_drops == 0 )); then
    converged=true
    break
  fi
  sleep 0.1
done

if [[ "$converged" != true ]]; then
  echo "eBPF exact accounting failed: offered=$PACKETS kernel=$kernel emitted=$emitted ring_drops=$ring_drops parse_errors=$parse_errors unsupported=$unsupported seen=$seen parsed=$parsed processed=$processed userspace_drops=$userspace_drops" >&2
  echo "--- agent log ---" >&2
  cat "$LOG" >&2
  echo "--- metrics ---" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi
if (( kernel != emitted + ring_drops + parse_errors + unsupported )); then
  echo "eBPF kernel accounting identity is inconsistent" >&2
  exit 1
fi
if (( emitted != seen || seen != parsed || parsed != processed + userspace_drops )); then
  echo "eBPF kernel-to-engine accounting identity is inconsistent" >&2
  exit 1
fi

# Freeze every userspace thread while keeping the tc link alive. Replaying
# more records than the 16 MiB ring can hold must produce counted ring drops;
# after resume, all successfully emitted records must still reach an explicit
# userspace terminal bucket.
base_kernel="$(metric flowsketch_agent_ebpf_packets_total <<<"$metrics")"
base_emitted="$(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics")"
base_ring_drops="$(metric flowsketch_agent_ebpf_ring_dropped_events_total <<<"$metrics")"
base_parse_errors="$(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics")"
base_unsupported="$(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics")"
base_seen="$(metric flowsketch_agent_packets_seen_total <<<"$metrics")"
base_parsed="$(metric flowsketch_agent_packets_parsed_total <<<"$metrics")"
base_processed="$(metric flowsketch_agent_events_processed_total <<<"$metrics")"
base_userspace_drops="$(metric flowsketch_agent_dropped_events_total <<<"$metrics")"
overload_offered=$(( PACKETS * OVERLOAD_LOOPS ))
sudo kill -STOP "$AGENT_PID"
AGENT_STOPPED=true
sudo ip netns exec "$NS" tcpreplay \
  --intf1 "$PEER_IF" \
  --topspeed \
  --loop "$OVERLOAD_LOOPS" \
  "$REPLAY" >/dev/null
sudo kill -CONT "$AGENT_PID"
sudo kill -CONT "$AGENT_LAUNCHER_PID" 2>/dev/null || true
AGENT_STOPPED=false

overload_converged=false
for _ in $(seq 1 300); do
  metrics="$(curl -fsS "http://127.0.0.1:$PORT/metrics")"
  overload_kernel=$(( $(metric flowsketch_agent_ebpf_packets_total <<<"$metrics") - base_kernel ))
  overload_emitted=$(( $(metric flowsketch_agent_ebpf_events_emitted_total <<<"$metrics") - base_emitted ))
  overload_ring_drops=$(( $(metric flowsketch_agent_ebpf_ring_dropped_events_total <<<"$metrics") - base_ring_drops ))
  overload_parse=$(( $(metric flowsketch_agent_ebpf_parse_errors_total <<<"$metrics") - base_parse_errors ))
  overload_unsupported=$(( $(metric flowsketch_agent_ebpf_unsupported_packets_total <<<"$metrics") - base_unsupported ))
  overload_seen=$(( $(metric flowsketch_agent_packets_seen_total <<<"$metrics") - base_seen ))
  overload_parsed=$(( $(metric flowsketch_agent_packets_parsed_total <<<"$metrics") - base_parsed ))
  overload_processed=$(( $(metric flowsketch_agent_events_processed_total <<<"$metrics") - base_processed ))
  overload_userspace_drops=$(( $(metric flowsketch_agent_dropped_events_total <<<"$metrics") - base_userspace_drops ))
  if (( overload_kernel == overload_offered && overload_ring_drops > 0 &&
    overload_parse == 0 && overload_unsupported == 0 &&
    overload_kernel == overload_emitted + overload_ring_drops &&
    overload_emitted == overload_seen && overload_seen == overload_parsed &&
    overload_parsed == overload_processed + overload_userspace_drops )); then
    overload_converged=true
    break
  fi
  sleep 0.1
done
if [[ "$overload_converged" != true ]]; then
  echo "eBPF overload accounting failed: offered=$overload_offered kernel=$overload_kernel emitted=$overload_emitted ring_drops=$overload_ring_drops parse_errors=$overload_parse unsupported=$overload_unsupported seen=$overload_seen parsed=$overload_parsed processed=$overload_processed userspace_drops=$overload_userspace_drops" >&2
  echo "--- agent log ---" >&2
  cat "$LOG" >&2
  echo "--- metrics ---" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

sudo kill "$AGENT_PID"
wait "$AGENT_LAUNCHER_PID" 2>/dev/null || true
AGENT_PID=""
AGENT_LAUNCHER_PID=""
detached=false
for _ in $(seq 1 50); do
  if (( $(program_count) == BASE_PROGRAMS )); then
    detached=true
    break
  fi
  sleep 0.1
done
if [[ "$detached" != true ]]; then
  echo "tc eBPF program remained attached after agent exit" >&2
  sudo "$BPFOOL" prog show name flowsketch_tc >&2 || true
  exit 1
fi

# Prove the configured fallback is operational rather than only parseable.
# A missing object must increment the fallback counter and capture the same
# mixed trace through AF_PACKET while running with CAP_NET_RAW only.
FALLBACK_PORT=$((PORT + 1))
LOG="$TMP/fallback-agent.log"
cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-ebpf-fallback
  listen: 127.0.0.1:$FALLBACK_PORT
  flushIntervalMs: 100
  source:
    kind: ebpf
    interface: $HOST_IF
    objectPath: $TMP/intentionally-missing.bpf.o
    ringBufferBytes: 16777216
    fallbackToAfPacket: true
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF
start_agent "-all,+net_raw"

fallback_ready=false
for _ in $(seq 1 150); do
  if metrics="$(curl -fsS "http://127.0.0.1:$FALLBACK_PORT/metrics" 2>/dev/null)"; then
    fallback_count="$(metric flowsketch_agent_ebpf_fallbacks_total <<<"$metrics")"
    fallback_ring="$(metric flowsketch_agent_capture_ring_bytes <<<"$metrics")"
    if (( fallback_count == 1 && fallback_ring > 0 )); then
      fallback_ready=true
      break
    fi
  fi
  if ! kill -0 "$AGENT_LAUNCHER_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ "$fallback_ready" != true ]]; then
  echo "explicit AF_PACKET fallback did not become ready" >&2
  cat "$LOG" >&2
  exit 1
fi
curl -fsS "http://127.0.0.1:$FALLBACK_PORT/healthz" >/dev/null
if (( $(program_count) != BASE_PROGRAMS )); then
  echo "failed eBPF startup left a kernel program attached during fallback" >&2
  exit 1
fi

sleep 1.2
metrics="$(curl -fsS "http://127.0.0.1:$FALLBACK_PORT/metrics")"
base_kernel="$(metric flowsketch_agent_kernel_packets_total <<<"$metrics")"
base_kernel_drops="$(metric flowsketch_agent_kernel_dropped_packets_total <<<"$metrics")"
base_seen="$(metric flowsketch_agent_packets_seen_total <<<"$metrics")"
base_parsed="$(metric flowsketch_agent_packets_parsed_total <<<"$metrics")"
base_unparsed="$(metric flowsketch_agent_packets_unparsed_total <<<"$metrics")"
base_processed="$(metric flowsketch_agent_events_processed_total <<<"$metrics")"
base_userspace_drops="$(metric flowsketch_agent_dropped_events_total <<<"$metrics")"
sudo ip netns exec "$NS" tcpreplay \
  --intf1 "$PEER_IF" \
  --topspeed \
  "$REPLAY" >/dev/null

fallback_converged=false
for _ in $(seq 1 200); do
  metrics="$(curl -fsS "http://127.0.0.1:$FALLBACK_PORT/metrics")"
  fallback_kernel=$(( $(metric flowsketch_agent_kernel_packets_total <<<"$metrics") - base_kernel ))
  fallback_kernel_drops=$(( $(metric flowsketch_agent_kernel_dropped_packets_total <<<"$metrics") - base_kernel_drops ))
  fallback_seen=$(( $(metric flowsketch_agent_packets_seen_total <<<"$metrics") - base_seen ))
  fallback_parsed=$(( $(metric flowsketch_agent_packets_parsed_total <<<"$metrics") - base_parsed ))
  fallback_unparsed=$(( $(metric flowsketch_agent_packets_unparsed_total <<<"$metrics") - base_unparsed ))
  fallback_processed=$(( $(metric flowsketch_agent_events_processed_total <<<"$metrics") - base_processed ))
  fallback_userspace_drops=$(( $(metric flowsketch_agent_dropped_events_total <<<"$metrics") - base_userspace_drops ))
  if (( fallback_kernel == PACKETS && fallback_kernel_drops == 0 &&
    fallback_seen == PACKETS && fallback_parsed == PACKETS &&
    fallback_unparsed == 0 &&
    fallback_parsed == fallback_processed + fallback_userspace_drops )); then
    fallback_converged=true
    break
  fi
  sleep 0.1
done
if [[ "$fallback_converged" != true ]]; then
  echo "explicit AF_PACKET fallback accounting failed: offered=$PACKETS kernel=$fallback_kernel kernel_drops=$fallback_kernel_drops seen=$fallback_seen parsed=$fallback_parsed unparsed=$fallback_unparsed processed=$fallback_processed userspace_drops=$fallback_userspace_drops" >&2
  cat "$LOG" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

sudo kill "$AGENT_PID"
wait "$AGENT_LAUNCHER_PID" 2>/dev/null || true
AGENT_PID=""
AGENT_LAUNCHER_PID=""

echo "eBPF tc ingress smoke passed without CAP_SYS_ADMIN or CAP_NET_RAW: exact_offered=$PACKETS exact_kernel=$kernel exact_emitted=$emitted exact_ring_drops=$ring_drops rejected_parse=1 rejected_unsupported=1 overload_offered=$overload_offered overload_emitted=$overload_emitted overload_ring_drops=$overload_ring_drops overload_userspace_drops=$overload_userspace_drops; explicit CAP_NET_RAW-only fallback captured=$fallback_seen"
