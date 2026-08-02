#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Prove that AF_PACKET selects LINKTYPE_RAW for ARPHRD_NONE interfaces such as
# Linux TUN and WireGuard instead of silently feeding raw IP into the Ethernet
# parser. The test uses a TUN device because it is available without an
# external WireGuard peer.

BIN="${1:-target/release/flowsketch}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${FLOWSKETCH_RAWIP_PORT:-$((22000 + $$ % 20000))}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/flowsketch-rawip.XXXXXX")"
TOKEN="${TMP##*.}"
INTERFACE="fskrt${TOKEN}"
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
  sudo -n ip tuntap del dev "$INTERFACE" mode tun 2>/dev/null || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
# shellcheck disable=SC2154
trap 'status=$?; echo "AF_PACKET raw-IP smoke failed at line $LINENO (exit $status)" >&2; cat "$LOG" >&2 2>/dev/null || true' ERR

for command in awk curl getcap ip mktemp python3 seq setcap sudo sysctl; do
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

sudo -n ip tuntap add dev "$INTERFACE" mode tun
sudo -n sysctl -q -w "net.ipv6.conf.$INTERFACE.disable_ipv6=1" >/dev/null
sudo -n ip addr add 10.241.0.1/24 dev "$INTERFACE"
sudo -n ip link set "$INTERFACE" up
[[ "$(<"/sys/class/net/$INTERFACE/type")" == "65534" ]]

cp -- "$BIN" "$CAP_BIN"
sudo -n setcap cap_net_raw=ep "$CAP_BIN"
[[ "$(getcap "$CAP_BIN")" == "$CAP_BIN cap_net_raw=ep" ]]

cat >"$CONFIG" <<EOF
agent:
  nodeName: linux-rawip-smoke
  listen: 127.0.0.1:$PORT
  flushIntervalMs: 100
  source:
    kind: af_packet
    interface: $INTERFACE
queries:
  - file: $ROOT/examples/queries/top-talkers.yaml
EOF

"$CAP_BIN" agent --config "$CONFIG" >"$LOG" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 100); do
  if curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$AGENT_PID" 2>/dev/null || break
  sleep 0.1
done
curl --connect-timeout 1 --max-time 2 -fsS \
  "http://127.0.0.1:$PORT/readyz" >/dev/null

# Attach to the persistent TUN queue and inject raw IPv4/UDP datagrams into
# the kernel receive path. Merely routing outbound traffic to an unconsumed
# TUN queue does not traverse the AF_PACKET receive hook on every kernel.
sudo -n python3 - "$INTERFACE" <<'PY'
import fcntl
import os
import socket
import struct
import sys

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


interface = sys.argv[1].encode()
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", interface, IFF_TUN | IFF_NO_PI))
source = socket.inet_aton("10.241.0.2")
destination = socket.inet_aton("10.241.0.1")
udp = struct.pack("!HHHH", 32000, 9464, 8, 0)
for sequence in range(200):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        sequence,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    os.write(fd, header + udp)
PY

metrics=""
parsed=0
processed=0
for _ in $(seq 1 100); do
  metrics="$(curl --connect-timeout 1 --max-time 2 -fsS \
    "http://127.0.0.1:$PORT/metrics")"
  parsed="$(awk '$1 == "flowsketch_agent_packets_parsed_total" { print int($2) }' <<<"$metrics")"
  processed="$(awk '$1 == "flowsketch_agent_events_processed_total" { print int($2) }' <<<"$metrics")"
  parsed="${parsed:-0}"
  processed="${processed:-0}"
  if (( parsed > 0 && processed > 0 )); then
    break
  fi
  sleep 0.1
done
if (( parsed == 0 || processed == 0 )); then
  echo "raw-IP capture produced no parsed events: parsed=$parsed processed=$processed" >&2
  printf '%s\n' "$metrics" >&2
  exit 1
fi

kill -TERM "$AGENT_PID"
if ! wait "$AGENT_PID"; then
  echo "raw-IP agent did not exit successfully after SIGTERM" >&2
  exit 1
fi
AGENT_PID=""
grep -q 'flowsketch agent graceful shutdown complete' "$LOG"

echo "AF_PACKET raw-IP smoke passed on ARPHRD_NONE TUN: parsed=$parsed processed=$processed graceful_shutdown=true"
