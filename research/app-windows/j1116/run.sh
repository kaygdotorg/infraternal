#!/bin/bash
# J1116 acceptance run (#146): the probe binary and its reader in two disposable network namespaces joined by a
# shaped veth pair. Usage (as root, e.g. through `perf-run --root`):
#   run.sh <probe-test-binary> <label> [seconds=60] [netem-limit-packets=50] [notsent-lowat-bytes=0] [NAME=value...]
# Extra NAME=value words are passed to the probe (experiment knobs: PROBE_AIMD_SPLIT=1, PROBE_PRESSURE_MS=n, PROBE_TRACE=1,
# and since J1167 PROBE_LOWAT=<bytes> (the socket option on the probe's own socket) and PROBE_IGNORE_RATE=1).
# The link rate defaults to 3mbit; set RATE=20mbit in the environment for another one (J1167).
# A nonzero lowat sets net.ipv4.tcp_notsent_lowat inside the sender's namespace only: it stands in for a server
# socket that keeps at most that many unsent bytes in the kernel. Both namespaces, the veth pair and the reader are
# removed on every exit (trap); nothing outside them is changed.
# Before binary: build the probe on a tree without pressure reports after
#   sed -i '/^ *\/\/ after-only begin$/,/^ *\/\/ after-only end$/d' crates/plugins/desktop/tests/slow_link_probe.rs
set -euo pipefail
BIN=$1; LABEL=$2; SECONDS_RUN=${3:-60}; LIMIT=${4:-50}; LOWAT=${5:-0}
HERE=$(cd "$(dirname "$0")" && pwd)
NS_S=j1116-send; NS_R=j1116-recv; A=vj1116a; B=vj1116b; PORT=7461
READER=
cleanup() {
  [ -n "$READER" ] && kill "$READER" 2>/dev/null || true
  ip netns del "$NS_S" 2>/dev/null || true
  ip netns del "$NS_R" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
ip netns add "$NS_S"; ip netns add "$NS_R"
ip link add "$A" netns "$NS_S" type veth peer name "$B" netns "$NS_R"
ip netns exec "$NS_S" ip addr add 10.211.16.1/30 dev "$A"
ip netns exec "$NS_R" ip addr add 10.211.16.2/30 dev "$B"
for ns in "$NS_S" "$NS_R"; do ip netns exec "$ns" ip link set lo up; done
ip netns exec "$NS_S" ip link set "$A" up; ip netns exec "$NS_R" ip link set "$B" up
# Server-to-viewer direction only: 3 Mbit/s, 20 ms one way, a bounded bottleneck queue.
ip netns exec "$NS_S" tc qdisc add dev "$A" root netem rate "${RATE:-3mbit}" delay 20ms limit "$LIMIT"
[ "$LOWAT" != 0 ] && ip netns exec "$NS_S" sysctl -qw net.ipv4.tcp_notsent_lowat="$LOWAT"
OUT=$(mktemp)
ip netns exec "$NS_R" python3 -I "$HERE/reader.py" 10.211.16.2 "$PORT" > "$OUT" 2>&1 & READER=$!
for _ in $(seq 1 50); do grep -q READY "$OUT" && break; sleep 0.1; done
echo "RUN label=$LABEL knobs=${*:6} seconds=$SECONDS_RUN limit=$LIMIT notsent_lowat=$(ip netns exec "$NS_S" sysctl -n net.ipv4.tcp_notsent_lowat) binary_sha256=$(sha256sum "$BIN" | cut -c1-16)"
ip netns exec "$NS_S" env "${@:6}" PROBE_ADDR=10.211.16.2:$PORT PROBE_SECONDS="$SECONDS_RUN" "$BIN" --ignored --exact slow_link_probe --nocapture --test-threads=1 2>&1 | grep -E 'METRIC|TRACE|panicked'
wait "$READER" || true; READER=
grep READER "$OUT"; rm -f "$OUT"
ip netns exec "$NS_S" tc -s qdisc show dev "$A" | sed -n '2p'
