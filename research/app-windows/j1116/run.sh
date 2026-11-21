#!/bin/bash
# J1116 acceptance run (#146): one probe binary behind a shaped link in a disposable network namespace.
# Usage (as root, e.g. through `perf-run --root`): run.sh <probe-test-binary> <label> [seconds] [netem-limit-packets]
# The namespace, the veth pair and the reader are removed on every exit (trap), so nothing outlives the run.
# Before binary: build the probe on a tree without pressure reports after
#   sed -i '/^ *\/\/ after-only begin$/,/^ *\/\/ after-only end$/d' crates/plugins/desktop/tests/slow_link_probe.rs
set -euo pipefail
BIN=$1; LABEL=$2; SECONDS_RUN=${3:-60}; LIMIT=${4:-50}
HERE=$(cd "$(dirname "$0")" && pwd)
NS=j1116-link; A=vj1116a; B=vj1116b; PORT=7461
READER=
cleanup() {
  [ -n "$READER" ] && kill "$READER" 2>/dev/null || true
  ip link del "$A" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
ip netns add "$NS"
ip link add "$A" type veth peer name "$B"
ip link set "$B" netns "$NS"
ip addr add 10.211.16.1/30 dev "$A"; ip link set "$A" up
ip netns exec "$NS" ip addr add 10.211.16.2/30 dev "$B"
ip netns exec "$NS" ip link set "$B" up; ip netns exec "$NS" ip link set lo up
# Server-to-viewer direction only: 3 Mbit/s, 20 ms one way, a bounded bottleneck queue.
tc qdisc add dev "$A" root netem rate 3mbit delay 20ms limit "$LIMIT"
tc qdisc show dev "$A"
OUT=$(mktemp)
ip netns exec "$NS" python3 -I "$HERE/reader.py" 10.211.16.2 "$PORT" > "$OUT" 2>&1 & READER=$!
for _ in $(seq 1 50); do grep -q READY "$OUT" && break; sleep 0.1; done
echo "RUN label=$LABEL seconds=$SECONDS_RUN limit=$LIMIT binary_sha256=$(sha256sum "$BIN" | cut -c1-16)"
PROBE_ADDR=10.211.16.2:$PORT PROBE_SECONDS=$SECONDS_RUN "$BIN" --ignored --exact slow_link_probe --nocapture --test-threads=1 2>&1 | grep -E 'METRIC|panicked|test result'
wait "$READER" || true; READER=
cat "$OUT"; rm -f "$OUT"
tc -s qdisc show dev "$A" | sed -n '1,3p'
