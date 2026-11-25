#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1230 (#260, from J1137/J1160) one loaded window, run on BOTH ends at the same wall-clock start T0.
#   window.sh <role a|b> <T0 epoch s> <outdir> <cc> <flows> <peer> [r]
# A trailing "r" reverses the load (iperf3 -R: B sends, A receives); probes still go A -> B.
# Role a: iperf3 client, <flows> TCP flows with <cc> for 60 s (+2 s omitted) to <peer>:5201
#   through the tunnel, full speed; from T0+4 s two TCP round-trip streams for 50 s, one request
#   every 20 ms: "key" (64 B request, 64 B reply) and "page" (64 B request, 1,200 B reply).
#   No ICMP probe: iputils busy-waits for its send tick and burns up to 0.8 CPU of these VMs
#   when the round trip is short (J1159 finding 2), which charges low-latency engines a cost
#   the probe creates.
# Both roles: snap.py at T0+12 and T0+52 (40 s steady window after slow start).
set -uo pipefail
R=/root/j1230
role=$1 t0=$2 out=$3 cc=$4 flows=$5 peer=$6 rev=
[[ ${7:-} == r ]] && rev=-R
mkdir -p "$out"
exec > "$out/window.log" 2>&1
until_t() { local now d; now=$(date +%s.%N); d=$(awk -v a="$1" -v b="$now" 'BEGIN{print a-b}'); awk -v d="$d" 'BEGIN{exit !(d>0)}' && sleep "$d"; return 0; }
at() { until_t "$(awk -v a="$t0" -v o="$1" 'BEGIN{print a+o}')"; }
status=0
if [[ $role == a ]]; then
    until_t "$t0"
    # J1230: on the two-tunnel ceiling row ($R/run/peer2 exists) the flows are split over both
    # tunnels, the first one taking the odd flow; a 1-flow window then uses the first tunnel only.
    f1=$flows f2=0 ip2_pid=
    if [[ -s $R/run/peer2 ]]; then f1=$(( (flows + 1) / 2 )) f2=$(( flows / 2 )); fi
    ip netns exec j30 $R/bin/iperf3 -c "$peer" -p 5201 -C "$cc" -P "$f1" -t 60 -O 2 $rev -J > "$out/iperf.json" 2> "$out/iperf.err" &
    ip_pid=$!
    if (( f2 > 0 )); then
        ip netns exec j30 $R/bin/iperf3 -c "$(cat $R/run/peer2)" -p 5202 -C "$cc" -P "$f2" -t 60 -O 2 $rev -J > "$out/iperf2.json" 2> "$out/iperf2.err" &
        ip2_pid=$!
    fi
    at 4
    ip netns exec j30 python3 -I $R/rr.py client "$peer" 7801 64 20 50 "$out/rr-key.json" > "$out/rr-key.log" 2>&1 &
    rk_pid=$!
    ip netns exec j30 python3 -I $R/rr.py client "$peer" 7801 1200 20 50 "$out/rr-page.json" > "$out/rr-page.log" 2>&1 &
    rp_pid=$!
fi
at 12
python3 -I $R/snap.py "$out/before.json"
at 52
python3 -I $R/snap.py "$out/after.json"
if [[ $role == a ]]; then
    wait "$ip_pid" || status=1
    if [[ -n $ip2_pid ]]; then wait "$ip2_pid" || status=1; fi
    wait "$rk_pid" || status=1
    wait "$rp_pid" || status=1
else
    # sleep: B has no load processes to wait for; stay until A's load has ended.
    at 64
fi
echo "$status" > "$out/done"
