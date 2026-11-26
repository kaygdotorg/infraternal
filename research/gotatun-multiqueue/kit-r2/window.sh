#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1239 (#260; J1230's window, from J1137/J1160) one loaded window, run on BOTH ends at the same
# wall-clock start T0.
#   window.sh <role a|b> <T0 epoch s> <outdir> <cc> <flows> <peer> <r|f> [rate-mbit] [perf]
# "r" reverses the load (iperf3 -R: B sends, A receives); probes still go A -> B.
# J1239 additions:
# - rate-mbit > 0 caps the load at that total (iperf3 -b rate/flows per stream; J1160's
#   rate-limited windows), so a p99 change is not just the cost of a higher rate.
# - qs.py samples the socket and eth0 queues on both ends over the steady window.
# - "perf" profiles the whole machine on B (the forward receiver) from T0+20 for 20 s with the
#   unpacked perf in $R/perf (perf record + syscall counts); a perf window's CPU and latency are
#   disturbed by the profiler and are never used as results.
# Role a: iperf3 client, <flows> TCP flows with <cc> for 60 s (+2 s omitted) to <peer>:5201
#   through the tunnel, full speed; from T0+4 s two TCP round-trip streams for 50 s, one request
#   every 20 ms: "key" (64 B request, 64 B reply) and "page" (64 B request, 1,200 B reply).
#   No ICMP probe: iputils busy-waits for its send tick and burns up to 0.8 CPU of these VMs
#   when the round trip is short (J1159 finding 2), which charges low-latency engines a cost
#   the probe creates.
# Both roles: snap.py at T0+12 and T0+52 (40 s steady window after slow start).
set -uo pipefail
R=/root/j1239
role=$1 t0=$2 out=$3 cc=$4 flows=$5 peer=$6 rev= rate=${8:-0} prof=${9:-}
[[ ${7:-} == r ]] && rev=-R
brate=()
(( rate > 0 )) && brate=(-b "$((rate / flows))M")
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
    ip netns exec j39 $R/bin/iperf3 -c "$peer" -p 5201 -C "$cc" -P "$f1" -t 60 -O 2 $rev "${brate[@]}" -J > "$out/iperf.json" 2> "$out/iperf.err" &
    ip_pid=$!
    if (( f2 > 0 )); then
        ip netns exec j39 $R/bin/iperf3 -c "$(cat $R/run/peer2)" -p 5202 -C "$cc" -P "$f2" -t 60 -O 2 $rev -J > "$out/iperf2.json" 2> "$out/iperf2.err" &
        ip2_pid=$!
    fi
    at 4
    ip netns exec j39 python3 -I $R/rr.py client "$peer" 7801 64 20 50 "$out/rr-key.json" > "$out/rr-key.log" 2>&1 &
    rk_pid=$!
    ip netns exec j39 python3 -I $R/rr.py client "$peer" 7801 1200 20 50 "$out/rr-page.json" > "$out/rr-page.log" 2>&1 &
    rp_pid=$!
fi
at 12
python3 -I $R/snap.py "$out/before.json"
python3 -I $R/qs.py "$out/qs.json" 40 "${QS_MS:-250}" > "$out/qs.log" 2>&1 &
qs_pid=$!
if [[ $role == b && $prof == perf ]]; then
    P=$R/perf
    at 20
    LD_LIBRARY_PATH=$P/lib $P/perf record -a -F 999 -o "$out/perf.data" -- sleep 20 > "$out/perf.log" 2>&1 &
    pr_pid=$!
    LD_LIBRARY_PATH=$P/lib $P/perf stat -a -x, -o "$out/perf-stat.csv" \
        -e syscalls:sys_enter_recvmmsg,syscalls:sys_enter_sendmmsg,syscalls:sys_enter_futex \
        -e syscalls:sys_enter_epoll_wait,syscalls:sys_enter_writev,syscalls:sys_enter_write \
        -e sched:sched_switch,sched:sched_wakeup,context-switches,cpu-migrations -- sleep 20 > /dev/null 2>&1 &
    ps_pid=$!
    wait "$pr_pid" "$ps_pid"
fi
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
wait "$qs_pid" || true
echo "$status" > "$out/done"
