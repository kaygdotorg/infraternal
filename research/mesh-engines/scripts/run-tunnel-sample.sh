#!/usr/bin/env bash
# Role: Run one rootless WireGuard data-plane sample under a CPU-weighted user scope.
# SPDX-License-Identifier: AGPL-3.0-only
#
# The inner namespace connects two peers over a veth pair, measures direct and
# tunneled ping latency, runs one- and four-stream iperf3 tests, and measures
# process RSS at 0, 100, and 1,000 configured peers. Private keys travel only
# through shell memory and pipes; they are not written to files or argv.

set -euo pipefail

usage() {
    printf 'usage: %s {kernel|boringtun|gotatun|neptun|wireguard-go} REPETITION\n' "$0" >&2
    exit 2
}

if [[ ${1:-} != --inside ]]; then
    [[ $# -eq 2 ]] || usage
    engine=$1
    repetition=$2
    case "$engine" in
        kernel|boringtun|gotatun|neptun|wireguard-go) ;;
        *) usage ;;
    esac
    [[ $repetition =~ ^[1-5]$ ]] || usage

    : "${WG_BIN:=wg}"
    : "${IPERF3_BIN:=iperf3}"
    : "${PYTHON_BIN:=python3}"
    case "$engine" in
        kernel) ENGINE_BIN=kernel ;;
        boringtun) : "${BORINGTUN_BIN:?set BORINGTUN_BIN}"; ENGINE_BIN=$BORINGTUN_BIN ;;
        gotatun) : "${GOTATUN_BIN:?set GOTATUN_BIN}"; ENGINE_BIN=$GOTATUN_BIN ;;
        neptun) : "${NEPTUN_BIN:?set NEPTUN_BIN}"; ENGINE_BIN=$NEPTUN_BIN ;;
        wireguard-go) : "${WIREGUARD_GO_BIN:?set WIREGUARD_GO_BIN}"; ENGINE_BIN=$WIREGUARD_GO_BIN ;;
    esac
    export WG_BIN IPERF3_BIN PYTHON_BIN ENGINE_BIN
    if [[ $ENGINE_BIN != kernel ]]; then
        ENGINE_BIN=$(realpath "$ENGINE_BIN")
        export ENGINE_BIN
    fi
    WG_BIN=$(command -v "$WG_BIN")
    IPERF3_BIN=$(command -v "$IPERF3_BIN")
    PYTHON_BIN=$(command -v "$PYTHON_BIN")
    export WG_BIN IPERF3_BIN PYTHON_BIN

    exec systemd-run --user --scope --quiet -p CPUWeight=10000 -- \
        unshare -Urnm -- "$0" --inside "$engine" "$repetition"
fi

engine=$2
repetition=$3
load_start=$(awk '{ print $1 "/" $2 "/" $3 }' /proc/loadavg)
mount -t tmpfs -o mode=1777 tmpfs /run
right_ns=''
left_pid=''
right_pid=''
mem_pid=''

shutdown() {
    [[ -n ${right_ns:-} ]] && kill "$right_ns" 2>/dev/null || true
    [[ -n ${left_pid:-} && $left_pid != 0 ]] && kill "$left_pid" 2>/dev/null || true
    [[ -n ${right_pid:-} && $right_pid != 0 ]] && kill "$right_pid" 2>/dev/null || true
    [[ -n ${mem_pid:-} && $mem_pid != 0 ]] && kill "$mem_pid" 2>/dev/null || true
}
trap shutdown EXIT

if [[ $engine == kernel ]]; then
    left_pid=''
    right_pid=''
else
    case "$engine" in
        boringtun) runner=("$ENGINE_BIN" --foreground --disable-drop-privileges -v error) ;;
        gotatun) runner=("$ENGINE_BIN" --foreground --disable-drop-privileges -v error) ;;
        neptun) runner=("$ENGINE_BIN" --foreground --disable-drop-privileges -v error) ;;
        wireguard-go) runner=("$ENGINE_BIN" -f) ;;
    esac
fi

ip link add veth-l type veth peer name veth-r
parent_net=$(readlink /proc/self/ns/net)
unshare -n sleep 300 &
right_ns=$!
for _ in {1..50}; do
    right_net=$(readlink /proc/$right_ns/ns/net 2>/dev/null || true)
    [[ -n $right_net && $right_net != "$parent_net" ]] && break
    sleep 0.02
done
[[ -n ${right_net:-} && $right_net != "$parent_net" ]] || {
    printf 'child network namespace did not become ready\n' >&2
    exit 1
}
ip link set veth-r netns "$right_ns"
ip addr add 192.0.2.1/24 dev veth-l
ip link set veth-l up
ip link set lo up
nsenter -t "$right_ns" -n ip addr add 192.0.2.2/24 dev veth-r
nsenter -t "$right_ns" -n ip link set veth-r up
nsenter -t "$right_ns" -n ip link set lo up

start_engine() {
    local side=$1 iface=$2
    if [[ $engine == kernel ]]; then
        if [[ $side == left ]]; then
            ip link add "$iface" type wireguard
            if [[ $iface == wgmem ]]; then mem_pid=0; else left_pid=0; fi
        else
            nsenter -t "$right_ns" -n ip link add "$iface" type wireguard
            right_pid=0
        fi
        return 0
    fi
    if [[ $side == left ]]; then
        "${runner[@]}" "$iface" >/dev/null 2>&1 &
        if [[ $iface == wgmem ]]; then mem_pid=$!; else left_pid=$!; fi
    else
        nsenter -t "$right_ns" -n -- "${runner[@]}" "$iface" >/dev/null 2>&1 &
        right_pid=$!
    fi
}

wait_link() {
    local side=$1 iface=$2
    for _ in {1..100}; do
        if [[ $side == left ]]; then
            ip link show "$iface" >/dev/null 2>&1 && return 0
        else
            nsenter -t "$right_ns" -n ip link show "$iface" >/dev/null 2>&1 && return 0
        fi
        sleep 0.02
    done
    printf 'timed out waiting for %s/%s\n' "$side" "$iface" >&2
    return 1
}

start_engine left wgL
start_engine right wgR
wait_link left wgL
wait_link right wgR

left_private=$($WG_BIN genkey)
right_private=$($WG_BIN genkey)
left_public=$(printf '%s\n' "$left_private" | "$WG_BIN" pubkey)
right_public=$(printf '%s\n' "$right_private" | "$WG_BIN" pubkey)

{
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n' "$left_private"
    printf '[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.2:51821\nAllowedIPs = 10.66.0.2/32\nPersistentKeepalive = 1\n' "$right_public"
} | "$WG_BIN" setconf wgL /dev/stdin
{
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51821\n' "$right_private"
    printf '[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.66.0.1/32\nPersistentKeepalive = 1\n' "$left_public"
} | nsenter -t "$right_ns" -n -- "$WG_BIN" setconf wgR /dev/stdin
ip addr add 10.66.0.1/24 dev wgL
ip link set wgL mtu 1420 up
nsenter -t "$right_ns" -n ip addr add 10.66.0.2/24 dev wgR
nsenter -t "$right_ns" -n ip link set wgR mtu 1420 up

latency() {
    local target=$1
    ping -n -c 100 -i 0.01 "$target" |
        sed -n 's/.*time=\([0-9.]*\).*/\1/p' |
        sort -n |
        awk 'NR == 50 { p50 = $1 } NR == 99 { p99 = $1 } END { if (NR < 99) exit 1; printf "%s,%s", p50, p99 }'
}

connected=0
for _ in {1..10}; do
    if ping -n -c 1 -W 1 10.66.0.2 >/dev/null 2>&1; then
        connected=1
        break
    fi
    sleep 0.1
done
if [[ $connected == 0 ]]; then
    printf 'tunnel handshake failed; left state:\n' >&2
    "$WG_BIN" show wgL >&2 || true
    ip route >&2 || true
    printf 'right state:\n' >&2
    nsenter -t "$right_ns" -n "$WG_BIN" show wgR >&2 || true
    nsenter -t "$right_ns" -n ip route >&2 || true
    exit 1
fi
base_lat=$(latency 192.0.2.2)
tunnel_lat=$(latency 10.66.0.2)

cpu_ticks() {
    local pid=$1 total=0 stat
    for stat in /proc/"$pid"/task/*/stat; do
        [[ -r $stat ]] || continue
        total=$((total + $(sed 's/^.*) //' "$stat" | awk '{ print $12 + $13 }')))
    done
    printf '%s' "$total"
}

engine_cpu_ticks() {
    if [[ $engine != kernel ]]; then
        printf '%s' "$(( $(cpu_ticks "$left_pid") + $(cpu_ticks "$right_pid") ))"
        return
    fi
    ps -eL -o pid=,tid=,comm= |
        awk '$3 ~ /wg-crypt-wg[LR]$/ { print $1, $2 }' |
        while read -r pid tid; do
            sed 's/^.*) //' "/proc/$pid/task/$tid/stat" | awk '{ print $12 + $13 }'
        done |
        awk '{ total += $1 } END { print total + 0 }'
}

cpu_hz=$(getconf CLK_TCK)
run_iperf() {
    local streams=$1 before after json bytes ticks=NA seconds_per_gbit mbps cpu_per_gbit
    before=$(engine_cpu_ticks)
    json=$("$IPERF3_BIN" -c 10.66.0.2 -t 3 -P "$streams" -J)
    after=$(engine_cpu_ticks)
    read -r mbps bytes < <(printf '%s' "$json" | "$PYTHON_BIN" -c 'import json,sys; d=json.load(sys.stdin)["end"]; s=d.get("sum_received") or d["sum_sent"]; print("%.3f" % (s["bits_per_second"]/1e6), s["bytes"])')
    if (( after <= before )); then
        cpu_per_gbit=NA
        ticks=0
    else
        ticks=$((after - before))
        seconds_per_gbit=$(awk -v t="$ticks" -v hz="$cpu_hz" -v b="$bytes" 'BEGIN { if (b == 0) print "NA"; else printf "%.4f", (t / hz) / (b * 8 / 1e9) }')
        cpu_per_gbit=$seconds_per_gbit
    fi
    printf '%s,%s,%s,%s,%s\n' "$streams" "$mbps" "$bytes" "$cpu_per_gbit" "$ticks"
}

nsenter -t "$right_ns" -n -- "$IPERF3_BIN" -s -B 10.66.0.2 -D
sleep 0.2
iperf1=$(run_iperf 1)
iperf4=$(run_iperf 4)
kill -TERM "$(nsenter -t "$right_ns" -n pgrep -x iperf3 | head -n 1)" 2>/dev/null || true

rss_bytes() {
    awk '/^VmRSS:/ { print $2 * 1024 }' "/proc/$1/status"
}

start_engine left wgmem
wait_link left wgmem
mem_private=$($WG_BIN genkey)
kernel_mem0=NA
kernel_mem100=NA
kernel_mem1000=NA
configure_mem_peers() {
    local count=$1
    printf '%s\n' "$mem_private" |
        WG_BENCH_COUNT="$count" "$PYTHON_BIN" -c 'import base64,os,secrets,sys; key=sys.stdin.readline().strip(); n=int(os.environ["WG_BENCH_COUNT"]); print("[Interface]\nPrivateKey = " + key); [print("\n[Peer]\nPublicKey = " + base64.b64encode(secrets.token_bytes(32)).decode() + "\nAllowedIPs = 10.77.%d.%d/32" % (i // 255, (i % 255) + 1)) for i in range(n)]' |
        "$WG_BIN" setconf wgmem /dev/stdin
}
if [[ $engine == kernel ]]; then
    mem0=NA
    mem100=NA
    mem1000=NA
    kernel_mem_file=/sys/fs/cgroup/$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)/memory.current
    if [[ -r $kernel_mem_file ]]; then
        kernel_mem0=$(cat "$kernel_mem_file")
        mem_private=$($WG_BIN genkey)
        configure_mem_peers 100
        sleep 0.2
        kernel_mem100=$(cat "$kernel_mem_file")
        configure_mem_peers 1000
        sleep 0.2
        kernel_mem1000=$(cat "$kernel_mem_file")
    fi
else
    sleep 0.2
    mem0=$(rss_bytes "$mem_pid")
    configure_mem_peers 100
    sleep 0.2
    mem100=$(rss_bytes "$mem_pid")
    configure_mem_peers 1000
    sleep 0.2
    mem1000=$(rss_bytes "$mem_pid")
fi

load_end=$(awk '{ print $1 "/" $2 "/" $3 }' /proc/loadavg)
IFS=, read -r base50 base99 <<< "$base_lat"
IFS=, read -r tun50 tun99 <<< "$tunnel_lat"
IFS=, read -r _ one_mbps one_bytes one_cpu one_ticks <<< "$iperf1"
IFS=, read -r _ four_mbps four_bytes four_cpu four_ticks <<< "$iperf4"
printf 'engine,repetition,loadavg_start,loadavg_end,base_ping_p50_ms,base_ping_p99_ms,tunnel_ping_p50_ms,tunnel_ping_p99_ms,iperf1_mbps,iperf1_cpu_seconds_per_gbit,iperf4_mbps,iperf4_cpu_seconds_per_gbit,rss_base_bytes,rss_100_bytes,rss_1000_bytes,kernel_cgroup_base_bytes,kernel_cgroup_100_bytes,kernel_cgroup_1000_bytes\n'
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$engine" "$repetition" "$load_start" "$load_end" "$base50" "$base99" "$tun50" "$tun99" \
    "$one_mbps" "$one_cpu" "$four_mbps" "$four_cpu" \
    "$mem0" "$mem100" "$mem1000" \
    "$kernel_mem0" "$kernel_mem100" "$kernel_mem1000"
