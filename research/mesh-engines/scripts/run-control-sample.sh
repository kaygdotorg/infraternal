#!/usr/bin/env bash
# Role: Run one 1,000-peer Linux Generic Netlink control sample in a CPU-weighted scope.
# SPDX-License-Identifier: AGPL-3.0-only
#
# A fresh rootless network namespace receives a kernel WireGuard link. The
# Rust benchmark applies and verifies 1,000 peers, updates one peer, removes
# one peer, and reads the device and per-peer statistics attributes.

set -euo pipefail

usage() {
    printf 'usage: %s REPETITION {nl-wireguard|minimal|nlink}\n' "$0" >&2
    exit 2
}

if [[ ${1:-} != --inside ]]; then
    [[ $# -eq 2 && $1 =~ ^[1-5]$ ]] || usage
    repetition=$1
    kind=$2
    case "$kind" in
        nl-wireguard) : "${NETLINK_BENCH_BIN:?set NETLINK_BENCH_BIN}"; selected=$NETLINK_BENCH_BIN ;;
        minimal) : "${NETLINK_MINIMAL_BENCH_BIN:?set NETLINK_MINIMAL_BENCH_BIN}"; selected=$NETLINK_MINIMAL_BENCH_BIN ;;
        nlink) : "${NETLINK_NLINK_BENCH_BIN:?set NETLINK_NLINK_BENCH_BIN}"; selected=$NETLINK_NLINK_BENCH_BIN ;;
        *) usage ;;
    esac
    NETLINK_BENCH_BIN=$(realpath "$selected")
    : "${WG_BIN:=wg}"
    WG_BIN=$(command -v "$WG_BIN")
    export NETLINK_BENCH_BIN WG_BIN
    exec systemd-run --user --scope --quiet -p CPUWeight=10000 -- \
        unshare -Urnm -- "$0" --inside "$repetition" "$kind"
fi

repetition=$2
kind=$3
mount -t tmpfs -o mode=1777 tmpfs /run
right_ns=''
cleanup() {
    [[ -n ${right_ns:-} ]] && kill "$right_ns" 2>/dev/null || true
}
trap cleanup EXIT
ip link add veth-c type veth peer name veth-c-r
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
ip link set veth-c-r netns "$right_ns"
ip addr add 192.0.2.1/24 dev veth-c
ip link set veth-c up
ip link set lo up
nsenter -t "$right_ns" -n ip addr add 192.0.2.2/24 dev veth-c-r
nsenter -t "$right_ns" -n ip link set veth-c-r up
nsenter -t "$right_ns" -n ip link set lo up
ip link add wgctl type wireguard
ip link set wgctl up
ip link add wgstatA type wireguard
nsenter -t "$right_ns" -n ip link add wgstatB type wireguard
stat_a_private=$("$WG_BIN" genkey)
stat_b_private=$("$WG_BIN" genkey)
stat_a_public=$(printf '%s\n' "$stat_a_private" | "$WG_BIN" pubkey)
stat_b_public=$(printf '%s\n' "$stat_b_private" | "$WG_BIN" pubkey)
{
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51830\n' "$stat_a_private"
    printf '[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.2:51831\nAllowedIPs = 10.66.1.2/32\n' "$stat_b_public"
} | "$WG_BIN" setconf wgstatA /dev/stdin
{
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51831\n' "$stat_b_private"
    printf '[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51830\nAllowedIPs = 10.66.1.1/32\n' "$stat_a_public"
} | nsenter -t "$right_ns" -n -- "$WG_BIN" setconf wgstatB /dev/stdin
ip addr add 10.66.1.1/24 dev wgstatA
nsenter -t "$right_ns" -n ip addr add 10.66.1.2/24 dev wgstatB
ip link set wgstatA up
nsenter -t "$right_ns" -n ip link set wgstatB up
ping -n -c 1 -W 2 10.66.1.2 >/dev/null
"$NETLINK_BENCH_BIN"
