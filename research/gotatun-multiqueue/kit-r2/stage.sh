#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1239 (#260, from J1199) stage binaries on A and B, ONLY while no hold is active on either VM, so
# nothing is copied during a hold (ours or another job's). Copies only files whose hash differs.
#   $J/stage/*  -> /root/j1239/bin/ on A and B (engines, iperf3, wg)
#   $J/perf/    -> /root/j1239/perf/ on B only (Debian's linux-perf 6.12.117 and the three
#                  libraries B lacks, unpacked with `ar`/`tar`; nothing is installed)
set -euo pipefail
J=$HOME/.cache/codex-scratch/j1239
A=root@calternal-perf-01-backup01.vpn.kayg.org
B=root@infraternal-perf-01-backup01.vpn.kayg.org
on() { local h=$1; shift; ssh -o BatchMode=yes "$h" "$@"; }
for h in $A $B; do
    on $h 'l=$(ls -d /run/j1*.lock 2>/dev/null || true); [ -z "$l" ] || { echo "hold active on $(hostname): $l"; exit 1; }'
done
for h in $A $B; do
    on $h 'mkdir -p /root/j1239/bin; chmod 700 /root/j1239'
    for f in "$J"/stage/*; do
        want=$(sha256sum "$f" | cut -c1-64) name=$(basename "$f")
        have=$(on $h "sha256sum /root/j1239/bin/$name 2>/dev/null | cut -c1-64")
        [[ $have == "$want" ]] || on $h "umask 077; cat > /root/j1239/bin/$name && chmod 700 /root/j1239/bin/$name" < "$f"
    done
    on $h 'echo $(hostname); sha256sum /root/j1239/bin/* | cut -c1-16,65-'
done
on $B 'test -x /root/j1239/perf/perf' || tar -C "$J" -cf - perf | on $B 'tar -C /root/j1239 -xf - --no-same-owner'
on $B 'LD_LIBRARY_PATH=/root/j1239/perf/lib /root/j1239/perf/perf --version'
