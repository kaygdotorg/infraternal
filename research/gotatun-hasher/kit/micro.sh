#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1204 (#260) micro-bench hold, driven from hd01 against ONE perf VM (default infraternal-perf-01,
# 6 vCPU). Waits until no other /run/j11*.lock exists (J1160/J1199 protocol), takes every perf
# lock, copies the two small static binaries (inside our own hold), records the machine, runs the
# criterion bench twice pinned to one CPU (rep 1 and rep 2 = the A/A floor), the probe-length
# probe, and fetches everything. The lock is released on exit.
set -uo pipefail
cd "$(dirname "$0")"
VM=${1:-infraternal-perf-01-backup01}
T=root@$VM.vpn.kayg.org
S=$HOME/.cache/codex-scratch/j1204
R=/root/j1204
BIN=${BIN:-hot_paths}
REPS=${REPS:-"1 2"}
ev=$S/evidence/micro-$(date -u +%m%dT%H%M)
mkdir -p "$ev"
on() { ssh -o BatchMode=yes -o ServerAliveInterval=15 "$T" "$@"; }
log() { echo "[$(date -u +%T)] $*"; }
cleanup() { on "rm -rf /run/j11-j1204.lock"; on "$R/lock.sh release" > /dev/null 2>&1; on "rm -rf $R" > /dev/null 2>&1; log released; }
trap cleanup EXIT
on "mkdir -p $R && chmod 700 $R && cat > $R/lock.sh && chmod 700 $R/lock.sh" < ./lock.sh
log "waiting for the lock on $VM"
on "$R/lock.sh take micro" || { log "lock failed"; exit 1; }
log "held"
for f in $BIN quality; do on "umask 077; cat > $R/$f && chmod 700 $R/$f" < "$S/stage/$f"; done
on "mkdir -p /run/j11-j1204.lock"
on "cd $R; sha256sum $BIN quality; uname -r; lscpu | grep -E 'Model name|MHz|L2|L3'; cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c; cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null; uptime; grep -E 'cpu ' /proc/stat" > "$ev/machine.txt" 2>&1
on "taskset -c 3 $R/quality" > "$ev/quality-x86.txt" 2>&1
for rep in $REPS; do
  log "criterion rep $rep"
  on "cd $R && taskset -c 3 ./$BIN --bench --warm-up-time 1 --measurement-time 3 --sample-size 50 --noplot" > "$ev/crit-rep$rep.txt" 2>&1
  echo "exit=$?" >> "$ev/crit-rep$rep.txt"
  on "uptime; grep -E '^cpu ' /proc/stat" >> "$ev/machine.txt" 2>&1
done
log "done: $ev"
