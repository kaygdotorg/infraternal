#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1227 (#260) hold for the whole-filter timing test (research/gotatun-hasher/patches/hbench-test.rs.txt):
# the same static test binary built from the baseline tree and from the foldhash-patched tree, run in
# order base h1 h1 base, twice, pinned to one CPU of infraternal-perf-01. Needs mesh-tests-base and
# mesh-tests-h1 in stage/. Same lock protocol as micro.sh.
set -uo pipefail
cd "$(dirname "$0")"
VM=${1:-infraternal-perf-01-backup01}
T=root@$VM.vpn.kayg.org
S=$HOME/.cache/codex-scratch/j1227
R=/root/j1227h
ev=$S/evidence/hbench-$(date -u +%m%dT%H%M)
mkdir -p "$ev"
on() { ssh -o BatchMode=yes -o ServerAliveInterval=15 "$T" "$@"; }
log() { echo "[$(date -u +%T)] $*"; }
cleanup() { on "rm -rf /run/j11-j1227.lock"; on "$R/lock.sh release" > /dev/null 2>&1; on "rm -rf $R" > /dev/null 2>&1; log released; }
trap cleanup EXIT
on "mkdir -p $R && chmod 700 $R && cat > $R/lock.sh && chmod 700 $R/lock.sh" < ./lock.sh
log "waiting for the lock on $VM"
on "$R/lock.sh take hbench" || { log "lock failed"; exit 1; }
on "mkdir -p /run/j11-j1227.lock"
log "held"
for f in mesh-tests-base mesh-tests-h1; do on "umask 077; cat > $R/$f && chmod 700 $R/$f" < "$S/stage/$f"; done
on "cd $R; sha256sum mesh-tests-*; uname -r; uptime" > "$ev/machine.txt" 2>&1
for rep in 1 2; do
  for v in base h1 h1 base; do
    log "rep $rep $v"
    on "cd $R && taskset -c 3 ./mesh-tests-$v --ignored hasher_bench --nocapture --test-threads 1" > "$ev/rep$rep-$v-$RANDOM.txt" 2>&1
  done
done
on "uptime" >> "$ev/machine.txt" 2>&1
log "done: $ev"
