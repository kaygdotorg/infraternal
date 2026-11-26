#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1227 (#260, from J1199) hold lock on one VM: takes every perf/build lock present (infraternal
# perf-run's, calternal's perf lock and build slot), so no other project's run overlaps a
# hold, and marks the hold with /run/j1227.lock. A sleeper owns the flocks; release kills it.
#   lock.sh take <tag> | release
set -euo pipefail
case $1 in
take)
    # Another job's hold on these VMs (other jobs share them) marks itself with /run/j11NN.lock:
    # wait until none is left, then mark ours. The flocks below are the real exclusion.
    for _ in $(seq 1 14400); do
        others=$(ls -d /run/j11*.lock 2>/dev/null | grep -v -e '^/run/j1227.lock$' -e '^/run/j11-j1227.lock$' || true)
        [[ -z $others ]] && break
        sleep 2
    done
    [[ -z $others ]] || { echo "other hold still present: $others" >&2; exit 1; }
    mkdir /run/j1227.lock
    echo "$2 $(date -u +%FT%TZ)" > /run/j1227.lock/tag
    # Open each lock read-only (no O_CREAT): fs.protected_regular=2 refuses root an O_CREAT
    # open of another user's file in the sticky /var/lock, and flock(2) needs no write access.
    script=''
    n=3
    for f in /var/lock/infraternal-perf.lock /var/lock/calternal-perf.lock /tmp/calternal-build-slot.1; do
        [[ -e $f ]] || continue
        script+="exec $n<'$f'; flock -x $n; "
        n=$((n + 1))
    done
    script+='echo $$ > /run/j1227.lock/holder; exec sleep 14400'
    setsid nohup sh -c "$script" > /dev/null 2>&1 < /dev/null &
    # J1227: the waiter is its own process group (setsid); remember it, so a timeout or a
    # release kills the waiter too instead of leaving it to grab the locks later and sit on them.
    echo $! > /run/j1227.lock/waiter
    for _ in $(seq 1 3600); do [[ -s /run/j1227.lock/holder ]] && break; sleep 1; done
    if [[ ! -s /run/j1227.lock/holder ]]; then
        kill -- -"$(cat /run/j1227.lock/waiter)" 2>/dev/null || true
        rm -rf /run/j1227.lock
        echo "lock wait timed out" >&2; exit 1
    fi
    # The marker other jobs wait on goes up only now that the flocks are ours: raised while still
    # queueing (as in the J1227 holds M1-M3) it blocks waiters although nothing is being measured.
    mkdir -p /run/j11-j1227.lock
    echo "held: $(ls -l /proc/$(cat /run/j1227.lock/holder)/fd | grep -o "/[^ ]*lock[^ ]*\|/tmp/[^ ]*" | tr "\n" " ")" ;;
release)
    [[ -s /run/j1227.lock/holder ]] && kill "$(cat /run/j1227.lock/holder)" 2>/dev/null || true
    [[ -s /run/j1227.lock/waiter ]] && kill -- -"$(cat /run/j1227.lock/waiter)" 2>/dev/null || true
    rm -rf /run/j1227.lock
    echo released ;;
esac
