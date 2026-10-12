#!/usr/bin/env bash
# Compare the exact live-base and integrated static images through the same native fixture [D41], #160/#168.
set -u
cd /root/infraternal-bench/prod4
exec 9>/var/lock/perf-bench.lock
flock 9
export INFRATERNAL_TEST_RTT=0
export INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/prod4/state
mkdir -p "$INFRATERNAL_TEST_STATE_ROOT"
uname -a
getconf _NPROCESSORS_ONLN
sha256sum base head
failed=0
for run in 1 2 3; do
    for revision in base head; do
        printf 'RUN revision=%s iteration=%s\n' "$revision" "$run"
        cat /proc/loadavg
        python3 scripts/verify-latency.py --samples 1000 --binary "./$revision" > "$revision-$run.log" 2>&1
        result=$?
        cat "$revision-$run.log"
        printf 'NATIVE_EXIT=%s\n' "$result"
        cat /proc/loadavg
        if (( result != 0 )); then failed=1; fi
    done
done
exit "$failed"
