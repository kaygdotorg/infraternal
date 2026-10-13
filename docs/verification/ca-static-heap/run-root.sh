#!/usr/bin/env bash
# Exercise only synthetic key-memory diagnostics under root systemd limits, #154.
set -u
cd /root/infraternal-bench/ca-heap
uname -a
cat /proc/loadavg
for mode in baseline candidate; do
    expected=0
    [[ "$mode" == baseline ]] && expected=1
    for limit in 8388608 infinity; do
        printf 'mode=%s LimitMEMLOCK=%s\n' "$mode" "$limit"
        systemd-run --quiet --wait --pipe -p "LimitMEMLOCK=$limit" \
            /root/infraternal-bench/ca-heap/heap-probe-x86_64-"$mode"
        status=$?
        printf 'exit=%s\n' "$status"
        [[ "$status" == "$expected" ]] || exit 10
    done
    printf 'mode=%s LimitMEMLOCK=unit-default\n' "$mode"
    systemd-run --quiet --wait --pipe /root/infraternal-bench/ca-heap/heap-probe-x86_64-"$mode"
    status=$?
    printf 'exit=%s\n' "$status"
    [[ "$status" == "$expected" ]] || exit 10
done
cat /proc/loadavg
