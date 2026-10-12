#!/bin/sh
# Measure every remote setup child separately in matched fresh-target profiles on the locked VM (#190).
set -eu
cd /root/infraternal-bench/addhost-fast
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0 ADDHOST_FAST_STEP_PROFILE=1
unset BREAKIT2_FDPASS_CANDIDATE BREAKIT2_HTTPS_CANDIDATE
for phase in production-baseline final; do
    mkdir -p "steps/$phase"
    for rtt in 0 150; do
        for sample in 01 02 03 04 05 06 07 08 09 10; do
            python3 docs/verification/addhost-breakit2/measure.py --fresh \
                --container-name addhost-fast-target --controller-ip 172.17.0.1 \
                --test-binary "./$phase/controller" --payload "./$phase/infraternal" \
                --rtt "$rtt" > "steps/$phase/rtt-$rtt-$sample.log" 2>&1
        done
    done
done
docker rm -f addhost-fast-target > steps/fixture-cleanup.log
