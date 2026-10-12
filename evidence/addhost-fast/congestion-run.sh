#!/bin/sh
# Compare existing kernel congestion controls on owned fixture sockets; no production choice (#190).
set -eu
cd /root/infraternal-bench/addhost-fast
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0 BREAKIT2_FDPASS_CANDIDATE=1
export ADDHOST_FAST_SENDBUF=0
unset BREAKIT2_HTTPS_CANDIDATE
mkdir -p congestion
for congestion in default cubic; do
    export ADDHOST_FAST_CONGESTION=$congestion
    for sample in 01 02 03; do
        python3 docs/verification/addhost-breakit2/measure.py --fresh \
            --container-name addhost-fast-target --controller-ip 172.17.0.1 \
            --test-binary ./negotiated-setup/controller --payload ./node-build/infraternal \
            --rtt 150 > "congestion/$congestion-$sample.log" 2>&1
    done
done
docker rm -f addhost-fast-target > congestion/fixture-cleanup.log
