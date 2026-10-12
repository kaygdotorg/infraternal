#!/bin/sh
# Compare bounded send-buffer candidates on the locked VM using the same node payload (#190).
set -eu
cd /root/infraternal-bench/addhost-fast
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0 BREAKIT2_FDPASS_CANDIDATE=1
unset BREAKIT2_HTTPS_CANDIDATE
mkdir -p sendbuf
for buffer in 0 262144 1048576; do
    export ADDHOST_FAST_SENDBUF=$buffer
    for sample in 01 02 03; do
        python3 docs/verification/addhost-breakit2/measure.py --fresh --container-name addhost-fast-target --controller-ip 172.17.0.1 --test-binary ./node-build/controller --payload ./node-build/infraternal --rtt 150 > "sendbuf/$buffer-$sample.log" 2>&1
    done
done
docker rm -f addhost-fast-target > sendbuf/fixture-cleanup.log
