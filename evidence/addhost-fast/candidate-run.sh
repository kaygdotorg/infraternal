#!/bin/sh
# Compare three fresh pinned HTTPS and SSH transfers per link profile on the locked VM (#190).
set -eu
cd /root/infraternal-bench/addhost-fast
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0
for transport in ssh https; do
    for rtt in 0 150; do
        for sample in 01 02 03; do
            if [ "$transport" = https ]; then export BREAKIT2_HTTPS_CANDIDATE=1; else unset BREAKIT2_HTTPS_CANDIDATE; fi
            python3 docs/verification/addhost-breakit2/measure.py --fresh --container-name addhost-fast-target --controller-ip 172.17.0.1 --test-binary ./candidate-https/controller --payload ./candidate-https/infraternal --rtt "$rtt" > "candidate-https/$transport-$rtt-$sample.log" 2>&1
        done
    done
done
docker rm -f addhost-fast-target > candidate-https/fixture-cleanup.log
