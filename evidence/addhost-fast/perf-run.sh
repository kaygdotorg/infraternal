#!/bin/sh
# Measures ten fresh disposable targets per link profile under the caller's shared VM lock (#190).
set -eu
cd /root/infraternal-bench/addhost-fast
phase=${1:?baseline or change name required}
case "$phase" in *[!a-zA-Z0-9_-]*|'') exit 2;; esac
mkdir -p "$phase"
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0
for rtt in 0 150; do
    for sample in 01 02 03 04 05 06 07 08 09 10; do
        python3 docs/verification/addhost-breakit2/measure.py \
            --fresh --container-name addhost-fast-target --controller-ip 172.17.0.1 \
            --test-binary "./$phase/controller" --payload "./$phase/infraternal" \
            --rtt "$rtt" > "$phase/rtt-$rtt-$sample.log" 2>&1
    done
done
docker rm -f addhost-fast-target > "$phase/fixture-cleanup.log"
python3 evidence/addhost-fast/report.py "$phase"
