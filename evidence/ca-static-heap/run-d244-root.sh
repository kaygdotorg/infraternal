#!/usr/bin/env bash
# Run the real static release proof as root with D244's 8 MiB limit; caller holds the perf lock.
set -euo pipefail
cd /root/infraternal-bench/ca-heap
mkdir -p runtime
chmod 700 runtime
# Root's IPC_LOCK capability can bypass a zero limit; explicitly remove it to
# prove the shipping server still refuses partial protection after the repair.
status=0
systemd-run --quiet --wait --pipe --collect -p CPUWeight=10000 -p LimitMEMLOCK=0 \
    -p 'CapabilityBoundingSet=~CAP_IPC_LOCK' \
    /root/infraternal-bench/ca-heap/candidate-x86 server \
    --data /root/infraternal-bench/ca-heap/zero-limit-data \
    --listen 127.0.0.1:4738 --behind-proxy --trusted-proxy 127.0.0.1 \
    --public-origin https://localhost --json || status=$?
[[ "$status" == 1 ]] || { printf 'zero-limit root server unexpectedly accepted key memory\n' >&2; exit 1; }
printf 'zero-limit root server: refused (exit 1)\n'
systemd-run --quiet --wait --pipe --collect -p CPUWeight=10000 -p LimitMEMLOCK=8388608 \
    python3 /root/infraternal-bench/ca-heap/run_d244_root.py "$@"
