#!/usr/bin/env bash
# Route only the unchanged fast RTT probe to the locked perf VM, requiring its success record.
set -euo pipefail
if [[ "${1:-}" == */latency_proxy.py && "${2:-}" == self-test ]]; then
    output=/home/kayg/.cache/codex-scratch/dev-backmerge-prod5-cont/rtt-output.txt
    netbird ssh --no-browser root@10.69.69.208 'printf "RTT_WAITING_FOR_LOCK\n"; flock -w 1800 /var/lock/perf-bench.lock python3 /root/infraternal-bench/dev-backmerge-prod5-cont/perf-rtt.py; result=$?; printf "RTT_EXIT=%s\n" "$result"' > "$output" 2>&1
    cat "$output"
    grep -q 'METRIC name=network_rtt_selftest .*result=PASS' "$output"
    grep -q '^RTT_EXIT=0$' "$output"
    exit 0
fi
exec /home/kayg/.nix-profile/bin/python3 "$@"
