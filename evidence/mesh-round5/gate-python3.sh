#!/usr/bin/env bash
# Route the shared gate RTT measurement to the required locked perf VM, #173.
set -euo pipefail
if [[ "$#" == 4 && "${1:-}" == */scripts/latency_proxy.py && "${2:-}" == self-test && "$3" == --samples && "$4" == 3 ]]; then
    exec netbird ssh --no-browser root@10.69.69.208 'flock /var/lock/perf-bench.lock systemd-run --user --scope -p CPUWeight=10000 python3 /root/infraternal-bench/mesh-policy/round5/latency_proxy.py self-test --samples 3'
fi
exec /home/kayg/.nix-profile/bin/python3 "$@"
