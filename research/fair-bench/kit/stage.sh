#!/bin/bash
# J1199: stage binaries on A and B (stage/ab) and C (stage/c), ONLY while no hold is active on any
# of the three VMs, so nothing is ever copied during a hold (ours or another job's). Copies only
# files whose hash differs.
set -euo pipefail
S=$HOME/.cache/codex-scratch/j1199/stage
declare -A HOSTS=([calternal-perf-01-backup01]=ab [infraternal-perf-01-backup01]=ab [calternal-perf-02-backup01]=c)
for h in "${!HOSTS[@]}"; do
  ssh -o BatchMode=yes root@$h.vpn.kayg.org 'l=$(ls -d /run/j1*.lock 2>/dev/null || true); [ -z "$l" ] || { echo "hold active on $(hostname): $l"; exit 1; }'
done
for h in "${!HOSTS[@]}"; do
  t=root@$h.vpn.kayg.org
  ssh -o BatchMode=yes $t 'mkdir -p /root/j1199/bin; chmod 700 /root/j1199'
  for f in "$S/${HOSTS[$h]}"/*; do
    want=$(sha256sum "$f" | cut -c1-64) name=$(basename "$f")
    have=$(ssh -o BatchMode=yes $t "sha256sum /root/j1199/bin/$name 2>/dev/null | cut -c1-64")
    [[ $have == "$want" ]] || ssh -o BatchMode=yes $t "umask 077; cat > /root/j1199/bin/$name && chmod 700 /root/j1199/bin/$name" < "$f"
  done
  ssh -o BatchMode=yes $t 'echo $(hostname); sha256sum /root/j1199/bin/* | cut -c1-16,65-'
done
