#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1227: stage the macro-bench binaries on A and B, ONLY while no hold is active on either VM,
# so nothing is copied during anyone's hold. Copies only files whose hash differs.
set -euo pipefail
S=$HOME/.cache/codex-scratch/j1227/stage-macro
HOSTS=(calternal-perf-01-backup01 infraternal-perf-01-backup01)
for h in "${HOSTS[@]}"; do
  ssh -o BatchMode=yes root@$h.vpn.kayg.org 'l=$(ls -d /run/j1*.lock 2>/dev/null || true); [ -z "$l" ] || { echo "hold active on $(hostname): $l"; exit 1; }'
done
for h in "${HOSTS[@]}"; do
  t=root@$h.vpn.kayg.org
  ssh -o BatchMode=yes $t 'mkdir -p /root/j1227/bin; chmod 700 /root/j1227'
  for f in "$S"/ab/*; do
    want=$(sha256sum "$f" | cut -c1-64) name=$(basename "$f")
    have=$(ssh -o BatchMode=yes $t "sha256sum /root/j1227/bin/$name 2>/dev/null | cut -c1-64")
    [[ $have == "$want" ]] || ssh -o BatchMode=yes $t "umask 077; cat > /root/j1227/bin/$name && chmod 700 /root/j1227/bin/$name" < "$f"
  done
  ssh -o BatchMode=yes $t 'echo $(hostname); sha256sum /root/j1227/bin/* | cut -c1-16,65-'
done
