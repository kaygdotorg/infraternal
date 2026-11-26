#!/bin/bash
# J1199: stage binaries on A and B (stage/ab) and C (stage/c), ONLY while no hold is active on any
# of the three VMs, so nothing is ever copied during a hold (ours or another job's). Copies only
# files whose hash differs.
set -euo pipefail
JOB=${FB_JOB:-j1199}   # J1237: another job stages under its own name
S=$HOME/.cache/codex-scratch/$JOB/stage
declare -A HOSTS=([calternal-perf-01-backup01]=ab [infraternal-perf-01-backup01]=ab [calternal-perf-02-backup01]=c)
# J1237: a VM with a hold is skipped (staging there later), the others are staged now.
declare -A SKIP
for h in "${!HOSTS[@]}"; do
  ssh -o BatchMode=yes root@$h.vpn.kayg.org 'l=$(ls -d /run/j1*.lock 2>/dev/null || true); [ -z "$l" ] || { echo "hold active on $(hostname): $l"; exit 1; }' || SKIP[$h]=1
done
for h in "${!HOSTS[@]}"; do
  [[ -z ${SKIP[$h]:-} ]] || { echo "skipped $h"; continue; }
  t=root@$h.vpn.kayg.org
  ssh -o BatchMode=yes $t "mkdir -p /root/$JOB/bin; chmod 700 /root/$JOB"
  for f in "$S/${HOSTS[$h]}"/*; do
    want=$(sha256sum "$f" | cut -c1-64) name=$(basename "$f")
    have=$(ssh -o BatchMode=yes $t "sha256sum /root/$JOB/bin/$name 2>/dev/null | cut -c1-64")
    [[ $have == "$want" ]] || ssh -o BatchMode=yes $t "umask 077; cat > /root/$JOB/bin/$name && chmod 700 /root/$JOB/bin/$name" < "$f"
  done
  # J1237: the scripted-owner browser app (playwright from the tracer's lockfile) and the headless shell's libraries.
  ssh -o BatchMode=yes $t "if [ -f /root/$JOB/bin/app-node_modules.tgz ]; then mkdir -p /root/$JOB/app && tar xzf /root/$JOB/bin/app-node_modules.tgz -C /root/$JOB/app --no-same-owner && mkdir -p /root/$JOB/app/node_modules && (cd /root/$JOB/app && for d in playwright playwright-core; do rm -rf node_modules/\$d; mv \$d node_modules/; done); fi; if [ -d /home/claude/nightly-latency/libs ] && [ ! -d /root/$JOB/libs ]; then cp -a /home/claude/nightly-latency/libs /root/$JOB/libs && sed -i \"s#/home/claude/nightly-latency/libs#/root/$JOB/libs#; s#/home/claude/nightly-latency/fontcache#/root/$JOB/fontcache#\" /root/$JOB/libs/fonts.conf; fi"
  ssh -o BatchMode=yes $t "echo \$(hostname); sha256sum /root/$JOB/bin/* | cut -c1-16,65-"
done
