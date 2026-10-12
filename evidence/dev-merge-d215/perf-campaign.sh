#!/usr/bin/env bash
# Compare dev and the D215 merge in alternating order on the locked perf VM [41][215][250].
set -uo pipefail
cd /root/infraternal-bench/dev-merge-d215
mkdir -p results
uname -a > results/machine.txt
getconf _NPROCESSORS_ONLN >> results/machine.txt
sha256sum binaries/dev binaries/merged > results/binaries.sha256
for round in 1 2; do
  if [[ $round == 2 ]]; then variants=(merged dev); else variants=(dev merged); fi
  for variant in "${variants[@]}"; do
    cat /proc/loadavg > "results/${variant}-${round}.load-before"
    INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
      python3 scripts/verify-latency.py --binary "binaries/$variant" > "results/${variant}-${round}.log" 2>&1
    echo $? > "results/${variant}-${round}.exit"
    cat /proc/loadavg > "results/${variant}-${round}.load-after"
  done
done
for spec in verify-session-bounds verify-session-exit-credit verify-session-exit-events verify-session-retention; do
  INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
    python3 "scripts/$spec.py" --binary binaries/merged > "results/$spec.log" 2>&1
  echo $? > "results/$spec.exit"
done
INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
  python3 scripts/verify-session-exit-credit.py --binary binaries/merged --exit-after-detach > results/exit-after-detach.log 2>&1
echo $? > results/exit-after-detach.exit
INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
  python3 scripts/verify-agent.py --binary binaries/merged > results/idle-canary.log 2>&1
echo $? > results/idle-canary.exit
