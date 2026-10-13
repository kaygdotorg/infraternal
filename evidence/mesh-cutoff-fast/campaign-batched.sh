#!/usr/bin/env bash
# Release the shared VM lock between short five-sample batches [256].
set -u
root=/root/infraternal-bench/mesh-cutoff-fast
failed=0
for variant in baseline head; do
 for backend in nft compat; do
  for first in 1 6 11 16 21 26 31; do
   last=$((first+4))
   [[ "$last" -gt 31 ]] && last=31
   flock -w 3600 /var/lock/perf-bench.lock systemd-run --user --scope -p CPUWeight=10000 env INFRATERNAL_CUTOFF_MEASURE=1 bash "$root/run-samples.sh" "$variant" "$backend" "$first" "$last"
   batch_exit=$?
   [[ "$batch_exit" == 0 || "$batch_exit" == 1 ]] || exit "$batch_exit"
   [[ "$batch_exit" == 1 ]] && failed=1
  done
 done
done
exit "$failed"
