#!/bin/sh
# Isolate root-only shipping runtime paths inside this job’s scratch space [217], #154.
set -eu
job_directory=/root/.cache/codex-scratch/ca-handoff
mkdir -p "$job_directory/r"
chmod 700 "$job_directory/r"
mount --bind "$job_directory/r" /run
exec env INFRATERNAL_TEST_BINARY="$job_directory/round2/infraternal" \
 "$job_directory/round2/server-tests" --ignored --exact \
 ca_handoff::shipping_tests::shipping_restart_reload_rollback_and_cold_start --nocapture
