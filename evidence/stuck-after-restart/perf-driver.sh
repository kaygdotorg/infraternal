#!/usr/bin/env bash
# Isolate real root PTYs and shell profiles inside this job's perf-VM directory; lock only measurements.
set -euo pipefail
bench=/root/infraternal-bench/stuck-after-restart
mkdir -p "$bench/run" "$bench/home" "$bench/data"
printf 'root:x:0:0:Restart fixture:%s/home:/bin/sh\n' "$bench" > "$bench/passwd-fixture"
export RESTART_BENCH="$bench"
exec 9>/var/lock/perf-bench.lock
exec unshare --mount --propagation private /bin/bash -eu <<'NAMESPACE'
mount --bind "$RESTART_BENCH/run" /run
mount --bind "$RESTART_BENCH/passwd-fixture" /etc/passwd
cd "$RESTART_BENCH/repo/apps/tracer"
export REAL_ROOT_NAMESPACE=1 RESTART_MEASURE=1 RESTART_SESSIONS=72 REAL_ONE_WAY_MS=75 TRACER_TEST_PORT=4399
export INFRATERNAL_TEST_STATE_ROOT=/run/r INFRATERNAL_TEST_DATA_ROOT="$RESTART_BENCH/data"
export INFRATERNAL_BIN="$RESTART_BENCH/repo/infraternal"
export PATH="/root/.bun/bin:$PATH"
flock -w 3600 9
bun real/perf-restart.ts
NAMESPACE
