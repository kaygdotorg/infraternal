#!/bin/sh
# Measures the immutable infraternal-agent transport tests on the locked perf VM.
set -u
cd /root/infraternal-bench/mat129-c2
export CARGO_TARGET_DIR=$PWD
export INFRATERNAL_MESH_PROOF_SCRATCH=$PWD/scale
export INFRATERNAL_MESH_IDLE_MS=60000
export INFRATERNAL_MESH_KEEPALIVE_MS=100
export RUST_BACKTRACE=0
./agent-tests review_silent_mesh_interruption_returns_to_fallback_within_local_reconnect_budget --ignored --nocapture --test-threads=1 > review-r5.log 2>&1
echo $? > review-r5.exit
./agent-tests mesh_idle_timer_cost_at_one_thousand_connections --ignored --nocapture --test-threads=1 > scale.log 2>&1
echo $? > scale.exit
printf 'Infraternal-agent proof outputs saved\n'
