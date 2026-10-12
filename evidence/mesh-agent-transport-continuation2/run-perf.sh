#!/bin/sh
# Runs immutable D215 real-PTY and transport proofs only under the perf VM lock.
set -u
cd /root/infraternal-bench/mat129-c2
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_TARGET_DIR=/root/infraternal-bench/mat129-c2
export INFRATERNAL_MESH_BINARY=$PWD/shipping-cli
export INFRATERNAL_MESH_PROOF=1
export RUST_BACKTRACE=0
for rtt in 0 150 300; do
  export INFRATERNAL_TEST_RTT=$rtt
  export INFRATERNAL_MESH_PROOF_SCRATCH=$PWD/rtt-$rtt
  export INFRATERNAL_MESH_PROOF_STATE=$PWD/s$rtt
  mkdir -p "$INFRATERNAL_MESH_PROOF_SCRATCH"
  test ! -e "$INFRATERNAL_MESH_PROOF_STATE" || exit 3
  cat /proc/loadavg > "$INFRATERNAL_MESH_PROOF_SCRATCH/load-before.txt"
  unshare -nm ./server-tests remote_runtime::tests::mesh_namespace::mesh_transport_real_namespaces_preserve_the_terminal --exact --ignored --nocapture --test-threads=1 > "$INFRATERNAL_MESH_PROOF_SCRATCH/test.log" 2>&1
  echo $? > "$INFRATERNAL_MESH_PROOF_SCRATCH/test.exit"
  cat /proc/loadavg > "$INFRATERNAL_MESH_PROOF_SCRATCH/load-after.txt"
  test ! -e "$INFRATERNAL_MESH_PROOF_STATE" || exit 4
  printf 'RTT %s: evidence saved\n' "$rtt"
done
./server-tests input_retention_cost_at_200_terminals --ignored --nocapture --test-threads=1 > retained-200.log 2>&1
echo $? > retained-200.exit
if [ "${1:-}" = namespace-only ]; then exit 0; fi
./agent-tests review_silent_mesh_interruption_returns_to_fallback_within_local_reconnect_budget --ignored --nocapture --test-threads=1 > review-r5.log 2>&1
echo $? > review-r5.exit
export INFRATERNAL_MESH_PROOF_SCRATCH=$PWD/scale
export INFRATERNAL_MESH_IDLE_MS=60000
export INFRATERNAL_MESH_KEEPALIVE_MS=100
./agent-tests mesh_idle_timer_cost_at_one_thousand_connections --ignored --nocapture --test-threads=1 > scale.log 2>&1
echo $? > scale.exit
printf 'Perf proofs complete; inspect exit files and public reports\n'
