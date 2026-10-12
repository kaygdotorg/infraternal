#!/usr/bin/env bash
# Runs the current-head functional/build gate while dispatching its timing self-test to the locked VM.
set -uo pipefail
export CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/mesh-agent-transport-round2/target"
export PATH="$PWD/evidence/mesh-agent-transport-continuation2/gate-bin:/home/kayg/.nix-profile/bin:$PATH"
export RUST_TEST_THREADS=1
export TRACER_TEST_PORT=4299
scripts/verify fast > evidence/mesh-agent-transport-continuation2/resumed-head-fast.log 2>&1
result=$?
printf 'Final gate exit=%s; evidence/mesh-agent-transport-continuation2/resumed-head-fast.log\n' "$result"
exit "$result"
