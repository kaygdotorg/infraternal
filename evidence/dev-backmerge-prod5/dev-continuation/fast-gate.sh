#!/usr/bin/env bash
# Runs the unchanged repository gate; its RTT self-test alone is delegated to the locked perf VM.
set -euo pipefail
umask 022
export CARGO_TARGET_DIR=/home/kayg/.cache/codex-scratch/dev-backmerge-prod5-cont/target
export INFRATERNAL_TEST_STATE_ROOT=/home/kayg/.cache/codex-scratch/b6
export TMPDIR="$INFRATERNAL_TEST_STATE_ROOT"
export RUST_TEST_THREADS=4
export TRACER_TEST_PORT=4977
export PATH="/home/kayg/.cache/codex-scratch/dev-backmerge-prod5-cont/bin:$CARGO_TARGET_DIR/auth-tools/zig:/home/kayg/.nix-profile/bin:$PATH"
scripts/verify fast
