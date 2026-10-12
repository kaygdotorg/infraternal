#!/usr/bin/env bash
# Runs the functional native gates for the D250 continuation without performance claims.
set -uo pipefail
umask 022
export CARGO_TARGET_DIR=/home/kayg/.cache/codex-scratch/dev-backmerge-prod5-cont/target
export INFRATERNAL_TEST_STATE_ROOT=/home/kayg/.cache/codex-scratch/b5c
export RUST_TEST_THREADS=4
export PATH="$CARGO_TARGET_DIR/auth-tools/zig:/home/kayg/.nix-profile/bin:$PATH"
failed=0
cargo fmt --all --check || failed=1
cargo clippy --locked --all-targets -p infraternal -p infraternal-server -p infraternal-agent -p infraternal-shim -p infraternal-plugin-ssh -p infraternal-plugin-release -- -D warnings || failed=1
cargo test --locked -p infraternal -p infraternal-server -p infraternal-agent -p infraternal-shim -p infraternal-plugin-ssh -p infraternal-plugin-release || failed=1
python3 crates/plugins/ssh/tests/previous_attempt_shell.py || failed=1
exit "$failed"
