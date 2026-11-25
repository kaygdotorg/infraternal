#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1230 fork gate (J1160's recipe): fmt, clippy -D warnings, gotatun lib tests, inside the fork's own
# flake. Usage: fork-check.sh <rev>
set -uo pipefail
cd "$HOME/worktrees/j1230-gt" && git fetch -q origin && git checkout -q --detach "$1" || { echo CHECKOUT_FAIL; exit 1; }
git log --oneline -1
mkdir -m 700 -p "$HOME/.j1230"
export TMPDIR=$HOME/.j1230 CARGO_TARGET_DIR=/mnt/build/targets/j1230-gt/fork CARGO_INCREMENTAL=0
R="target.'cfg(unix)'.runner=\"env\""
cargo --version
cargo fmt --all -- --check; echo "FMT_EXIT=$?"
nice -n10 cargo clippy -j6 -p gotatun --all-targets --no-default-features --features device,ring,tun -- -D warnings 2>&1 | tail -40; echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
nice -n10 cargo test -j6 -p gotatun --lib --no-default-features --features device,ring,tun --config "$R" 2>&1 | grep -v "^test .* ok$" | tail -40; echo "TEST_EXIT=${PIPESTATUS[0]}"
echo FORK_CHECK_DONE
