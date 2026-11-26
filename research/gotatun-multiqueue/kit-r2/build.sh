#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1239 (#260) bench build on compute01, inside `nix develop ~/worktrees/j1239`: gotatun-cli from the
# fork checkout ~/worktrees/j1239-gt at <rev> (ring + mimalloc, static musl, J1199's recipe, as
# J1230), copied to ~/.cache/codex-scratch/j1239/bin/<name>. TESTS=1 also runs fmt, clippy
# -D warnings and the gotatun lib tests; TESTS=only runs just those.
#   build.sh <rev> <name>
set -uo pipefail
rev=$1 name=$2
J=$HOME/.cache/codex-scratch/j1239
WT=$HOME/worktrees/j1239
src=$HOME/worktrees/j1239-gt
mkdir -m 700 -p "$HOME/.j1239"
export TMPDIR=$HOME/.j1239 CARGO_INCREMENTAL=0
out=$J/bin; mkdir -p "$out"
T=x86_64-unknown-linux-musl
IXT=/mnt/build/targets/j1239-ix
GT=/mnt/build/targets/j1239-gt
mkdir -p $IXT $GT
( cd "$WT" && CARGO_TARGET_DIR=$IXT scripts/auth-toolchain > /dev/null ) || { echo AUTH_TOOLCHAIN_FAIL; exit 1; }
ln -sfn $IXT/auth-tools $GT/auth-tools
export PATH="$IXT/auth-tools/zig:$PATH"
cd "$src" && git fetch -q origin && git checkout -q --detach "$rev" || { echo CHECKOUT_FAIL; exit 1; }
git log --oneline -1
if [[ ${TESTS:-0} != 0 ]]; then
    cargo fmt --all -- --check; echo "FMT_EXIT=$?"
    F="--no-default-features --features device,ring,tun"
    CARGO_TARGET_DIR=$GT/host nice -n10 cargo clippy -j6 --locked -p gotatun --all-targets $F -- -D warnings 2>&1 | tail -30; echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
    CARGO_TARGET_DIR=$GT/host nice -n10 cargo test -j6 --locked -p gotatun --lib $F --config "target.'cfg(unix)'.runner=\"env\"" 2>&1 | grep -E '^test result|FAILED|panicked' | tail -30; echo "TEST_EXIT=${PIPESTATUS[0]}"
fi
[[ ${TESTS:-0} == only ]] && { echo BUILD_DONE; exit 0; }
CARGO_TARGET_DIR=$GT CC_x86_64_unknown_linux_musl=$WT/.cargo/musl-cc.sh AR_x86_64_unknown_linux_musl=$WT/.cargo/musl-ar.sh \
    nice -n10 cargo build -j6 --locked --release -p gotatun-cli --no-default-features --features ring,mimalloc --target $T \
      --config "target.$T.linker=\"$WT/.cargo/rust-lld.sh\"" --config "target.$T.rustflags=[\"-C\",\"target-feature=+crt-static\"]" 2>&1 | tail -30
echo "GT_EXIT=${PIPESTATUS[0]}"
cp $GT/$T/release/gotatun $out/$name && sha256sum $out/$name && file $out/$name
echo BUILD_DONE
