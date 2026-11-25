#!/bin/bash
# J1199 (#260) second bench build on compute01, inside `nix develop <wt>`: infraternal + coordinator_fixture
# at current dev (with J1159's pin and the later guard changes) in its own worktree and target, and
# gotatun-cli at e87fef91 (ring + mimalloc, static musl). The musl C wrapper finds the pinned Zig under
# "<target>/auth-tools", so the fork's target links to the one auth-toolchain installed.
set -uo pipefail
J=$HOME/.cache/codex-scratch/j1199
WT=$HOME/worktrees/j1199b
mkdir -m 700 -p "$HOME/.j1199"
export TMPDIR=$HOME/.j1199 CARGO_INCREMENTAL=0
out=$J/bin2; mkdir -p "$out"
T=x86_64-unknown-linux-musl
cd "$WT"
export CARGO_TARGET_DIR=/mnt/build/targets/j1199b
scripts/auth-toolchain > /dev/null || { echo AUTH_TOOLCHAIN_FAIL; exit 1; }
export PATH="$CARGO_TARGET_DIR/auth-tools/zig:$PATH"
nice -n10 scripts/static-cargo build -j6 --locked --release --package infraternal --target $T; echo "IX_EXIT=$?"
nice -n10 scripts/static-cargo build -j6 --locked --release -p infraternal-plugin-mesh --example coordinator_fixture --target $T; echo "CF_EXIT=$?"
cp $CARGO_TARGET_DIR/$T/release/infraternal $out/infraternal
cp $CARGO_TARGET_DIR/$T/release/examples/coordinator_fixture $out/coordinator_fixture
src=$HOME/worktrees/j1199-gt-j59
GT=/mnt/build/targets/j1199-gt-j59
mkdir -p $GT; ln -sfn $CARGO_TARGET_DIR/auth-tools $GT/auth-tools
( cd "$src" && git checkout -q --detach e87fef91fcab0dd338c5ecfcdd1afaa516bebf17 && CARGO_TARGET_DIR=$GT \
    CC_x86_64_unknown_linux_musl=$WT/.cargo/musl-cc.sh AR_x86_64_unknown_linux_musl=$WT/.cargo/musl-ar.sh \
    nice -n10 cargo build -j6 --locked --release -p gotatun-cli --no-default-features --features ring,mimalloc --target $T \
      --config "target.$T.linker=\"$WT/.cargo/rust-lld.sh\"" --config "target.$T.rustflags=[\"-C\",\"target-feature=+crt-static\"]" )
echo "GT_j59_EXIT=$?"
cp $GT/$T/release/gotatun $out/gotatun-j59
git -C "$WT" log --oneline -1; git -C "$src" log --oneline -1
cd "$out" && sha256sum * && file *
echo BUILD_DONE
