#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build the product's Mac bench harness at one infraternal commit and the kit's own Go tool
# (#260, J674). Run as `claude` on the Mac VM under `lockf -k /tmp/mac-bench.lock`:
#
#   lockf -k /tmp/mac-bench.lock bash build-harness.sh harness <full-sha> <name>
#   lockf -k /tmp/mac-bench.lock bash build-harness.sh j421net
#
# `harness` builds the `infraternal-plugin-mesh` test binary at <full-sha> in a worktree under
# $HOME/worktrees/h2h-mac and copies it to $KIT_HOME/bin/<name> (the `mac_bench_device` test
# lives on the bench branches, not on dev, so pass the commit that carries it). `j421net` builds
# it from tools/j421net next to this script. Every target dir is deleted on exit.
set -euo pipefail
J=${KIT_HOME:-/Users/Shared/h2h-mac}
BIN=$J/bin; mkdir -p "$BIN"
here=$(cd "$(dirname "$0")" && pwd)
case ${1:?harness|j421net} in
  j421net)
    cd "$here/../tools/j421net" && CGO_ENABLED=0 go build -trimpath -o "$BIN/j421net" . && shasum -a 256 "$BIN/j421net" ;;
  harness)
    REV=${2:?full sha}; NAME=${3:?binary name}
    WT=$HOME/worktrees/h2h-mac; TARGET=$HOME/worktrees/h2h-mac-target
    TC=$(ls -d "$HOME"/.rustup/toolchains/*-aarch64-apple-darwin/bin | tail -1)
    LOG=$J/build-$NAME.log
    cd "$HOME/infraternal" && git fetch -q origin
    [ -d "$WT" ] || git worktree add -q --detach "$WT" "$REV"
    cd "$WT" && git checkout -q --detach "$REV"
    trap 'rm -rf "$TARGET"' EXIT
    PATH="$TC:$PATH" RUSTC="$TC/rustc" CC=/usr/bin/clang CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET" \
      nice -n 5 cargo test -j3 --release --features agent -p infraternal-plugin-mesh --lib --no-run > "$LOG" 2>&1
    BIN_PATH=$(sed -nE 's/.*Executable .*\(([^)]*)\).*/\1/p' "$LOG" | tail -1)
    test -x "$BIN_PATH"
    cp "$BIN_PATH" "$BIN/$NAME"; chmod 755 "$BIN/$NAME"
    echo "BUILD_HEAD=$(git rev-parse HEAD)"; shasum -a 256 "$BIN/$NAME"
    grep -o "gotatun?rev=[0-9a-f]*" Cargo.lock | head -1 ;;
esac
