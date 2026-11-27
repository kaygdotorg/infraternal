#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build every binary the Mac windows run, from THIS checkout (#260, J674, J679). Run as `claude`
# on the Mac VM under the Mac lock, from a fresh `git archive` of the branch under test:
#
#   lockf -k /tmp/mac-bench.lock bash mac/build-harness.sh harness <name> [<gotatun-rev>]
#   lockf -k /tmp/mac-bench.lock bash mac/build-harness.sh j421net
#   lockf -k /tmp/mac-bench.lock bash mac/build-harness.sh daemons   # tailscale(d) + netbird, pinned
#
# `harness` builds the `infraternal-plugin-mesh` test binary (it carries the ignored
# `mac_bench_device` test, the product's own Mac data path with one static peer) and copies it to
# $KIT_HOME/bin/<name>. Without a GotaTun rev it is the PIN: the GotaTun that the checkout's
# Cargo.toml and Cargo.lock name, built with `--locked`. With a rev it is a CANDIDATE: the same
# checkout with only the pinned `gotatun` rev replaced (any rev of the
# same GotaTun fork that cargo can fetch), built in a throw-away copy, so pin and candidate differ
# in nothing but the GotaTun source. Typical pair:
#
#   build-harness.sh harness mesh-bench-pin
#   build-harness.sh harness mesh-bench-cand <rev-of-the-candidate>
#
# Nothing is built from a different tree than the checkout: no hand-built binaries, no worktrees
# of other branches (owner rule: always the latest code). The summary line prints the checkout's
# KIT_COMMIT (from `KIT_COMMIT` if the archive carries it, else `git rev-parse` if it is a clone),
# the resolved GotaTun source line from the lock file and the binary's sha256, so each receipt
# names what it measured. The target dir is deleted on exit (the Mac disk is small).
set -euo pipefail
J=${KIT_HOME:-/Users/Shared/h2h-mac}
BIN=$J/bin; mkdir -p "$BIN"
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
case ${1:?harness|j421net|daemons} in
  daemons)
    # tailscale, tailscaled and netbird from the source tags pinned in pins.txt (sha256 checked),
    # so check-pins.sh can refuse a window whose clients are another version.
    PINS=$here/../../pins.txt; W=$(mktemp -d "${TMPDIR:-/tmp}/h2h-daemons.XXXXXX"); trap 'rm -rf "$W"' EXIT
    for n in tailscale netbird; do
      read -r url sha < <(awk -v n="$n-src" '$1 == n && $2 == "darwin-arm64" {print $3, $4}' "$PINS")
      [ -n "$url" ] || { echo "no darwin-arm64 pin for $n" >&2; exit 1; }
      curl -sSL -o "$W/$n.tgz" "$url"
      [ "$(shasum -a 256 "$W/$n.tgz" | cut -d' ' -f1)" = "$sha" ] || { echo "sha256 mismatch for $n source" >&2; exit 1; }
      mkdir "$W/$n" && tar -xzf "$W/$n.tgz" -C "$W/$n" --strip-components=1
    done
    export CGO_ENABLED=0 GOFLAGS=-trimpath
    (cd "$W/tailscale" && go build -o "$BIN/tailscale" ./cmd/tailscale && go build -o "$BIN/tailscaled" ./cmd/tailscaled)
    # NetBird reports "development" unless its release version is linked in.
    (cd "$W/netbird" && go build -ldflags "-X github.com/netbirdio/netbird/version.version=$(awk '$1=="netbird-src"&&$2=="darwin-arm64"{print $3}' "$PINS" | sed -nE 's#.*/v([0-9.]+)\.tar\.gz#\1#p')" -o "$BIN/netbird" ./client)
    bash "$here/check-pins.sh" "$PINS" "$BIN" tailscale netbird ;;
  j421net)
    cd "$here/../../tools/j421net" && CGO_ENABLED=0 go build -trimpath -o "$BIN/j421net" . && shasum -a 256 "$BIN/j421net" ;;
  harness)
    NAME=${2:?binary name}; REV=${3:-}
    TARGET=$HOME/worktrees/h2h-mac-target-$NAME; SRC=$root; LOCKED=--locked
    TC=$(ls -d "$HOME"/.rustup/toolchains/*-aarch64-apple-darwin/bin | tail -1)
    LOG=$J/build-$NAME.log
    COPY=
    trap 'rm -rf "$TARGET" $COPY' EXIT
    if [ -n "$REV" ]; then
      COPY=$HOME/worktrees/h2h-mac-src-$NAME; SRC=$COPY
      rm -rf "$COPY"; mkdir -p "$COPY"
      # tar keeps the copy exact and skips build output. swap-gotatun-rev.sh replaces the rev,
      # re-resolves the lock and FAILS unless Cargo.lock changed only in the gotatun entry, so the
      # candidate build can use --locked like the pin and differs from it in GotaTun alone.
      (cd "$root" && tar --exclude=./target --exclude=./node_modules --exclude=./.git -cf - .) | tar -xf - -C "$COPY"
      PATH="$TC:$PATH" RUSTC="$TC/rustc" bash "$here/swap-gotatun-rev.sh" "$COPY" "$REV"
    fi
    cd "$SRC"
    PATH="$TC:$PATH" RUSTC="$TC/rustc" CC=/usr/bin/clang CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET" \
      nice -n 5 cargo test -j3 --release $LOCKED --features agent -p infraternal-plugin-mesh --lib --no-run > "$LOG" 2>&1
    BIN_PATH=$(sed -nE 's/.*Executable .*\(([^)]*)\).*/\1/p' "$LOG" | tail -1)
    test -x "$BIN_PATH"
    cp "$BIN_PATH" "$BIN/$NAME"; chmod 755 "$BIN/$NAME"
    COMMIT=$(cat "$root/KIT_COMMIT" 2>/dev/null || git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)
    echo "BUILD_KIT_COMMIT=$COMMIT"; echo "BUILD_NAME=$NAME gotatun_arg=${REV:-pin}"
    shasum -a 256 "$BIN/$NAME"
    grep -o "gotatun?rev=[0-9a-f]*#[0-9a-f]*" "$SRC/Cargo.lock" | head -1 ;;
esac
