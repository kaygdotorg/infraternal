#!/usr/bin/env bash
# Build a C archive from the Go engine and measure the incremental size in a stripped Rust host.
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
embed_dir=$(cd -- "$script_dir/../go-embed" && pwd)

: "${WIREGUARD_GO_SRC:?set WIREGUARD_GO_SRC to the pinned Go engine source checkout}"
wireguard_go_src=$(cd -- "$WIREGUARD_GO_SRC" && pwd)
expected_go_revision=2631ce99a06f27120d581611cf125d68bc6aa565
actual_go_revision=$(git -C "$wireguard_go_src" rev-parse HEAD)
[[ $actual_go_revision == "$expected_go_revision" ]] || {
    printf 'expected Go engine revision %s, got %s\n' "$expected_go_revision" "$actual_go_revision" >&2
    exit 1
}

: "${GO_BIN:=go}"
: "${RUSTC_BIN:=$HOME/.rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/bin/rustc}"
: "${CC:=gcc}"
scratch_root=${MESH_ENGINES_SCRATCH:-$HOME/.cache/codex-scratch/mesh-engines}
mkdir -p "$scratch_root"
build_dir=$(mktemp -d "$scratch_root/go-embedding.XXXXXX")
cleanup() {
    rm -rf -- "$build_dir"
}
trap cleanup EXIT

cp "$embed_dir/main.go" "$embed_dir/host.rs" "$embed_dir/host-empty.rs" "$build_dir/"
cat > "$build_dir/go.mod" <<EOF
module example.org/wgbridge

go 1.23.1

require golang.zx2c4.com/wireguard v0.0.0

replace golang.zx2c4.com/wireguard => $wireguard_go_src
EOF

export CGO_ENABLED=1
export CC
export GOMODCACHE=${GOMODCACHE:-$scratch_root/go/pkg/mod}
export GOCACHE=${GOCACHE:-$scratch_root/go/build-cache}
cd "$build_dir"
"$GO_BIN" mod tidy
"$GO_BIN" build -trimpath -buildmode=c-archive -ldflags='-s -w' -o libwgbridge.a .
"$RUSTC_BIN" --edition=2024 host.rs -C opt-level=3 -C strip=symbols \
    -L native="$build_dir" -l static=wgbridge \
    -C link-arg=-pthread -C link-arg=-ldl -C link-arg=-lm -C link-arg=-lresolv \
    -o host-go-embedded
"$RUSTC_BIN" --edition=2024 host-empty.rs -C opt-level=3 -C strip=symbols -o host-empty

archive_bytes=$(stat -c '%s' libwgbridge.a)
embedded_bytes=$(stat -c '%s' host-go-embedded)
baseline_bytes=$(stat -c '%s' host-empty)
if [[ ${GO_EMBED_RUN:-1} == 1 ]]; then
    printf '# Role: Repeatable Go c-archive and stripped Rust-host binary size measurements.\n'
    printf 'run,source_revision,archive_bytes,stripped_host_bytes,stripped_empty_host_bytes,incremental_bytes\n'
fi
printf '%s,%s,%s,%s,%s,%s\n' \
    "${GO_EMBED_RUN:-1}" "$actual_go_revision" "$archive_bytes" "$embedded_bytes" "$baseline_bytes" "$((embedded_bytes - baseline_bytes))"
unshare -Urnm -- "$build_dir/host-go-embedded"
