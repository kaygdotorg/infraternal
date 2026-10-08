#!/usr/bin/env bash
# Role: Builds static musl baseline, candidate size probes, and benchmark harness.
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
harness_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$harness_dir/../../.." && pwd)
scratch_dir=${QUIC_RESEARCH_SCRATCH:-"$HOME/.cache/codex-scratch/quic-research"}
target_dir=${CARGO_TARGET_DIR:-"$scratch_dir/target"}
manifest="$harness_dir/Cargo.toml"
size_dir="$scratch_dir/size-binaries"
mkdir -p -- "$size_dir"

build_target() {
  local feature=$1
  local binary=$2
  systemd-run --quiet --user --scope -p CPUWeight=10000 \
    /nix/var/nix/profiles/default/bin/nix shell nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 \
    --command /usr/bin/env \
    CARGO_TARGET_DIR="$target_dir" \
    CC="$harness_dir/zig-musl-cc" \
    CC_x86_64_unknown_linux_musl="$harness_dir/zig-musl-cc" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$harness_dir/musl-rust-linker" \
    /home/kayg/.nix-profile/bin/cargo build \
    --manifest-path "$manifest" --release --bin "$binary" \
    --features "$feature" --target x86_64-unknown-linux-musl
}

for feature in size-baseline size-quinn size-openssl-native; do
  build_target "$feature" size-probe
  cp -- "$target_dir/x86_64-unknown-linux-musl/release/size-probe" "$size_dir/$feature"
done
build_target measure quic-stack-bench

mkdir -p -- "$repo_dir/research/quic-stacks/raw"
{
  printf '# Role: File sizes of static musl release/LTO baseline and candidate probes. SPDX-License-Identifier: AGPL-3.0-only\n'
  printf 'candidate,bytes\n'
  for feature in size-baseline size-quinn size-openssl-native; do
    printf '%s,%s\n' "$feature" "$(stat -c %s "$size_dir/$feature")"
  done
} > "$repo_dir/research/quic-stacks/raw/size-binaries.csv"
