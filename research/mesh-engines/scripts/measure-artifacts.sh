#!/usr/bin/env bash
# Measure release executable sizes before and after stripping for the engine and netlink harness builds.
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

: "${BORINGTUN_BIN:?set BORINGTUN_BIN to the BoringTun release executable}"
: "${GOTATUN_BIN:?set GOTATUN_BIN to the GotaTun release executable}"
: "${NEPTUN_BIN:?set NEPTUN_BIN to the NepTUN release executable}"
: "${WIREGUARD_GO_BIN:?set WIREGUARD_GO_BIN to the WireGuard Go release executable}"
: "${NETLINK_BENCH_BIN:?set NETLINK_BENCH_BIN to the nl-wireguard benchmark executable}"
: "${NETLINK_MINIMAL_BENCH_BIN:?set NETLINK_MINIMAL_BENCH_BIN to the typed client benchmark executable}"
: "${NETLINK_NLINK_BENCH_BIN:?set NETLINK_NLINK_BENCH_BIN to the nlink benchmark executable}"

: "${STRIP_BIN:=strip}"
STRIP_BIN=$(command -v "$STRIP_BIN")
scratch_root=${MESH_ENGINES_SCRATCH:-$HOME/.cache/codex-scratch/mesh-engines}
mkdir -p "$scratch_root"
build_dir=$(mktemp -d "$scratch_root/artifact-size.XXXXXX")
cleanup() {
    rm -rf -- "$build_dir"
}
trap cleanup EXIT

printf '# Role: Candidate release executable sizes before and after ELF symbol stripping.\n'
printf 'artifact,release_bytes,stripped_bytes\n'
for artifact in \
    "boringtun,$BORINGTUN_BIN" \
    "gotatun,$GOTATUN_BIN" \
    "neptun,$NEPTUN_BIN" \
    "wireguard-go,$WIREGUARD_GO_BIN" \
    "nl-wireguard-bench,$NETLINK_BENCH_BIN" \
    "typed-minimal-bench,$NETLINK_MINIMAL_BENCH_BIN" \
    "nlink-bench,$NETLINK_NLINK_BENCH_BIN"; do
    name=${artifact%%,*}
    source=${artifact#*,}
    stripped="$build_dir/$name"
    cp -- "$source" "$stripped"
    "$STRIP_BIN" --strip-unneeded "$stripped"
    printf '%s,%s,%s\n' "$name" "$(stat -c '%s' "$source")" "$(stat -c '%s' "$stripped")"
done
