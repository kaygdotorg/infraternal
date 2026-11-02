#!/usr/bin/env bash
# Runs the mesh-only DNS-01 integration against pinned Traefik and Pebble test artifacts [#281].
set -euo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ "$(uname -m)" == x86_64 ]] || {
    printf 'The pinned namespace receipt is for the x86_64 test VM.\n' >&2
    exit 2
}
scratch_root="${INFRATERNAL_PROXY_E2E_ROOT:-${HOME}/.cache/codex-scratch/j62/pebble}"
scratch_parent="$(dirname -- "$scratch_root")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch_parent/target}"
pebble_root="$scratch_root/pebble-v2.9.0"
component_root="$scratch_root/traefik-component"
asset_root="$scratch_root/assets"
mkdir -p "$pebble_root" "$component_root" "$asset_root"

fetch_verified() {
    local url="$1" destination="$2" digest="$3"
    if [[ -f "$destination" ]] && printf '%s  %s\n' "$digest" "$destination" | sha256sum --check --status; then
        return
    fi
    local temporary="$destination.download"
    rm -f -- "$temporary"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 180 --output "$temporary" "$url"
    printf '%s  %s\n' "$digest" "$temporary" | sha256sum --check --status
    mv -f -- "$temporary" "$destination"
}

pebble_release="https://github.com/letsencrypt/pebble/releases/download/v2.9.0"
fetch_verified \
    "$pebble_release/pebble-linux-amd64.tar.gz" \
    "$asset_root/pebble-linux-amd64.tar.gz" \
    ca8b055fb6caf44e48f8bdaf351a7c8a643d63efc88f40d70cc1444bce298c04
fetch_verified \
    "$pebble_release/pebble-challtestsrv-linux-amd64.tar.gz" \
    "$asset_root/pebble-challtestsrv-linux-amd64.tar.gz" \
    5f59142f26e80378bc73fabd85b4de15c362595b211ccb4e85f6584421d19913

mkdir -p "$pebble_root/bin" "$pebble_root/test/config" \
    "$pebble_root/test/certs/localhost"
pebble_bin="$pebble_root/bin/pebble"
challenge_bin="$pebble_root/bin/pebble-challtestsrv"
staging_bin_dir=""
traefik_stage=""
cleanup_staged_executables() {
    if [[ -n "$staging_bin_dir" ]]; then
        rm -rf -- "$staging_bin_dir"
    fi
    if [[ -n "$traefik_stage" ]]; then
        rm -f -- "$traefik_stage"
    fi
}
trap cleanup_staged_executables EXIT
staging_bin_dir="$(mktemp -d "$pebble_root/bin/.extract.XXXXXX")"
staged_pebble="$staging_bin_dir/pebble"
staged_challenge="$staging_bin_dir/pebble-challtestsrv"
# Cached test executables are 0500; same-filesystem staging avoids truncating them on reruns.
tar --extract --to-stdout --gzip --file "$asset_root/pebble-linux-amd64.tar.gz" \
    pebble-linux-amd64/linux/amd64/pebble > "$staged_pebble"
tar --extract --to-stdout --gzip --file "$asset_root/pebble-challtestsrv-linux-amd64.tar.gz" \
    pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv > "$staged_challenge"
chmod 0500 "$staged_pebble" "$staged_challenge"
[[ -x "$staged_pebble" && -x "$staged_challenge" ]] || {
    printf 'Pinned Pebble archives did not contain the expected binaries.\n' >&2
    exit 1
}
mv -f -- "$staged_pebble" "$pebble_bin"
mv -f -- "$staged_challenge" "$challenge_bin"
[[ -x "$pebble_bin" && -x "$challenge_bin" ]] || {
    printf 'Pinned Pebble archives did not contain the expected binaries.\n' >&2
    exit 1
}

pebble_source="https://raw.githubusercontent.com/letsencrypt/pebble/39065bb084771bb1c31046e0fd0c3c200a9e8b45"
fetch_verified \
    "$pebble_source/test/config/pebble-config.json" \
    "$pebble_root/test/config/pebble-config.json" \
    735f32ae7ff73cc9ac6c4505c0387f0773f16776f5f71fcd9886c413ae5b702e
fetch_verified \
    "$pebble_source/test/certs/localhost/cert.pem" \
    "$pebble_root/test/certs/localhost/cert.pem" \
    c87fb918d9bac8db11aa54493b5f0cf6e0725a3fe73f617d1c64737e1ab4caf9
fetch_verified \
    "$pebble_source/test/certs/localhost/key.pem" \
    "$pebble_root/test/certs/localhost/key.pem" \
    0977979255b0e0721c17335c056b627f66a43cf56e5a52f3cda81fb111ecf00e
fetch_verified \
    "$pebble_source/test/certs/pebble.minica.pem" \
    "$pebble_root/test/certs/pebble.minica.pem" \
    0c502e52627ff7de972c7e9e065640103b4589b4e2d23d3fcf21bef1e3c8c67c
fetch_verified \
    "$pebble_source/test/certs/pebble.minica.key.pem" \
    "$pebble_root/test/certs/pebble.minica.key.pem" \
    a612f783391ddf9d73fe59b1d5155d93b39da717d861d41dab0bc6a43042394f
chmod 0600 "$pebble_root/test/certs/localhost/key.pem" \
    "$pebble_root/test/certs/pebble.minica.key.pem"

python3 "$repo_root/scripts/release/traefik_component.py" \
    --release-version 0.1.0 --os linux --arch amd64 --output "$component_root"
manifest="$component_root/proxy-traefik-linux-amd64.json"
archive="$component_root/components/0.1.0/proxy/linux/amd64/traefik_v3.7.17_linux_amd64.tar.gz"
traefik_bin="$component_root/bin/traefik"
mkdir -p "$(dirname -- "$traefik_bin")"
traefik_stage="$(mktemp "$(dirname -- "$traefik_bin")/.traefik.XXXXXX")"
expected_executable_sha="$(jq -er '.executable_sha256' "$manifest")"
tar --extract --to-stdout --gzip --file "$archive" traefik > "$traefik_stage"
printf '%s  %s\n' "$expected_executable_sha" "$traefik_stage" | sha256sum --check --status
chmod 0500 "$traefik_stage"
mv -f -- "$traefik_stage" "$traefik_bin"

export INFRATERNAL_PROXY_E2E_PEBBLE="$pebble_bin"
export INFRATERNAL_PROXY_E2E_CHALLTESTSRV="$challenge_bin"
export INFRATERNAL_PROXY_E2E_PEBBLE_ROOT="$pebble_root"
export INFRATERNAL_PROXY_E2E_PEBBLE_CA="$pebble_root/test/certs/pebble.minica.pem"
export INFRATERNAL_PROXY_E2E_TRAEFIK="$traefik_bin"
cd "$repo_root"
cargo test --offline --jobs 4 -p infraternal-plugin-proxy \
    --test namespace_pebble -- --ignored --nocapture
