#!/usr/bin/env bash
# Compile x86_64 musl C after applying the D264 AES-GCM dispatch patch.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${TARGET:?Cargo must supply the build target}" == x86_64-unknown-linux-musl ]]; then
    source_root="$(pwd -P)"
    if [[ -f "$source_root/crypto/modes/asm/aes-gcm-avx512.pl" ]]; then
        marker="$source_root/.infraternal-d264-avx512-gcm"
        if [[ ! -f "$marker" ]]; then
            python3 "$root/scripts/patch-openssl-avx512-gcm.py" "$source_root"
        fi
    fi
fi
exec "$root/.cargo/musl-cc.sh" "$@"
