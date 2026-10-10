#!/usr/bin/env bash
# Role: Run five independent data-plane samples and retain their raw CSV rows.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Each sample receives a fresh pair of rootless network namespaces and its own
# systemd user scope, so process and peer-memory measurements start clean.

set -euo pipefail

[[ $# -eq 1 ]] || {
    printf 'usage: %s {kernel|boringtun|gotatun|neptun|wireguard-go}\n' "$0" >&2
    exit 2
}
engine=$1
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)

for repetition in 1 2 3 4 5; do
    output=$("$script_dir/run-tunnel-sample.sh" "$engine" "$repetition")
    if [[ $repetition == 1 ]]; then
        printf '%s\n' "${output%%$'\n'*}"
    fi
    printf '%s\n' "${output##*$'\n'}"
done
