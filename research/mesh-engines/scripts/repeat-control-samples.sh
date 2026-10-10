#!/usr/bin/env bash
# Role: Run five fresh Linux Generic Netlink samples and write raw CSV rows.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Every repetition gets a new interface and user scope, preventing one run's
# peers or process allocations from influencing the next run.

set -euo pipefail

[[ $# -eq 1 ]] || {
    printf 'usage: %s {nl-wireguard|minimal|nlink}\n' "$0" >&2
    exit 2
}
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
kind=$1

for repetition in 1 2 3 4 5; do
    output=$("$script_dir/run-control-sample.sh" "$repetition" "$kind")
    if [[ $repetition == 1 ]]; then
        printf 'repetition,%s\n' "${output%%$'\n'*}"
    fi
    printf '%s,%s\n' "$repetition" "${output##*$'\n'}"
done
