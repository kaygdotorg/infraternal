#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Lossy mobile-data profiles on the perf VM, one announced two-row hold per call.
# Usage: run-mobile.sh <scenario> <window 1..3> <part 1|2|r>   (r = re-run the row named by $J317C_RETRY_TAG)
#   scenario: mobile-40ms-loss-1 | mobile-80ms-jitter-loss-2-50mbit | mobile-150ms-gemodel-5,
#             or the same with -legacy-egress for the old shaping (labelled by scenario ID)
# Rows: kernel WG, wireguard-go b3bc704, shipped 84b7bb2 ring, J225c ring. The first call for a
# root creates it without a LAN calibration (its limits do not apply to lossy paths).
# Run it detached (setsid nohup) and poll the log; it prints MATRIX_EXIT=<n> last.
set -uo pipefail
S=$HOME/.cache/codex-scratch/j317c
kit=$S/mk
bin=$kit/bin
out=${J317C_OUT:-$S/matrix-mobile}
export H2H_MATRIX_RPS_POLICY=d348-side-rx
stack=${J317C_STACK_ID:-gotatun-j225c-1e3674b}
sha=${J317C_STACK_SHA:-1e3674b7271fe558d7048bcebc7c9b81af8086fe}
[[ ${1:-} == mobile-* && ${2:-} =~ ^[1-3]$ && ${3:-} =~ ^[12r]$ ]] || { echo 'usage: run-mobile.sh <mobile-scenario> <1..3> <1|2|r>' >&2; exit 2; }
part_args=(--part "$3")
if [[ $3 == r ]]; then
    [[ -n ${J317C_RETRY_TAG:-} ]] || { echo 'part r needs J317C_RETRY_TAG=<row tag>' >&2; exit 2; }
    part_args=(--retry-tag "$J317C_RETRY_TAG")
fi
mode=(--no-calibrate)
[[ -d $out ]] || mode=(--skip-calibration)
python3 -I "$kit/lib/matrix.py" run --kit "$kit" --scenario "$1" --tcp-flow 1 --tcp-flow 8 \
    --wg-bin "$bin/wg" --wireguard-go-bin "$bin/wireguard-go" \
    --calibration-variant "$stack" --out "$out" --windows 3 \
    --gotatun-binary "gotatun-shipped-84b7bb2=$bin/gotatun-shipped-84b7bb2" \
    --source "gotatun-shipped-84b7bb2=84b7bb28e385d57dfb80493e78202898fad24d1e" \
    --gotatun-binary "$stack=$bin/$stack" --source "$stack=$sha" \
    --engine-label "gotatun-shipped-84b7bb2=GotaTun (shipped, 84b7bb2)" \
    --engine-label "$stack=GotaTun (J225c, ${sha:0:7})" \
    --select-gotatun gotatun-shipped-84b7bb2 --select-gotatun "$stack" \
    "${mode[@]}" --batch "$2" "${part_args[@]}"
echo "MATRIX_EXIT=$?"
