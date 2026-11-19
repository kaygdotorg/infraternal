#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# hold.sh [--log FILE] [--cap CAP] NAME -- PERF-ALL-ARGS...
#
# Runs one hold through perf-all.sh with the cap applied inside perf-run (perf-run-cap.sh), then
# appends the REAL exit status to the log: one `<UTC time> NAME exit N` line for the hold and one
# `<UTC time> NAME row CASE exit N` line per case that wrote a status.json under --out.
# The status is read the moment the hold returns. (An earlier driver printed `$?` after a
# command substitution, so its log held the status of `date`, not of the hold: #260, J676.)
# Pass --out DIR in PERF-ALL-ARGS; the rows are read from there. The hold's own exit status is
# this script's exit status. H2H_PERF_ALL overrides perf-all.sh (tests); H2H_HOLD_NO_PAUSE skips
# the pause that lets a waiting job take the non-FIFO lock between holds.
set -uo pipefail

log=holds.log cap=17m
while (($#)); do
    case $1 in
        --log) log=${2:?--log needs a file}; shift 2 ;;
        --cap) cap=${2:?--cap needs a value}; shift 2 ;;
        *) break ;;
    esac
done
name=${1:?hold name}
shift
[[ ${1:-} == -- ]] || { echo 'usage: hold.sh [--log FILE] [--cap CAP] NAME -- PERF-ALL-ARGS...' >&2; exit 2; }
shift
kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

out=
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
    [[ ${args[i]} == --out ]] && out=${args[i + 1]:-}
done

note() { printf '%s %s\n' "$(date -u +%T)" "$*" >> "$log"; }

note "$name start cap $cap"
status=0
PERF_RUN="$kit/perf-run-cap.sh" H2H_HOLD_CAP=$cap \
    bash "${H2H_PERF_ALL:-$kit/perf-all.sh}" "$@" || status=$?
note "$name exit $status"
if [[ -n $out ]]; then
    for file in "$out"/*/status.json; do
        [[ -f $file ]] || continue
        row=$(basename -- "$(dirname -- "$file")")
        code=$(sed -n 's/.*"exit": *\([0-9][0-9]*\).*/\1/p' "$file")
        note "$name row $row exit ${code:-unknown}"
    done
fi
[[ -n ${H2H_HOLD_NO_PAUSE:-} ]] || sleep 30  # sleep: let a waiting job take the non-FIFO lock between holds
exit "$status"
