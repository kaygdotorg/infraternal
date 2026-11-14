#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# perf-run-cap.sh [perf-run options] -- COMMAND [ARG...]
#
# A drop-in for perf-run (point PERF_RUN at it) that applies the hold cap to the MEASURED command
# only, through hold-cap.sh. The cap sits inside perf-run, so it neither counts the time queued
# for the lock nor lets perf-run release the lock while the hold's processes still run (#260).
# H2H_HOLD_CAP is the cap (default 17m); H2H_REAL_PERF_RUN overrides the real perf-run path.
set -euo pipefail
pre=()
while (($#)) && [[ $1 != -- ]]; do pre+=("$1"); shift; done
[[ ${1:-} == -- ]] || { echo 'perf-run-cap.sh: expected -- before the command' >&2; exit 2; }
shift
here=$(dirname -- "${BASH_SOURCE[0]}")
exec "${H2H_REAL_PERF_RUN:-/usr/local/bin/perf-run}" "${pre[@]}" -- \
    bash "$here/hold-cap.sh" "${H2H_HOLD_CAP:-17m}" -- "$@"
