#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Capture one bounded J526 flow under perf sched, then join the raw streams.
set -euo pipefail

if (($# < 5 || $# > 6)); then
    echo 'usage: run_loaded_latency_window.sh OUT DURATION_SECONDS J88C_KIT COORDINATOR INFRATERNAL_BIN [--pipeline-diagnostics]' >&2
    exit 2
fi

out=$1
duration=$2
kit=$3
coordinator=$4
binary=$5
pipeline_args=()
if (($# == 6)); then
    [[ $6 == '--pipeline-diagnostics' ]] || {
        echo 'the optional sixth argument must be --pipeline-diagnostics' >&2
        exit 2
    }
    pipeline_args+=(--pipeline-diagnostics)
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python=${PYTHON:-python3}

[[ $duration =~ ^[0-9]+$ && $duration -ge 60 && $duration -le 840 ]] || {
    echo 'duration must be between 60 and 840 seconds per perf-lock window' >&2
    exit 2
}
[[ -x $kit/bin/h2h && -x $coordinator && -x $binary ]] || {
    echo 'J88c h2h, coordinator fixture, and product binary must be executable' >&2
    exit 2
}
[[ ! -e $out ]] || {
    echo "window output already exists: $out" >&2
    exit 2
}
mkdir -p "$out"

trace_start_ns=$("$python" -c 'import time; print(time.monotonic_ns())')
record_status=0
set +e
perf sched record --clockid mono -o "$out/perf.data" -- \
    unshare -Urn "$python" -I "$script_dir/loaded_latency_soak.py" \
        --binary "$binary" \
        --coordinator "$coordinator" \
        --kit-dir "$kit" \
        --output "$out" \
        --duration-seconds "$duration" \
        "${pipeline_args[@]}"
record_status=$?
set -e
trace_end_ns=$("$python" -c 'import time; print(time.monotonic_ns())')
if [[ -f $out/perf.data ]]; then
    chmod 0644 "$out/perf.data"
fi
if ((record_status != 0)); then
    exit "$record_status"
fi

PYTHONPATH="${script_dir%/*}" "$python" -m gotatun_break_it.trace \
    --probes "$out/probes.jsonl" \
    --counters "$out/counters.jsonl" \
    --perf-data "$out/perf.data" \
    --scheduler-start-ns "$trace_start_ns" \
    --scheduler-end-ns "$trace_end_ns" \
    --output "$out/report.json"
echo "loaded-latency report: $out/report.json"
