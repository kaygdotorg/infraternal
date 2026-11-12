#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Start a filtered scheduler trace for every app thread before starting traffic.
set -euo pipefail

if (($# < 5)); then
    echo 'usage: run_loaded_latency_window.sh OUT DURATION_SECONDS J88C_KIT COORDINATOR INFRATERNAL_BIN [--queue-depth-sampling] [--pipeline-diagnostics] [--underlay-rate-mbit N]' >&2
    exit 2
fi

out=$1
duration=$2
kit=$3
coordinator=$4
binary=$5
shift 5
window_args=()
pipeline_seen=0
queue_seen=0
rate_seen=0
while (($#)); do
    case $1 in
        --pipeline-diagnostics)
            ((pipeline_seen == 0)) || { echo 'pipeline diagnostics may be selected only once' >&2; exit 2; }
            pipeline_seen=1
            window_args+=(--pipeline-diagnostics)
            shift
            ;;
        --queue-depth-sampling)
            ((queue_seen == 0)) || { echo 'queue-depth sampling may be selected only once' >&2; exit 2; }
            queue_seen=1
            window_args+=(--queue-depth-sampling)
            shift
            ;;
        --underlay-rate-mbit)
            (($# >= 2)) || { echo '--underlay-rate-mbit requires a value' >&2; exit 2; }
            ((rate_seen == 0)) || { echo 'underlay rate may be selected only once' >&2; exit 2; }
            [[ $2 =~ ^[0-9]+$ ]] && ((10#$2 >= 100 && 10#$2 <= 10000)) || {
                echo 'underlay rate must be between 100 and 10000 Mbit/s' >&2
                exit 2
            }
            rate_seen=1
            window_args+=(--underlay-rate-mbit "$2")
            shift 2
            ;;
        *)
            echo "unknown window option: $1" >&2
            exit 2
            ;;
    esac
done
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python=${PYTHON:-python3}
perf_binary=${PERF:-$(command -v perf || true)}

[[ $duration =~ ^[0-9]+$ && $duration -ge 60 && $duration -le 840 ]] || {
    echo 'duration must be between 60 and 840 seconds per perf-lock window' >&2
    exit 2
}
[[ -x $kit/bin/h2h && -x $coordinator && -x $binary ]] || {
    echo 'J88c h2h, coordinator fixture, and product binary must be executable' >&2
    exit 2
}
[[ -n $perf_binary && -x $perf_binary ]] || {
    echo 'perf is not executable; set PERF to the pinned perf binary' >&2
    exit 2
}
[[ ! -e $out ]] || {
    echo "window output already exists: $out" >&2
    exit 2
}
mkdir -p "$out"

agent_pids=$out/agent-pids.json
capture_start=$out/capture-start
soak_stdout=$out/soak.stdout
soak_stderr=$out/soak.stderr
perf_log=$out/perf-record.log
soak_pid=
perf_pid=

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n ${soak_pid:-} ]] && kill -0 "$soak_pid" 2>/dev/null; then
        kill -INT -- "-$soak_pid" 2>/dev/null || true
        wait "$soak_pid" 2>/dev/null || true
    fi
    if [[ -n ${perf_pid:-} ]] && kill -0 "$perf_pid" 2>/dev/null; then
        kill -INT "$perf_pid" 2>/dev/null || true
        wait "$perf_pid" 2>/dev/null || true
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

trace_start_ns=$("$python" -c 'import time; print(time.monotonic_ns())')
setsid unshare -Urn "$python" -I "$script_dir/loaded_latency_soak.py" \
    --binary "$binary" \
    --coordinator "$coordinator" \
    --kit-dir "$kit" \
    --output "$out" \
    --duration-seconds "$duration" \
    --agent-pids "$agent_pids" \
    --capture-start-marker "$capture_start" \
    "${window_args[@]}" \
    >"$soak_stdout" 2>"$soak_stderr" &
soak_pid=$!

deadline=$((SECONDS + 60))
while [[ ! -s $agent_pids ]]; do
    if ! kill -0 "$soak_pid" 2>/dev/null; then
        set +e
        wait "$soak_pid"
        soak_status=$?
        set -e
        cat "$soak_stderr" >&2
        echo "loaded soak exited before publishing agent PIDs: $soak_status" >&2
        exit 1
    fi
    if ((SECONDS >= deadline)); then
        echo 'loaded soak did not publish agent PIDs within 60 seconds' >&2
        exit 1
    fi
    # sleep: poll the readiness file while the configured mesh peers stay idle.
    sleep 0.05
done

PERF="$perf_binary" "$python" -I "$script_dir/perf_capture.py" \
    --perf "$perf_binary" \
    --agent-pids "$agent_pids" \
    --output "$out/perf.data" \
    >"$perf_log" 2>&1 &
perf_pid=$!

deadline=$((SECONDS + 30))
while [[ ! -s $out/perf.data ]]; do
    if ! kill -0 "$perf_pid" 2>/dev/null; then
        set +e
        wait "$perf_pid"
        perf_status=$?
        set -e
        cat "$perf_log" >&2
        echo "TID-filtered scheduler capture exited before recording: $perf_status" >&2
        exit 1
    fi
    if ((SECONDS >= deadline)); then
        echo 'TID-filtered scheduler capture did not create perf.data within 30 seconds' >&2
        exit 1
    fi
    # sleep: wait for perf to open the filtered scheduler trace before enabling traffic.
    sleep 0.05
done
touch "$capture_start"

if wait "$soak_pid"; then
    soak_status=0
else
    soak_status=$?
fi
soak_pid=
kill -INT "$perf_pid" 2>/dev/null || true
if wait "$perf_pid"; then
    perf_status=0
else
    perf_status=$?
fi
perf_pid=
trace_end_ns=$("$python" -c 'import time; print(time.monotonic_ns())')
if [[ -f $out/perf.data ]]; then
    chmod 0644 "$out/perf.data"
fi
if ((soak_status != 0)); then
    cat "$soak_stderr" >&2
    exit "$soak_status"
fi
if ((perf_status != 0 && perf_status != 130)); then
    cat "$perf_log" >&2
    exit "$perf_status"
fi

PERF="$perf_binary" PYTHONPATH="${script_dir%/*}" "$python" -m gotatun_break_it.trace \
    --probes "$out/probes.jsonl" \
    --counters "$out/counters.jsonl" \
    --perf-data "$out/perf.data" \
    --scheduler-start-ns "$trace_start_ns" \
    --scheduler-end-ns "$trace_end_ns" \
    --output "$out/report.json"
echo "loaded-latency report: $out/report.json"
