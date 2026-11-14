#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run one complete pinned R4b comparison inside a single perf-run lock.
set -euo pipefail

kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# The engine that --ab and --calibration rows run: the GotaTun CLI (default) or the
# product binary (`infraternal`, case mesh-infraternal). One engine per run, so a
# calibration always bounds the same code path its A/B holds measure (#260, J610).
ab_engine=${H2H_AB_ENGINE:-gotatun}
[[ $ab_engine == gotatun || $ab_engine == infraternal ]] || { echo 'H2H_AB_ENGINE must be gotatun or infraternal' >&2; exit 2; }
[[ $(id -un) == claude ]] || { echo 'run as claude on the perf VM' >&2; exit 2; }
housekeeping=${H2H_CPUSET_HOUSEKEEPING:-0,5}
taskset -pc "$housekeeping" "$$" >/dev/null
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 perf-all coordinator is not pinned to housekeeping CPUs $housekeeping" >&2
    exit 2
}

mode=""
label=""
out=""
scenario=""
calibration_status="uncalibrated"
partial=0
wg_bin=""
wireguard_go_bin=""
rows=()
tcp_flow_args=()
declare -A binaries sources
binary_count=0
source_count=0

usage() {
    cat <<'USAGE'
usage:
  perf-all.sh --validate [--out DIR]
  perf-all.sh --smoke --row TAG=ENGINE [--binary TAG=PATH] [--source TAG=SHA] [--out DIR]
  perf-all.sh --calibration [--row warmup=gotatun] --row control-a=gotatun --row control-b=gotatun --row control-c=gotatun [--binary TAG=PATH] [--out DIR]
    (controls may be given in any order; a leading warmup row is run and discarded;
     H2H_LAN_PING_COUNT and H2H_LAN_TPUT_SECONDS set the probe count and load window)
  perf-all.sh --matrix --scenario SCENARIO [--tcp-flow COUNT ...] \
    --label BASELINE --row TAG=kernel-plain --row TAG=wireguard-go \
    --row TAG=gotatun [--row TAG=gotatun ...] --binary TAG=PATH --source TAG=SHA \
    --wg-bin PATH --wireguard-go-bin PATH [--out DIR]
    perf-all.sh --hold --label CUT --row kernel-before=kernel-plain --row wireguard-go-before=wireguard-go \
    --row control-a=gotatun --row candidate-a=gotatun --row candidate-b=gotatun \
    --row control-b=gotatun --row wireguard-go-after=wireguard-go --row kernel-after=kernel-plain \
    --binary TAG=PATH [--source TAG=SHA] [--out DIR]
  perf-all.sh --ab --label NAME --row control-a=gotatun --row candidate-a=gotatun \
    --row candidate-b=gotatun --row control-b=gotatun --binary TAG=PATH --source TAG=SHA [--out DIR]
    (one ABBA round in a single hold: four calibration-shaped LAN windows, no kernel or
     wireguard-go rows, so the round fits in under 17 minutes)
  perf-all.sh --mixed --label HOLD --row TAG=ENGINE ... [--binary TAG=PATH --source TAG=SHA] [--out DIR]
    (one cross-engine hold: two to four different engines, each once, run in the given
     order as calibration-shaped LAN windows; take the orders from lib/latin_square.py
     and pool the holds with lib/head_to_head.py)
  perf-all.sh --soak --label CUT --row control=gotatun --row candidate=gotatun \
    --binary TAG=PATH [--source TAG=SHA] [--out DIR]

The matched engine matrix runs five counterbalanced windows. Each window has
one row for each selected source variant, including one kernel row and one
wireguard-go row, under one perf-run lock. All rows use the same scenario probes, MTU 1420, D348 pinning,
and audit. The candidate hold order remains separate. Unpinned results are
historical data and must be reported separately.
USAGE
}

set_mode() {
    local requested=$1
    [[ -z $mode ]] || { echo 'choose one mode' >&2; exit 2; }
    mode=$requested
}

parse_pair() {
    local value=$1 out_name=$2 out_value=$3
    [[ $value == *=* ]] || { echo "expected NAME=VALUE, got: $value" >&2; exit 2; }
    printf -v "$out_name" '%s' "${value%%=*}"
    printf -v "$out_value" '%s' "${value#*=}"
}

while (($#)); do
    case $1 in
        --validate) set_mode validate ;;
        --smoke) set_mode smoke ;;
        --calibration) set_mode calibration ;;
        --matrix) set_mode matrix ;;
        --hold) set_mode hold ;;
        --ab) set_mode ab ;;
        --soak) set_mode soak ;;
        --mixed) set_mode mixed ;;
        --label) (($# >= 2)) || { echo '--label needs a value' >&2; exit 2; }; label=$2; shift ;;
        --scenario) (($# >= 2)) || { echo '--scenario needs a value' >&2; exit 2; }; scenario=$2; shift ;;
        --tcp-flow)
            (($# >= 2)) || { echo '--tcp-flow needs a value' >&2; exit 2; }
            [[ $2 =~ ^[1-9][0-9]*$ ]] || { echo '--tcp-flow must be a positive integer' >&2; exit 2; }
            tcp_flow_args+=(--tcp-flow "$2")
            shift
            ;;
        --partial) partial=1 ;;
        --calibration-status) (($# >= 2)) || { echo '--calibration-status needs a value' >&2; exit 2; }; calibration_status=$2; shift ;;
        --wg-bin) (($# >= 2)) || { echo '--wg-bin needs a value' >&2; exit 2; }; wg_bin=$2; shift ;;
        --wireguard-go-bin) (($# >= 2)) || { echo '--wireguard-go-bin needs a value' >&2; exit 2; }; wireguard_go_bin=$2; shift ;;
        --out) (($# >= 2)) || { echo '--out needs a value' >&2; exit 2; }; out=$2; shift ;;
        --row)
            (($# >= 2)) || { echo '--row needs a value' >&2; exit 2; }
            parse_pair "$2" tag engine
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid row tag: $tag" >&2; exit 2; }
            [[ $engine == gotatun || $engine == infraternal || $engine == kernel || $engine == kernel-plain || $engine == wireguard-go || \
               $engine == tailscale || $engine == netbird-userspace || $engine == underlay ]] || {
                echo "invalid engine for row $tag: $engine" >&2; exit 2;
            }
            for existing in "${rows[@]}"; do
                [[ ${existing%%=*} != "$tag" ]] || { echo "duplicate row tag: $tag" >&2; exit 2; }
            done
            rows+=("$tag=$engine")
            shift
            ;;
        --binary)
            (($# >= 2)) || { echo '--binary needs a value' >&2; exit 2; }
            parse_pair "$2" tag path
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ && -x $path ]] || {
                echo "binary for $tag must name an executable file" >&2; exit 2;
            }
            [[ $path != *$'\n'* && $path != *$'\t'* ]] || { echo 'binary paths cannot contain tabs or newlines' >&2; exit 2; }
            binaries[$tag]=$(readlink -f -- "$path")
            binary_count=$((binary_count + 1))
            shift
            ;;
        --source)
            (($# >= 2)) || { echo '--source needs a value' >&2; exit 2; }
            parse_pair "$2" tag source
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ && $source =~ ^[0-9a-fA-F]{7,64}$ ]] || {
                echo "source for $tag must be a commit SHA" >&2; exit 2;
            }
            sources[$tag]=$source
            source_count=$((source_count + 1))
            shift
            ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[[ -n $mode ]] || { usage >&2; exit 2; }
if [[ $mode != matrix && ${#tcp_flow_args[@]} -gt 0 ]]; then
    echo '--tcp-flow is available only with --matrix' >&2
    exit 2
fi
if [[ $mode == validate ]]; then
    ((${#rows[@]} == 0 && binary_count == 0 && source_count == 0)) || {
        echo '--validate does not take row, binary, or source options' >&2; exit 2;
    }
else
    ((${#rows[@]} > 0)) || { echo "$mode requires at least one --row" >&2; exit 2; }
fi

check_row() {
    local index=$1 want_tag=$2 want_engine=$3 actual_tag actual_engine
    [[ ${rows[$index]} == *=* ]] || { echo "missing row $want_tag" >&2; exit 2; }
    actual_tag=${rows[$index]%%=*}
    actual_engine=${rows[$index]#*=}
    [[ $actual_tag == "$want_tag" && $actual_engine == "$want_engine" ]] || {
        echo "row $((index + 1)) must be $want_tag=$want_engine, got $actual_tag=$actual_engine" >&2
        exit 2
    }
}

case $mode in
    validate) ;;
    smoke)
        ((${#rows[@]} == 1)) || { echo '--smoke takes exactly one row' >&2; exit 2; }
        ;;
    calibration)
        # Three controls, in any order (the order is the position-effect
        # experiment), optionally preceded by one discarded `warmup` row that
        # runs the same binary and is never read by the spread report.
        offset=0
        if ((${#rows[@]} == 4)); then
            check_row 0 warmup "$ab_engine"
            offset=1
        elif ((${#rows[@]} != 3)); then
            echo '--calibration takes three control rows, optionally after one warmup row' >&2; exit 2
        fi
        declare -A seen_control=()
        for ((i = offset; i < ${#rows[@]}; i++)); do
            [[ ${rows[$i]#*=} == "$ab_engine" ]] || { echo "row $((i + 1)) must be a $ab_engine control" >&2; exit 2; }
            seen_control[${rows[$i]%%=*}]=1
        done
        [[ ${#seen_control[@]} == 3 && -n ${seen_control[control-a]:-} && \
           -n ${seen_control[control-b]:-} && -n ${seen_control[control-c]:-} ]] || {
            echo '--calibration needs control-a, control-b and control-c exactly once each' >&2; exit 2
        }
        for ((i = 1; i < ${#rows[@]}; i++)); do
            first=${rows[0]%%=*}
            tag=${rows[$i]%%=*}
            [[ ${binaries[$first]:-} == "${binaries[$tag]:-}" ]] || {
                echo 'all calibration rows must use the same binary' >&2; exit 2;
            }
            [[ -n ${sources[$first]:-} && ${sources[$first]} == "${sources[$tag]:-}" ]] || {
                echo 'all calibration rows need the same source SHA' >&2; exit 2;
            }
        done
        ;;
    matrix)
        # A --partial window is one half of a window that runs as two shorter holds
        # (matrix.py run --part); it needs no particular engine mix, but each
        # control engine may still appear only once.
        if ((partial)); then
            ((${#rows[@]} >= 1)) || { echo '--matrix --partial needs at least one row' >&2; exit 2; }
        else
            ((${#rows[@]} >= 3)) || { echo '--matrix needs kernel, wireguard-go, and at least one GotaTun row' >&2; exit 2; }
        fi
        declare -A matrix_engine_counts
        for row in "${rows[@]}"; do
            tag=${row%%=*}
            engine=${row#*=}
            case $engine in
                kernel-plain|wireguard-go|gotatun) ;;
                *) echo "--matrix does not accept engine $engine" >&2; exit 2 ;;
            esac
            matrix_engine_counts[$engine]=$(( ${matrix_engine_counts[$engine]:-0} + 1 ))
        done
        if ((partial)); then
            [[ ${matrix_engine_counts[kernel-plain]:-0} -le 1 && ${matrix_engine_counts[wireguard-go]:-0} -le 1 ]] || {
                echo '--matrix --partial allows at most one row per control engine' >&2; exit 2;
            }
        else
            [[ ${matrix_engine_counts[kernel-plain]:-0} == 1 && \
               ${matrix_engine_counts[wireguard-go]:-0} == 1 && \
               ${matrix_engine_counts[gotatun]:-0} -ge 1 ]] || {
                echo '--matrix window needs exactly one row per control and one or more GotaTun variants' >&2; exit 2;
            }
        fi
        [[ $scenario == best-lan || $scenario == best-lan-15k || $scenario == mobile-* || $scenario == wan-50ms || $scenario == wan-150ms-loss-0.5 || \
           $scenario == wan-150ms-loss-2 || $scenario == wan-20ms-loss-1 || \
           $scenario == small-udp || $scenario == peer-scale || $scenario == handshake-storm || \
           $scenario == cpu-contended || $scenario == idle ]] || {
            echo "--matrix requires a known --scenario, got: $scenario" >&2; exit 2;
        }
        [[ -n $label ]] || { echo '--matrix requires --label' >&2; exit 2; }
        [[ $calibration_status == passed || $calibration_status == failed || \
           $calibration_status == uncalibrated || $calibration_status == calibrated || \
           $calibration_status == 'uncalibrated, owner-directed' ]] || {
            echo '--calibration-status must be passed, failed, calibrated, uncalibrated, or uncalibrated, owner-directed' >&2; exit 2;
        }
        [[ -x $wg_bin && -x $wireguard_go_bin ]] || {
            echo '--matrix requires executable --wg-bin and --wireguard-go-bin paths' >&2; exit 2;
        }
        wg_bin=$(readlink -f -- "$wg_bin")
        wireguard_go_bin=$(readlink -f -- "$wireguard_go_bin")
        ;;
    hold)
        ((${#rows[@]} == 8)) || { echo '--hold takes exactly eight rows' >&2; exit 2; }
        check_row 0 kernel-before kernel-plain
        check_row 1 wireguard-go-before wireguard-go
        check_row 2 control-a gotatun
        check_row 3 candidate-a gotatun
        check_row 4 candidate-b gotatun
        check_row 5 control-b gotatun
        check_row 6 wireguard-go-after wireguard-go
        check_row 7 kernel-after kernel-plain
        [[ -n $label ]] || { echo '--hold requires --label CUT' >&2; exit 2; }
        [[ ${binaries[control-a]:-} == "${binaries[control-b]:-}" ]] || {
            echo 'control-a and control-b must use the same binary' >&2; exit 2;
        }
        [[ -n ${binaries[candidate-a]:-} && ${binaries[candidate-a]} == "${binaries[candidate-b]:-}" ]] || {
            echo 'candidate-a and candidate-b must use the same executable' >&2; exit 2;
        }
        [[ ${sources[control-a]:-} == "${sources[control-b]:-}" && ${sources[candidate-a]:-} == "${sources[candidate-b]:-}" ]] || {
            echo 'each repeated binary must have one matching source SHA' >&2; exit 2;
        }
        [[ -n ${sources[control-a]:-} && -n ${sources[candidate-a]:-} ]] || {
            echo 'control and candidate rows need source SHAs' >&2; exit 2;
        }
        ;;
    ab)
        # One ABBA round of calibration-shaped LAN windows in a single hold: the
        # order cancels linear drift, and each repeated binary must be identical.
        ((${#rows[@]} == 4)) || { echo '--ab takes exactly four rows' >&2; exit 2; }
        check_row 0 control-a "$ab_engine"
        check_row 1 candidate-a "$ab_engine"
        check_row 2 candidate-b "$ab_engine"
        check_row 3 control-b "$ab_engine"
        [[ -n $label ]] || { echo '--ab requires --label' >&2; exit 2; }
        [[ -n ${binaries[control-a]:-} && ${binaries[control-a]} == "${binaries[control-b]:-}" ]] || {
            echo 'control-a and control-b must use the same binary' >&2; exit 2;
        }
        [[ -n ${binaries[candidate-a]:-} && ${binaries[candidate-a]} == "${binaries[candidate-b]:-}" ]] || {
            echo 'candidate-a and candidate-b must use the same binary' >&2; exit 2;
        }
        [[ ${binaries[control-a]} != "${binaries[candidate-a]}" ]] || { echo 'control and candidate binaries must differ' >&2; exit 2; }
        [[ -n ${sources[control-a]:-} && ${sources[control-a]} == "${sources[control-b]:-}" && \
           -n ${sources[candidate-a]:-} && ${sources[candidate-a]} == "${sources[candidate-b]:-}" ]] || {
            echo 'each repeated binary needs one matching source SHA' >&2; exit 2;
        }
        ;;
    mixed)
        # One cross-engine hold (J638): at most four windows keep it under the 17-minute
        # hold cap (J629's four took 13m15s). Each engine once, so a Latin square over
        # the holds balances position and carryover (lib/latin_square.py).
        ((${#rows[@]} >= 2 && ${#rows[@]} <= 4)) || { echo '--mixed takes two to four rows' >&2; exit 2; }
        [[ -n $label ]] || { echo '--mixed requires --label' >&2; exit 2; }
        declare -A mixed_seen=()
        for row in "${rows[@]}"; do
            engine=${row#*=}
            [[ -z ${mixed_seen[$engine]:-} ]] || { echo "--mixed runs each engine at most once; $engine repeats" >&2; exit 2; }
            mixed_seen[$engine]=1
            tag=${row%%=*}
            if [[ $engine == gotatun || $engine == infraternal ]] && [[ -z ${sources[$tag]:-} ]]; then
                echo "row $tag needs --source $tag=SHA" >&2; exit 2
            fi
        done
        ;;
    soak)
        ((${#rows[@]} == 2)) || { echo '--soak takes exactly two rows' >&2; exit 2; }
        check_row 0 control gotatun
        check_row 1 candidate gotatun
        [[ -n $label && -n ${binaries[control]:-} && -n ${binaries[candidate]:-} ]] || {
            echo '--soak requires --label and both binary paths' >&2; exit 2;
        }
        [[ -n ${sources[control]:-} && -n ${sources[candidate]:-} ]] || {
            echo '--soak requires source SHAs for both binaries' >&2; exit 2;
        }
        ;;
esac

for row in "${rows[@]}"; do
    tag=${row%%=*}
    engine=${row#*=}
    if [[ ( $engine == gotatun || $engine == infraternal ) && $mode != smoke && -z ${binaries[$tag]:-} ]]; then
        echo "row $tag needs --binary $tag=PATH" >&2
        exit 2
    fi
    if [[ $engine == gotatun && $mode == matrix && -z ${sources[$tag]:-} ]]; then
        echo "row $tag needs --source $tag=FULL_SHA" >&2
        exit 2
    fi
done

if [[ -z $out ]]; then
    out="$kit/results/j88i-pinned-$mode-$(date -u +%Y%m%dT%H%M%SZ)"
fi
[[ ! -e $out ]] || { echo "results directory already exists: $out" >&2; exit 2; }
mkdir -p "$out/receipts"
out=$(cd -- "$out" && pwd -P)
if [[ $mode == matrix ]]; then
    python3 -I "$kit/lib/matrix.py" config "$scenario" "${tcp_flow_args[@]}" > "$out/scenario.json"
fi
plan="$out/rows.tsv"
: > "$plan"
chmod 0644 "$plan"
for row in "${rows[@]}"; do
    tag=${row%%=*}
    engine=${row#*=}
    printf '%s\t%s\t%s\t%s\n' "$tag" "$engine" "${binaries[$tag]:-}" "${sources[$tag]:-}" >> "$plan"
done

# Any outgoing ssh from this host to a NetBird peer runs `netbird ssh detect/proxy`
# as the calling user (/etc/ssh/ssh_config.d/99-netbird.conf), so a non-root
# `netbird` process means another job is copying files out. Refuse to start
# on top of it; the root service is the only `netbird` we expect.
foreign_netbird=$(ps -eo user=,pid=,comm= | awk '$1 != "root" && $3 ~ /^netbird/ {print $1 "/" $2}' | paste -sd, -)
[[ -z $foreign_netbird ]] || {
    echo "refusing to start: non-root netbird process running ($foreign_netbird); another job is using outgoing ssh on this host" >&2
    exit 2
}
runner=${PERF_RUN:-/usr/local/bin/perf-run}
[[ -x $runner ]] || { echo "perf runner is not executable: $runner" >&2; exit 2; }
echo "D348 pinned $mode: $label; results $out"
run_env=(H2H_CPUSET_AUDIT=1 H2H_RESULTS="$out" "H2H_CPUSET_HOUSEKEEPING=$housekeeping")
if [[ $mode == validate ]]; then
    run_env+=(H2H_LAN_TPUT_SECONDS=10)
fi
if [[ $mode == matrix ]]; then
    run_env+=("H2H_MATRIX_SCENARIO=$scenario" "H2H_MATRIX_CALIBRATION_STATUS=$calibration_status" \
        "H2H_MATRIX_CONFIG=$out/scenario.json" "H2H_WG_BIN=$wg_bin" "H2H_WIREGUARD_GO_BIN=$wireguard_go_bin")
fi
if [[ $mode == calibration || $mode == ab || $mode == mixed ]]; then
    run_env+=(H2H_CALIBRATION_ONLY=1)
fi
if [[ -n ${H2H_MATRIX_RPS_POLICY:-} ]]; then
    run_env+=("H2H_MATRIX_RPS_POLICY=$H2H_MATRIX_RPS_POLICY")
fi
[[ -z ${H2H_ETHTOOL_BIN:-} ]] || run_env+=("H2H_ETHTOOL_BIN=$H2H_ETHTOOL_BIN")
# Default sampling (#260, J562): 8,000 probes inside a 72 s load (the load default
# lives in lib/common.sh), so every probe is sent under load at both 1 and 8 flows.
# Longer sampling stays opt-in: H2H_LAN_PING_COUNT=15000 with H2H_LAN_TPUT_SECONDS=85
# leaves about 150 samples above p99, but a three-control batch with it failed two
# gates. The mesh case fails the window if the probes outlive the load (D345).
if [[ $mode == calibration || $mode == ab || $mode == mixed ]] && [[ -z ${H2H_LAN_PING_COUNT:-} ]]; then
    H2H_LAN_PING_COUNT=8000
fi
if [[ -n ${H2H_LAN_PING_COUNT:-} ]]; then
    # perf-run enters a sudo scope, so measured overrides must be command env assignments.
    run_env+=("H2H_LAN_PING_COUNT=$H2H_LAN_PING_COUNT")
fi
# A longer probe run needs a load window at least as long (ping paces at 5 ms),
# or its tail samples an unloaded link. Every measured mode forwards it, validated
# here so a typo stops the run before it takes the lock. Validation pins its own 10 s.
if [[ $mode != validate && -n ${H2H_LAN_TPUT_SECONDS:-} ]]; then
    [[ $H2H_LAN_TPUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { echo 'H2H_LAN_TPUT_SECONDS must be a positive integer' >&2; exit 2; }
    run_env+=("H2H_LAN_TPUT_SECONDS=$H2H_LAN_TPUT_SECONDS")
fi
run_status=0
set +e
taskset -c "$housekeeping" "$runner" --root --out "$out/receipts" -- \
    env "${run_env[@]}" \
    bash "$kit/runner-overlays/J88i-pinned-run.sh" "$kit" "$out" "$mode" "$label" "$plan"
run_status=$?
set -e

# Take a second locked, read-only pass after the measured scope exits. Baseline
# manifests verify cgroup masks, workqueues, IRQ affinities, and perf.slice files.
mkdir -p "$out/restore-receipts"
restore_status=0
set +e
restore_args=("$out/cpuset-restoration.txt")
[[ -s $out/cgroup-masks-before.tsv ]] && restore_args+=("$out/cgroup-masks-before.tsv") || restore_args+=("")
[[ -s $out/workqueue-masks-before.tsv ]] && restore_args+=("$out/workqueue-masks-before.tsv") || restore_args+=("")
[[ -s $out/irq-affinity-before.tsv ]] && restore_args+=("$out/irq-affinity-before.tsv") || restore_args+=("")
[[ -s $out/perf-slice-dropins-before.json ]] && restore_args+=("$out/perf-slice-dropins-before.json") || restore_args+=("")
if ((run_status == 0)) && [[ ! -s $out/cgroup-masks-before.tsv || ! -s $out/workqueue-masks-before.tsv || ! -s $out/irq-affinity-before.tsv || ! -s $out/perf-slice-dropins-before.json ]]; then
    echo 'D348 baseline manifests are missing after a successful measured scope' >&2
    restore_status=2
else
    taskset -c "$housekeeping" "$runner" --root --out "$out/restore-receipts" -- \
        bash "$kit/runner-overlays/J88i-verify-restored.sh" "${restore_args[@]}"
    restore_status=$?
fi
set -e
if ((restore_status != 0)); then
    echo 'D348 perf.slice restoration was not verified after the measured scope exited' >&2
    exit 2
fi
if ((run_status != 0)); then
    exit "$run_status"
fi
echo "results: $out"
if [[ $mode == calibration ]]; then
    spread_report="$out/calibration-spread.json"
    spread_status=0
    set +e
    python3 -I "$kit/lib/calibration_spread.py" "$out" --case "mesh-$ab_engine" --expected-probes "${H2H_LAN_PING_COUNT:-8000}" --output "$spread_report"
    spread_status=$?
    set -e
    if ((spread_status != 0)); then
        echo "D348 control calibration failed the unpinned max/min spread gate; candidate holds are not enabled ($spread_report)" >&2
        exit "$spread_status"
    fi
fi
