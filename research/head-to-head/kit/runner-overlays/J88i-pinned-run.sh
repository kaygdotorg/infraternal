#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Execute one D348 validation, calibration, hold or soak under the shared lock.
set -euo pipefail

kit=$1
out=$2
mode=$3
label=$4
plan=$5
mkdir -p "$out"
source "$(dirname -- "${BASH_SOURCE[0]}")/J88i-cpuset-state.sh"
side_a=${H2H_CPUSET_A:-1-2}
side_b=${H2H_CPUSET_B:-3-4}
housekeeping=${H2H_CPUSET_HOUSEKEEPING:-0,5}
perf_cpus=${H2H_CPUSET_PERF:-0-5}
[[ $(id -u) == 0 ]] || { echo 'D348 host placement must run as root' >&2; exit 2; }

# Another job's leftover engine process (a daemon that outlived its hold) would sit beside every
# row of this hold, and nothing in the machine snapshots would show it. Checking here, under the
# lock and before anything is changed, is the only moment the answer is current: a hold that
# queued for the lock for minutes has a stale pre-flight check. The host runs exactly one
# tailscaled (a root service), so more are orphans too.
stray_engines=$(ps -eo pid=,user=,etimes=,comm= | awk '$4 ~ /^(gotatun|wireguard-go|boringtun|iperf|netbird-server)/')
tailscaled_count=$(ps -eo comm= | grep -c '^tailscaled$' || true)
# Any other live scope under perf.slice is a previous hold's leftover: this hold's own scope is
# the only one that may exist now (perf-run runs every hold in a transient perf.slice scope).
own_scope=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
stray_scopes=""
for scope in /sys/fs/cgroup/perf.slice/*.scope; do
    [[ -d $scope ]] || continue
    [[ ${scope#/sys/fs/cgroup} == "$own_scope" ]] && continue
    # cgroup files report size 0, so test for content, not for `-s`.
    [[ -n $(head -c 1 "$scope/cgroup.procs" 2>/dev/null) ]] && stray_scopes+=" $(basename "$scope"):$(head -c 120 "$scope/cgroup.procs" | tr '\n' ',')"
done
stray_named=$(ps -eo pid=,user=,etimes=,comm= | awk '$4 ~ /^(infraternal|yes)$/')
if [[ -n $stray_engines ]] || ((tailscaled_count > 1)) || [[ -n $stray_scopes || -n $stray_named ]]; then
    echo "refusing to measure: stray processes under the lock (tailscaled count $tailscaled_count): $stray_engines$stray_named; other perf.slice scopes:$stray_scopes" >&2
    exit 5
fi

topology=$(lscpu --parse=CPU,CORE,SOCKET | awk -F, '!/^#/ {print}')
cpu_list=$(printf '%s\n' "$topology" | awk -F, '{print $1}' | paste -sd, -)
guest_core_count=$(printf '%s\n' "$topology" | awk -F, '{print $2 "/" $3}' | sort -u | awk 'END {print NR}')
[[ $(nproc --all) == 6 && $cpu_list == 0,1,2,3,4,5 && $guest_core_count == 6 ]] || {
    echo "unexpected six-vCPU guest topology: nproc=$(nproc --all) CPUs=$cpu_list virtual_cores=$guest_core_count" >&2
    exit 2
}
[[ $side_a == 1-2 && $side_b == 3-4 && $housekeeping == 0,5 && $perf_cpus == 0-5 ]] || {
    echo "unexpected D348 masks: A=$side_a B=$side_b housekeeping=$housekeeping perf=$perf_cpus" >&2
    exit 2
}

# Resolve a systemd unit to its cgroup v2 directory so CPU masks come from
# the kernel's live state rather than systemd's presentation format.
unit_cgroup() {
    local unit=$1 group
    group=$(systemctl show "$unit" -p ControlGroup --value)
    [[ $group == /* ]] || { echo "$unit has no cgroup path" >&2; return 2; }
    printf '/sys/fs/cgroup%s\n' "$group"
}

# Read one live cpuset file; missing cgroup state is an error, never a fallback.
unit_cpus() {
    local unit=$1 file=$2 group
    group=$(unit_cgroup "$unit") || return
    [[ -r "$group/$file" ]] || { echo "$unit cgroup lacks $file" >&2; return 2; }
    cat "$group/$file"
}

units=(init.scope system.slice user.slice perf.slice)
declare -A old_cpuset old_effective old_dropins old_irq_affinity
for unit in "${units[@]}"; do
    old_cpuset[$unit]=$(unit_cpus "$unit" cpuset.cpus)
    old_effective[$unit]=$(unit_cpus "$unit" cpuset.cpus.effective)
    old_dropins[$unit]=$(systemctl show "$unit" -p DropInPaths --value)
    [[ $unit == perf.slice || -z ${old_dropins[$unit]} ]] || {
        echo "refusing to alter $unit with existing drop-ins: ${old_dropins[$unit]}" >&2
        exit 2
    }
done
old_cpus=${old_cpuset[perf.slice]}
old_perf_effective=${old_effective[perf.slice]}
perf_allowed_before=$(systemctl show perf.slice -p AllowedCPUs --value)
[[ -n $old_perf_effective ]] || {
    echo "perf.slice has no effective CPU baseline: cpuset.cpus=$old_cpus" >&2
    exit 2
}
perf_dropin_baseline="$out/perf-slice-dropins-before.json"

for unit in init.scope system.slice user.slice; do
    baseline_cpus=${old_cpuset[$unit]}
    baseline_effective=${old_effective[$unit]}
    [[ $baseline_effective == 0-5 && ( -z $baseline_cpus || $baseline_cpus == 0-5 ) ]] || {
        echo "$unit must inherit or be configured for 0-5 before D348, got cpuset.cpus=$baseline_cpus effective=$baseline_effective" >&2
        exit 2
    }
done

# Encode empty TSV fields because Bash treats tab separators as whitespace and
# collapses adjacent separators while reading the restore manifest.
manifest_field() {
    [[ -n $1 ]] && printf '%s' "$1" || printf '%s' '__EMPTY__'
}

# Keep a machine-readable baseline so the second perf-run scope can verify
# real cgroup files after this scope has gone away.
: > "$out/cgroup-masks-before.tsv"
for unit in "${units[@]}"; do
    group=$(unit_cgroup "$unit")
    printf '%s\t%s\t%s\t%s\t%s\n' "$unit" "${group#/sys/fs/cgroup}" \
        "$(manifest_field "${old_cpuset[$unit]}")" "$(manifest_field "${old_effective[$unit]}")" \
        "$(manifest_field "${old_dropins[$unit]}")" \
        >> "$out/cgroup-masks-before.tsv"
done

# The global and per-workqueue cpumasks all start from their own exact values.
# Pinning them together keeps unbound kernel work off the measured CPUs.
workqueue_mask_files=(/sys/devices/virtual/workqueue/cpumask)
for path in /sys/devices/virtual/workqueue/*/cpumask; do
    [[ -f $path ]] && workqueue_mask_files+=("$path")
done
declare -A old_workqueue_mask
: > "$out/workqueue-masks-before.tsv"
for path in "${workqueue_mask_files[@]}"; do
    [[ -r $path && -w $path ]] || { echo "cannot read and set workqueue cpumask $path" >&2; exit 2; }
    old_workqueue_mask[$path]=$(cat "$path")
    printf '%s\t%s\n' "$path" "${old_workqueue_mask[$path]}" >> "$out/workqueue-masks-before.tsv"
done

host_net_irqs=()
declare -A irq_seen
for netdev in /sys/class/net/*; do
    [[ -e "$netdev/device/driver" ]] || continue
    driver=$(basename "$(readlink -f "$netdev/device/driver")")
    [[ $driver == virtio_net ]] || continue
    device=$(basename "$(readlink -f "$netdev/device")")
    while read -r irq; do
        [[ -n $irq && -z ${irq_seen[$irq]+x} ]] || continue
        affinity_file="/proc/irq/$irq/smp_affinity_list"
        [[ -r $affinity_file && -w $affinity_file ]] || {
            echo "cannot read and pin $netdev IRQ $irq" >&2
            exit 2
        }
        irq_seen[$irq]=1
        host_net_irqs+=("$irq")
        old_irq_affinity[$irq]=$(cat "$affinity_file")
    done < <(awk -v prefix="$device-" '$1 ~ /^[0-9]+:/ && index($0, prefix) {gsub(":", "", $1); print $1}' /proc/interrupts)
done

: > "$out/irq-affinity-before.tsv"
for irq in "${host_net_irqs[@]}"; do
    printf '%s\t%s\n' "$irq" "${old_irq_affinity[$irq]}" >> "$out/irq-affinity-before.tsv"
done

# Capture every restorable baseline before installing the EXIT trap or changing
# any host setting. A missing manifest therefore means the hold never mutated
# CPU placement, even if an earlier validation failed.
python3 -I "$kit/lib/perf_slice_dropins.py" snapshot \
    --drop-in-paths "${old_dropins[perf.slice]}" \
    --allowed-cpus "$perf_allowed_before" \
    --output "$perf_dropin_baseline" \
    --raw-dir "$out/perf-slice-dropins-before-files"

restored=0
# Restore saved settings. The perf-run scope itself remains inside perf.slice,
# so its widened parent cgroup mask is checked by the second locked pass after
# that transient scope exits; the runtime files and AllowedCPUs are checked here.
restore() {
    ((restored == 0)) || return 0
    local rc=0 command_rc=0 settled=0 cpus effective paths attempt irq unit path allowed current_perf_dropins
    for path in "${workqueue_mask_files[@]}"; do
        printf '%s\n' "${old_workqueue_mask[$path]}" > "$path" || command_rc=1
    done
    for irq in "${host_net_irqs[@]}"; do
        printf '%s\n' "${old_irq_affinity[$irq]}" > "/proc/irq/$irq/smp_affinity_list" || command_rc=1
    done
    # Other slices had no existing overrides, so revert only the runtime
    # properties this hold created there. perf.slice is restored from its exact
    # captured file bytes below; systemctl revert would delete the baseline.
    for unit in init.scope system.slice user.slice; do
        systemctl set-property --runtime "$unit" "AllowedCPUs=${old_effective[$unit]}" >/dev/null || command_rc=1
    done
    for unit in init.scope system.slice user.slice; do
        systemctl revert "$unit" >/dev/null || command_rc=1
    done
    current_perf_dropins=$(systemctl show perf.slice -p DropInPaths --value) || command_rc=1
    if ((command_rc == 0)); then
        python3 -I "$kit/lib/perf_slice_dropins.py" restore \
            --baseline "$perf_dropin_baseline" \
            --current-drop-in-paths "$current_perf_dropins" \
            --control-dir /run/systemd/system.control/perf.slice.d || command_rc=1
        systemctl daemon-reload >/dev/null || command_rc=1
    fi
    for attempt in {1..50}; do
        rc=0
        for unit in "${units[@]}"; do
            cpus=$(unit_cpus "$unit" cpuset.cpus) || rc=1
            effective=$(unit_cpus "$unit" cpuset.cpus.effective) || rc=1
            paths=$(systemctl show "$unit" -p DropInPaths --value)
            if [[ $unit != perf.slice ]]; then
                cpuset_state_matches "$cpus" "${old_cpuset[$unit]}" \
                    "$effective" "${old_effective[$unit]}" || rc=1
            fi
            [[ $paths == "${old_dropins[$unit]}" ]] || rc=1
        done
        for irq in "${host_net_irqs[@]}"; do
            [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "${old_irq_affinity[$irq]}" ]] || rc=1
        done
        for path in "${workqueue_mask_files[@]}"; do
            [[ $(cat "$path") == "${old_workqueue_mask[$path]}" ]] || rc=1
        done
        cpus=$(unit_cpus perf.slice cpuset.cpus) || rc=1
        effective=$(unit_cpus perf.slice cpuset.cpus.effective) || rc=1
        allowed=$(systemctl show perf.slice -p AllowedCPUs --value) || rc=1
        [[ $allowed == "$perf_allowed_before" ]] || rc=1
        if ((rc == 0 && command_rc == 0)); then
            settled=1
            break
        fi
        sleep 0.1
    done
    if ((settled)); then
        paths=$(systemctl show perf.slice -p DropInPaths --value) || command_rc=1
        python3 -I "$kit/lib/perf_slice_dropins.py" verify \
            --baseline "$perf_dropin_baseline" \
            --drop-in-paths "$paths" \
            --allowed-cpus "$allowed" || command_rc=1
    fi
    if ((!settled || command_rc != 0)); then
        echo "host placement restore failed: command_status=$command_rc cpuset.cpus=$cpus DropInPaths=$paths perf.slice cpuset.cpus.effective=$effective AllowedCPUs=$allowed" >&2
        return 1
    fi
    restored=1
    {
        echo "restored at $(date -Is)"
        for unit in "${units[@]}"; do
            printf '%s cpuset.cpus=%s cpuset.cpus.effective=%s dropins=%s\n' "$unit" \
                "$(unit_cpus "$unit" cpuset.cpus)" \
                "$(unit_cpus "$unit" cpuset.cpus.effective)" \
                "$(systemctl show "$unit" -p DropInPaths --value)"
        done
        printf 'perf.slice AllowedCPUs=%s\n' "$allowed"
        printf 'perf.slice cgroup restore deferred until perf-run scope exits: cpuset.cpus=%s expected=%s cpuset.cpus.effective=%s expected=%s\n' \
            "$cpus" "$old_cpus" "$effective" "$old_perf_effective"
        for irq in "${host_net_irqs[@]}"; do
            printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
        done
        for path in "${workqueue_mask_files[@]}"; do
            printf 'workqueue_cpumask_%s=%s\n' "${path##*/}" "$(cat "$path")"
        done
    } > "$out/host-layout-restored.txt"
    echo "host slices, IRQ affinities, workqueue masks, and exact perf.slice drop-ins restored; final perf.slice cgroup masks are verified by the post-scope audit (currently cpuset.cpus=$cpus effective=$effective)"
    return 0
}
finish() {
    local rc=$?
    trap - EXIT
    if ! restore; then
        ((rc != 0)) || rc=2
    fi
    exit "$rc"
}
trap finish EXIT
trap 'exit 143' TERM INT

for path in "${workqueue_mask_files[@]}"; do
    printf '21\n' > "$path"
    [[ $(cat "$path") == 21 ]] || {
        echo "workqueue cpumask did not pin to housekeeping CPUs $housekeeping: $path=$(cat "$path")" >&2
        exit 2
    }
done

for unit in init.scope system.slice user.slice; do
    systemctl set-property --runtime "$unit" "AllowedCPUs=$housekeeping" >/dev/null
done
systemctl set-property --runtime perf.slice "AllowedCPUs=$perf_cpus" >/dev/null
for unit in init.scope system.slice user.slice; do
    [[ $(unit_cpus "$unit" cpuset.cpus) == "$housekeeping" && \
       $(unit_cpus "$unit" cpuset.cpus.effective) == "$housekeeping" ]] || {
        echo "$unit did not inherit housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(unit_cpus perf.slice cpuset.cpus) == "$perf_cpus" && \
   $(unit_cpus perf.slice cpuset.cpus.effective) == "$perf_cpus" ]] || {
    echo "perf.slice did not accept test CPUs $perf_cpus" >&2
    exit 2
}
taskset -pc "$housekeeping" "$$" >/dev/null
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 coordinator was not pinned to housekeeping CPUs $housekeeping" >&2
    exit 2
}
for irq in "${host_net_irqs[@]}"; do
    printf '%s\n' "$housekeeping" > "/proc/irq/$irq/smp_affinity_list"
    [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "$housekeeping" ]] || {
        echo "host network IRQ $irq did not move to housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 coordinator affinity is not restricted to housekeeping CPUs $housekeeping" >&2
    exit 2
}
runner_cpus_allowed=$(awk '/^Cpus_allowed:/ {print $2}' /proc/self/status)
runner_allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
{
    echo "topology: nproc_all=$(nproc --all)"
    printf 'CPU,CORE,SOCKET\n%s\n' "$topology"
    echo 'host_cpu_topology: isolcpus configured; vCPU-to-host-CPU mapping is 1:1; exact host CPU IDs are not guest-visible'
    printf 'side_a=%s\nside_b=%s\nhousekeeping=%s\n' "$side_a" "$side_b" "$housekeeping"
    printf 'perf_slice_cpuset=%s\nperf_slice_effective=%s\n' \
        "$(unit_cpus perf.slice cpuset.cpus)" \
        "$(unit_cpus perf.slice cpuset.cpus.effective)"
    printf 'runner_cpus_allowed=%s\nrunner_allowed=%s\n' "$runner_cpus_allowed" "$runner_allowed"
    for unit in init.scope system.slice user.slice netbird.service tailscaled.service containerd.service docker.service systemd-journald.service; do
        state=$(systemctl show "$unit" -p ActiveState --value)
        property=$(systemctl show "$unit" -p AllowedCPUs --value)
        cpus=""
        effective=""
        if [[ $state == active ]]; then
            cpus=$(unit_cpus "$unit" cpuset.cpus)
            effective=$(unit_cpus "$unit" cpuset.cpus.effective)
        fi
        printf 'unit=%s state=%s AllowedCPUs_property=%s cpuset.cpus=%s cpuset.cpus.effective=%s\n' \
            "$unit" "$state" "$property" "$cpus" "$effective"
        if [[ $unit == *.service && $state == active ]]; then
            # Service cpuset.cpus may be empty because it inherits system.slice.
            [[ $effective == "$housekeeping" ]] || {
                echo "$unit is not confined to housekeeping CPUs $housekeeping" >&2
                exit 2
            }
        fi
    done
    for irq in "${host_net_irqs[@]}"; do
        printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
    done
    for path in "${workqueue_mask_files[@]}"; do
        printf 'workqueue_cpumask_%s=%s\n' "${path##*/}" "$(cat "$path")"
    done
} > "$out/cpuset-preflight.txt"
cp "$out/cpuset-preflight.txt" "$out/host-layout-pinned.txt"

export H2H_CPUSET_PIN=1
export H2H_CPUSET_A="$side_a"
export H2H_CPUSET_B="$side_b"
export H2H_CPUSET_HOUSEKEEPING="$housekeeping"
export H2H_CPUSET_PERF="$perf_cpus"
export H2H_LOCK=external
export H2H_USER=claude
export H2H_CPUSET_AUDIT=1
export H2H_CPUSET_AUDIT_REQUIRE_CLEAN=1

run_row() {
    local tag=$1 engine=$2 binary=$3 source_sha=$4 smoke=$5
    local case_name row_dir row_label
    case $engine in
        gotatun) case_name=mesh-gotatun ;;
        infraternal) case_name=mesh-infraternal ;;
        kernel) case_name=mesh-netbird ;;
        kernel-plain) case_name=mesh-kernel-plain ;;
        wireguard-go) case_name=mesh-wireguard-go ;;
        underlay) case_name=mesh-underlay ;;
        tailscale) case_name=mesh-tailscale ;;
        netbird-userspace) case_name=mesh-netbird-userspace ;;
        *) echo "unknown engine $engine for $tag" >&2; return 2 ;;
    esac
    # A non-root `netbird` process is an outgoing ssh from another job (see
    # perf-all.sh). Give a short one 30 s to finish, then fail the row by name
    # instead of measuring beside it.
    local foreign_netbird waited
    for waited in $(seq 30); do
        foreign_netbird=$(ps -eo user=,pid=,comm= | awk '$1 != "root" && $3 ~ /^netbird/ {print $1 "/" $2}' | paste -sd, -)
        [[ -n $foreign_netbird ]] || break
        sleep 1 # sleep: wait for another job's short-lived outgoing ssh to finish
    done
    if [[ -n $foreign_netbird ]]; then
        echo "D348 row $tag not started: non-root netbird process still running after 30 s ($foreign_netbird)" >&2
        return 4
    fi
    row_dir="$out/$tag"
    row_label="perf VM $(hostname), $(uname -m); D348 A=$side_a B=$side_b housekeeping=$housekeeping; $mode $label; row $tag=$engine"
    mkdir -p "$row_dir"
    local -a args=(--only "$case_name" --label "$row_label")
    [[ $smoke == 1 ]] && args+=(--smoke)
    local -a matrix_env=(
        "H2H_MATRIX_SCENARIO=${H2H_MATRIX_SCENARIO:-}"
        "H2H_MATRIX_ROW_TAG=$tag"
        "H2H_MATRIX_ENGINE=$engine"
        "H2H_MATRIX_CALIBRATION_STATUS=${H2H_MATRIX_CALIBRATION_STATUS:-uncalibrated}"
    )
    if [[ $mode == soak ]]; then
        taskset -c "$housekeeping" env "${matrix_env[@]}" H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
            H2H_INFRATERNAL_BIN="$binary" H2H_INFRATERNAL_SOURCE="$source_sha" \
            H2H_SOAK_SECONDS=3600 bash "$kit/run.sh" "${args[@]}"
    else
        taskset -c "$housekeeping" env "${matrix_env[@]}" H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
            H2H_INFRATERNAL_BIN="$binary" H2H_INFRATERNAL_SOURCE="$source_sha" \
            bash "$kit/run.sh" "${args[@]}"
    fi
}

# Run every planned row even after one fails so the table keeps matched results
# from later engines; report a nonzero plan status after preserving those rows.
run_plan() {
    local smoke=$1 tag engine binary source_sha
    local plan_status=0 row_status
    while IFS=$'\t' read -r tag engine binary source_sha; do
        [[ -n $tag ]] || continue
        echo "D348 row start: $tag engine=$engine binary=${binary:-kit-default} source=${source_sha:-unknown}"
        if run_row "$tag" "$engine" "$binary" "$source_sha" "$smoke"; then
            echo "D348 row finish: $tag"
        else
            row_status=$?
            printf 'D348 row failed: %s (exit %s); continuing to remaining rows\n' \
                "$tag" "$row_status" >&2
            plan_status=1
        fi
    done < "$plan"
    return "$plan_status"
}

case $mode in
    validate)
        smoke_dir="$out/cpuset-smoke"
        mkdir -p "$smoke_dir"
        # The overlay is installed into the harness root, beside its smoke helper.
        bash "$kit/cpuset-harness-smoke.sh" "$kit" "$smoke_dir"
        run_row validate-underlay underlay "" "" 1
        run_row validate-kernel kernel "" "" 1
        run_row validate-kernel-plain kernel-plain "" "" 1
        printf 'cpuset masks, runnable-task audit, veth/namespace counters, NetBird kernel smoke, and direct MTU-1420 kernel WireGuard smoke completed\n' \
            > "$out/validation.txt"
        ;;
    smoke)
        run_plan 1
        ;;
    calibration|hold|matrix|ab)
        run_plan 0
        ;;
    soak)
        run_plan 0
        ;;
    *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
