#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Verify restored host cgroups, perf.slice drop-ins, workqueues and IRQs after perf-run exits.
set -euo pipefail

output=$1
cgroup_manifest=${2:-}
workqueue_manifest=${3:-}
irq_manifest=${4:-}
perf_slice_baseline=${5:-}
cgroup_root=${J88I_CGROUP_ROOT:-/sys/fs/cgroup}
results=()
failed=0
source "$(dirname -- "${BASH_SOURCE[0]}")/J88i-cpuset-state.sh"

# Decode the manifest marker used for empty cpuset and DropInPaths values.
manifest_value() {
    [[ $1 == '__EMPTY__' ]] && printf '' || printf '%s' "$1"
}

if [[ -n $cgroup_manifest ]]; then
    [[ -r $cgroup_manifest ]] || { echo "missing cgroup baseline manifest: $cgroup_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r unit group expected_cpus expected_effective expected_dropins; do
        [[ -n $unit ]] || continue
        expected_cpus=$(manifest_value "$expected_cpus")
        expected_effective=$(manifest_value "$expected_effective")
        expected_dropins=$(manifest_value "$expected_dropins")
        cgroup="$cgroup_root$group"
        cpus=$(cat "$cgroup/cpuset.cpus")
        effective=$(cat "$cgroup/cpuset.cpus.effective")
        actual_group=$(systemctl show "$unit" -p ControlGroup --value)
        dropins=$(systemctl show "$unit" -p DropInPaths --value)
        if [[ $actual_group != "$group" || $dropins != "$expected_dropins" ]] || \
           ! cpuset_state_matches "$cpus" "$expected_cpus" "$effective" "$expected_effective"; then
            printf '%s restoration failed: cgroup=%s expected=%s cpuset.cpus=%s expected=%s cpuset.cpus.effective=%s expected=%s DropInPaths=%s expected=%s\n' \
                "$unit" "$actual_group" "$group" "$cpus" "$expected_cpus" \
                "$effective" "$expected_effective" "$dropins" "$expected_dropins" >&2
            failed=1
        fi
        allowed=$(systemctl show "$unit" -p AllowedCPUs --value)
        systemd_effective=$(systemctl show "$unit" -p EffectiveCPUs --value)
        results+=("$unit restored: cpuset.cpus=$cpus cpuset.cpus.effective=$effective DropInPaths=$dropins (AllowedCPUs=$allowed EffectiveCPUs=$systemd_effective informational)")
    done < "$cgroup_manifest"
else
    if [[ -n $perf_slice_baseline ]]; then
        echo 'D348 perf.slice snapshot exists but the cgroup baseline manifest is missing' >&2
        failed=1
    else
        # The runner saves every baseline before installing its mutation trap;
        # no snapshot means it exited before changing host placement.
        results+=("perf.slice placement untouched: no baseline snapshot was captured before the hold could mutate host state")
    fi
fi

if [[ -n $perf_slice_baseline ]]; then
    [[ -r $perf_slice_baseline ]] || {
        echo "missing perf.slice drop-in baseline: $perf_slice_baseline" >&2
        exit 2
    }
    paths=$(systemctl show perf.slice -p DropInPaths --value)
    allowed=$(systemctl show perf.slice -p AllowedCPUs --value)
    helper="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../lib" && pwd -P)/perf_slice_dropins.py"
    if python3 -I "$helper" verify \
        --baseline "$perf_slice_baseline" \
        --drop-in-paths "$paths" \
        --allowed-cpus "$allowed"; then
        results+=("perf.slice runtime drop-ins restored exactly: DropInPaths=${paths:-<none>} AllowedCPUs=${allowed:-<empty>}")
    else
        failed=1
    fi
fi

if [[ -n $workqueue_manifest ]]; then
    [[ -r $workqueue_manifest ]] || { echo "missing workqueue baseline manifest: $workqueue_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r path expected; do
        [[ -n $path ]] || continue
        actual=$(cat "$path")
        if [[ $actual != "$expected" ]]; then
            printf 'workqueue cpumask restore failed: %s=%s expected=%s\n' "$path" "$actual" "$expected" >&2
            failed=1
        fi
        results+=("workqueue cpumask restored: $path=$actual")
    done < "$workqueue_manifest"
fi

if [[ -n $irq_manifest ]]; then
    [[ -r $irq_manifest ]] || { echo "missing IRQ baseline manifest: $irq_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r irq expected; do
        [[ -n $irq ]] || continue
        path="/proc/irq/$irq/smp_affinity_list"
        actual=$(cat "$path")
        if [[ $actual != "$expected" ]]; then
            printf 'IRQ affinity restore failed: irq=%s cpus=%s expected=%s\n' "$irq" "$actual" "$expected" >&2
            failed=1
        fi
        results+=("IRQ affinity restored: irq=$irq cpus=$actual")
    done < "$irq_manifest"
fi

if ((failed)); then
    exit 2
fi
printf '%s\n' "${results[@]}" > "$output"
cat "$output"
