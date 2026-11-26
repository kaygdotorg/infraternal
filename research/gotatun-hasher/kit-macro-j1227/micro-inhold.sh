#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1227 (#260): the criterion micro-bench, run INSIDE a macro hold (series.sh took the locks on
# both VMs already), so the perf VM is waited for once. Driven from hd01 against node B (6 vCPU),
# pinned to one CPU, before any netns or engine exists. Usage: micro-inhold.sh <evidence dir>
set -uo pipefail
ev=$1
S=$HOME/.cache/codex-scratch/j1227
B=root@infraternal-perf-01-backup01.vpn.kayg.org
M=/root/j1227/micro
FILTER=${FILTER:-flow_start|allowed_ips}
REPS=${REPS:-"1 2"}
mkdir -p "$ev"
on() { ssh -o BatchMode=yes -o ServerAliveInterval=15 "$B" "$@"; }
on "mkdir -p $M && chmod 700 $M"
for f in hot_paths quality symmetric_quality; do on "umask 077; cat > $M/$f && chmod 700 $M/$f" < "$S/stage/$f"; done
on "cd $M; sha256sum hot_paths quality symmetric_quality; uname -r; lscpu | grep -E 'Model name|MHz|L2|L3'; cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c; cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null; uptime; grep -E 'cpu ' /proc/stat" > "$ev/machine.txt" 2>&1
on "taskset -c 3 $M/quality" > "$ev/quality-x86.txt" 2>&1
on "taskset -c 3 $M/symmetric_quality" > "$ev/symmetric-quality-x86.md" 2>&1
for rep in $REPS; do
  echo "[$(date -u +%T)] criterion rep $rep"
  on "cd $M && taskset -c 3 ./hot_paths --bench '$FILTER' --warm-up-time 1 --measurement-time 3 --sample-size 50 --noplot" > "$ev/crit-rep$rep.txt" 2>&1
  echo "exit=$?" >> "$ev/crit-rep$rep.txt"
  on "uptime; grep -E '^cpu ' /proc/stat" >> "$ev/machine.txt" 2>&1
done
on "rm -rf $M"
echo "[$(date -u +%T)] micro done: $ev"
