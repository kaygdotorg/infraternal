#!/usr/bin/env bash
# Role: Runs five measured repetitions under a high-priority user scope and records host load.
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
harness_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$harness_dir/../../.." && pwd)
scratch_dir=${QUIC_RESEARCH_SCRATCH:-"$HOME/.cache/codex-scratch/quic-research"}
target_dir=${CARGO_TARGET_DIR:-"$scratch_dir/target"}
results_dir=${1:-"$repo_dir/research/quic-stacks/raw"}
binary="$target_dir/x86_64-unknown-linux-musl/release/quic-stack-bench"
mkdir -p -- "$results_dir"

ip_bin=$(/nix/var/nix/profiles/default/bin/nix shell nixpkgs#iproute2 --command /bin/sh -c 'command -v ip')
tc_bin=$(/nix/var/nix/profiles/default/bin/nix shell nixpkgs#iproute2 --command /bin/sh -c 'command -v tc')
printf '# Role: Load-average and timestamp record for each benchmark repetition. SPDX-License-Identifier: AGPL-3.0-only\n' > "$results_dir/run-context.csv"
printf 'label,repeat,attempt,utc,load1,load5,load15,tasks,last_pid,nofile_soft\n' >> "$results_dir/run-context.csv"

run_one() {
  local label=$1 mode=$2 repeat=$3
  shift 3
  local csv="$results_dir/$label.csv"
  local log load1 load5 load15 tasks last_pid run_status success=0
  for attempt in 1 2 3; do
    log="$results_dir/$label-$repeat-a$attempt.log"
    read -r load1 load5 load15 tasks last_pid < /proc/loadavg
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$label" "$repeat" "$attempt" "$(date -u +%FT%TZ)" \
      "$load1" "$load5" "$load15" "$tasks" "$last_pid" 8192 \
      >> "$results_dir/run-context.csv"
    printf '# Role: Raw command output for %s repetition %s attempt %s. SPDX-License-Identifier: AGPL-3.0-only\n' \
      "$label" "$repeat" "$attempt" > "$log"
    if [[ "$mode" == "loopback" ]]; then
      systemd-run --quiet --user --scope -p CPUWeight=10000 \
        /usr/bin/bash -c 'ulimit -n 8192; exec /usr/bin/timeout --kill-after=5s 120s "$@"' \
        benchmark-scope "$@" >> "$log" 2>&1 || run_status=$?
    else
      systemd-run --quiet --user --scope -p CPUWeight=10000 \
        /usr/bin/bash -c 'ulimit -n 8192; exec /usr/bin/unshare -Urn "$@"' \
        benchmark-scope "$harness_dir/netem-run.sh" "$ip_bin" "$tc_bin" \
        150ms 15ms "$mode" /usr/bin/timeout --kill-after=5s 120s "$@" \
        >> "$log" 2>&1 || run_status=$?
    fi
    if [[ "${run_status:-0}" == 0 ]]; then
      success=1
      break
    fi
    printf 'attempt %s failed with status %s; see %s\n' "$attempt" "$run_status" "$log" >&2
    unset run_status
  done
  if [[ "$success" == 0 ]]; then
    return 1
  fi
  if [[ ! -f "$csv" ]]; then
    printf '# Role: Raw measured benchmark rows for %s. SPDX-License-Identifier: AGPL-3.0-only\n' "$label" > "$csv"
    awk '/^stack,workload,/ || /^stack,connections,/ { print; exit }' "$log" >> "$csv"
  fi
  awk -F, '($1 == "quinn-rustls-ring" || $1 == "openssl-native-3.6.3") { row = $0 } END { if (row != "") print row }' "$log" >> "$csv"
}

for stack in quinn openssl; do
  for repeat in 1 2 3 4 5; do
    run_one "handshake-loopback-$stack" loopback "$repeat" "$binary" bench-handshake "$stack" 1000
    run_one "handshake-300ms-$stack" 0% "$repeat" "$binary" bench-handshake "$stack" 1
  done
done

for repeat in 1 2 3 4 5; do
  run_one "0rtt-loopback-quinn" loopback "$repeat" "$binary" bench-0rtt quinn
  run_one "0rtt-300ms-quinn" 0% "$repeat" "$binary" bench-0rtt quinn
done

for stack in quinn openssl; do
  for streams in 1 4; do
    for repeat in 1 2 3 4 5; do
      run_one "throughput-loopback-$stack-$streams" loopback "$repeat" \
        "$binary" bench-throughput "$stack" "$streams" 1048576
      run_one "throughput-300ms-loss1-$stack-$streams" 1% "$repeat" \
        "$binary" bench-throughput "$stack" "$streams" 1048576
    done
  done
  for repeat in 1 2 3 4 5; do
    run_one "memory-1000-$stack" loopback "$repeat" "$binary" bench-memory "$stack" 1000
  done
done
