#!/usr/bin/env bash
# Run the exact production parser ASAN targets serially on the perf VM.
set -euo pipefail
cd /root/infraternal-bench/mat129-cont
uname -a > fuzz-environment.txt
cat /proc/loadavg >> fuzz-environment.txt
for target in remote_cursor_decode remote_standby_decode shim_frame_decode; do
    mkdir -p "fuzz/artifacts/$target"
    max_len=128
    [[ "$target" != shim_frame_decode ]] || max_len=1048580
    status=0
    timeout 90s "$PWD/fuzz/runtime/ld-linux-x86-64.so.2" --library-path "$PWD/fuzz/runtime" "$PWD/fuzz/$target" "fuzz/corpus/$target" -max_total_time=31 -rss_limit_mb=1024 -timeout=10 -max_len="$max_len" -artifact_prefix="fuzz/artifacts/$target/" > "fuzz-$target.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "fuzz-$target.exit"
    [[ "$status" == 0 ]] || exit "$status"
done
