#!/bin/bash
# Many-host matrix on the perf VM: usage `perf-run -- bash matrix.sh <set-name> "<H:T> <H:T> ..." [strace]`
# J1246: INFRATERNAL_MANY_RUNTIME=production|current picks the fixture server's runtime (default production).
# One JSON line per point is appended to $OUT/<set>.jsonl; an optional third argument wraps the
# server test in a seccomp-bpf strace (counts SQLite busy-handler sleeps and fsyncs; timing
# rows come from the runs without it). Root dirs are removed after each point.
set -u
cd "$HOME/j1246"; ulimit -Sn 65536
SET=$1; POINTS=$2; MODE=${3:-plain}
OUT=$HOME/j1246/out; mkdir -p "$OUT"
TEST=bin/server-test
if [ "$MODE" = strace ]; then
  cat > wrap.sh <<W
#!/bin/sh
exec $HOME/.cache/codex-scratch/j1164/strace -f --seccomp-bpf -qq -ttt -e trace=nanosleep,clock_nanosleep,fsync,fdatasync -e signal=none -o \$STRACEOUT $PWD/bin/server-test "\$@"
W
  chmod +x wrap.sh; TEST=./wrap.sh
fi
for p in $POINTS; do
  H=${p%%:*}; T=${p##*:}; R=$HOME/j1246r; rm -rf "$R"
  export STRACEOUT=$OUT/$SET-h$H-t$T.strace
  # keys per typist stay at 8/s for 15 s; 20 typists spread over the hosts
  timeout 1500 python3 measure.py --test-binary $TEST --agent-binary bin/infraternal --repo "$HOME/j1246/repo" \
      --root "$R" --hosts "$H" --terminals "$T" --typists 20 --idle-seconds 15 --settle 5 --type-seconds 15 ${NOREATTACH:+--skip-reattach} \
      > "$OUT/$SET-h$H-t$T.raw" 2> "$OUT/$SET-h$H-t$T.err"
  rc=$?
  tail -n1 "$OUT/$SET-h$H-t$T.raw" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); d['set']='$SET'; d['H']=$H; d['T']=$T; d['rc']=$rc; print(json.dumps(d))" >> "$OUT/$SET.jsonl" 2>/dev/null || echo "{\"set\":\"$SET\",\"H\":$H,\"T\":$T,\"rc\":$rc,\"failed\":true}" >> "$OUT/$SET.jsonl"
  echo "point H=$H T=$T rc=$rc"
  if [ "$MODE" = strace ]; then python3 strace_count.py "$STRACEOUT" <(tail -n1 "$OUT/$SET-h$H-t$T.raw") > "$OUT/$SET-h$H-t$T.strace.json" 2>/dev/null; rm -f "$STRACEOUT"; fi
  cp "$R/fixture.log" "$OUT/$SET-h$H-t$T.fixture.log" 2>/dev/null
  # the fixture's own cleanup retires its agents; make sure none outlive the point
  rm -rf "$R"
done
echo MATRIX_DONE
