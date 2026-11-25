#!/bin/bash
# Profile the hottest matrix point on the perf VM: `perf-run --root -- bash profile.sh H T`.
# perf record follows the whole fixture (server, agents, shims); the server runs as `claude`
# via runuser so it behaves as in the other runs. Needs `nix build nixpkgs#perf` (a 3 MiB fetch).
set -u
export HOME=/home/claude; cd /home/claude/j1220; ulimit -Sn 65536
H=$1; T=$2; OUT=$HOME/j1220/out; mkdir -p "$OUT"
PERF=$(nix build --no-link --print-out-paths nixpkgs#perf 2>/dev/null | tail -1)/bin/perf
cat > prof-wrap.sh <<W
#!/bin/sh
exec $PERF record -e cpu-clock -F 499 -g -o $OUT/perf-h$H-t$T.data -- runuser -u claude -- env HOME=/home/claude $PWD/bin/server-test "\$@"
W
chmod +x prof-wrap.sh
# A VM has no PMU, so sample the software cpu-clock; show the reason if even that fails.
$PERF record -e cpu-clock -o /dev/null -- true 2>&1 | head -3
R=$HOME/j1220r; rm -rf "$R"
# The driver runs as root (perf record needs it and the test is its child); the server and the
# agents drop to `claude` inside the wrapper. Their directories must belong to claude.
install -d -o claude -g claude -m 700 "$R" "$R/s"
timeout 1500 python3 measure.py --test-binary ./prof-wrap.sh --agent-binary bin/infraternal --repo "$HOME/j1220/repo" \
   --root "$R" --hosts "$H" --terminals "$T" --typists 20 --idle-seconds 10 --settle 5 --type-seconds 15 > "$OUT/prof-h$H-t$T.raw" 2> "$OUT/prof-h$H-t$T.err"
echo rc=$?
cp "$R/fixture.log" "$OUT/prof-h$H-t$T.fixture.log" 2>/dev/null
$PERF report -i "$OUT/perf-h$H-t$T.data" --no-children --sort comm,sym --stdio -F overhead,comm,sym 2>/dev/null | head -80 > "$OUT/perf-h$H-t$T.comm-sym.txt"
$PERF report -i "$OUT/perf-h$H-t$T.data" --no-children --sort pid --stdio 2>/dev/null | head -20 > "$OUT/perf-h$H-t$T.pid.txt"
rm -rf "$R"
echo PROFILE_DONE
# The 128-per-host points ride in the same lock slot (reconnect phase skipped: see summary.md).
chown -R claude:claude "$OUT" 2>/dev/null
runuser -u claude -- env HOME=/home/claude NOREATTACH=1 bash matrix.sh D "2:128 3:128"
