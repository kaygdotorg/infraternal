#!/bin/bash
# J1204 (#260): static x86_64 musl test binaries of the mesh plugin WITH the agent feature (the packet filter is
# compiled only then), from the baseline tree and the patched tree. Reuses each tree's own target dir.
set -uo pipefail
export TMPDIR=$HOME/.j1204 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
T=x86_64-unknown-linux-musl
out=$HOME/.cache/codex-scratch/j1204/bin
for v in base h1; do
  WT=$HOME/worktrees/j1204-$v
  export CARGO_TARGET_DIR=/mnt/build/targets/j1204-$v
  cd "$WT"
  export PATH=$CARGO_TARGET_DIR/auth-tools/zig:$PATH
  LOCKED=--locked; [ $v = h1 ] && LOCKED=
  nice -n10 scripts/static-cargo test --release -p infraternal-plugin-mesh --features agent --lib --no-run $LOCKED --target $T --message-format=json > $HOME/.j1204/test2-$v.json 2> $HOME/.j1204/test2-$v.err; echo "TB_${v}_EXIT=$?"
  tb=$(python3 -I -c "import json
for l in open('$HOME/.j1204/test2-$v.json'):
    try: m=json.loads(l)
    except Exception: continue
    if m.get('reason')=='compiler-artifact' and m.get('executable') and m['target']['name']=='infraternal_plugin_mesh': print(m['executable'])" | tail -1)
  cp "$tb" $out/mesh-tests-$v
done
ls -l $out; sha256sum $out/mesh-tests-*
$out/mesh-tests-base --list 2>&1 | grep -c hasher_bench
echo TESTS_DONE
