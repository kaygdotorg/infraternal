#!/bin/bash
# J1204 (#260): static x86_64 musl builds of the product (infraternal + coordinator_fixture) from two trees:
#   base = origin/dev be2641544 as is, h1 = the same plus the throwaway foldhash patch (research/gotatun-hasher/patches).
# One build-slot run, each tree with its own target dir (one target per source tree, #542).
set -uo pipefail
mkdir -m 700 -p "$HOME/.j1204"
export TMPDIR=$HOME/.j1204 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
T=x86_64-unknown-linux-musl
out=$HOME/.cache/codex-scratch/j1204/bin; mkdir -p "$out"
for v in base h1; do
  WT=$HOME/worktrees/j1204-$v; LOCKED=--locked; [ $v = h1 ] && LOCKED=
  export CARGO_TARGET_DIR=/mnt/build/targets/j1204-$v
  cd "$WT"
  scripts/auth-toolchain > /dev/null || { echo AUTH_TOOLCHAIN_FAIL; exit 1; }
  export PATH=$CARGO_TARGET_DIR/auth-tools/zig:$PATH
  nice -n10 scripts/static-cargo build -j6 $LOCKED --release --package infraternal --target $T; echo "IX_${v}_EXIT=$?"
  nice -n10 scripts/static-cargo build -j6 $LOCKED --release -p infraternal-plugin-mesh --example coordinator_fixture --target $T; echo "CF_${v}_EXIT=$?"
  # The timing test (patches/hbench-test.rs) as a static test binary for the perf VMs.
  nice -n10 scripts/static-cargo test --release -p infraternal-plugin-mesh --lib --no-run $LOCKED --target $T --message-format=json > $HOME/.j1204/test-$v.json 2> $HOME/.j1204/test-$v.err; echo "TB_${v}_EXIT=$?"
  tb=$(python3 -I -c "import json,sys
for l in open('$HOME/.j1204/test-$v.json'):
    try: m=json.loads(l)
    except Exception: continue
    if m.get('reason')=='compiler-artifact' and m.get('executable') and m['target']['name']=='infraternal_plugin_mesh': print(m['executable'])" | tail -1)
  cp "$tb" $out/mesh-tests-$v
  cp $CARGO_TARGET_DIR/$T/release/infraternal $out/infraternal-$v
  cp $CARGO_TARGET_DIR/$T/release/examples/coordinator_fixture $out/coordinator_fixture-$v
  rm -rf "$CARGO_TARGET_DIR/$T/release/incremental"
done
cd "$out" && sha256sum * && ls -l * && file *
echo BUILD_DONE
