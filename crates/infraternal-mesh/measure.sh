#!/usr/bin/env bash
# Reproduce mesh CPU/wall/RSS scale evidence in a weighted scope, with fresh processes per shape.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/codex-scratch/mesh-core/target}"
measure_root="${MESH_MEASURE_ROOT:-$HOME/.cache/codex-scratch/mesh-core/measurements}"
export MESH_MEASURE_ROOT="$measure_root"
if [[ "${1:-}" != --scoped ]]; then
    cargo build --locked --release -p infraternal-mesh --example measure
    exec systemd-run --user --scope -p CPUWeight=10000 "$0" --scoped
fi
mkdir -p "$measure_root"
report_environment() {
    printf 'ENVIRONMENT utc=%s machine=%s cpu=%s cores=%s load=%s weight=10000\n' \
        "$(date -u +%FT%TZ)" "$(uname -n)" \
        "$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)" \
        "$(getconf _NPROCESSORS_ONLN)" "$(cut -d' ' -f1-3 /proc/loadavg)"
}
measure="$CARGO_TARGET_DIR/release/examples/measure"
for nodes in 100 1000 10000; do
    for arrows in 1 5 20; do
        { report_environment; "$measure" compile "$nodes" "$arrows"; } > "$measure_root/compile-$nodes-$arrows.log"
        cat "$measure_root/compile-$nodes-$arrows.log"
    done
done
for mode in incremental view; do
    { report_environment; "$measure" "$mode" 10000 20; } > "$measure_root/$mode-10000-20.log"
    cat "$measure_root/$mode-10000-20.log"
done
