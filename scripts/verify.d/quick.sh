# `scripts/verify quick`: the few-minute pre-check that runs before the full gate (#329).
#
# It runs what fails most often, cheapest first, and stops at the first failure:
#   0. migration names (D347), Nix Cargo vendoring, and the pinned native terminal source recipe
#   1. cargo fmt --check (whole workspace; it needs no compilation)
#   1b. the doc-coverage ratchet (D345): coverage per crate or package never goes down
#   2. cargo clippy (workspace, same flags as the gate) when any Rust package changed against the
#      merge base with origin/dev
#   3. the unit tests (lib and bin targets) of the changed packages, never of a cargo-fuzz package
#      (its bins loop forever, #329) and under a hard timeout that fails loudly instead of hanging
#   4. the tracer typecheck and D365 theme contrast audit, only when TypeScript changed; before them,
#      "ui literals" (ui-literals.py): the change must not add pixel font sizes, pixel corner radii or pasted easing curves (#345)
# It is NOT the gate. It does not check dependents of a changed crate, integration tests, the
# static release builds, cargo-deny, the architecture checks or the size report. A green quick
# run is never quoted as the gate; `scripts/verify fast` stays the gate (docs/PROCESS.md).
# Sourced by scripts/verify after rust.sh, whose rust_run_gate and summary it reuses.

# Runs `cargo test <args>` under the quick pre-check's hang bound (rust.sh).
quick_cargo_test() {
    rust_bounded_cargo_test "${VERIFY_QUICK_TEST_TIMEOUT:-1500}" "$@"
}

# Prints the comma-separated `package/feature` list that `verify fast` gives the named packages (#581).
# `fast` runs `cargo test --workspace`, so each package is built with the features the whole workspace
# unifies onto it. Running `-p <pkg>` alone drops the ones that only a dependent asks for: infraternal
# turns on infraternal-server's `remote`, which compiles auth/admin_window_tests.rs, so the row failed
# (E0433) on unmodified dev (J1162). `cargo metadata` resolves that same unification, so each workspace
# member's node features are the set to pass. The qualified form lets one cargo call select several
# packages. `default` is left out: a selected package always gets its default features.
# Prints nothing when no named package has a feature.
quick_features_for() {
    if (($# == 0)); then return 0; fi
    cargo metadata --format-version 1 --locked | python3 -c '
import json, sys
names = set(sys.argv[1:])
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
by_id = {p["id"]: p["name"] for p in meta["packages"] if p["id"] in members}
flags = []
for node in meta["resolve"]["nodes"]:
    name = by_id.get(node["id"])
    if name in names:
        flags += [f"{name}/{feature}" for feature in sorted(node["features"]) if feature != "default"]
print(",".join(sorted(flags)))
' "$@"
}

# Run the inexpensive pre-check rows, stopping before compilation on a policy failure.
verify_quick() {
    local base="${VERIFY_QUICK_BASE:-origin/dev}"
    local scope token name
    local -a packages=() cargo_scope=() excludes=()
    local tracer=0 whole=0 fuzz=0

    if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
        printf 'verify quick: base ref %s not found; run `git fetch origin` or set VERIFY_QUICK_BASE\n' "$base" >&2
        return 1
    fi
    scope="$(python3 "${script_dir}/verify.d/changed-scope.py" "$base")" || return $?
    while read -r token name; do
        case "$token" in
            workspace) whole=1 ;;
            package) packages+=("$name") ;;
            tracer) tracer=1 ;;
            fuzz) fuzz=1 ;;
            exclude) excludes+=(--exclude "$name") ;;
        esac
    done <<< "$scope"

    RUST_GATE_ROWS=()
    RUST_GATE_FAILED=0
    printf 'quick scope vs merge base with %s: workspace=%s packages=[%s] tracer=%s\n' \
        "$base" "$whole" "${packages[*]}" "$tracer"

    rust_run_gate "scope guard" python3 "${script_dir}/test-verify-quick-scope.py"
    rust_run_gate "migration names" python3 "${script_dir}/verify.d/migration-names.py"
    if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
    rust_run_gate "Nix Cargo vendoring" scripts/check-nix-vendor
    rust_run_gate "VT source recipe" python3 scripts/test-build-vt-pinned.py
    if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
    rust_run_gate "fmt" cargo fmt --all --check
    if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi

    # Whole-repo and cheap, so it always runs, whatever changed.
    rust_run_gate "doc coverage ratchet" verify_doc_coverage
    rust_run_gate "shape lints off (D351)" python3 scripts/test-shape-lints.py
    rust_run_gate "doc comments on diff" verify_diff_docs
    rust_run_gate "fixed test waits" python3 scripts/verify.d/diff-practices.py sleeps "${VERIFY_QUICK_BASE:-origin/dev}"
    if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi

    if ((whole)); then
        cargo_scope=(--workspace "${excludes[@]}")
    else
        for name in "${packages[@]}"; do cargo_scope+=(-p "$name"); done
    fi
    if ((${#cargo_scope[@]} || fuzz)); then
        # Clippy always runs for the whole workspace, never `-p <changed>`: Cargo unifies features over
        # the selected packages only, and a narrower set makes feature-dependent lints fire in
        # untouched crates (infraternal-shim's unnecessary_wraps, measured on #329) that the gate,
        # with the workspace's features, never reports. Same flags as the gate, so the gate reuses
        # these check artifacts in a shared target. Only the test run is limited to the changed packages.
        rust_run_gate "clippy (workspace)" cargo clippy --workspace --all-targets --locked -- -D warnings
        if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
    fi
    if ((${#cargo_scope[@]})); then
        # --lib --bins: unit tests only. Integration tests and doc tests belong to the full gate.
        # The timeout is a backstop: a test binary that never ends must fail the row (124), not hang
        # the job and a build slot for the length of the hang (#329). quick_cargo_test starts it
        # after the build, so a cold compile never counts against it (#509).
        if ((whole)); then
            rust_run_gate "unit tests (changed)" quick_cargo_test "${cargo_scope[@]}" --lib --bins --locked
        else
            # `--lib` makes Cargo refuse a package that has no library (the `infraternal` CLI is
            # bin-only), so bin-only packages are tested with `--bins` alone, in their own run.
            local -a lib_scope=() bin_scope=() lib_names=() bin_names=()
            local bin_only lib_features bin_features
            bin_only="$(cargo metadata --no-deps --format-version 1 --locked | python3 -c '
import json, sys
meta = json.load(sys.stdin)
for pkg in meta["packages"]:
    if not any("lib" in t["kind"] or "rlib" in t["kind"] or "proc-macro" in t["kind"] for t in pkg["targets"]):
        print(pkg["name"])
')" || return $?
            for name in "${packages[@]}"; do
                if grep -qxF "$name" <<< "$bin_only"; then bin_scope+=(-p "$name"); bin_names+=("$name")
                else lib_scope+=(-p "$name"); lib_names+=("$name"); fi
            done
            if ((${#lib_scope[@]})); then
                lib_features="$(quick_features_for "${lib_names[@]}")" || return $?
                local -a lib_feature_args=()
                [[ -n "$lib_features" ]] && lib_feature_args=(--features "$lib_features")
                rust_run_gate "unit tests (changed)" quick_cargo_test "${lib_scope[@]}" "${lib_feature_args[@]}" --lib --bins --locked
                if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
            fi
            if ((${#bin_scope[@]})); then
                bin_features="$(quick_features_for "${bin_names[@]}")" || return $?
                local -a bin_feature_args=()
                [[ -n "$bin_features" ]] && bin_feature_args=(--features "$bin_features")
                rust_run_gate "unit tests (changed, bin-only)" quick_cargo_test "${bin_scope[@]}" "${bin_feature_args[@]}" --bins --locked
            fi
        fi
        if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
    fi

    if ((tracer)); then
        # Under a second: counts only the files this change touches (see ui-literals.py), so it runs before the slow typecheck.
        rust_run_gate "ui literals" python3 "${script_dir}/verify.d/ui-literals.py" "$base"
        if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
        rust_run_gate "tracer typecheck" bash -c \
            'cd "$1/apps/tracer" && bun install --frozen-lockfile && bun run check' _ "$(cd -- "${script_dir}/.." && pwd)"
        if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
        # D365 makes every text token meet 4.5:1 in each theme, so run the same audit from the pre-check whenever tracer changes.
        rust_run_gate "D365 theme contrast audit" bash -c \
            'cd "$1/apps/tracer" && bun test ../../packages/ui/src/theme-audit.test.ts' _ "$(cd -- "${script_dir}/.." && pwd)"
    fi
    rust_print_summary
    if ((RUST_GATE_FAILED)); then return 1; fi
    printf '\nQUICK pre-check passed. This is not the gate: run scripts/verify fast before reporting done.\n'
}
