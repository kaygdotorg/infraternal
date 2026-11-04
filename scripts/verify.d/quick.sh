# `scripts/verify quick`: the few-minute pre-check that runs before the full gate (#329).
#
# It runs what fails most often, cheapest first, and stops at the first failure:
#   1. cargo fmt --check (whole workspace; it needs no compilation)
#   1b. the doc-coverage ratchet (D345): coverage per crate or package never goes down
#   2. cargo clippy (workspace, same flags as the gate) when any Rust package changed against the
#      merge base with origin/dev
#   3. the unit tests (lib and bin targets) of the changed packages, never of a cargo-fuzz package
#      (its bins loop forever, #329) and under a hard timeout that fails loudly instead of hanging
#   4. the tracer typecheck, only when TypeScript changed
# It is NOT the gate. It does not check dependents of a changed crate, integration tests, the
# static release builds, cargo-deny, the architecture checks or the size report. A green quick
# run is never quoted as the gate; `scripts/verify fast` stays the gate (docs/PROCESS.md).
# Sourced by scripts/verify after rust.sh, whose rust_run_gate and summary it reuses.

verify_quick() {
    local base="${VERIFY_QUICK_BASE:-origin/dev}"
    local scope token name
    local -a packages=() cargo_scope=() excludes=() test_prefix=()
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
    rust_run_gate "fmt" cargo fmt --all --check
    if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi

    # Whole-repo and cheap, so it always runs, whatever changed.
    rust_run_gate "doc coverage ratchet" verify_doc_coverage
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
        # the job and a build slot for the length of the hang (#329).
        if command -v timeout >/dev/null; then
            test_prefix=(timeout --kill-after=30 "${VERIFY_QUICK_TEST_TIMEOUT:-1500}")
        fi
        rust_run_gate "unit tests (changed)" ${test_prefix[@]+"${test_prefix[@]}"} cargo test "${cargo_scope[@]}" --lib --bins --locked
        if ((RUST_GATE_FAILED)); then rust_print_summary; return 1; fi
    fi

    if ((tracer)); then
        rust_run_gate "tracer typecheck" bash -c \
            'cd "$1/apps/tracer" && bun install --frozen-lockfile && bun run check' _ "$(cd -- "${script_dir}/.." && pwd)"
    fi
    rust_print_summary
    if ((RUST_GATE_FAILED)); then return 1; fi
    printf '\nQUICK pre-check passed. This is not the gate: run scripts/verify fast before reporting done.\n'
}
