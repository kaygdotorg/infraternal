# Rust checks used by the shared scripts/verify dispatcher.

RUST_GATE_ROWS=()
RUST_GATE_FAILED=0

rust_run_gate() {
    local name="$1"
    shift
    local result

    printf '\n==> %s\n' "$name"
    if "$@"; then
        result="PASS"
    else
        local exit_code=$?
        result="FAIL (${exit_code})"
        RUST_GATE_FAILED=1
    fi
    RUST_GATE_ROWS+=("${name}|${result}")
}

rust_print_summary() {
    local row
    local name
    local result

    printf '\n+---------------------------+--------------+\n'
    printf '| %-25s | %-12s |\n' "Rust gate" "Result"
    printf '+---------------------------+--------------+\n'
    for row in "${RUST_GATE_ROWS[@]}"; do
        IFS='|' read -r name result <<< "$row"
        printf '| %-25s | %-12s |\n' "$name" "$result"
    done
    printf '+---------------------------+--------------+\n'
}

rust_check_static_binary() {
    local target="$1"
    local target_dir="${CARGO_TARGET_DIR:-target}"
    local binary="${target_dir}/${target}/release/infraternal"
    local description
    local size_bytes
    local baseline_size_bytes
    local allowance_bytes=262144
    local max_size_bytes

    if [[ ! -x "$binary" ]]; then
        printf 'expected executable not found: %s\n' "$binary" >&2
        return 1
    fi

    description="$(file -b "$binary")"
    printf '%s: %s\n' "$binary" "$description"
    if ! grep -Eqi 'statically linked|static-pie linked' <<< "$description"; then
        printf 'file did not identify a static executable: %s\n' "$binary" >&2
        return 1
    fi
    if readelf -l "$binary" | grep -q 'INTERP'; then
        printf 'unexpected PT_INTERP in %s\n' "$binary" >&2
        return 1
    fi

    case "$target" in
        x86_64-unknown-linux-musl) baseline_size_bytes=20042272 ;;
        aarch64-unknown-linux-musl) baseline_size_bytes=17862968 ;;
        *)
            printf 'no static binary size baseline configured for target: %s\n' "$target" >&2
            return 1
            ;;
    esac

    max_size_bytes=$((baseline_size_bytes + allowance_bytes))
    size_bytes="$(stat -c '%s' "$binary")"
    printf 'PT_INTERP: absent; size: %s bytes (baseline %s + allowance %s = max %s)\n' \
        "$size_bytes" "$baseline_size_bytes" "$allowance_bytes" "$max_size_bytes"
    if ((size_bytes > max_size_bytes)); then
        printf 'binary exceeds the %s-byte size budget: %s bytes\n' \
            "$max_size_bytes" "$size_bytes" >&2
        return 1
    fi
}

rust_check_cli_stub() {
    local binary="$1"
    local mode="$2"
    local output
    local exit_code=0

    output="$("$binary" "$mode" --json 2>&1)" || exit_code=$?
    if [[ "$exit_code" -ne 2 || "$output" != *'"schema_version": 1'* || "$output" != *'"state": "unavailable"'* ]]; then
        printf 'unexpected %s stub: exit=%s output=%s\n' "$mode" "$exit_code" "$output" >&2
        return 1
    fi

    printf '%s subcommand: exit 2, versioned JSON unavailable result\n' "$mode"
}

# Disabled CLI plugins must leave both their actions and role crates out of the binary.
rust_check_cli_plugin_compile_out() {
    local dependency_tree
    local plugin
    local failed=0
    local plugins=(
        infraternal-agent
        infraternal-mesh
        infraternal-plugin-backup
        infraternal-plugin-host-facts
        infraternal-plugin-mesh
        infraternal-plugin-relay
        infraternal-plugin-ssh
        infraternal-server
        sqlx
        tokio
    )

    dependency_tree="$(cargo tree --locked --package infraternal --no-default-features --edges normal --prefix none)" || return $?
    for plugin in "${plugins[@]}"; do
        if grep -Fq "${plugin} v" <<<"$dependency_tree"; then
            printf 'disabled CLI plugin dependency remains in the build graph: %s\n' "$plugin" >&2
            failed=1
        fi
    done
    if ((failed)); then
        return 1
    fi

    printf 'disabled CLI plugin dependencies: absent from normal dependency graph\n'
    cargo test --locked --package infraternal --bin infraternal --no-default-features
}

rust_static_build_check() {
    local target
    local targets=("x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl")
    local target_dir="${CARGO_TARGET_DIR:-target}"
    local x86_binary="${target_dir}/x86_64-unknown-linux-musl/release/infraternal"

    for tool in cargo file readelf stat; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'required static-build tool is missing: %s\n' "$tool" >&2
            return 1
        fi
    done

    scripts/auth-toolchain || return $?

    for target in "${targets[@]}"; do
        cargo build --locked --release --package infraternal --target "$target" || return $?
        rust_check_static_binary "$target" || return $?
    done

    rust_check_cli_stub "$x86_binary" "server" || return $?
    rust_check_cli_stub "$x86_binary" "agent"
}

rust_verify_fast() {
    RUST_GATE_ROWS=()
    RUST_GATE_FAILED=0

    rust_run_gate "fmt" cargo fmt --all --check
    rust_run_gate "VT native fmt" zig fmt --check crates/infraternal-shim/native/snapshot.zig
    rust_run_gate "CLI plugin compile-out" rust_check_cli_plugin_compile_out
    rust_run_gate "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
    rust_run_gate "test" cargo test --workspace --locked
    rust_run_gate "cargo-deny" cargo deny check
    rust_run_gate "static builds" rust_static_build_check
    rust_print_summary

    return "$RUST_GATE_FAILED"
}
