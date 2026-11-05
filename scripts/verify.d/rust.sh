# Rust checks used by the shared scripts/verify dispatcher.

RUST_GATE_ROWS=()
RUST_GATE_FAILED=0

rust_run_gate() {
    local name="$1"
    shift
    local result
    local started=$SECONDS

    printf '\n==> %s\n' "$name"
    if "$@"; then
        result="PASS"
    else
        local exit_code=$?
        result="FAIL (${exit_code})"
        RUST_GATE_FAILED=1
    fi
    RUST_GATE_ROWS+=("${name}|${result}")
    printf '(%s: %ss)\n' "$name" "$((SECONDS - started))"
}

# Doc-comment coverage may never go down (D345): scripts/doc-coverage compares every unit with
# scripts/doc-coverage-baseline.json. The fixture test comes first so a broken scanner cannot
# pass the ratchet by miscounting. Pure python, a few seconds, shared by `quick` and `fast`.
verify_doc_coverage() {
    python3 scripts/test-doc-coverage.py && python3 scripts/doc-coverage --check
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
    local delta_bytes
    local baseline_bytes
    local expected_machine
    local elf_header
    local program_headers

    if [[ ! -x "$binary" ]]; then
        printf 'expected executable not found: %s\n' "$binary" >&2
        return 1
    fi

    python3 scripts/release/check-production-trust.py "$binary" || return $?

    description="$(file -b "$binary")"
    printf '%s: %s\n' "$binary" "$description"
    if ! grep -Eqi 'statically linked|static-pie linked' <<< "$description"; then
        printf 'file did not identify a static executable: %s\n' "$binary" >&2
        return 1
    fi
    program_headers="$(readelf -l "$binary")" || return $?
    if grep -q 'INTERP' <<< "$program_headers"; then
        printf 'unexpected PT_INTERP in %s\n' "$binary" >&2
        return 1
    fi

    # Keep the last merged measurements for per-slice attribution, not approval.
    case "$target" in
        x86_64-unknown-linux-musl)
            baseline_bytes=22418256
            expected_machine='Advanced Micro Devices X86-64'
            ;;
        aarch64-unknown-linux-musl)
            baseline_bytes=20453280
            expected_machine='AArch64'
            ;;
        *)
            printf 'no static binary size baseline configured for target: %s\n' "$target" >&2
            return 1
            ;;
    esac

    elf_header="$(LC_ALL=C readelf -h "$binary")" || return $?
    if ! grep -Eq "Class:[[:space:]]+ELF64$" <<< "$elf_header" ||
        ! grep -Eq "Machine:[[:space:]]+${expected_machine}$" <<< "$elf_header"; then
        printf 'wrong ELF target: expected %s in %s\n' "$target" "$binary" >&2
        return 1
    fi

    size_bytes="$(stat -c '%s' "$binary")" || return $?
    delta_bytes=$((size_bytes - baseline_bytes))
    printf 'PT_INTERP: absent; size: %s bytes; baseline %s; delta %+d bytes (report only, D243 amended 2026-11-01)\n' \
        "$size_bytes" "$baseline_bytes" "$delta_bytes"
}

rust_check_cli_stub() {
    local binary="$1"
    local mode="$2"
    local output
    local exit_code=0

    output="$("$binary" "$mode" --json 2>&1)" || exit_code=$?
    # The envelope is one compact line per result (D299).
    if [[ "$exit_code" -ne 2 || "$output" != *'"schema_version":1'* || "$output" != *'"state":"unavailable"'* ]]; then
        printf 'unexpected %s stub: exit=%s output=%s\n' "$mode" "$exit_code" "$output" >&2
        return 1
    fi

    printf '%s subcommand: exit 2, versioned JSON unavailable result\n' "$mode"
}

# A group typed alone lists its commands in one envelope and exits 0 (#239): `agent` does too.
rust_check_cli_group() {
    local binary="$1"
    local group="$2"
    local output
    local stderr_file
    local stderr_present=no
    local exit_code=0

    stderr_file="$(mktemp)" || return 1
    output="$("$binary" "$group" --json 2>"$stderr_file")" || exit_code=$?
    [[ ! -s "$stderr_file" ]] || stderr_present=yes
    rm -f "$stderr_file"
    if [[ "$exit_code" -ne 0 || "$stderr_present" != no ]] || ! python3 -c '
import json
import sys

lines = sys.stdin.read().splitlines()
if len(lines) != 1:
    raise SystemExit(1)
result = json.loads(lines[0])
if result.get("schema_version") != 1:
    raise SystemExit(1)
expected = f"{sys.argv[1]} join"
commands = result.get("data", {}).get("commands", [])
if not any(isinstance(command, dict) and command.get("command") == expected for command in commands):
    raise SystemExit(1)
' "$group" <<<"$output" 2>/dev/null; then
        printf 'unexpected %s group: exit=%s, expected one versioned JSON envelope; stderr_present=%s\n' \
            "$group" "$exit_code" "$stderr_present" >&2
        return 1
    fi

    printf '%s group: exit 0, one parsed versioned JSON listing of its commands\n' "$group"
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
        infraternal-plugin-canvas
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
    # Every run counts: a failure in an early run must fail the row, not be hidden by
    # a later run that passes. All three still run, so one log shows every failure.
    cargo test --locked --package infraternal --bin infraternal --no-default-features || failed=1
    # The hidden commands of unbuilt components are compiled out of default builds (D243);
    # the one-source tests for them (D16) run in the build that keeps them (D299 C5).
    cargo test --locked --package infraternal --bin infraternal --features placeholders || failed=1
    cargo test --locked --package infraternal-agent --package infraternal-mesh \
        --package infraternal-plugin-backup --package infraternal-plugin-relay \
        --package infraternal-plugin-ssh --lib --features infraternal-plugin-api/placeholders cli || failed=1
    return "$failed"
}

# D244/#154 checks the shipping provider, never a GNU test executable or C probe.
rust_check_static_key_memory() {
    local target="$1"
    local binary="$2"
    local host="$(uname -m)"

    case "$host:$target" in
        x86_64:x86_64-unknown-linux-musl|aarch64:aarch64-unknown-linux-musl) ;;
        *)
            # Kernel page protection must be checked on the native architecture;
            # an emulator's successful syscall result is not kernel evidence.
            printf 'SKIP key memory: %s (host %s; native execution required)\n' "$target" "$host"
            return 0
            ;;
    esac

    printf 'key memory: %s; memlock=8388608 bytes\n' "$target"
    # The hidden diagnostic succeeds only for initialization=1 (locking and
    # dump exclusion), regardless of the invoking user's development policy.
    prlimit --memlock=8388608 -- "$binary" __key-memory-check
}

rust_static_build_check() {
    local target
    local targets=("x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl")
    local target_dir="${CARGO_TARGET_DIR:-target}"
    local native_binary
    case "$(uname -m)" in
        x86_64) native_binary="${target_dir}/x86_64-unknown-linux-musl/release/infraternal" ;;
        aarch64) native_binary="${target_dir}/aarch64-unknown-linux-musl/release/infraternal" ;;
        *) printf 'unsupported static build host: %s\n' "$(uname -m)" >&2; return 1 ;;
    esac
    local failed=0

    for tool in cargo file readelf stat prlimit python3 bun; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'required static-build tool is missing: %s\n' "$tool" >&2
            return 1
        fi
    done

    scripts/auth-toolchain || return $?
    scripts/test-auth-toolchain-pin || return $?
    python3 scripts/test-musl-cc.py || return $?
    python3 scripts/test-native-metadata.py || return $?
    python3 scripts/test-rustc-paths.py || return $?
    python3 scripts/test-path-remap-flags.py || return $?
    python3 scripts/release/production_trust_test.py || return $?

    for target in "${targets[@]}"; do
        scripts/static-cargo build --locked --release --package infraternal --target "$target" || return $?
        if [[ "$target" == x86_64-unknown-linux-musl ]]; then
            if [[ "$(uname -m)" == x86_64 ]]; then
                CARGO_TARGET_DIR="$target_dir" python3 scripts/test-openssl-avx512-gcm.py || return $?
            else
                printf 'SKIP x86 AES-GCM runtime vector: host %s; native x86_64 execution required\n' "$(uname -m)"
            fi
        fi
        # Keep every artifact defect, but still exercise both shipping providers.
        rust_check_static_binary "$target" || failed=1
        rust_check_static_key_memory "$target" "${target_dir}/${target}/release/infraternal" || failed=1
    done

    CARGO_TARGET_DIR="$target_dir" python3 scripts/test-static-size.py || failed=1
    # Inspect both freshly built images; iterate never qualifies stale artifacts.
    CARGO_TARGET_DIR="$target_dir" bun test scripts/release/static-metadata-review.test.ts || failed=1
    rust_check_cli_stub "$native_binary" "server" || failed=1
    rust_check_cli_group "$native_binary" "agent" || failed=1
    return "$failed"
}

# Runs the Rust gate. Mode "final" (scripts/verify fast) is the full gate. Mode
# "iterate" (scripts/verify iterate) runs every check except the static
# release builds and what only they can check (linkage, D244 key heap, D243
# size), which dominate the time and are rechecked by the final mode.
rust_verify_fast() {
    local mode="${1:-final}"

    RUST_GATE_ROWS=()
    RUST_GATE_FAILED=0

    rust_run_gate "fmt" cargo fmt --all --check
    rust_run_gate "migration names" python3 scripts/verify.d/migration-names.py
    rust_run_gate "migration tooling tests" python3 scripts/test-migration-names.py
    rust_run_gate "VT native fmt" zig fmt --check crates/infraternal-shim/native/*.zig
    rust_run_gate "CLI plugin compile-out" rust_check_cli_plugin_compile_out
    rust_run_gate "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
    rust_run_gate "SSH runtime test helper" cargo build --locked -p infraternal-plugin-ssh --example recovery-helper
    rust_run_gate "real-binary fixture paths" python3 scripts/test-agent-fixture.py
    rust_run_gate "Traefik component manifest" python3 -m unittest discover -s scripts/release -p traefik_component_test.py
    rust_run_gate "release component publication" python3 scripts/release/test.py
    rust_run_gate "test" cargo test --workspace --locked
    rust_run_gate "SSH inode reuse fixture" scripts/test-ssh-inode-reuse
    # The shared host (#205) patches the native engine and its allocator;
    # the workspace run builds neither. Its shim lib tests are the gate.
    rust_run_gate "shim process-per-user" cargo test --locked --package infraternal-shim --features process-per-user --lib
    rust_run_gate "cargo-deny" cargo deny check
    rust_run_gate "gate architecture" python3 scripts/test-verify-architecture.py
    rust_run_gate "doc coverage ratchet" verify_doc_coverage
    if [[ "$mode" == final ]]; then
        rust_run_gate "static builds" rust_static_build_check
    fi
    rust_print_summary

    return "$RUST_GATE_FAILED"
}
