# Bun checks for dependency-free TypeScript packages.

ts_verify_fast() {
    local protocol_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../packages/protocol" && pwd)"

    if ! command -v bun >/dev/null 2>&1; then
        printf 'required TypeScript test tool is missing: bun\n' >&2
        return 1
    fi

    printf '\n==> TypeScript protocol compiler\n'
    (cd -- "$protocol_dir" && bun x --package typescript@5.9.3 tsc --project tsconfig.json) || return $?

    # The Rust/TS differential test runs the Rust stream oracle. Build it first, so
    # the test measures decoding and never times out on a cold compile.
    printf '\n==> Rust stream oracle (for the differential test)\n'
    (cd -- "$protocol_dir/../.." && cargo build --quiet -p infraternal-protocol --example stream_oracle) || return $?

    printf '\n==> TypeScript protocol tests\n'
    (cd -- "$protocol_dir" && bun test --timeout 30000)
}
