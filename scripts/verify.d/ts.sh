# Bun checks for the protocol and production tracer, including its compressed transfer budget.

ts_verify_fast() {
    local protocol_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../packages/protocol" && pwd)"
    local repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

    if ! command -v bun >/dev/null 2>&1; then
        printf 'required TypeScript test tool is missing: bun\n' >&2
        return 1
    fi

    printf '\n==> Vendored Ghostty artifact checksums\n'
    (cd -- "$repo_dir/apps/tracer/vendor/ghostty-web" && sha256sum --check SHA256SUMS) || return $?

    printf '\n==> TypeScript protocol compiler\n'
    (cd -- "$protocol_dir" && bun x --package typescript@5.9.3 tsc --project tsconfig.json) || return $?

    printf '\n==> Tracer compiler, precompression and bundle transfer budget\n'
    (cd -- "$repo_dir/apps/tracer" && bun install --frozen-lockfile && bun run check && bun test precompress.test.ts browser-build.test.ts && bun run build && bun run transfer-budget.ts) || return $?

    # The Rust/TS differential test runs the Rust stream oracle. Build it first, so
    # the test measures decoding and never times out on a cold compile.
    printf '\n==> Rust stream oracle (for the differential test)\n'
    (cd -- "$protocol_dir/../.." && cargo build --quiet -p infraternal-protocol --example stream_oracle) || return $?

    printf '\n==> TypeScript protocol tests\n'
    (cd -- "$protocol_dir" && bun test --timeout 30000)
}
