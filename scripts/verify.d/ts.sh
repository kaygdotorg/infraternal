# Bun checks for the protocol and production tracer, including its compressed transfer budget.

ts_verify_fast() {
    local protocol_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../packages/protocol" && pwd)"
    local repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

    if ! command -v bun >/dev/null 2>&1; then
        printf 'required TypeScript test tool is missing: bun\n' >&2
        return 1
    fi

    printf '\n==> Compiler metadata generator checks\n'
    (cd -- "$repo_dir" && bun test scripts/release/build-metadata.test.ts) || return $?

    printf '\n==> Private server fixture startup cleanup\n'
    (cd -- "$repo_dir" && bun test apps/tracer/real/server-startup.test.ts) || return $?

    printf '\n==> Vendored Ghostty artifact checksums\n'
    (cd -- "$repo_dir/apps/tracer/vendor/ghostty-web" && sha256sum --check SHA256SUMS) || return $?

    printf '\n==> TypeScript protocol compiler\n'
    (cd -- "$protocol_dir" && bun x --package typescript@7.0.2 tsc --project tsconfig.json) || return $?

    # Resolve connection suite filenames in the shell: Bun's combined substring
    # filters omitted them despite a green frontend row (#244). A separate run
    # also isolates their browser globals from the canvas fixture globals.
    printf '\n==> Tracer compiler, precompression and bundle transfer budget\n'
    (cd -- "$repo_dir/apps/tracer" && bun install --frozen-lockfile && bun run check && bun test precompress.test.ts browser-build.test.ts docs-build.test.ts src/perf-detector.test.ts src/stale-screen.test.ts src/synchronized-output.test.ts src/terminal-fit-lifecycle.test.ts src/account-storage.test.ts src/hints.test.ts test/layout-coalescing-review.test.ts test/layout-identity-review.test.ts real/attachment-bookkeeping.test.ts real/restart-namespace.test.ts src/offline-drawing.test.ts src/session-notifications.test.ts src/sign-out.test.ts src/canvas ../../packages/ui/src/spring.test.ts ../../packages/ui/src/theme-audit.test.ts test/no-overshoot.test.ts test/motion-speed.test.ts chunk-classes.test.ts test/recovery-ui.test.ts test/recovery-crypto.test.ts test/recovery-rotation.test.ts test/add-passkey.test.ts test/recovery-wait.test.ts test/link-doubt.test.ts test/close-reasons.test.ts src/close-reasons.test.ts src/review-close-log.test.ts src/onboarding-load.test.ts src/approval-link.test.ts src/join-review.test.ts src/key-lifetime.test.ts && bun test ./src/connection*.test.ts && bun test ./src/terminal-queries.test.ts ./src/terminal-query*.test.ts ./src/terminal-write-slices.test.ts && bun run build && bun run transfer-budget.ts) || return $?

    # The Rust/TS differential test runs the Rust stream oracle. Build it first, so
    # the test measures decoding and never times out on a cold compile.
    printf '\n==> Rust stream oracle (for the differential test)\n'
    (cd -- "$protocol_dir/../.." && cargo build --quiet -p infraternal-protocol --features desktop --example stream_oracle) || return $?

    printf '\n==> TypeScript protocol tests\n'
    (cd -- "$protocol_dir" && bun test --timeout 30000)
}
