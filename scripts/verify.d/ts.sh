# Bun checks for dependency-free TypeScript packages.

ts_verify_fast() {
    local protocol_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../packages/protocol" && pwd)"

    if ! command -v bun >/dev/null 2>&1; then
        printf 'required TypeScript test tool is missing: bun\n' >&2
        return 1
    fi

    printf '\n==> TypeScript protocol compiler\n'
    (cd -- "$protocol_dir" && bun x --package typescript@5.9.3 tsc --project tsconfig.json) || return $?

    printf '\n==> TypeScript protocol tests\n'
    (cd -- "$protocol_dir" && bun test)
}
