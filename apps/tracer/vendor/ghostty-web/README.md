<!-- Role: records the pinned source build and licensing for the tracer renderer. -->
# Vendored ghostty-web source build

The tracer uses the ESM browser artifact built from Coder's `ghostty-web` source,
pinned at upstream `main` commit `835eb2749f640a139693bb64fd67de3c1b50a598`
(2026-11-18; its `package.json` still says 0.4.0). That history contains the #180
fix, `bec9e162b137478fb032d7edf60a2f29a6e5f04b`, which clears scrolled row cells
in the WASM patch: the parent control traps on the 5,679-byte reproducer.
Compared with the earlier pin `5f0c6b7` (0.5.0-rc.0, a release commit not
reachable from `main`), `835eb27` has no library, WASM or build change; the two differ only in
CI and release tooling. The pin moved because `835eb27` is on `main` and cannot
disappear with a deleted release branch.

The Ghostty core is **not** the submodule upstream records (`5714ed07`,
2025-12-01). It is `e75f8956c576ea8acf6ee4e70d45f918738e7512` (2026-03-13), the
newest core that upstream's WASM API still fits: the same day Ghostty added a
terminal C API of its own (`ghostty_terminal_new` and friends) that collides with
the one `ghostty-web` patches in, and Ghostty 1.4 needs Zig 0.17. `build.sh` fetches
the core by that SHA. The build uses Bun 1.4.2 and Zig 0.15.2; `build.sh` checks
these exact versions, and Git fetches both source commits by their immutable SHAs.
`wasm-api.patch` is upstream's `patches/ghostty-wasm-api.patch` rebased onto that
core, with our theme API folded in (it used to be a separate patch of the patch):
the stream handler follows the core's new `vt()` contract (no error return) and
`semantic_prompt` action, `Screen.zig`'s #180 hunk follows the cursor-pin rework,
the stream keeps the Zig layout of its actions (the core's C layout does not compile
yet), and upstream's `.gitignore` hunk is dropped. The theme API (`ghostty_terminal_set_theme_color`)
updates ANSI palette entries and default foreground, background, and cursor
colors in the existing terminal. Cells continue to retain palette indices, and
truecolor cells remain literal RGB values. The API avoids sending synthetic VT
data through the parser or PTY. `local-theme-api.patch` is its TypeScript side.
`cell-metrics.patch` measures cell height from
the font ascent and descent, defaults the line-height factor to 1.0, and rounds
cell dimensions to device pixels. `link-underline.patch` paints temporary link
underlines with the active theme cursor colour while preserving batched text
rendering. `renderer-disposal.patch` removes global mouse handlers during
ordinary disposal and partial-open failure, including disposable sign-in
warm-up. `buffered-writes.patch` adds synchronous ordered input slices backed by one temporary
allocation, with checked bounds, scoped callback lifetime and one paint/effects
pass. It changes no parser or WASM ABI. `zero-pages.patch` edits the Ghostty core so the freestanding browser build
zeroes every page it hands out; upstream does so only in safe builds, so
a new or reset terminal showed the previous terminal's rows (#241). `wasm-api.patch` replaces the file upstream's `build-wasm.sh` applies; the TypeScript patches
apply to the `ghostty-web` checkout in the order above and `zero-pages.patch` to the core. The script
runs the upstream locked install and its four constituent build steps. It does
not use the upstream aggregate `build` task because that task invokes a second,
non-frozen `prebuild` install.
The temporary checkout and Zig outputs live under
`$HOME/.cache/codex-scratch/fix-cell-metrics/ghostty-builds/` by default, can
be relocated with `GHOSTTY_BUILD_SCRATCH_ROOT`, and are removed on exit.

Rebuild and compare the emitted files with this vendored copy, or pass `--update`
to regenerate the checked-in build outputs and checksum file:

```sh
nix shell nixpkgs#zig_0_15 -c apps/tracer/vendor/ghostty-web/build.sh --check
apps/tracer/vendor/ghostty-web/build.sh --update
```

The checked-in browser ESM embeds the WASM as a data URL, and the separate WASM
file is kept next to it. The tracer's production build (#573) does not ship that
copy: `apps/tracer/browser-build.ts` cuts the base64 out of the ESM while
bundling, and `apps/tracer/src/engine-wasm.ts` imports `dist/ghostty-vt.wasm`
itself, so the bundler emits it as `ghostty-vt-<hash>.wasm`. The browser fetches
that file (served as `application/wasm`, cached as immutable, preloaded for a
signed-in device) and compiles it with `WebAssembly.instantiateStreaming`. The
engine is then passed to every `Terminal` as its `ghostty` option, so the
artifact's own `init()` is not used by the app. The pinned files are unchanged
by this: `SHA256SUMS` still covers the ESM, the WASM and the declaration file
exactly as `build.sh` produced them, and `scripts/verify fast` checks it. A
re-pinned ESM must still contain the data URL, or the production build stops
with a message saying so.

Both this project and the embedded Ghostty VT source use MIT. Their original
license texts are included as `LICENSE` and `GHOSTTY-LICENSE`. Once an official
release contains the crash fix and a Ghostty core newer than 2026-03-13, replace this
pin with that release after the same browser regressions pass.
