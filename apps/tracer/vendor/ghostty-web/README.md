<!-- Role: records the pinned source build and licensing for the tracer renderer. -->
# Vendored ghostty-web source build

The tracer uses the ESM browser artifact built from Coder's `ghostty-web` source,
pinned at upstream `main` commit `835eb2749f640a139693bb64fd67de3c1b50a598`
(2026-11-18; its `package.json` still says 0.4.0). That history contains the #180
fix, `bec9e162b137478fb032d7edf60a2f29a6e5f04b`, which cleared scrolled row cells
in its WASM patch (the core now does this itself): the parent control traps on the
5,679-byte reproducer.
Compared with the earlier pin `5f0c6b7` (0.5.0-rc.0, a release commit not
reachable from `main`), `835eb27` has no library, WASM or build change; the two differ only in
CI and release tooling. The pin moved because `835eb27` is on `main` and cannot
disappear with a deleted release branch.

The Ghostty core is **not** the submodule upstream records (`5714ed07`,
2025-12-01). It is the signed libghostty-vt 1.0.2 release (2026-11-24), the same
source and dependency archives, SHA-256 pins (`scripts/libghostty-vt.sha256`) and
minisign key that the native engine builds from (`scripts/build-vt`), so the server
and the browser run one revision of the terminal engine. `build.sh` downloads both
archives, checks the hashes and signatures, and builds the WebAssembly offline from
the dependency archive (`--system`). The build uses Bun 1.4.4 and Zig 0.17.1 (the
versions the development shell provides); `build.sh` checks these exact versions, and
Git fetches the ghostty-web commit by its immutable SHA.

Upstream's `patches/ghostty-wasm-api.patch` is no longer used. Since 2026-03-13 the
core has an official terminal C API whose names (`ghostty_terminal_*`,
`ghostty_render_state_*`) are the ones that patch added, with another shape and no
bulk read of the viewport; the page needs that bulk read (one call per frame, not one
per cell). `web-engine.zig` is therefore our own file, added to the core as
`src/terminal/c/web.zig` and exported as `ghostty_web_*`: terminal lifecycle,
resize, write, the viewport and scrollback reads, grapheme and hyperlink lookups,
modes, the theme colour setter and the reply queue. It drives the core's own terminal
stream handler, so every state change is the core's; only the four replies the page has
always answered itself (DSR 5 and 6, DA1 and DA2) are produced and queued for
`readResponse`, and every other query stays unanswered, because the server-side engine
answers them and a second answer would reach the program twice (D307; the
`terminal-query-property` test proves it for all 30 corpus forms). `wasm-core.patch`
is the one line that makes the core compile that file into the browser build, and
`web-api-names.patch` renames the TypeScript binding's calls to the `ghostty_web_*`
names. The core's `libghostty-vt` feature switches (`-Dvt-features=-all,+input_encode`)
compile out what the page never calls (snapshots, formatters, selection, search,
render-state objects, colour utilities, grid references, Kitty graphics), which is
250 KB of WebAssembly. Two older core patches are gone because the core now has them:
the cleared rows after a scroll (#180, `Screen.zig`) and zeroed pages in the
freestanding build (#241). The theme API (`ghostty_web_terminal_set_theme_color`)
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
pass. It changes no parser or WASM ABI. The TypeScript patches apply to the `ghostty-web` checkout in the order above, with
`web-api-names.patch` last. The script runs the upstream locked install and its
constituent steps (clean, our offline Zig build, `vite build`, copy of the WASM). It
does not use the upstream aggregate `build` task, because that task invokes a second,
non-frozen `prebuild` install and a `build-wasm.sh` that patches a git submodule.
The temporary checkout and Zig outputs live under
`$HOME/.cache/codex-scratch/fix-cell-metrics/ghostty-builds/` by default, can
be relocated with `GHOSTTY_BUILD_SCRATCH_ROOT`, and are removed on exit.

Rebuild and compare the emitted files with this vendored copy, or pass `--update`
to regenerate the checked-in build outputs and checksum file:

```sh
nix develop -c apps/tracer/vendor/ghostty-web/build.sh --check
nix develop -c apps/tracer/vendor/ghostty-web/build.sh --update
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
license texts are included as `LICENSE` and `GHOSTTY-LICENSE`. Upstream ghostty-web has had no commit since this pin (its `main` is `835eb27`, and its
newest release is v0.4.0). Once an official release carries the crash fix on a core as
new as ours, replace this pin with that release after the same browser regressions pass.
