<!-- Role: records the pinned source build and licensing for the tracer renderer. -->
# Vendored ghostty-web source build

The tracer uses the ESM browser artifact built from Coder's unreleased
`ghostty-web` 0.5.0-rc.0 source. Pin `5f0c6b7720e5ac241208afe7a2335981ded1b486`
contains the tested #180 fix, `bec9e162b137478fb032d7edf60a2f29a6e5f04b`, which
clears scrolled row cells in the WASM patch. The parent control traps on the
5,679-byte reproducer; this pin passed all seven reproducers and all three full
stress fixtures in Node and Chromium in the `spike-renderer` evidence.

The `ghostty` Git submodule is pinned at
`5714ed07a1012573261b7b7e3ed2add9c1504496`. The build uses Bun 1.4.2 and Zig
0.15.2. These exact versions are checked by `build.sh`; Git fetches both source
commits by their immutable SHAs. `local-theme-api.patch` adds a WASM API that
updates ANSI palette entries and default foreground, background, and cursor
colors in the existing terminal. Cells continue to retain palette indices, and
truecolor cells remain literal RGB values. The API avoids sending synthetic VT
data through the parser or PTY. `cell-metrics.patch` measures cell height from
the font ascent and descent, defaults the line-height factor to 1.0, and rounds
cell dimensions to device pixels. `link-underline.patch` paints temporary link
underlines with the active theme cursor colour while preserving batched text
rendering. `renderer-disposal.patch` removes global mouse handlers during
ordinary disposal and partial-open failure, including disposable sign-in
warm-up. `buffered-writes.patch` adds synchronous ordered input slices backed by one temporary
allocation, with checked bounds, scoped callback lifetime and one paint/effects
pass. It changes no parser or WASM ABI. `zero-pages.patch` edits the Ghostty submodule so the freestanding browser build
zeroes every page it hands out; upstream does so only in safe builds, so
a new or reset terminal showed the previous terminal's rows (#241). The patches apply in that order. The script
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

The checked-in browser ESM embeds the WASM as a data URL. The separate WASM
file and generated declarations are kept as build outputs for checksum and
rebuild verification; the tracer only imports the ESM. `SHA256SUMS` covers the
ESM, separate WASM and declaration file, and `scripts/verify fast` checks it.

Both this project and the embedded Ghostty VT source use MIT. Their original
license texts are included as `LICENSE` and `GHOSTTY-LICENSE`. Once an official
release contains the crash fix, replace this pin with that release after the
same browser regressions pass.
