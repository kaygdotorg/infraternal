# Third-party notices and provenance

The package includes the following third-party material. The full license text
is kept beside each asset; retain those files when copying or rebuilding the
package.

## Bklit chart primitives

- License: MIT.
- Copyright notice: `charts/src/vendor/BKLIT-MIT-LICENSE.txt` and
  `web/bklit-LICENSE.txt`.
- Source snapshot: `charts/src/vendor/bklit/`.
- Generated adapter source: `charts/src/bklit-charts.tsx` and
  `charts/src/bklit-charts.css`.
- Generated browser bundle: `web/bklit-charts.js`.
- Upstream project: <https://github.com/bklit/bklit-ui>. The checked-in source
  snapshot does not include a version or commit identifier; do not invent one
  for a release.
- SHA-256, calculated over the checked-in bytes at this snapshot:

  ```text
  vendor tree (path + bytes, sorted):
  304e71c799128a32884812a10240fd307ae879f247d8fee78efcf19a33ccd724
  charts/src/bklit-charts.tsx:
  c539cf5ffc9fc63676885a7761d72bc8754a7adeb924cc80c81de02f2bbb6ab5
  web/bklit-charts.js:
  12c8db2dbe4ca0e59a35a8614f185c463fb074ef6bd12c16f97c71ef5daf31a7
  ```

## Torph

- License: MIT.
- Copyright notice: `web/torph-LICENSE.txt`.
- Shipped artifact: `web/torph.js`.
- Upstream project: <https://github.com/lochie/torph>. This release carries the
  minified browser artifact; the local snapshot does not record a version or
  commit, so verify those details before publication if a source offer is
  required.
- SHA-256 of `web/torph.js`:

  ```text
  6a5bb136d7d3572af6dda3089f44642a5c5453a620ddd1cf5fa26f33c8517db8
  ```

## Fonts

The interface uses only these self-hosted fonts. Each has an OFL 1.1 notice in
`web/fonts/`.

- Alan Sans, `web/fonts/AlanSans-Variable.woff2`, project source:
  <https://github.com/alan-eu/Alan-Sans>. Copyright notice and full license:
  `web/fonts/alan-sans-OFL.txt`.
- Space Mono, `web/fonts/SpaceMono-Regular.woff2` and
  `web/fonts/SpaceMono-Bold.woff2`, project source:
  <https://github.com/googlefonts/spacemono>. Copyright notice and full
  license: `web/fonts/space-mono-OFL.txt`.

SHA-256 of the checked-in font files:

```text
AlanSans-Variable.woff2  e928f269f2eaf13dde2014f7465e6ce4c141958f77b0b19bd691aa8b8b152b34
SpaceMono-Regular.woff2  e0c8e616bda27642f4c3cebaecff6525d901e73afc8a227cbbb0f2af4810f300
SpaceMono-Bold.woff2     af7cf6d2b897ec453acdcdacde4e9bcc8410718af5914de865b453e09f10eebc
```

## JavaScript build dependencies

`charts/package-lock.json` pins the exact npm registry versions and integrity
metadata used to build the chart bundle. It includes React, visx, d3, Motion,
TypeScript, esbuild, and their transitive dependencies. The lockfile records
the package metadata; a release should generate an SBOM and rerun `npm audit`
against the current registry rather than treating this snapshot as a permanent
vulnerability guarantee.

The corresponding production dependency license texts are copied under
`licenses/dependencies/`, with one directory entry per shipped dependency.
Keep that inventory with the image and release archive when redistributing the
generated browser bundle.

SHA-256 of the checked-in lockfile:

```text
dcc1da86523f98c511e0cd1f76fb94e83ce91a121cd06f2ff4b1b260dd0786b0
```

## Rebuild note

Run `npm ci`, `npm run typecheck`, and `npm run build` from `charts/`. The build
writes the generated chart files into `web/`; it does not require or retain
`node_modules` in the release tree. Recompute the checksums and update this
notice whenever a vendored artifact or generated output changes.
