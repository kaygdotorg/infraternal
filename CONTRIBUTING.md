# Contributing

Start with the [README](README.md), [architecture](docs/architecture.md), and
[security boundary](SECURITY.md). Use synthetic services and metrics in tests.
Never include production configuration, credentials, private hostnames or logs
in a commit, issue, screenshot, fixture, or generated asset.

## Local checks

Run from the repository root. Python 3.10+ runs the service and tests; Node.js
and npm are needed only for JavaScript checks or rebuilding the chart bundle.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --input-type=module --check < web/app.js
node --input-type=module --check < web/theme.js
```

Use `PYTHONDONTWRITEBYTECODE=1` to avoid adding Python cache files to the release
staging tree. Test the server with a copy of the example configuration stored
outside the checkout, as shown in the README.

## Chart changes

Edit `charts/src/bklit-charts.tsx` and its stylesheet, not the generated bundle.
Use the committed dependency lockfile:

```sh
cd charts
npm ci
npm run typecheck
npm run build
cd ..
```

Commit the source and generated `web/bklit-charts.js`, `web/bklit-charts.css`,
and license output together. Check regenerated checksums and dependency notices
in `THIRD_PARTY_NOTICES.md`; preserve the licenses under `licenses/` and vendor
notices. `node_modules/` is ignored and excluded from container build contexts.
Do not include it in release archives. Review both `npm audit --omit=dev` and
`npm audit` when changing dependencies; results depend on the current registry.
After chart validation and dependency audits, remove `charts/node_modules/`
before rerunning the full Python suite or staging a release: the package
contract test deliberately rejects dependency-install directories in that tree.

## Review expectations

Keep changes focused and explain the user-visible behavior and relevant checks
in the pull request. Add regression tests for parsing, freshness, aggregation,
caching and security boundary changes. For UI changes, exercise the homepage
and a service page at narrow and wide widths, both color modes, keyboard
navigation, reduced motion, graph mode switching and scrolling.

Reuse `surfaceCard`/`surfacePill` and shared CSS tokens. Preserve graph root
lifecycles when updating data; rebuilding every chart on each update increases
scroll and interaction cost. Document non-obvious invariants and tradeoffs near
the code, rather than adding comments that merely repeat an expression.

## Before publishing

Scan all Git history and the proposed working tree with a secret scanner such
as Gitleaks. Inspect configuration examples, binary assets, generated bundles,
commit messages and author metadata as well as ordinary source files. Record
findings privately; do not paste potential secrets into public issues. If a
real credential is found, revoke it before coordinating history cleanup.

Follow the [container guide](docs/containers.md) for building and deploying.
Verify the actual image and public routes, retain rollback artifacts, and do
not describe desktop viewport tests as proof of physical Safari behavior.
