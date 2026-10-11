<!-- Evidence for fixes to the signed-release verification review [D224,D225,D206,#157]. -->
# Release pipeline round 2

Original head: `087d2a70`. Review tests were imported unchanged from
`review-release-pipeline`; the additional startup test checks cleanup before any
network request and preservation of active, unrelated and unsafe cache contents.

## Regression evidence

- `review-red.log`: separate build directories admitted two publishers: two lists,
  eight uploads, four replacements. Duplicate `result` was admitted with exit 0.
- `review-final.log`: one list, four uploads, zero replacements; duplicate `result`
  rejected with exit 1 and a constant plain reason. Both Bun review tests pass.
- `payload-red.log`: two interrupted downloads retained 2,097,152 bytes after restart.
- `payload-green.log`: retained bytes fall from 2,097,152 to zero. Eight payload tests
  pass, including the constructor startup safety test (`startup-red.log` is its
  failing pre-fix receipt).
- `scripts-final.log`: three Python tests pass, including six recursive duplicate
  cases across storage and Worker answers. No index reader exists in this pipeline;
  the nested index-shaped answer exercises the same strict decoder.
- `named-gates.log`: exact `cargo test -p infraternal-server release_verify` and
  `release_payload` gates. No live bucket or Worker was contacted.

## Measurements

`measurements-final.log` records machine, load and weighted scope. On
infraternal-dev (8 cores, x86_64, kernel 6.12.111+deb13-amd64, CPUWeight=10000),
the 20 MiB baseline/fixed cold fetches took 192.180/189.304 ms; warm p50 over
50 samples was 100.341/97.751 ms; eight concurrent warm hosts took
211.646/209.106 ms. Both made four cold requests and no warm requests.
Load ranged from 10.91/21.47/21.71 to 9.78/20.88/21.51. These single-run
comparisons show no observed regression; they are not a statistical speedup claim.

The exact-source optimized harness uses the real SSH plugin and repository lock
versions, with no behavior stubs. `measurement-sources.txt` records source hashes;
`run-measurements.py` and `cleanup-measurement.rs` preserve its measurement driver
and additional ignored test. Cleaning 50 abandoned staging directories, each with
a sparse 20 MiB file (1,048,576,000 logical bytes total), took 2.342 ms and retained
zero bytes. Sparse files measure metadata/unlink work, not payload write throughput.
The driver's maxrss field is cumulative child-fixture usage, not production RSS.

## Review checklist

The fixed publisher lock is independent of build directories and held through
signing and verification. Its inode is never unlinked. All parsed release response
objects reject duplicate fields recursively and never echo provider diagnostics.
Cache collection is restricted to canonical UUID staging directories and owned,
private, single-link recognized files; symlinks, unknown contents and active
flocks remain untouched. Creation and collection share a short directory lock.
Only verified bundles are atomically published. No dependencies, protocol,
authentication, UI, trust anchors or fallback rules changed.

`gate-attempts.log` records failed full-gate attempts, including a corrected lint
and intermittent pre-existing daemon/socket fixture failures. No assertions were
weakened and no baseline-equivalence waiver was taken. The final receipt and size
comparison accompany `result.md`. `ts-fast.log` records the separately run
TypeScript dispatcher (the known static-size failure stops the main dispatcher
before TypeScript). It passes tracer compiler, units, build, transfer budgets and
36 protocol tests with 34,462 assertions. `static-size.log` records both static
architectures and the x86_64 +14,176-byte delta against the independent original
head receipt. ARM uses the default marker; the original review used the production
marker for ARM, so no matched-marker ARM delta is claimed.
