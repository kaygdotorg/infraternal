<!-- Release pipeline validation, measurements and independent-review artifacts for #157 and D184/D220/D224/D225. -->
# Release pipeline evidence

All production changes are committed separately on `release-pipeline`; issue
[kayg/infraternal#157](https://git.kayg.org/kayg/infraternal/issues/157)
is the continuation record. No live upload, signer call or deployment occurred.
The public anchors remain the supplied two-key file. The author ran the security
checklist in [the operations guide](../../docs/operations/release.md).

## Workspace gate

[verify-fast.log](verify-fast.log) is the complete, unmodified output of
`scripts/verify fast` under the job's scratch target directory. Formatting,
native formatting, clippy, workspace tests and cargo-deny pass. The server
suite passes 279 tests, with 32 existing/explicit diagnostic ignores. The
static size row retains the known pre-existing failure; no limit was changed.
The [no-default-features server check](no-default-features.log) also passes
in 2m 26s, confirming that the SSH downloader compiles out with its component.
The x86_64 gate binary is 20,028,096 bytes, up 131,104 bytes from the measured
production-line baseline of 19,896,992 bytes at `9fba1eb2`. The gate's separate
fixed size maximum remains 16,404,816 bytes. The [real pipeline build](pipeline-build.log) completed both musl targets using
the production marker and pinned Zig; [binary-sizes.log](binary-sizes.log)
records actual sizes, absence of PT_INTERP and the emitted release marker.

| Architecture | Production-line baseline | Release bytes | Growth | Unchanged gate maximum |
| --- | ---: | ---: | ---: | ---: |
| x86_64 | 19,896,992 | 20,028,096 | +131,104 | 16,404,816 |
| aarch64 | 17,729,832 | 17,848,344 | +118,512 | 13,817,816 |

Both baselines are at `9fba1eb2`, recorded on #157; the
[baseline ARM build](baseline-arm-build.log) preserves its receipt. The local
bundle contains workspace version `0.1.0`; every packaged checksum passes.
A second `scripts/release/build` refuses that existing version with exit 1.
The bundle was never uploaded.

The SSH test fixture now sets its private umask before socket binding:
[red](ssh-socket-red.log), [green](ssh-socket-green.log). This fixes the
fixture race without relaxing the real SSH control-socket permission check.
The enrollment fixture admits its issued certificate using post-issuance time,
fixing the gate's observed `Denied` at its old pre-issuance timestamp without
changing production certificate admission.

## Local release and browser tests

[Publishing stand-in tests](release-script-tests.log) pass both cases. They
exercise isolated copies of the scripts, throwaway signing keys, a local bucket
and signer, immutable versions, malformed/tampered data and version mismatch.
The [synthetic Bearer alphabet red case](release-script-red.log) preceded its
encoding fix. No production credential or private signing key is used.

The tracer type check is recorded in [tracer-check.log](tracer-check.log).
The add-host model passes 30 tests after its named-failure red case:
[red](ui-message-red.log), [green](ui-message-green.log); the separate wire
failure decoder test also passes; [the combined unit run](tracer-unit-tests.log) passes 31 tests.

Existing production wizard/chip specs passed 38 tests with four pre-existing
skips; the added phone capture initially hit the optional preview FPS overlay:
[initial run](wizard-browser-initial.log). With the preview overlay disabled,
both added desktop/phone cases pass in [the corrected capture run](production-screenshots.log).
The prototype suite passed 13 other cases and exposed a stale Backspace
expectation: [initial run](prototype-browser-initial.log). Its corrected case
passes [separately](prototype-browser-correction.log). The shared chip component
was not changed. All browser runs use `TRACER_TEST_PORT=4817` and production builds.

The screenshots are artifacts for independent review; this job does not assess
its own visual quality:

- [Desktop, 1440 × 900](release-verification-1440.png)
- [iPhone viewport, 393 × 852](release-verification-393.png)

## Verification and cache measurements

[measurements.log](measurements.log) records the actual optimized test runs on
`infraternal-dev`: x86_64, eight CPUs, Intel Core i9-9900K at 3.60 GHz,
Rust 1.99.0, `systemd-run --user --scope -p CPUWeight=10000`. The temporary
native harness compiled the production verifier/downloader/resolver modules
with release LTO, one codegen unit and the server's size optimization. This
avoids compiling unrelated workspace benchmarks during timing; its source
methods are the committed ignored tests, not a replacement implementation.

| Measurement | Result |
| --- | ---: |
| 20 MiB opened-file verification, p50 of 50 runs | 105.790 ms |
| Cross-architecture binary step, cold cache | 308.227 ms |
| Same step, warm cache, p50 of 50 runs | 104.661 ms |
| Eight concurrent warm lookups (the existing host concurrency limit) | 439.572 ms |
| Cold / additional warm network requests | 4 / 0 |

Payloads are 20,971,520 bytes. The diagnostics report the upper median of
the 50 sorted samples. Load averages were `14.94 26.04 32.13` for
verification and `14.94 25.85 32.03` for cache resolution. Cold/warm numbers
cover the named binary-acquisition step with a loopback HTTP bucket and real
OpenSSH signatures; they exclude SSH transfer, target startup and Internet TLS
latency. Warm hits still authenticate the signed manifest, signed exact VERSION
and payload. Each verifier allocates a 64 KiB hash buffer: eight concurrent
verifiers use 512 KiB for those buffers, excluding metadata/crypto overhead.

## Fuzzing

[fuzz.log](fuzz.log) is the complete sanitizer execution at CPUWeight=30. The
compiled target ran 3,918,244 cases in 301 seconds, with no crash; final coverage
was 635, feature count 1331, corpus 208/40 KiB and observed peak RSS 480 MiB.
Compilation used nightly-2026-10-01 under CPUWeight=10000, then the already built
ASan target ran for the requested five minutes at CPUWeight=30. Build outputs
were under `$HOME/.cache/codex-scratch/release-pipeline`, and are disposable.
The reproduction commands and seed generator are in the operations guide.
