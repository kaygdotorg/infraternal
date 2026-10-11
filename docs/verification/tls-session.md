<!-- Native TLS session regression, security checks and measurements for #149 [24,28,40,53,64,86]. -->
# Standalone TLS session cookie fields

On production base `d82d0fb9`, owner registration over real localhost TLS with
HTTP/2 ALPN returns 200. A session read with joined cookies returns 200, but
separate ceremony/session Cookie fields return 401. The existing HTTP reader
(`auth/http.rs:106–111` at that base) uses `HeaderMap::get`, which reads only the
first field. This proves the issued session is already unlocked. A real TLS
front recombining cookies on an HTTP/1 upstream hop returns 200 before the fix.

One borrowed, allocation-free capability reader now scans all Cookie fields.
It requires exactly one canonical 43-character capability and rejects invalid
text or duplicates anywhere in the request. HTTP auth, ceremony binding and
socket upgrades reuse it. Hash comparison, expiry, pending unlock, exact Origin,
Secure/HttpOnly/SameSite/Path attributes, and source admission are preserved.
Standalone does not trust forwarding metadata. The TLS tests deliberately send
malformed forwarding metadata to standalone; the proxy front replaces it with
valid metadata for its explicitly trusted loopback upstream.

The native/proxy tests trust only their generated self-signed localhost cert,
assert h2 ALPN, and use the existing real ES256 authenticator, browser PRF/wrap
fixture and WebAuthn verifier. Cert keys, capabilities and recovery material
stay in process memory; fixture databases are deleted before final assertions.
Joined/split and reordered cookies succeed; duplicate/missing cookies and wrong
Origin return 401 in both modes. The regressions are enabled in the final tree.

Before: native 0 passed/1 failed (401 vs 200, 0.82 s); proxy 1 passed (1.58 s).
After the HTTP fix: native/proxy 2 passed, 0 failed (1.47 s).
Browser suite: 4 isolated passkey scenarios and 2 real-verifier recovery scenarios
pass on Chromium 149.0.7827.55, including native crypto and original DEK recovery.
WebSocket split/duplicate tests also both failed before replacing that reader.

## Measurements

Machine: infraternal-dev, x86_64; benchmark inside
`systemd-run --user --scope -p CPUWeight=10000`. Load averages were
4.14/9.58/20.31 before and 4.37/9.54/20.24 after three alternating old/new runs.
The harness is the checked-in cookie measurement, compiled with `rustc -C
opt-level=3 --test --target x86_64-unknown-linux-musl` against the gate's optimized
axum rlib and dependencies. It executes 200,000 requests per session × 50 sessions
in each run. These are parser averages, excluding TLS, SQLite and authenticator
latency; they are not an end-to-end percentile claim.

| Run | Old ns/request | Strict ns/request |
| --- | ---: | ---: |
| 1 | 69.63 | 148.97 |
| 2 | 66.65 | 165.23 |
| 3 | 58.79 | 147.13 |

Medians: 66.65 → 148.97 ns/request, +82.32 ns; 50 requests add 4.12 µs.
This cost is justified by whole-request duplicate detection and identical strict
capability validation in every adapter. No allocation or retained state is added:
0 bytes/session × 50 = 0 bytes.

The initial stripped static x86_64 binary was 16,435,312 bytes, already 30,496
bytes above the 16,404,816-byte gate limit. Test dependencies/fixtures add 0 bytes;
ceremony step adds 512 bytes; HTTP step removes 192 bytes; socket step removes
832 bytes. Final size is 16,434,800 bytes: 512 bytes smaller than the base and
29,984 bytes over the existing limit. The size gate stops at x86_64 before its
aarch64 build; only x86_64 size is measured here. D205 permits reporting
the existing size-row failure. No dependency versions or production engines are
added; h2/tokio-openssl direct dev dependencies reuse the existing server stack.

## Review and verification

Auth B1/S1/S2/N1 checklist from `auth.md`: no transaction/crypto/authority policy
changes; both admission partitions and exact Origin remain; native TLS plus
browser cryptography pass; one cookie implementation is reused without secret
copies or new session state. The parser has malformed/duplicate/non-text tests
and a fuzz target exercising split fields and duplicate denial.

An initial attachment fixture failed because it creates `target/ac<PID>` without
creating target. An ignored local target symlink to the job scratch build root
satisfies that prerequisite without changing tracked gate code. The existing
socket test `expired_handshake_releases_user_permits` intermittently fails its
one-millisecond boundary at socket_tests.rs:206. Paired repetitions reproduced
the same failure on detached dev `0510bd85` before and after the ceremony change,
with unchanged socket/auth runtime source. This is the brief's #118 exception;
complete test rows have also passed. No timeout or security bound was changed.

Because the existing static size failure exits `scripts/verify fast` before TS,
`ts_verify_fast` was run separately and passed: tracer checks/build/transfer
budget plus 36 protocol tests (34,462 assertions).

Reproduce native/proxy regressions with a job-specific scratch CARGO_TARGET_DIR:

```sh
TRACER_TEST_PORT=4349 RUST_TEST_THREADS=1 cargo test --locked \
  -p infraternal-server --lib tls_tests -- --nocapture
TRACER_TEST_PORT=4349 scripts/verify-auth-browser
TRACER_TEST_PORT=4349 RUST_TEST_THREADS=1 scripts/verify fast
```

Use the repository's Nix Zig 0.15.2/make/perl environment as necessary. The final
head, atomic step measurements and verbatim gate summaries are recorded on #149.

The final code/fuzz gate passes 145 server tests, 0 failures, 13 intentionally
ignored scale measurements. All other Rust rows pass except the existing static
size row. The docs-only gate output is recorded verbatim on #149 at completion.

Instrumented nightly/ASAN fuzzing completed **1,781,320 runs in 61 seconds** with
cov=290, ft=1384, corpus=352/58 KiB and RSS=366 MiB, without a crash. These are
coverage counters/features, not source-coverage percentages or production RSS.
The run used max_len=4096, rss_limit_mb=512 and CPUWeight=10000 on infraternal-dev;
load was 3.87/2.86/2.87 before the build/run and 7.64/9.95/6.56 after it.
The target includes the production reader source and adds duplicates to every
successful parse, asserting denial for both session and ceremony prefixes.

Atomic code commits: dev dependencies `c66adfcc`, test foundation `4f3ebcf8`,
ceremony reader `31540288`, HTTP reader/enabled TLS tests `8e6c6198`, socket reader
`dd0d7a6b`. Fuzz harness `7d564415`; the final documentation head is recorded on #149.

Final `scripts/verify fast` output (verbatim summary, exit 1 only for size):

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

Final server test output: `145 passed; 0 failed; 13 ignored; 0 measured;
0 filtered out; finished in 354.46s`. No tests were skipped to make the gate
pass; 12 existing ignored measurements and the new optimized cookie measurement
remain explicit. The new measurement was executed separately at 50 sessions.
