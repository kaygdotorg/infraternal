<!-- Records verbatim gate summaries and reproducible commands for #151; size exceptions follow D205. -->
# Gate evidence

The final source passes all non-size Rust rows. The weighted local run used
`RUST_TEST_THREADS=1`, `CARGO_BUILD_JOBS=2` and `TRACER_TEST_PORT=4351`.
Earlier unweighted socket failures are retained on #151; the complete weighted
rerun passed all 263 server tests and all 9 real shim tests, so no load waiver is
needed for this final result.

Verbatim `scripts/verify fast` summary:

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

Verbatim static check (x86):

```text
PT_INTERP: absent; size: 19656320 bytes (baseline 16142672 + allowance 262144 = max 16404816)
binary exceeds the 16404816-byte size budget: 19656320 bytes
```

This historical maximum is already exceeded by the exact production base
(19,613,216 bytes). The branch adds 43,104 bytes (0.22%) with no new production
dependency. D205 permits the reported exception. ARM was built separately because
the dispatcher stops at the x86 size failure: 17,533,960 bytes, static, stripped,
no PT_INTERP. No ARM delta from the base is claimed.

Because the Rust size row stops the dispatcher before TypeScript, the same
`ts_verify_fast` function was run separately: compiler, all unit/canvas tests,
production build, precompression and transfer gates passed. Critical JS:
gzip 288,093 / 307,200 bytes, brotli 239,205 / 256,000 bytes. Protocol output:

```text
 36 pass
 0 fail
 34462 expect() calls
Ran 36 tests across 10 files. [4.80s]
```

Parser fuzzing: 2,372,685 ASan executions in 46 seconds, cov=2049 / ft=6838,
no crash. Production policy/refusal/process-birth parsers were exercised, with
release LTO disabled only for the fuzz invocation.

The production browser run uses the final static artifact identified by SHA256
4939fc4d3a09c62a3b80febbb7a7fdfa1cef846189cbdb6618899ddcf271f32b,
`INFRATERNAL_BIN` pointing to that artifact, `TRACER_TEST_PORT=4351`, and a
weighted local scope. Its final summary (verbatim):

```text
  3 skipped
  41 passed (7.4m)
```

All 41 runnable specs passed; the three existing skips are two disabled-Mesh
profile cases and the opt-in scale spec. The new refusal checks include both
desktop and phone picker viewport assertions. Earlier fixture failures and their
corrections are recorded on #151; timing budgets were not relaxed.

Reviewer checks covered lifetime identity/PID reuse, stale-socket permissions,
ordered exit delivery and delayed credit, disabled-plugin work, memory arithmetic,
JSON bounds and public-copy sanitization, trusted count injection, existing
freshness/host ownership/UID authorization, unchanged frame layouts, dependency
reuse and UI reuse. Production captures are linked in the capture README for
independent visual review; they are not an author's visual-quality judgment.
