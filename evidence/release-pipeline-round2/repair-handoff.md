<!-- Repair handoff for signed-release verification findings [D224,D225,D206,#157]. -->
# Release pipeline round 2

All three P2 fixes are committed and pushed on `release-pipeline`:
fixed per-user publication flock, recursive duplicate JSON refusal (including
Worker answers), and restart-safe partial cache cleanup with active-download locks.
Review tests remain unchanged. Implementation/doc commits: `81aba503`, `282c9305`,
`58fecd5e`, `406ef6e2`, `83b2b270`.

Python: 3 passed. Bun review: 2 passed. Rust release verification: 2 passed;
payload: 8 passed. Restart residue: 2,097,152 -> 0 bytes. Full workspace tests
pass (server: 281 passed, 33 ignored). Separate TypeScript dispatcher passes.

Final `scripts/verify fast` ran locally with `RUST_TEST_THREADS=1`,
`TRACER_TEST_PORT=4299`, scratch `CARGO_TARGET_DIR` and CPUWeight=10000.
Its summary, verbatim:

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

The known size overrun remains: x86_64 is 20,042,272 bytes, **+14,176 bytes**
versus `087d2a70` (20,028,096), above the existing 16,404,816-byte ceiling [D205].
Both architectures build static without PT_INTERP. No baseline waiver was taken.

20 MiB baseline/fixed cold: 192.180/189.304 ms; warm p50: 100.341/97.751 ms;
eight warm hosts: 211.646/209.106 ms. Cleanup of 50 abandoned sparse staging
files (1 GiB logical total) took 2.342 ms, retaining zero bytes. These are measured
observations under shared host load, not a statistical speedup claim.

[Evidence, machine/load, limits and checklist](evidence/release-pipeline-round2/README.md).
No live bucket or Worker was contacted. Issue #157 records the commits and gates.
