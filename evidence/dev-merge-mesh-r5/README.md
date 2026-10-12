<!-- Integration evidence for mesh rounds 4–5 into dev, D242 and #173. -->
# Mesh rounds 4–5 integration

Source mesh head: `ca8f55554921118fc9d2a2f168f467267217bae8`.
Starting dev: `efac27a598027a09abd008df952629a3cb549de5`.
Mesh merge: `8ab067009a059352aa9bdb945e1fec210fc0c77c`.
Advanced dev: `21b37bca7099c6a80ca0ddcdbfa2b6a73bc5d81f`.
Advanced-dev merge: `75a70d3aed10c35abe0a9c972aaf46d5b9ded5a9`.

The merge preserves dev's retained cancellation signals and adds the mesh weak
runtime publication handle. It also preserves the admission and pre-commit
fresh confirmation checks and watched liveness deadline logic unchanged.
Distinct migration paths collided at SQLx version 0023: the original merged
fixture run failed before auth checks. Dev's existing 0023 stays; mesh host
revocation becomes 0024 with byte-identical SQL. No test or guarantee is weakened.

| Checkpoint | Passed | Failed |
| --- | ---: | ---: |
| Mesh ordinary all-feature tests | 43 | 0 |
| Named kernel regressions | 16 | 0 |
| Packet checks, nft and nf_tables, IPv4/IPv6 | 340 | 0 |
| Incoming/outgoing exact-state checks, both backends | 344 | 0 |
| Failed-journal rollback assertions | 8 | 0 |
| Saved-intent recovery attempts | 20 | 0 |
| Tracer/shared functional tests | 176 | 0 |
| Protocol tests, serialized retry | 37 | 0 |

`auth-sockets-merged.log` confirms both requested fresh-delete and liveness
regressions plus freshness expiry during writer wait pass. Its broader run has
31 passing cases, two failures and two measurement-only ignored cases. Both
failed socket cases pass unchanged in the same executable when isolated; logs
are `socket-isolated-*.log`. No load waiver is inferred. The complete combined-source gate subsequently
passes all workspace tests: 1,010 passed, zero failed, 134 ignored across 105
result rows, including 25 CLI compile-out cases. Both earlier failed socket
cases and the unchanged fresh-delete/liveness/writer-wait tests pass there.
The three auth test files match dev byte for byte; six mesh review/helper files
match the source branch. See the two regression-provenance JSON files.

Initial duplicate-version, namespace compiler-cache and missing fixture-state
root errors remain in their original logs. `run-kernel.py` invokes immutable
executables in fresh namespaces after host-side compilation. Cache bypass on
its retry avoids sccache's namespace/host network error; production sources and
assertions stay unchanged. The initial differential test hits Cargo's build
lock deadline; `protocol-retry.log` records the 37-case serialized pass.

The pre-update fast run stops intentionally after workspace Clippy, before
workspace tests/static compilation, to include new dev first. It is not final
gate evidence. `gate-bin` routes only the RTT self-test to the authorized VM
under `flock -w 3600` and applies the inherited development-only qualification
in `gate-profile.toml`; release profiles and size ceilings are unchanged.
Build-host durations in raw test output are diagnostics, not performance claims.
Prior round-5 56/56 VM results are inherited evidence, not new integration
measurements. See the author `reviewer-checklist.md`.

The standalone updated-dev native run lacks Zig on PATH at the mouse probe;
its stderr is retained separately. The unchanged probe passes with the pinned
Zig PATH, and the complete gate supplies that PATH itself. No test executable
or clock was suspended: only the second Cargo dispatcher waited for the first
runner to finish, as recorded in `native-run-order.txt`.

Complete combined-source `scripts/verify fast` exits 1 solely on D243 size.
Static x86 is 22,530,608 bytes against 16,404,816; ARM is 19,943,688 against
13,817,816. Both have no PT_INTERP and pass production-trust checks. Native x86
key memory initialization is 1 (locked and dump-excluded); ARM runtime is not
claimed on the x86 host. The full raw output is `fast-updated-dev.log`; artifact
hashes are in `static-artifacts.json`. The Rust failure stops the script before
its TypeScript phase; the separate compiler/build/176 + 37 test receipts above
cover that phase. No size threshold or runtime limit changes.

The evidence-only seal follows both source merges. The fresh named-head gate
runs afterward with the same production and test sources, and its complete
verbatim output, head, counts and checksum are recorded on #173. Its local
receipt is `final-head-fast.log`; the narrowly ignored receipt files avoid an
additional evidence commit changing the head after that final check.

Combined-source summary, verbatim:

```text
+---------------------------+--------------+
| Rust gate                 | Result       |
+---------------------------+--------------+
| fmt                       | PASS         |
| VT native fmt             | PASS         |
| CLI plugin compile-out    | PASS         |
| clippy                    | PASS         |
| test                      | PASS         |
| cargo-deny                | PASS         |
| static builds             | FAIL (1)     |
+---------------------------+--------------+
```

