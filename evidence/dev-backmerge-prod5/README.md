<!-- Records source integration and reproducible merge evidence for D250, #169. -->
# Production backmerge

Base: dev `ee104344d0fd8eeb7155e08c2ab39cc32adefdba` (D215 already integrated).
First merge parent: live production `5bf3f42ede08c47c5fb7ad33d977c831fe6e5cc8`.
Second requested parent: start-fresh `84be60625eff7581ee5cd4d06ae835364a614f5c`.
Only this task branch is pushed; no deployment or dev/main update.

## Integration choices

The eight conflicts retain dev's signed-payload steps, action-based CLI and
replay fences alongside production's readiness boundary, Start fresh states,
durable exact-owner retirement, ended-strip changes and D244 key custody.
The hidden key-memory diagnostic is a registered action behind remote, preserving
its imported key-free success/refusal test. The automatic merge's missing test
module guard is restored. Production readiness and dev payload fixtures now
assert the additive replay fence and combined read-only ownership check.

Migration 0023 is preserved alongside dev 0020/0021/0022. The new real-SQLite
fixture models production's already-applied 0023 above its missing dev migrations,
then checks that filling the gap preserves retirement data and checksums.

D243's size-check function is byte-for-byte identical to dev. The maxima remain
16,404,816 bytes x86 and 13,817,816 bytes ARM; no profile, budget, engine or
foundational dependency choice is made by this integration.

## First merge checks

Strict touched-crate Clippy and fmt pass. Native CLI: 68 pass. Payload-source:
2 pass. Real-shell install: 48 pass. Ownership shell: 15 pass including SF-1.
The full server run has 410 pass and only the initially incomplete new migration
fixture failing; its corrected migration matrix passes 8/8. Shim: 79 pass,
13 ignored. Remote-disabled CLI: 25 pass, including hidden-diagnostic absence.
Raw transcripts retain earlier fixture/lint failures rather than hiding them.

Browser replay: 40/40 functional cases. Initial run: 26 pass/14 fail (whole-test
30s limits and IPv6 loopback refusal). Replay uses IPv4 and a 120s whole-test
envelope with every existing per-assertion deadline unchanged. Reproduce from
apps/tracer with TRACER_TEST_PORT=4967 and the adjacent
playwright.functional.config.mts, --timeout=120000, and specs addhost-wizard,
addhost-start-fresh-captures and ended-strip. Captures are from the optimized
browser build with synthetic provisioning and canvas fixtures; no independent
visual verdict or physical iPhone proof is claimed.

TypeScript fast gate: 176 selected tests, protocol 36 tests/34,462 assertions;
compiler, vendor checksums, production build and transfer pass. Critical:
295,009 gzip/245,764 Brotli bytes. Deferred: 49,759/43,998 bytes. Largest on-demand:
15,855/14,121 bytes. Caps unchanged. Initial overlapping-dist build failure is
retained; the serial production gate passes.

Functional logs' durations and incidental counters are not accepted performance
measurements. Final fast's unchanged 3-sample RTT self-test is delegated to perf
VM 208 under the shared lock. Static builds and final branch-head gate follow the
second merge; the issue is the final state of record.

## Later start-fresh merge

The separate merge adds b52d57a1's bound-socket refusal and a83c5d91's shared
Start fresh label, plus 84be6062's evidence. Production's SF-1 ancestry guard is
retained. The combined ownership shell passes 16/16; strict SSH Clippy, fmt and
all SSH tests pass. The standalone gate explicitly enables tokio/test-util for
the inherited dev paused-clock payload fixture (the workspace graph already
supplies it); production dependencies and profiles are unchanged.

## Source-head milestone

Source head `62b3950aac6bd982fef47ad1ec39abf1d211052e`: scripts/verify fast exits 1
solely at the unchanged D243 static caps. Workspace tests: 958 pass, 0 fail,
116 ignored across 95 result rows; compile-out separately 25/0. Fmt, VT fmt,
strict workspace Clippy and cargo-deny pass. No #118 exemption is used.

| Target | Stripped bytes | Unchanged maximum | Structural/runtime result |
| --- | ---: | ---: | --- |
| x86_64 musl | 22,438,672 | 16,404,816 | Static PIE, no PT_INTERP; key initialization=1 under 8 MiB |
| aarch64 musl | 19,871,968 | 13,817,816 | Static, no PT_INTERP; runtime key memory requires native ARM |

The gate exercises both targets despite the first size failure. Its wrapper
argument tests and versioned CLI stub checks pass. Release settings, dependencies,
features and size thresholds are not changed to make this pass. This is an
unwaived size failure; it is not a claim that the branch is ready to fast-forward.
Full verbatim transcript: verify-fast-source.log; input/artifact hashes adjacent.

The static failure prevents the dispatcher from reaching TypeScript; the separate
TypeScript gate already passes on the identical frontend source. The final
branch-head replay is quoted verbatim on #169 after this evidence-only commit.
Its RTT runner also records pinned-VM machine, load and exact probe hash while
holding the shared lock; build-host durations/counters are not performance proof.

Reproduce the functional browser suite from apps/tracer:

```sh
TRACER_TEST_PORT=4967 bun x playwright test \
  -c ../../evidence/dev-backmerge-prod5/playwright.functional.config.mts \
  --timeout=120000 test/addhost-wizard.spec.ts \
  test/addhost-start-fresh-captures.spec.ts test/ended-strip.spec.ts
```

The saved harness was moved to ESM .mts and its package-local configuration import
was retained; listing now resolves all 40 cases. Initial loader failure retained.
