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
playwright.functional.config.ts, --timeout=120000, and specs addhost-wizard,
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
