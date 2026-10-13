<!-- Focused F1–F3 correction, scale evidence and reviewer handoff for issues #29 and #28. -->
# Focused auth audit correction

Server started at `f1b996c`, client at `faa3154`. Work is confined to `t-server`
and `t-web-auth`; `t-web` was untouched. Client commit `58040df` changes only
`src/auth.ts` and auth handling in `test/mock-server.ts`. No push or deployment.
The state of record and complete verbatim gate outputs are on
[issue #29](https://git.kayg.org/kayg/infraternal/issues/29).

## Corrections and red evidence

The reviewer probes were ported in `04f7366`, run red, then activated by each
fix. Additional handshake probes in `772a585` also ran red. No focused defect
remains ignored; only the three release measurement tests are ignored by fast.
The tests use the real ES256 verifier, SQLite, WebSockets and Unix socket pairs;
backend response timing is controlled, not the auth verifier. Native production
browser checks use Chromium 149.0.7827.55 PRF/HKDF/AES-GCM.

| Finding | Before | Correction and evidence |
| --- | --- | --- |
| F1, cross-tab completion | B session 401→200 after A completion, then terminal on reload | `33fb6a5` plus client `58040df`: page-memory id identifies exact pending cookie; completion and failed-login cleanup deny mismatches without cookie/row changes. Native two-tab now 401→401 and signed-out reload; matching completion succeeds once. |
| F2, busy authority | logout/recovery/edited expiry remain open 1502/1503/1501 ms, then late success and one row | `c56c96f`: nested waits race revocation/expiry; actual authority checks and SQL predicates guard mutations/success. Optimized probes close logout/recovery below 1 ms and edited expiry in 26 ms, with no late success or row. Backend no-reply returns failure near 5003 ms, ignores late success and services the next Ping. |
| F3, handshake authority | revoked Hello/Resume and expired Hello mint Welcome; waiting pre-Hello stays open beyond 100 ms | final `5265026`: whole handshake watches authority, reads never slide expiry, token checked under writer lock, rollback metadata staged before SQL waits. Hello/Resume/expiry/pre-Hello regressions pass; measured pre-Hello 629 us and Resume 25.675 ms, both below 100 ms. |

The handshake now uses one absolute five-second budget for both Hello
directions, authority reads and Resume. A recurring capacity-test failure was
traced to cancellation dropping the fixture’s sole in-memory SQLite connection:
a retained assertion proved its sessions table had disappeared. Fixture-only
`54ab29d` disables checkout ping, following [SQLx cancellation guidance](https://docs.rs/sqlx/0.8.6/sqlx/struct.Pool.html#method.acquire);
production disk-pool settings are unchanged. All 54 server tests now pass. An intermediate sliding handshake read extended the reviewer's near-term
expiry; non-sliding reads preserve it. Both failures and corrections are on #29.

F1 deliberately adds no DEK-possession verifier. A client with its own matching
cookie/id can claim completion without unwrapping; the owner accepted that client
consistency boundary. `contracts/keywrap.md` records it. SHA256 domain separation
binds the page id to the cookie without exposing the cookie or adding persistent
state. The pending flag consumes it atomically. Envelopes, AAD, HKDF info and v1/v2
metadata are unchanged. Native paired v3/v1/v2 retain prompt counts 1/2/2;
corrupt-unwrap/logout429 and restart/old-spent-token checks pass.

## Measurements and budgets

Machine: eight Intel i9-9900K 3.60 GHz x86_64 KVM vCPUs, 31 GiB RAM.
No concurrent compilation during final measurements. SQLite is in memory; socket
numbers include loopback control and exclude real PTY/network/phone/perf-VM work.

| Measurement | Scale | p50 / p99 | Load (1/5/15 min) |
| --- | --- | --- | --- |
| Socket authority/control | 16 simultaneous × 200 rounds = 3200 | 1160 / 2130 us, below 5 ms | 7.26 / 6.50 / 5.75 |
| Identified challenge | pending 824..1024, n=200, two passkeys | 52 / 147 us, below 1 ms | 7.40 / 6.54 / 5.77 |
| Discoverable challenge | pending 824..1024, n=200 | 4 / 21 us, below 1 ms | same |
| Signed discoverable finish with transaction id | pending 1024, n=200 | 490 / 4149 us, below 10 ms | same |
| Writer lookup | 16 connections × 32 writers = 512, n=3200 | 177 / 388 us, below 1 ms | 7.40 / 6.54 / 5.77 |

Pending inline state remains 136 bytes × 1024 = 139264 bytes, excluding heap and
hash-table allocations. Process RSS 12992→14452 KiB (+1460 KiB); entry 1025 is
denied. Discovery reuses the retained allocation. Finish timing now includes
HTTP's completion-id generation (`628ab1a`), with the real ES256 verifier.

Final measurements use the corrected in-memory fixture. A loaded attempt failed
the socket budget at 1123/7911 us (load 8.07/6.20/5.42, 15 runnable tasks);
a five-second CPU sample found 0.9% idle. Another loaded capacity run had
low-capacity identified p99 2598 us (load 10.24/7.16/5.79). These failures
remain on #29. The preceding production-code measurement, with checkout ping
enabled, passed socket 1253/2475 us at load 2.48/2.94/5.91. Final repetitions
above passed unchanged budgets; load averages alone do not prove causation.

The first watchdog design failed quiet scale at 4345/11956 us. `27f2141` reuses
one authoritative entry read and checks the revocation generation/deadline after
waits, retaining actual authority reads/SQL predicates at backend/persistence
boundaries. Stored-expiry checks run every 25 ms only while work is pending;
established idle sockets retain event/deadline wakeups. Historical #29 baseline
1123/2190 us is not a controlled A/B. The current small observed difference remains
within budget and the retained regressions justify it by proving prompt revocation
and denying late rows/success. No threshold was loosened.

Production Playwright passes 4/4 in 44.9 s, 500-key p99 16.60 ms (<20 ms), resume
79.50 ms (<300 ms). Setup/sign-in first-contentful-paint p99 366.9/90.9 ms, n=30
per screen, local production build. A concurrent-build run failed at 29.2 ms;
that failure remains recorded, and the clean rerun passes. These browser terminal
numbers use the clearly marked transport test double, not a production PTY.
Native auth passes four isolated scenarios; paired Rust/production browser and
process-restart checks pass. Historical production screenshots were removed under
D262. Fresh screenshots for independent review belong in
`$HOME/.cache/codex-scratch/tracer-<pid>/evidence/playwright/`, including
`onboarding-setup-recovery--906cd--match-the-browser-contract/returning-sign-in-iphone-15.png`
and `terminal-first-run-passkey-29742-esume-and-the-latency-probe/tracer-terminal.png`.
This job does not approve its own visual quality.

## Reproduce and self-review

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
# Run the same fast command in t-web-auth (nix may need its installed absolute path).
# In t-web-auth/apps/tracer:
bun x playwright test
# In t-server:
nix shell nixpkgs#gnumake nixpkgs#perl -c scripts/verify browser
cargo test -p infraternal-server review3_ -- --nocapture
bun scripts/browser-auth/review3-two-tabs.mjs ../t-web-auth/apps/tracer/dist
bun scripts/browser-auth/check-tracer.mjs ../t-web-auth/apps/tracer/dist
AUTH_TEST_PRF_VERSION=v1 bun scripts/browser-auth/check-tracer.mjs ../t-web-auth/apps/tracer/dist
AUTH_TEST_PRF_VERSION=v2 bun scripts/browser-auth/check-tracer.mjs ../t-web-auth/apps/tracer/dist
bun scripts/browser-auth/check-unlock.mjs ../t-web-auth/apps/tracer/dist
bun scripts/browser-auth/check-restart.mjs ../t-web-auth/apps/tracer/dist
cargo test --release -p infraternal-server socket_authority_latency_at_user_capacity -- --ignored --nocapture
cargo test --release -p infraternal-server discoverable_latency_at_pending_capacity -- --ignored --nocapture
cargo test --release -p infraternal-server writer_admission_at_user_capacity -- --ignored --nocapture
```

Checked the auth/server B1/S1/S2/N1 checklist from `docs/verification/auth.md`:
exact Origin/cookie/transaction boundaries; replay, mismatch and foreign-cookie
denial; counters and native crypto; revocation after commit; reads never resurrect
expiry; SQL authority predicates survive cancellation; staged Welcome rollback
matches only its tentative token; transport drops before metadata cleanup; timers,
backend and writer waits bounded; module/invariant comments and no capability
logging/storage/argv. Established operations authenticate on entry; backend and
persistence boundaries recheck actual stored authority. Storage-only unit tests
omit session authority, while production handshakes/writer admission always pass
an exact session hash. No library, dependency, schema or foundational engine was
added. Parser bytes are unchanged; existing fuzz targets in `fuzz/fuzz_targets/`
and stream differential coverage remain in place.

#28's broader production host-daemon/PTY and longer-drop writer blockers remain
as recorded on that issue. Already-dispatched host work may complete; these fixes
withhold late socket success and terminal-row persistence, not cancel host work
through an invented backend protocol. Physical Safari/iPhone and independent
security/visual review remain external. `DECISIONS.md` is unchanged, and the
missing `docs/PROCESS.md` is covered by the owner's supplied job contract.
