<!-- Records the round-three deploy review fixes, exact regressions and acceptance receipts for #188. -->
# Deploy review fixes, round three

Issue [#188](https://git.kayg.org/kayg/infraternal/issues/188), review target
`a4da1436`, exact local review source `4c30bb42` (the named remote branch was
absent). Test commits were cherry-picked without changing their assertions:
`c2d8ae30`, `c24cbc7c`, `facc421d`, `7bdd97c8`.

| Review | Fix | Evidence |
| --- | --- | --- |
| R1 P1 | `84a8d847`: authenticate the server and actual separate x86 payload; `edffaef5` avoids a redundant retained-image hash | [red](review-red.log), [green real SSHSIG](admission-green.log) |
| R2 P2 | `25750a87`: try alias/web restoration independently, always attempt retained warm process rollback, require operator recovery on incomplete filesystem repair | [red](review-red.log), [green ENOSPC](alias-green.log) |
| R3 P2 | `ad067b38`: web-only swaps leave binary production tags/main unchanged | [red](review-red.log), [green transport/ref boundary](scripts-green.log) |
| R4 P2 | `bd83af23`: capture the kernel-resolved path for relative invocation before sealed recovery, preserving absolute service paths; reuse the parent #157 fix-forward choice | [red real memfd exec](path-red.log), [green restart/fmt/Clippy](restart-green.log) |

All three script regressions pass; all 15 existing deployment cases and the
actual-signature staging packaging case pass. The full restart unit filter
passes 27 cases, with one explicit optimized measurement ignored. The exact
PATH recovery case changes from 0 pass/1 fail to 1 pass/0 fail. The tracer
[type check](tracer-check.log) passes. These build-host durations are functional
diagnostics, not performance evidence. `65c827b0` adds the exact script review
suite to every fast gate; the Rust regression already runs in workspace tests.
`4ce0f6f6` documents the repaired operator behavior and cut-over prerequisites.

Author checklist: complete remote admission checks actual signed artifact bytes,
including reused directories; signed identity, strict signature parsing and
sealed execution remain unchanged. Alias/web allocation errors cannot bypass
process recovery, and mixed installed state never gets a fully healthy rollback
claim. The live database is never overwritten. Web-only swaps cannot publish a
false running-executable identity. Recovery retains pinned immutable bytes and
its correct installation target; absolute service aliases remain verbatim.
No trust override, dependency, crypto engine, protocol, timeout or release-profile
change. Signing is ephemeral staging-only; administrator sessions and CA material
stay in memory/private pipes. No production deployment, production signer use,
production tag/main change, service installation or issue closure.

Final branch-head gate receipts are quoted verbatim on #188. The inherited
D243 static-size ceiling remains unchanged; a size-failing receipt cannot
publish a production build. Independent review is still required before merge.

# Staging reproof after the handoff-path fix

[Raw receipt](staging-proof.txt), throwaway run `r953087ad` on
`infraternal-perf-test`, kernel `6.12.69+deb13-amd64`, exclusive perf lock.
Load before `1.25 0.65 0.52`, after `1.27 0.69 0.53`.

| Check | Result |
| --- | --- |
| Signed A/B handoffs | 12 accepted; CA stayed unlocked after one real passkey unlock |
| Listener-gap bracket p50 / p99 | 18.576 / 102.768 ms, nearest rank, n=12 |
| Worst actual probe spacing | 101.438 ms |
| Full deploy transaction p50 / p99 | 677.560 / 802.080 ms, including backup and both separately authenticated x86 files |
| Retained scale | 50 users, 10000 node records, 128 real PTYs |
| Continuity | All 128 original shim PIDs survive; all 128 resume fresh input/output |
| Signed unusable C | Refused before shutdown; B remains serving |
| Actual failed-deploy rollback | Verified retained B serving with unlocked CA |
| Backup | Integrity OK, 10000 nodes and 50 users retained; previous-image signature verified |
| Teardown | Own transient unit/processes/data/CA/runtime removed; run directory absent before lock release |

Gap values conservatively bracket listener availability. The 100 ms connect
bound produces occasional 101 ms probe spacing, so the p99 is an upper bracket,
not a precise physical blackout or terminal reconnect-budget result. The full
transaction records include the added separate-payload authentication; security
requires checking those actual distribution bytes rather than substituting the
server alias. No speed comparison between different-load runs is claimed.
The same fixture qualifications apply: A/B execute one staging program with
different signed identities/hashes; the signed ARM placeholder is never executed
or a production artifact. Private signing material was deleted before transport.
The prior acceptance and its original receipt remain unchanged in the parent
evidence directory. Production was untouched.

Milestone fast gate: all native rows and production trust pass. Stripped x86
is 21882704 bytes, 256 bytes above the prior review target's 21882448 bytes;
the unchanged D243 ceiling is 16404816 bytes. This is the sole gate failure;
ARM/TS full-gate phases are skipped after it. The separately run tracer type
check passes. Final branch-head output follows verbatim on #188.
