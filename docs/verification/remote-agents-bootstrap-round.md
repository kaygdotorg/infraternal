<!-- Records production CA bootstrap, admission isolation, lifecycle, scale and atomic-gate evidence for #78. -->
# Remote infraternal agent bootstrap round

> Historical raw logs and receipts were removed under D262. Fresh output belongs under
> `$HOME/.cache/codex-scratch/remote-agents-bootstrap/evidence/` and should be attached to #78
> with the `issue-attach` helper.

This round adds first-use machine certificate setup under fresh administrator passkey verification [151][168], separates authenticated owner admission from anonymous joins, bounds pre-auth sockets, reserves known-source capacity, stabilizes fixture hashing and adds QUIC liveness [198][199][201][205]. No dependency, foundation engine, shipping profile or size budget changed. Nothing was pushed or deployed.

## First-use contract

The add-host flow calls POST `/remote/ca/bootstrap/start` with the pinned exact Origin and existing administrator cookie. Perform fresh passkey user verification, derive HKDF-SHA256 locally from the account DEK, returned base 64 url salt and `infraternal/ca-wrap/v1|<member>|<generation>`, then POST `{ceremony, proof, scoped_key:[32 bytes]}` to `/remote/ca/bootstrap/finish`. Success is only `{locked:false}`; create the invitation afterward. The declared action is `remote.ca.bootstrap`, labelled “Set up machine certificates”. No existing unlock UI hook was present; no product UI or screenshots were added.

First setup atomically publishes private `active/` state: public issuer, remote TLS leaf/key and wrapped administrator copies. CA signing material has no plaintext disk representation. The SQLite writer lock serializes publication and role changes. An interrupted in-memory installation recovers only published public trust, still locked, then requires fresh proof to unlock the retained copy. Retained trust is never replaced. Administrator grants without recipient keys remain pending per D151; their own device wraps the same unlocked issuer. Role changes advance generation, remove the old copy and preserve at least one current retained issuer-matching copy. Removing the last administrator is refused. HTTPS trust is independent of machine trust, with an explicit leaf pin or public system roots; legacy invitations remain compatible.

## Regressions and real lifecycle

The independent review patch reproduced both original admission failures: 0/2 passed in 0.39 s; the fixes passed 2/2 in 0.27 s. The final HTTP regression uses eight distinct canonical sources and an explicit body-read notification, proving that all eight anonymous slots are held despite the per-source cap. The first-bootstrap HTTP test returned 404 before implementation. The fixture wait regression failed 0/1 in 0.00 s on the old try-acquire path. The QUIC relay regression failed 0/1 in 2.77 s on the old liveness settings, then passed with acknowledged idle probes and a silent-path timeout. The test accelerates the same configuration helper to 50 ms/250 ms; production uses 15 s/60 s. Acknowledged probes preserve healthy connections; four intervals tolerate transient loss while bounding expired NAT paths.

The release lifecycle exposed a TLS leaf subject equal to its issuer subject. OpenSSL cold path-building failed 0/1 in 0.00 s; distinct subjects passed 1/1. Self-review reproduced last-copy removal with only pending remaining grants (0/1, 0.76 s) and a lost public memory projection after durable publication (0/1, 0.83 s). Both fixes passed in the complete saved source:22 CA-administration tests passed, 4 ignored, 22.21 s; server/all-target clippy passed.

A real stripped release server process bootstrapped without a fixture signer in its serving process, cold-restarted locked and unlocked its retained copy through actual registered signed passkey verification. A local rootless infraternal agent consumed an invitation on private stdin, joined and persisted its identity, reconnected and renewed with the same key. Owner revocation closed a live authenticated QUIC observer using that actual renewed identity. The final test asserts the observer is live before revocation and receives an application close afterward. The registered passkey is software-backed; this is real verifier/crypto/process evidence, not physical hardware or browser evidence.

Measured on infraternal-dev, 8 cores, load 8.46/7.59/8.58: bootstrap 99.871 ms; join CLI→durable identity 46.545 ms; reconnect→durable renewal 731.182 ms; revoke→live QUIC close 21.390 ms. The test ages only public ledger half-life metadata 302400 s to exercise the normal scheduler without waiting 84 h; seven-day DER certificates stay unchanged. Timing excludes the deliberate 1.1 s fixture delay. Evidence: `r11-e2e3.log`; the final stricter lifecycle run is recorded on #78.

## Performance and bounded memory

All measurements ran locally under `systemd-run --user --scope -p CPUWeight=10000`, without own build overlap. No load generator or perf VM was used. Optimized musl server tests measured:

| Measurement at 1000 records/sources | Result | Limits |
|---|---:|---|
| Source admission, 100000 calls | mean 114 ns | One represented source reused while 1000 source permits remain held; isolated bucket policy |
| Source map payload |113344 bytes | Capacity 1792; excludes allocator/hash control, not RSS |
| Live administrator guard | p50 55.950 us, p99 106.630 us | SQLite memory, begin/read/rollback included |
| Actual CA unlock finish, 100 samples | wall p50 1.058 ms, p99 5.894 ms |1000 real private copies, one measured registered principal; excludes client signing/HTTP/setup |
| Unlock process CPU | p50 1.204 ms, p99 1.892 ms | Coordination included; wall scheduling differs under load |
| Unlock process RSS |15608→15908 KiB |1000 copy/record metadata; not 1000 online passkey devices |
| Encrypted copies retained RSS |15252→15544 KiB |1000 envelopes, 499175 serialized bytes; HTTP/database/passkey excluded |
| Copy publication with durability | p50 9.436 ms, p99 16.904 ms |1000 disk copies; fsync/rename/directory sync included |
| Bounded private copy reads | p50 51 us, p99 4635 us | decode included, GCM opening excluded |

Scale load was 6.56/7.20/7.89 through 7.94/7.47/7.98. Admission cost projects 114 us per 1000 calls. Five source maps at the measured 1000-entry shape total 566720 bytes of counted payload; this is arithmetic, not allocator-inclusive RSS. Anonymous/owner HTTP pools each hold 8×8192 bytes; CA bodies 8×32768 bytes: combined application payload cap 393216 bytes. Source maps cap 4096 entries each; known address hints cap 10000. Anonymous TLS 48 slots plus 16 known slots are separate from 48 two-second TCP first-byte checks and 16 100 ms NAT probes. Per-source limits prevent one address taking all capacity. Every hint still requires durable certificate authority and control admission. No cleanup worker is added. At 1000 live hosts, 15-second keep-alives imply 66.7 scheduled probes/second; this is cadence arithmetic, not measured wire bandwidth.

Three alternating paired optimized malformed CA-body diagnostics at 1000 requests measured baseline p50 2940/5228/2952 ns and p99 32863/50633/25664 ns; protected p50 65247/63739/64850 ns and p99 3110239/130956/338141 ns. Median p50 adds 61898 ns/request, 61.898 ms per 1000. The live administrator check before reserved body capacity justifies this cost. Shared load 37.77/32.62/24.54 makes tail latency noisy. Both executables were optimized musl builds; the baseline diagnostic's static `profile=debug` label is inherited. Evidence: `r11-baseline-release-build.log`, `r11-release-tests-build2.log`, `r11-body-before-{1,2,3}.log`, `r11-body-after-{1,2,3}.log`, `r11-scale.log`.

## Parser, feature removal and review

The existing CA decoder fuzz target also exercises bounded administrator-role and membership-proof decoders, unknown fields, suffixes and identifier bounds. ASAN completed 2339788 executions in 61 seconds without a crash (`r11-fuzz3.log`). Coverage symbols failed to link with ThinLTO; only the fuzz build used `CARGO_PROFILE_RELEASE_LTO=false`. The shipping profile remains stripped and optimized. New code is behind the remote feature. The CLI stub checks skipped after the ARM size row passed separately on the final tree (`r11-final-cli-stubs.log`). Core-only CLI/all-target clippy passed (`r11-feature-off.log`). `cargo tree -d` showed only existing unrelated version duplicates; no registry dependency was added.

Author review applied the auth B1/S1/S2/N1 checks in `docs/verification/auth.md`: final live session/membership/registered credential authority is rechecked under the writer lock; wrong-purpose, stale, replayed and missing-UV proofs fail; cookie/origin/current authority precede protected body capacity; parser bounds/deadlines and cancellation stay bounded; publication is durable/private and keeps the issuer fixed; pending grants cannot remove the final unlock path; public recovery never unlocks; no secret is reflected or passed on argv; role/storage/HTTP/runtime/liveness modules describe their invariants. The release test uses independent HTTPS trust and actual newly generated CA state. A physical passkey and the separate add-host UI branch still require the owner's end-to-end run.

The first final evidence gate hit a terminal-open refusal while the shared host PTY counter was 4089/4096. The focused real-daemon retry passed all 24 abrupt stops in 39 seconds as capacity freed; no host limit, other job or source was changed and no baseline exemption was used. The complete final gate was rerun. Logs: `r11-final-fast-pty-failed.log`, `r11-final-daemon-retry.log`.

## Atomic commits and sizes

| Step | Commit | x86 bytes / delta | ARM bytes / delta |
|---|---|---:|---:|
| 1. test(auth): wait for bounded fixture hashing capacity | `c8cfe6e1961b` | 18359248 / +4512 | 16347456 / +16 |
| 2. remote(quic): keep idle hosts live and expire silent paths | `e730b602ec6a` | 18359248 / +0 | 16347456 / +0 |
| 3. remote(http): isolate live owner admission from anonymous joins | `f106c1d91c8f` | 18374736 / +15488 | 16361200 / +13744 |
| 4. remote(transport): bound pre-auth sockets and reserve known sources | `98816f8ca9bd` | 18393072 / +18336 | 16376864 / +15664 |
| 5. remote(ca): publish durable Ed25519 issuer material | `7142a63ec9cf` | 18394064 / +992 | 16378048 / +1184 |
| 6. remote(enrollment): keep HTTPS trust independent of machine certificates | `677a2ed80500` | 18403344 / +9280 | 16386864 / +8816 |
| 7. remote(ca): authorize first setup through fresh passkey proof | `20ff2672f054` | 18604752 / +201408 | 16570776 / +183912 |
| 8. remote(ca): rewrap administrator grants by membership generation | `b70464bba6ea` | 18687856 / +83104 | 16646856 / +76080 |
| 9. test(remote): exercise fresh setup and the complete release host lifecycle | `d319b7ae6e48` | 18687856 / +0 | 16646856 / +0 |
| 10. docs(remote): record setup API and production admission contracts | `85af7b8119d9` | 18687856 / +0 | 16646856 / +0 |
| 11. test(remote): fill anonymous admission from distinct sources | `5ae8ff91928d` | 18687856 / +0 | 16646856 / +0 |

Sizes are stripped/static with no PT_INTERP. The base b701a6ea sizes were 18354736 x86 and 16347440 ARM bytes. Final enabled growth is attributable to reachable CA generation/publication and passkey/role HTTP actions, independent HTTPS trust, bounded admission and transport timers; fixtures/docs do not add a shipping dependency. No heavy library was added. Every commit ran `scripts/verify fast`; all non-size rows passed. ARM exceeds the old 16196376-byte limit and is reported under D205, without changing the limit/profile. The size failure stops fast before TypeScript, so the unchanged TypeScript stage passed separately and is repeated on the final tree.

Reproduce with the pinned repo toolchains, private CARGO_TARGET_DIR and TRACER_TEST_PORT=4782. When CARGO_TARGET_DIR is external, temporarily link the worktree target path to it: the existing Zig wrapper and infraternal-agent fixture resolver still read that path. Remove this temporary link after verification. Run `scripts/verify fast`; for the release lifecycle, set INFRATERNAL_REMOTE_TEST_BINARY to the stripped x86 binary and run `cargo test -p infraternal-server --features remote fresh_release_bootstrap_join_renew_revoke -- --ignored --nocapture --test-threads=1`. Ports 4701/7443 must be exclusively available. Run scale diagnostics from an optimized server test executable with `cost_at_1000 --ignored --nocapture --test-threads=1`. Small unedited logs are under `$HOME/.cache/codex-scratch/remote-agents`; #78 is the state of record and records per-commit/final gate output verbatim.

## Final committed-code checks

The stricter release lifecycle passed on the complete committed source. Verbatim public timing record:

```text
REMOTE_BOOTSTRAP_E2E cold_restart_locked=true retained_copy_unlock=true bootstrap_us=83204 join_cli_to_durable_identity_us=33560 renewal_reconnect_to_durable_identity_us=50611 revoke_to_live_quic_close_us=12300 rootless=true fixture_signer_injected=false aged_public_half_life_fixture=true host_key_retained=true machine=infraternal-dev cores=8 load=6.18 6.27 6.27 7/9427 1772339
```

Core-only all-target clippy and the separate TypeScript production stage passed again. The final source had no dependency additions; `r11-final-duplicates.log` records the enabled shipping tree. This evidence-only commit adds zero shipping bytes.
