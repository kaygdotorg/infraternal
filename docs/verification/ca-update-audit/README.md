<!-- Records defensive CA custody and release-verification evidence for the exact production pin, #154. -->
# CA custody and update verification audit

> Historical raw receipts were removed under D262. `run-audit.py` writes per-phase output under
> `$HOME/.cache/codex-scratch/ca-update-audit-<phase>/evidence/` by default and honors
> `INFRATERNAL_EVIDENCE_DIR`; attach fresh receipts to #154 with the `issue-attach` helper.

Scope: branch `audit-ca-update`, production base
`15d15c257c6985c838b41f6db5216b6544f60bd0`, 2026-10-11. No production
access, deployment or key inspection. All cryptographic fixtures use ephemeral
synthetic keys; tests never print or persist private material. Findings are
appended below as tests run. Only the unlock audit event may change production
code. Unresolved regressions are explicit ignored tests, run with `--ignored`;
they must fail until their security property is implemented.

## Contract and implementation boundary

Read CLAUDE.md, DECISIONS.md, docs/ARCHITECTURE.md, docs/PROCESS.md and all
104 existing #154 comments before work. No parent is linked. D168, D224 and
D226 are absent from this pinned DECISIONS.md; their owner-approved definitions
were read from the existing local `origin/dev` object, without changing decisions.
D168 locks on cold start, transfers only in memory on update; D224 requires
built-in signing and spare public keys and SSHSIG namespace
`infraternal-release`; D226 derives channel from signed VERSION (stable semver,
edge UTC timestamp) and forbids silent stable-to-edge fallback.

Production facts supplied by the orchestrator (not independently observed here):
core limit 0, fs.suid_dumpable=0, no swap, VmLck 0 kB, no secret environment or
argv. A plain systemctl restart is a cold start and locks by D168. This audit
cannot claim that a production CA remained unlocked during a real signed update.

The pinned source has no `apps/release-signer/src/index.js`, channel-fetch,
signed VERSION verification, release key pin, archive extraction or automatic
signed-update client. The available apply boundary is local server restart.
`restart_binary.rs:95` accepts every file passed to its signature hook. External
operator verification is documented in `docs/operations/deploy.md`; it is not
client verification. Crafted VERSION/SHA256SUMS/channel cases cannot exercise
nonexistent real verification code. The audit tests the actual opened-fd boundary
and records these cases as unimplemented rather than substituting a mock verifier.

## Summary

| ID | Severity | Property | Result |
| --- | --- | --- | --- |
| CA-01 | P2 | Persistent unlocked key pages lack mlock | FAIL; unresolved, mitigated by supplied host policy |
| CA-02 | P2 | Unlock custody event absent | FAIL before; PASS after authorized audit event |
| CA-03 | P2 | No temporal budget on CA starts | FAIL; unresolved |
| UP-01 | P1 | Replacement signature hook is a no-op | FAIL; unresolved |
| UP-02 | P2 | Opened inode remains writable before exec | FAIL; unresolved |
| UP-03 | P1 | Late exec failure stops existing service | FAIL; unresolved |
| SIG-01 | P1 | Worker accepts absent/mismatched VERSION | FAIL; supplemental newer source |
| SIG-02 | P2 | Worker accepts newline manifest names | FAIL; supplemental newer source |

## SIG-01 — P1: Worker can publish an unbound release identity (supplemental source)

Source not deployed in the audited pin: `origin/dev` at
`c0239ad6f24f921072dbca2829506ea5e65f8629`,
`apps/release-signer/src/index.js:86–117`. Worker source SHA256
`f55fbc9a5f3df4d6b88e7395f68b7afbbbc65094752d11e803a412b73539c746`.
`signer_missing-version` and `signer_mismatched-version`: **FAIL**, HTTP 200
instead of the regression's required refusal (409). A stable `1.2.3` request
with no VERSION, or with VERSION containing `edge-20261011T071500Z`, is signed
and publishes a stable pointer. Worker signs sorted SHA256SUMS in namespace
`infraternal-release`. When present, VERSION's file hash is covered, but its
presence and equality to the requested version are not checked. The pointer's
version, channel, file list and signed_at are separate unsigned metadata.
This is not a claim that a correctly implemented client must accept these
releases: it must independently require signed VERSION, equality to the pointer,
selected channel and monotone version (explicit rollback is separate).

Test `signer_coverage`: **PASS**, real WebCrypto Ed25519 and independent ssh-keygen verification of the
Worker's SSHSIG; altered SUMS and another public key refuse, VERSION bytes
are hashed. R2 uses an in-memory storage fixture; private keys exist only in
this test process. No production key, Worker endpoint or credentials are read.
The historical signer receipts were removed under D262. Reproduction output for
the `after` phase goes under `$HOME/.cache/codex-scratch/ca-update-audit-after/evidence/`.

## SIG-02 — P2: Worker permits ambiguous checksum filenames (supplemental source)

Same source, `apps/release-signer/src/index.js:91–109`.
`signer_unsafe-name`: **FAIL**, HTTP 200. Flat object name `artifact\noutside`
contains no slash and is included unescaped in a line-oriented SHA256SUMS.
The signer should refuse control characters before signing. A strict client
must also refuse ambiguous or path-bearing manifest entries. No archive parser
exists in the production pin, so archive extraction safety is not claimed.
The historical unsafe-name receipt was removed under D262. Fresh phase output
goes under `$HOME/.cache/codex-scratch/ca-update-audit-after/evidence/`.

Reproduce supplemental tests by extracting that exact public source object to a
job scratch `.mjs` file, then running `node
 docs/verification/ca-update-audit/signer-audit.mjs <snapshot> <case>`.
Cases: `coverage` passes; `missing-version`, `mismatched-version`, `unsafe-name`
are committed failing tests. The harness refuses a different source hash.

## CA-01 — P2: persistent unlocked key pages are not locked

`crates/infraternal-server/src/ca.rs:67–69`, `ca_memory.rs:174–180`,
`ca/wrapping.rs:68,133–145`, `ca_handoff.rs:53–60`.
Test `unlocked_signer_requires_persistent_locked_pages`: **FAIL**,
`unlocked_ca_vm_lck_kib=0`, one unlocked server in an isolated process with
PR_SET_DUMPABLE=false. Matches the supplied production VmLck observation.
Persistent Ed25519 state lives in the OpenSSL PKey allocation, referenced by
CaMaterial clones (EVP_PKEY_up_ref), not by independent Rust seed clones.
Signer handles used for enrollment, renewal, bootstrap and handoff keep the
provider key alive until the final reference drops. There is no explicit lock
operation or timer. Cold restart discards the process address space.

Pinned OpenSSL 3.6.3 source: `crypto/ec/ecx_key.c:81,105` allocates with
OPENSSL_secure_zalloc and clears the private key on final free;
`crypto/mem_sec.c:183–190` falls back to ordinary zeroed heap when the secure
heap is uninitialized. No secure-heap initialization exists in the repository.
This source review is not a dynamic proof of post-free zeroization.
Rust wrapping/export buffers use Zeroizing, but are ordinary, movable heap
allocations until copied into LockedBytes. Parsed HTTP intake also retains
ordinary body Bytes until drop. No CA private PEM or DER serialization is used;
`ca_bootstrap.rs:171–175` serializes the separate remote TLS leaf key.

Dedicated handoff buffers are page-aligned, mlocked and MADV_DONTDUMP, maximum
4096 bytes requested, 2090-byte frame. Export peaks at two 4 KiB pages (8 KiB ×
one simultaneous server transfer); receive needs one page. The raw OpenSSL
export vector and persistent key are outside those mappings. Anonymous socket
kernel buffers hold the bounded frame and are not user-zeroizable. Drop clears
full dedicated mappings with volatile writes before unmapping (source review).

Production no-swap/core-limit facts and first-entry PR_SET_DUMPABLE=false mitigate
exposure; **no production key leak is observed or claimed**. Persistent-page and
transient-body protection remain limitations, not assurance from a green gate.
Evidence: `before-unlocked_signer_requires_persistent_locked_pages.txt`.

## CA-02 — P2: successful unlock lacks a custody audit event

`crates/infraternal-server/src/ca_administration.rs:301–304` (before change).
`unlock_audit_records_principal_time_outcome_without_material`: **FAIL before**,
0 events instead of 3 for success, replay and failed decrypt. This confirms the
orchestrator's journal observation on synthetic real-passkey authority.
The authorized additive audit event is implemented in a separate commit;
after-test results will be appended. No material or proof diagnostic is allowed.
Evidence: `before-unlock_audit_records_principal_time_outcome_without_material.txt`.

## CA-03 — P2: concurrency admission does not provide a temporal request budget

`crates/infraternal-server/src/ca_http.rs:71,113–125`,
`ca_administration.rs:201–207`, `runtime.rs:819–821`.
`sequential_unlock_starts_require_a_temporal_budget`: **FAIL**, 31 successful
starts in 72 ms. Eight concurrent HTTP/crypto permits, a 1024-entry pending
registry and a five-second deadline bound simultaneous work/storage, but no
per-principal/time bucket protects these routes; the auth middleware's temporal
budget excludes `/remote/ca/`. Requires an already authenticated administrator;
this is availability hardening, not an unlock bypass. The regression proposes
30/minute (matching ordinary auth) for owner discussion; this audit does not
change a contract or select the final budget. Existing concurrent-admission and
expired-ceremony tests remain required.
Evidence: `before-sequential_unlock_starts_require_a_temporal_budget.txt`.

## UP-01 — P1: actual replacement admission does not verify a signature

`crates/infraternal/src/restart_binary.rs:95–97`;
`restart.rs:258–260,303`. Test
`unsigned_or_tampered_replacement_is_refused_before_exec`: **FAIL**, all four
unsigned/tampered/truncated/65 MiB sparse candidates admitted, zero executed.
The actual verify_release_fd hook always returns Ok. No pinned public key,
signed manifest, signed VERSION or downgrade/channel policy is consulted.
An eligible root-owned marked replacement can consequently receive a handoff
without any release signature check. Root ownership and all protected parent
checks still apply: this is not an unauthenticated remote execution finding.
External operator verification is currently the only documented release control.
Do not rely on this path as client-side signed update verification.
Evidence: `before-unsigned_or_tampered_replacement_is_refused_before_exec.txt`.

## UP-02 — P2: opened inode pinning does not freeze its contents

`crates/infraternal/src/restart_binary.rs:35,86`, `restart.rs:303`.
`admitted_inode_cannot_change_in_place_before_execution`: **FAIL**. After
Opened::open accepts a fixture, rewriting that same inode changes the bytes
visible on the retained descriptor. A pathname rename to another inode is
protected (`pathname_replacement_keeps_the_admitted_inode`: **PASS**), but a
future implemented signature hook must also address writes to the accepted
inode before exec. Today's no-op verifier is UP-01; this test is not evidence
of bypassing an implemented cryptographic check. Current operational policy
already forbids modifying staged executable inodes in place.
Evidence: `before-admitted_inode_cannot_change_in_place_before_execution.txt`.

## UP-03 — P1: late exec failure removes the running service

`crates/infraternal/src/restart.rs:359–370`.
`unusable_admitted_image_keeps_the_existing_service_running`: **FAIL**. Empty
executable passes admission; replace shuts down its runtime; fexecve refuses;
replacement returns failure and the prior listener is gone. Supervised recovery
is cold and locks, contrary to the owner's stronger failed-update continuity
requirement. D168 allows failed handoff to count as cold, so this records that
specific owner requirement gap rather than altering the decision. Refused paths
and failed replies before shutdown do keep serving (existing regression suite).
Evidence: `before-unusable_admitted_image_keeps_the_existing_service_running.txt`.

## Verified boundaries and limits

All following tests use the production implementation, not authentication or
cryptography mocks. New audit tests complement existing regressions rather than
duplicating the existing passkey/HTTP fixtures. Initial targeted run:
`ca_update_audit_tests` 3 PASS (the protection-failure test was added after this
binary built), replacement audit ordinary tests 2 PASS, handoff 7 PASS,
administrator authority 23 PASS/6 existing or explicit audit ignores. Updated
counts will be appended after the current source is rebuilt.

| Property | Real test | Result/evidence |
| --- | --- | --- |
| Fresh registered administrator passkey; replay refused | actual_passkey_unlocks_cold_ca_once_and_leaves_no_extra_browser_session | PASS; before-ca_administration_tests.txt |
| Revoked role/session, changed generation, removed credential, expiry refuse | revoked_membership_or_original_session_cannot_finish_an_existing_ca_ceremony; changed_generation_expired_session_or_removed_credential_cannot_unlock | PASS; same transcript |
| Ordinary login/foreign session cannot authorize unlock | ordinary_login_ceremony_has_no_ca_unlock_purpose; foreign_browser_cannot_consume_the_original_ca_unlock_ceremony | PASS; same transcript |
| Wrong wrap key/missing UV fails closed | wrong_wrapping_key_or_missing_user_verification_leaves_ca_locked | PASS; same transcript |
| All 32 ciphertext/16 tag bytes refuse and static CaError formats contain no seed | every_ciphertext_byte_and_tag_mutation_refuses_without_material_in_errors | PASS; before-ca_update_audit_tests.txt |
| Public-only HTTP response, static/empty parser refusal, 32 KiB bound | ca_http_real_passkey_unlock_returns_only_lock_status_without_a_session_cookie; ca_http_parser_is_bounded_and_errors_do_not_reflect_wrapping_material | PASS; before-ca_administration_tests.txt |
| No timer, 1000 signer loads remain usable, wrong issuer leaves live signer intact; cold locks | no_timer_locks_signing_and_wrong_issuer_cannot_replace_the_unlocked_source | PASS; before-ca_update_audit_tests.txt; finite validation is not an elapsed-time proof |
| Handoff socket CLOEXEC, failed prepare preserves signer, dumpability disabled | handoff_descriptor_is_close_on_exec_and_prepare_failure_preserves_source | PASS; before-ca_update_audit_tests.txt |
| Same PID/UID exec succeeds; different PID refuses | real_exec_retains_unlock_but_another_process_cannot_import_the_channel | PASS; before-tests.txt |
| Truncation/version/issuer/trailing-byte/malformed frame refuses; cold successor stays locked | real_exec_failures_and_killed_receiver_never_unlock_a_cold_successor; parser_property_corpus_is_bounded_and_never_accepts_trailing_bytes | PASS; before-tests.txt; 4097 lengths plus every-byte mutation |
| Handoff pages lo/dd in kernel smaps; descriptor cleanup failure closes fd0 | serialized_seed_frame_is_locked_and_excluded_from_core_dumps; failed_null_open_or_duplication_closes_private_stdin | PASS; before-tests.txt |
| Process dumpability disabled at actual CLI entry | process_dumpability_is_disabled_before_dispatch | PASS; before-process_dumpability_is_disabled_before_dispatch.txt |
| Final symlink, parent escape, writable executable refused | symlink_parent_escape_and_writable_candidates_are_refused | PASS; before-audit_tests.txt |
| Path replacement retains original inode | pathname_replacement_keeps_the_admitted_inode | PASS; before-audit_tests.txt; real fexecve regression also in full gate |

Error secrecy follows the zero-field CaError/RemoteEnrollmentError types, static
HTTP status mapping, absence of private-material Debug/Serialize implementations
and the source scan, as well as tested malformed input paths. It is not possible
to force every allocator, syscall, database or provider failure using these tests;
no exhaustive post-drop heap, compiler zeroization, root memory-access or kernel
buffer-clearing proof is claimed. Core limit zero is a supplied production fact;
generated unit `install.rs:171–174` does not set LimitCORE explicitly, while
`main.rs:701` disables process dumpability before loading any CA material.
The only helper restoring dumpability is the existing SSH prompt authentication
path after detaching stdin; child-launch and fd0 regressions are retained.

## Required update-case coverage

| Crafted input/property | Actual available boundary | Result |
| --- | --- | --- |
| Tampered/unsigned binary | Opened::open → verify_release_fd | FAIL, admitted (UP-01) |
| Tampered SUMS | Worker real signature over SUMS, supplemental source | PASS: altered signed message refuses; no production client parser |
| Signature by another key | Worker SSHSIG verified with another public key, supplemental | PASS: cryptographic refusal; no production public-key pin |
| Valid signed older release/downgrade under a new version | No production VERSION/current-version verifier | UNIMPLEMENTED; UP-01, not a passing downgrade test |
| Cross-channel edge signature on stable | Worker stable request with signed edge VERSION | FAIL signer identity check (SIG-01); client channel validator absent |
| Stable pointer pointing at edge | Worker publishes that exact inconsistent pointer in mismatched-version case | FAIL signer consistency; production pointer consumer absent |
| Truncated/oversized file | 0-byte /65 MiB sparse opened candidates | FAIL admission (UP-01); handoff frame bounds independently PASS |
| Symlink/path tricks | Opened path symlink/parent escape/writable checks | PASS; archive extraction absent, not assessed as safe |
| Archive/manifest names | Worker newline flat filename | FAIL (SIG-02); nested paths skipped by Worker, no production extractor |
| TOCTOU pathname rename | Retained file descriptor, real fexecve regression | PASS; same-inode write FAIL (UP-02) |
| Signer unreachable | Local replacement never contacts signer or enforces release proof | No fail-closed online update client exists; cannot assert keep-running behavior from an absent endpoint |
| Failed exec | Actual runtime replacement with unusable admitted file | FAIL keeps-running property (UP-03); custody recovered cold |

Version grammar in the reviewed Worker is the regex
`[0-9]+\.[0-9]+\.[0-9]+` or `edge-[0-9]{8}T[0-9]{6}Z`, fully anchored.
It checks syntax only (not canonical semver leading zeros or Gregorian dates).
Channel is derived from the request string; signed VERSION contents are not
compared. No observed client field can be declared safely trusted: the client
is absent at this pin. The cryptographic signature covers file hashes and exact
VERSION bytes when present, not unsigned pointer fields or anti-rollback state.

## Gate setup evidence

First invocation stopped because make was not on PATH. The existing Nix store
GNU make was selected on this job's command PATH; nothing was installed or
modified outside the worktree/scratch target. Initial test-only Clippy warnings
were corrected without suppressions. The next initial run was interrupted when
`umask 002` produced mode0775 executables and the unchanged replacement trust
check correctly refused them; two control fixtures then awaited a successful
replacement indefinitely. This was fixture configuration, not a permission-check
exception. Subsequent runs use `umask 022`, CPUWeight=10000, two Rust harness
threads, `TRACER_TEST_PORT=5854`, and the isolated job CARGO_TARGET_DIR. Owned
scratch executables were normalized to remove group/world write. No #118 waiver
has been used. Initial full fast gate completed: fmt, VT native fmt, Clippy, workspace tests and
cargo-deny PASS; only the known static-size ceiling fails. x86 stripped static
PIE/no PT_INTERP is 20,064,976 bytes vs ceiling 16,404,816. Server 296 PASS/35
ignored. Final post-instrumentation results are recorded below.

## CA-02 resolution — authorized audit event only

`crates/infraternal-server/src/ca_administration.rs:234–374` now emits
`server_ca_unlock` with server-attributed user, wall-clock Unix seconds and
outcome. A scope guard records success, refusal and cancellation; installation
is marked before the rollback await so a later error/cancellation cannot claim
custody stayed locked. No proof, cookie, key, envelope or error diagnostics enter
the guard. Unknown/foreign/replayed ceremonies use `<unattributed>` rather than
an input-supplied identity. This adds no timer, background task, dependency or
authority change. HTTP syntax/header refusals outside parsed finish are unchanged.

`unlock_audit_records_principal_time_outcome_without_material` at
`crates/infraternal-server/src/auth/ca_unlock_audit_tests.rs:26`: **FAIL before**
(0 events), **PASS after** (4 events: success, replay refusal, wrong wrapping-key
refusal, database-wait cancellation). It asserts principal/time/outcome and that
captured output contains no fixture cookie/ceremony or material-bearing field
names; the guard structurally cannot receive proof or key buffers. Cancellation uses the real SQLite pool with its only connection held.
Evidence: `before-unlock_audit_records_principal_time_outcome_without_material.txt`
and `after-unlock_audit_records_principal_time_outcome_without_material.txt`.

## Before/after cost and final targeted results

Same real-passkey benchmark, 100 finishes with 1000 active administrator records,
1 registered credential and encrypted envelopes in SQLite, GNU debug build on
infraternal-dev (8 logical CPUs), `systemd-run --user --scope -p CPUWeight=10000`.
No concurrent build/browser command of this job and no generated host load.
Capture formats real JSON events in memory; kernel/journal I/O is excluded.

| Measurement | Before | After |
| --- | ---: | ---: |
| Finish wall p50 | 3.557 ms | 3.847 ms |
| Finish wall p99 | 8.205 ms | 9.963 ms |
| Finish process CPU p50 | 3.806 ms | 4.061 ms |
| Finish process CPU p99 | 6.921 ms | 6.355 ms |
| RSS before → after | 36,832 → 37,816 KiB | 35,464 → 36,432 KiB |
| Audit events / formatted bytes | 0 / 0 | 100 / 26,800 |
| Load before (1/5/15 min) | 6.90 / 14.64 / 20.30 | 18.56 / 27.23 / 23.88 |
| Load after (1/5/15 min) | 8.20 / 14.31 / 20.04 | 15.20 / 25.92 / 23.52 |

Observed median wall delta is +0.290 ms (+8.2%); p99 +1.758 ms. Shared-host load
windows differ, so these are diagnostic observations, not a causal logging
estimate or a release latency-budget proof. CPU includes harness coordination.
At 100 unlocks the event volume is 26.8 KB (268 B/event), and the observed summed
median delta is 29.0 ms. Unlock is a rare custody operation, not a terminal-input
path; there is no idle task or per-session retained event storage.
Evidence: `unlock-cost-{before,after}.txt`. No production journal-cost claim.

Fresh whole-workspace test binaries were built before both audit phases. The
post-change runner matched every expected result: 5 unresolved production-property
regressions FAIL; repaired audit-event test PASS; ordinary custody 4 PASS,
replacement paths 2 PASS, handoff 7 PASS, administrator authority 25 PASS/6 ignored,
and process-dumpability startup PASS. Supplemental signer coverage PASS and all
3 signer refusal regressions FAIL. Expected failures remain ignored in the
ordinary gate, and the runner explicitly executes them. `audit-{before,after}.txt`
records command status, elapsed time, host/load and each transcript path.
Remote-disabled `cargo check --locked -p infraternal --no-default-features` PASS;
no foundational library or build-time feature was added.

## Post-instrumentation gate interruption and baseline comparison

First post-change fast run had one ordinary socket-test failure:
`auth::tests::socket_tests::review_control::pending_mesh_writers_preserve_authority_pool_capacity`
(`review_control.rs:243`). Control pong passed (17 ms), but a queued Result was
not successful after this fixture's two-second freshness window. Initial full
pre-change gate passed it. Both the exact test on detached local `dev` at
`ded3abd609e5290a7027b6888ecd9864a2d30374` and this branch subsequently **PASS**
in the same load window, 2.031s versus 2.004s, pong 1ms versus 2ms. Load was
24.64/28.41/29.30 →25.55/28.53/29.33. This does not reproduce the original failure
on baseline, so **no #118 waiver or causal host-load conclusion is claimed**.
Full gate reruns with one harness thread; no timeout/assertion changes.
Evidence: `fast-final.txt`, `baseline-build.txt`, `socket-baseline-comparison.txt`.

The first serial rerun did not execute tests: after the baseline reused this
job's target, compilation saw protocol metadata lacking this branch's
`CLOSE_SESSION_GONE`/`SESSION_GONE_REASON` despite both constants being present
in its source. Only `infraternal-protocol` debug artifacts in the owned scratch
target were cleared (`cargo clean --profile dev -p infraternal-protocol`,
418 files/56.9 MiB); production source and lockfile were unchanged. Rebuilt
verification is recorded separately; baseline and audit targets should be kept
separate in future reproductions. Evidence: `fast-final-serial.txt`,
`cache-recovery.txt`, `fast-final-rebuilt.txt`.

## Final gate and disposition

`scripts/verify fast` on the unchanged final production/test source, rebuilt
native protocol cache, `umask 022`, `RUST_TEST_THREADS=1`, unique tracer port
5854 and this job's scratch CARGO_TARGET_DIR: **exit 1 only for the known static
size ceiling**. Server tests: **297 PASS, 0 FAIL, 35 ignored**. No #118 waiver.
The earlier socket failure and cache compilation failure remain in evidence.
Verbatim gate summary:

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

x86_64 artifact is stripped static PIE with no PT_INTERP: **20,067,504 bytes**
versus **16,404,816** allowed, over by **3,662,688**. Its own pre-logging build
was 20,064,976 bytes, so the logging change adds **2,528 bytes**. The existing
ceiling is unchanged. This check returns before ARM, so no final ARM pass is
claimed. Separate `ts_verify_fast` **PASS** (154 tracer/36 protocol tests,
compiler, precompression, transfer budget and vendored checksums), because the
Rust size failure prevents the dispatcher from reaching TypeScript. Evidence:
`fast-final-rebuilt.txt` and `ts-final.txt`; remote-disabled check is `feature-off.txt`.

Disposition: CA-02 repaired and tested; **five unresolved production-property
findings and two supplemental signer findings**, with explicit failing tests
committed. No P0 or observed production material leak. Signature verification
cannot be called solid at this pin: the actual replacement hook is a no-op.
No production access, deployment, dependency, decision or other production fix.
The author checklist accompanies this report; independent review is still a
separate PROCESS step, and the issue stays open for owner follow-up.

## Authorized follow-up scope (#154)

The follow-up brief extends the original logging-only audit: repair CA-01 and
CA-03 on `audit-ca-update` from `9bcd5d79660229388efc65511e945e555b853117`;
repair SIG-01/SIG-02 on `signer-hardening` from `origin/dev`
`ded3abd609e5290a7027b6888ecd9864a2d30374`. The original observations and
before-state transcripts above remain historical evidence. No production access,
Worker deployment, decision change or foundational dependency selection occurs.

### Deferred UP-01, UP-02 and UP-03: release-pipeline implementation contract

These findings remain unresolved here and belong to `release-pipeline`'s
signed-lookup/trust engine. The admission sequence must:

1. Verify the exact signed manifest using the built-in pinned release public
   key(s), namespace `infraternal-release`, and its supported canonical format.
   Require exactly one VERSION and unambiguous flat artifact names. Verify each
   selected image and VERSION hash against that manifest; require VERSION to
   equal the signed identity, derive the channel from that identity, and require
   equality with the explicitly selected channel. Unsigned pointer/index fields
   are discovery hints. Enforce monotone versions against durable admitted state;
   explicit signed rollback is a separate policy. Never silently select edge
   when stable has no admissible release. This repairs UP-01.
2. Copy the selected, bounded image into a private memfd; finish all writes and
   apply `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`. Verify the
   signature/hash against the bytes in the sealed descriptor and retain it for
   execution. Both verification and exec must use this same sealed descriptor,
   with no pathname reopen or trust in the still-writable source inode. This
   repairs UP-02, including writes to an already-open inode.
3. Before shutting down the existing runtime, preflight that sealed image in a
   bounded `--self-check` child. It must report the verified signed version and
   exit successfully; pass no CA handoff, proof or secret to that child. Verify
   its reply against the admitted identity. A malformed/unusable/wrong-version
   image or timeout leaves the existing listener, runtime and unlocked signer
   serving. Only after successful preflight may the update perform its normal
   authenticated signer handoff and exec from the retained sealed descriptor.
   This repairs UP-03's currently reproduced late-exec continuity failure.

Preflight does not make later OS exec failures impossible; the pipeline also
needs a tested recovery path for resource failures after shutdown. Preserve the
current unsigned/tampered, in-place mutation and unusable-image failing tests
until their production boundaries are repaired; add signed identity/channel,
rollback, seal and self-check-child regressions against that real engine.

## CA-01 repair and sizing (#154)

The optional shim dependency prerequisite `cadac1dd` reuses the already pinned
OpenSSL. `0f689f46` adds the audited once-only secure-heap boundary and extends
exclusive LockedBytes to the existing 32 KiB HTTP ceiling. `a1e6f85c` initializes
it before cold private-key generation and inherited signer import. OpenSSL return
0 or 2 refuses root startup with a static memlock/dump-protection error; non-root
development logs a warning and continues startup. There is no teardown of a heap
holding live keys. `7ef543a5` streams admitted HTTP chunks into LockedBytes and
drops that mapping before the authority awaits. Transport/kernel chunks remain
outside this allocator; transient parsed/decrypted/exported Rust material stays
short-lived and zeroizing. No exhaustive allocator/root-access/kernel-clearing
claim is made.

Heap initialization alone did not fix imported Ed25519 seeds: the pinned raw
provider importer uses ordinary malloc (`import-probe.txt`, secure delta 0).
The existing DER decoder allocates 32 secure bytes and retains them during real
signing (`import-probe-final.txt`). Unlock and handoff now reuse that decoder
through a fixed 48-byte PKCS#8 in LockedBytes. Persistence, public issuer and raw
handoff formats are unchanged. The repaired regression checks secure allocation
and release deltas as well as VmLck and kernel `lo`/`dd` flags, so an unused locked
heap cannot produce a false positive. Root protection-refusal and real handoff
regressions also pass.

Fresh explicit remote-feature CA suite: **56 PASS, 0 FAIL, 10 ignored**;
`ca01-remote-gates.txt`. The earlier package-only command omitted remote and ran
zero CA tests, so it is not CA verification. The broader shim run had a missing
Zig PATH error; adding the already staged gate toolchain made its public mouse
probe pass. Checkpoint fast attempts retain their mesh continuation failure;
no #118 waiver is inferred. Targeted fmt and remote-feature Clippy pass.

Isolated GNU debug server-library processes on infraternal-dev, **12 CPUs**,
CPUWeight=10000, no own build/browser overlap. Load was **36.98/38.61/31.36**.
The 10,000-key sizing test compares the same real OpenSSL generation path with
and without secure-heap initialization; it is a conservative allocation stress
case, not a claim that a server stores 10,000 host private keys.

| Measurement | Before secure heap | After secure heap |
| --- | ---: | ---: |
| Live private keys | 10,000 | 10,000 |
| VmLck | 0 KiB | 1,024 KiB |
| Secure allocations | 0 B | 320,512 B |
| RSS before keys → live keys | 9,964 → 18,408 KiB | 11,880 → 18,216 KiB |
| Secure bytes after dropping all keys | 0 B | 512 B |

32 B/key × 10,000 = 320,000 B; the remaining 512 B is provider random state.
The 1,048,576 B heap leaves 728,064 B (69.4%) headroom. Locked storage is one
heap per process, not one per session. On this x86_64 host with 4 KiB pages, eight admitted HTTP mappings add at most
256 KiB (other page sizes use 8 × round_up(32 KiB, page_size)); fixed DER imports temporarily add a page each. RSS includes process,
allocator and provider initialization; the -192 KiB live-RSS difference is not
an allocator speed/memory improvement claim or whole-server budget proof.
A real wrapped/unlocked signer fixture separately records VmLck **1,024 KiB**,
RSS **11,332 → 18,840 KiB**, secure usage **832 B**, and a further imported-key
secure delta of exactly **32 B**. Its historical before regression had VmLck0.
The historical hardening receipts were removed under D262. The hardening phase
now writes under `$HOME/.cache/codex-scratch/ca-update-audit-hardening/evidence/`.

## CA-03 repair and admission boundaries (#154)

`0c2cf292` extracts ordinary auth's existing bounded fixed-window mechanism;
`7aebe5af` shares a **30 starts / 60 seconds** budget across unlock, bootstrap
and administrator-membership start routes. Keys are authenticated session user
IDs, so another cookie or ceremony kind cannot reset the budget. Ordinary auth
retains its trusted-IP/device keys and limits. The exact ordinary-auth refusal
is HTTP429, `Retry-After: 60`, body `too many requests`; its capacity refusal is
also preserved. There is no idle cleanup task: expired entries are reclaimed on
admission, with at most 4,096 principals. Backward time cannot reset a window.
Existing fresh-proof authority, concurrency and request deadlines remain required.
Finish/status routes are available after start-budget exhaustion.

The original regression failed **31/31 accepted in98ms**; now **30/31 accepted
in155ms**, with exact refusal headers/body. Cross-cookie/cross-route isolation
passes. Independent helper tests cover principal separation, the 59/60-second
boundary, backward clocks, map capacity and expiry reclamation. Final targeted
fmt/Clippy, helper test and five real HTTP/intake tests pass; no skipped/zero-test
filter is used as proof. Evidence: `ca03-final-{targeted,regressions}.txt`,
`ca03-clippy-retry.txt`, `temporal-boundaries.txt`.

Debug helper-only capacity diagnostic: **4,096 principals**, **1,000 calls**,
wall p50 **109,965 ns**, p99 **360,132 ns**; 12 CPUs, CPUWeight10000, load
**36.16/38.56/32.77**, no own build/browser overlap. At the configured maximum,
4,096 × 30 = **122,880 starts/minute** (2,048/s); summed p50 wall demand would
be 225.2 ms/s. This excludes authentication/SQLite/HTTP/mutex costs and is not a
release CPU or latency certification. It measures reuse of the existing O(n)
reclamation mechanism at its actual bounded capacity. Evidence: `budget-scale.txt`.

## SIG-01/SIG-02 separate Worker repair (#154)

`signer-hardening`, from origin/dev lineage `50a89572`, with decision-only base
head `25e4e026` at resume: SIG-01 `a7c11bfb`, SIG-02 `9e60256d`, documentation
`50be0d21`. **No deployment.** The production branch does not contain the Worker.

- Require VERSION bytes equal the requested version, with an optional single
  final LF; absent/mismatched/extra identity data returns **409** before writes.
  Validate and hash the same storage read.
- Sign additive MANIFEST and MANIFEST.sig with the existing SSHSIG key and
  namespace. Canonical LF bytes are a format line, `version <version>`,
  `channel <derived channel>`, then the exact sorted SHA256SUMS. Index/channel
  pointers remain unsigned hints. Keep SHA256SUMS and its existing signature
  format for operator compatibility; identity-aware clients must require the
  manifest plus pinned-key, selected-channel, VERSION/hash and monotone checks.
- Refuse unsafe/nested filenames with static **400**, rather than skipping them.
  Names are 1–128 ASCII bytes, initial alphanumeric, then alphanumeric/dot/
  underscore/hyphen. Newline, CR, NUL, separators, whitespace, non-ASCII and
  leading option/path syntax are refused before publication.

**23 real Worker tests PASS**, including independent ssh-keygen verification
and version/channel/hash/other-key mutation refusals. SIG-01 missing/mismatched
identity and all14 unsafe-name cases failed before. Exact framing, verify commands
and manual owner deployment notes live in `apps/release-signer/README.md` on that
branch; no binding or key rotation is required. Historical receipts from that
branch were removed under D262; the result summary is retained here.

Worker local WebCrypto/in-memory R2 diagnostic, 30 samples each on this same
12-CPU host, CPUWeight10000, no own build/browser overlap; load36.98/38.61/31.36
→37.30/38.62/31.44. Each extra synthetic artifact has1,024bytes.

| Uploaded files (incl VERSION and executable) | Before wall p50 / p99 | After wall p50 / p99 | Published metadata before → after |
| --- | ---: | ---: | ---: |
| 12 | 5.971 / 72.334 ms | 4.327 / 71.889 ms | 2,092 → 3,389 B |
| 1,002 | 154.055 / 353.751 ms | 132.072 / 390.513 ms | 121,612 → 201,029 B |

The added manifest/signature cost **1,297 B** at12 files and **79,417 B** at1,002.
Unequal noisy-host scheduling does not establish a speed improvement; this is
not deployed Worker CPU/network/storage latency. Reproducer: `signer-cost.mjs
<absolute Worker path> <before|after>` under CPUWeight10000, using baseline Worker
from50a89572 and repaired Worker from50be0d21. Keys remain ephemeral in memory.
Evidence: `signer-cost-{before,after}.txt`.

Signer head50be0d21 full fast: every non-size row PASS; **291 server tests PASS,
0 FAIL, 32 ignored**. Static x86 PIE/no PT_INTERP **20,294,992 B** vs ceiling
**16,404,816 B**, delta **0 B** versus its same-base pre-fix gate. ARM is not run
because the existing x86 size failure returns first. Verbatim summary:

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

## Hardening milestone gate and author disposition

On the repaired production source: **303 server tests PASS, 0 FAIL, 35 ignored**;
all non-size Rust rows PASS. The initial resume fast attempt stopped at the
latency-proxy self-test (configured300ms, observedp50347.05ms/p99347.93ms).
The unchanged retry passed at295.81ms median/302.09ms p99 and finished every
Rust row. No timeout/assertion changes or #118 waiver. Static x86_64 is stripped
PIE with no PT_INTERP: **20,090,448 B**, ceiling **16,404,816 B**, over by
**3,685,632 B**. Delta versus9bcd5d79/cadac1dd (**20,067,504 B**) is
**+22,944 B** for the CA protection/admission changes. The existing ceiling is
unchanged; ARM is not reached. Evidence: `milestone-fast{,-retry}.txt`.

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

The separate TypeScript phase passes (154 tracer /36 protocol tests, compiler,
precompression, transfer budget and vendored checksums): `ts-fast.txt`.
Remote-disabled `cargo check --locked -p infraternal --no-default-features`
passes: `feature-off.txt`. Ordinary auth's original recovery/source-admission
regression also passes: `ordinary-auth-admission.txt`.

The updated `run-audit.py --phase hardening` uses fresh workspace test binaries
and its own evidence directory. All11 expected results match: repaired CA-01,
CA-03 and CA-02 PASS; custody5 PASS/1scale ignore; ordinary replacement2 PASS;
handoff8 PASS; administrator authority27 PASS/5existing diagnostic ignores;
startup dumpability PASS. The three UP-01/02/03 regressions are deliberately
executed and still **FAIL**, as required by their deferred scope. This is not a
passing signature-admission or failed-update-continuity claim. Evidence:
`audit-hardening.txt` and `hardening-*.txt`.

Author checklist reviewed for the changed memory, authority and signer surfaces.
No production access, deployment, foundational engine choice, decision change,
price or credential lookup. Only audit-ca-update and signer-hardening are pushed.
The final branch-head recheck and head SHAs are recorded on #154 with verbatim
gate output; the issue remains open. Independent review and the owner's manual
Worker deployment remain separate from this completed repair scope.
