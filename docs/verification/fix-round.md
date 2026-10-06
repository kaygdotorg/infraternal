<!-- Auth/server fix-round evidence, limits and reviewer handoff for #28, #29 and #30. -->
# Auth and server fix round

This round started from server `6e5d956` and client `7a5e5db`, on `t-server`
and `t-web`. Nothing was pushed or deployed. D108 is the owner's #30 instruction;
the supplied DECISIONS.md ends at 86 and is unchanged. docs/PROCESS.md is absent.

## Regression evidence

Every targeted finding was reproduced before its fix at these starting heads.
The retained tests exercise SQLite, the approved ES256 verifier, actual Unix
socket pairs and actual WebSockets; browser checks use native Chromium resident
passkeys, PRF and WebCrypto against the real Rust router.

| Finding | Red evidence | Retained regression / correction |
|---|---|---|
| Public identified login (#29) | known UUID returned 200, expected 401 | `audit_no_public_credential_listing`; matching authenticated fresh tap only |
| Failed unwrap/logout 429 (#29) | session remained valid after failed local unwrap | `audit_logout_survives_admission_exhaustion`, pending-unlock expiry regression; production `check-unlock.mjs` injects corrupt nonce and logout 429 and asserts ordinary session 401 and signed-out reload |
| Cross-browser ceremony (#29) | browser B redeemed A's proof with 200 | `audit_ceremony_browser_binding`; hash of host-only cookie checked before consuming proof |
| New enrollment prompts (#30) | browser expected one native get, received two; enrollment/discovery inputs differed | enrollment/discovery constant-input test; native v3/v1/v2 prompt counts 1/2/2 |
| Live socket revocation (#28) | logout followed by Ping received Pong | `revoked_idle_socket_loses_all_authority`; live dispatch/output check, expiry deadline and committed-revocation notification |
| Shared actor isolation (#28) | full one-byte queue blocked beyond 100 ms | `full_output_queue_must_not_block_shared_actor`; full queues retire only that attachment, bounded writes |
| Pre-Hello admission (#28) | socket 17 upgraded, expected denial | `half_open_sockets_obey_user_limit`, `expired_handshake_releases_user_permits`, `fragmented_wire_frame_has_a_completion_deadline`; socket 17 denied, half-open slots released after five seconds, incomplete frame ends at 5001 ms |
| Multi-device offsets (#28) | fresh device inherited session Ack 77, expected zero | `second_device_does_not_inherit_first_device_input_ack`, ownership/u64/capacity/non-reuse tests; durable independent writer Ack and stable leg-B identity |
| Restart credit (#28) | replacement received only AttachTerm, no Credit(1024) | `reattach_must_restore_output_credit`; Output(3) + Snapshot(7) leave exactly 1014, output sequence remains 3 |
| Close handling (#28) | dropped stream receiver restarted all sessions; clean control Close became 1011 | `stream_close_must_not_restart_all_sessions`, `clean_control_close_is_not_an_internal_error` |
| Client resume negotiation (#28 follow-up) | enforcing RESUME_NEXT left pending b undelivered (expected ab, got a) | existing terminal browser replay test; Hello advertises bit zero only before adjacent Resume |

New enrollments use SHA256(`infraternal/keywrap/prf/v3`) [D108]. Stored NULL v1
and UUID-derived v2 inputs retain the existing local second prompt; no automatic
rewrap, ciphertext relabeling or AAD change occurs. The server cannot observe
local GCM failure. It withholds terminal authority until unlock completion,
retains pending sessions for a fixed five minutes without sliding reads, and
makes exact-Origin logout exempt from both admission layers.

## Scale and gates

Machine: x86_64 KVM, eight Intel i9-9900K vCPUs at 3.60 GHz. These are local
measurements, not physical-phone/network or pinned performance-VM evidence.

- Live socket authority: 16 simultaneous sockets × 200 Ping/Pong rounds = 3200;
  release p50 1062 us, p99 2091 us, load 3.11/2.33/2.67. This includes local
  WebSocket control traffic and SQLite authority reads, not PTY rendering.
- Shared actor: four queued events on one stalled reader, 511 healthy readers,
  200 one-byte events each = 102200. Development p50 below 1 us, p99 3 us,
  load 1.21/1.75/2.18. This isolates actor dispatch; it does not measure large
  payloads, network or total production memory.
- Auth, 1024 pending, two real ES256 credentials, n=200 per row; load
  2.12/3.36/2.83. Identified challenge p50/p99 81/190 us at 0..200 and
  96/221 us at 824..1024. Discovery including binding p50/p99 4/19 us and
  4/22 us respectively. Signed finish including binding and pending unlock
  transaction p50/p99 434/800 us. Entry 1025 denied. Inline Login is
  136 bytes × 1024 = 139264 bytes (excludes heap/hash-table allocations).
  Whole-process RSS 13028→14484 KiB (+1456 KiB); discovery reuses allocations.
  These retain the 1 ms challenge and 10 ms finish local budgets. SQLite memory
  and server verifier only; client signing is outside finish timing.
- Writer lookup: 16 connections × 32 writers = 512, 3200 release lookups,
  p50 224 us, p99 504 us, below the 1 ms local budget; same load and SQLite
  memory. This is full per-user retained capacity, not global 8192 simultaneous
  streams or disk durability. Verbatim measurements are posted on #28/#29.
- Native auth gate passes four isolated scenarios on Chromium 149.0.7827.55.
  Paired production tracer checks prove v3/v1/v2 native prompt counts 1/2/2 and
  failed unwrap/logout 429 denies authority. An intermediate paired run was
  invalidated by a concurrent production-build asset replacement; stable-build
  reruns pass. A missing Playwright executable was installed under HOME.
- An intermediate browser suite under concurrent builds reported p99 29.8 ms,
  failing its 20 ms limit. With this job no longer building, the final browser
  suite passes 4/4: 500-key probe p99 16.40 ms, time-to-resume 77.00 ms.
  No threshold was relaxed. Final gate output is posted verbatim on the issues.

Production screenshots are in the client `apps/tracer/test-results/` Playwright
attachments (onboarding 390×844 and desktop; returning sign-in light/dark and
terminal). They are supplied for review; this job does not approve visual quality.

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
nix shell nixpkgs#gnumake nixpkgs#perl -c scripts/verify browser
bun scripts/browser-auth/check-tracer.mjs ../t-web/apps/tracer/dist
AUTH_TEST_PRF_VERSION=v1 bun scripts/browser-auth/check-tracer.mjs ../t-web/apps/tracer/dist
AUTH_TEST_PRF_VERSION=v2 bun scripts/browser-auth/check-tracer.mjs ../t-web/apps/tracer/dist
bun scripts/browser-auth/check-unlock.mjs ../t-web/apps/tracer/dist
cargo test --release -p infraternal-server discoverable_latency_at_pending_capacity -- --ignored --nocapture
cargo test --release -p infraternal-server writer_admission_at_user_capacity -- --ignored --nocapture
# In t-web/apps/tracer, after the production build:
bun x playwright test
```

## Self-review and remaining blockers

The auth checklist B1/S1/S2/N1 in `docs/verification/auth.md` was checked:
transaction authority/counters, exact Origin/cookie boundaries, native browser
and legacy-envelope proofs, and module/invariant comments. Existing approved
webauthn-rs/OpenSSL [86] remains; no foundational engine or dependency was added.
Revocation notification follows commit, live expiry checks fail closed, pending
reads never extend expiry, writer ownership is pinned under the SQLite writer
lock, and unsigned Ack remains an eight-byte big-endian blob. Socket permits
release through owned RAII guards and full output queues never await consumers.
Parser bytes are unchanged; the fast gate retains stream differential/fuzz-style
split schedules, and the existing parser fuzz targets remain available.

#28 is not fully done. `crates/infraternal-agent/src/lib.rs` contains no host
daemon implementation and `infraternal agent --fd` exits "not implemented".
Production daemon-to-real-PTY multi-device deduplication and crash replay cannot
be proved from this checkout. The backend must implement the recorded per-writer
identity/deduplication contract above the raw-byte shim. Beyond the existing
120-second connection resume window the client needs a durable writer capability
before safely replaying unacknowledged input; the current v1 fields cannot prove
which writer accepted it. This limitation and the requested additive contract
choice are recorded on #28. Physical Safari/iPhone testing and independent
security/visual review remain external. No green gate is claimed as proof of
these missing integrations.

## Merged-dev follow-up (#34)

The missing-daemon statements above describe this standalone fix-round checkout.
Merged dev now contains the real inherited-socket daemon and independent shim
writers; real shared-device PTY deduplication/crash replay and native browser
acceptance are recorded in [integration.md](integration.md). The beyond-120s
writer-capability choice and physical-device/independent review boundaries remain.
