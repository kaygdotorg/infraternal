<!-- Records the author security/custody review for #154; independent review is still required by PROCESS §2. -->
# Author checklist

- [x] Exact production pin retained; no merge, dependency, engine or decision change.
- [x] No production access, deployment, host-key acceptance, credentials lookup or load generators.
- [x] Scope includes memory source, provider/wrapping/export copies, mapping syscalls, enrollment/renewal and runtime.
- [x] D168 cold/no-timer semantics separated from the stronger failed-update continuity requirement.
- [x] Original authority, single-use ceremony, exact purpose, counter/credential, membership-generation and session checks retained.
- [x] Real passkey/SQLite/AES-GCM/OpenSSL/socket/exec tests, not verifier mocks.
- [x] Persistent mlock gap reproduced in an isolated process; no production leak inferred.
- [x] Signature no-op and absent deployed signed-update client recorded without claiming unsupported replay/channel/refusal tests pass.
- [x] Path inode pinning distinguished from in-place modification; no crafted candidate executed by unsigned-admission test.
- [x] Supplementary Worker source pinned by revision/hash, not described as deployed; actual SSHSIG also checked by ssh-keygen.
- [x] Failing audit event test recorded before instrumentation. Only unlock audit logging may change production behavior.
- [x] Logs/fixtures contain no private material; generated signing keys remain in memory, public verify artifacts are removed.
- [x] New files have role documentation; no new UI, actions, polling tasks or foundational libraries.
- [x] Audit guard covers successful/refused/canceled parsed authority attempts and accurate installed/error custody outcomes.
- [x] Before/after 1000-membership/100-unlock formatting numbers recorded with machine/load and limits.
- [x] Every non-size fast row passes; the existing size ceiling is reported, not raised.
- [x] Remote-disabled build verified; atomic commits and #154 step/finish record updated.
- [x] Only own scratch/build artifacts removed after evidence preservation.

The author checklist is not an independent review or a live production update proof.

## Authorized hardening follow-up

The initial checklist above records the logging-only audit scope. The follow-up
brief authorizes CA-01/CA-03 here and SIG-01/SIG-02 on signer-hardening.

- [x] Existing pinned OpenSSL and auth fixed-window admission reused; no engine selection.
- [x] Root initialization refuses result 0/2; non-root warns; initialization precedes inherited signer import and cold key generation.
- [x] Secure import counter tested, because VmLck alone can describe only an unused heap.
- [x] Raw seed persistence/handoff format and cold/no-timer authority remain unchanged.
- [x] Transient intake uses existing page ownership; buffer release precedes authority awaits.
- [x] Signer validates/hashes the same VERSION read; canonical signed identity derives channel from requested version.
- [x] Filename refusals are static and occur before publishing output/pointers.
- [x] Legacy signatures preserved; identity-aware consumers require the additive manifest without fallback.
- [x] UP-01/02/03 remain deferred with signed admission, sealed-descriptor and preflight notes.

- [x] Shared start budget covers cookies/routes; principal isolation, clock/window/capacity boundaries and unchanged ordinary auth response are tested.
- [x] Actual imported-seed secure allocation, root refusal and real handoff tests pass.
- [x] 10,000-key and 4,096-principal diagnostics include load/scale and explicit limits.
- [x] All repaired regressions pass; deferred UP regressions still reproduce; no zero-test filter or load waiver is counted as proof.
- [x] Both branch gates pass every non-size row; ceilings/deltas remain explicit.
- [x] Remote-disabled build passes and only the authorized branches are pushed.

Evidence and scope limits are appended to README. Independent review remains separate.
