<!-- Design proposal for #250: replace durable browser layout retry coordination with server-owned state. -->
# Layout retries without a durable browser journal

**Recommendation: no multi-tab durable journal.** Each tab keeps an optimistic
layout and its unconfirmed intents in memory; the server is the only durable
merge point. Show a persistent **Not saved — keep this tab open** state while
edits await confirmation. Closing, crashing or iOS discarding that tab can lose
unconfirmed edits. Confirmed server state survives. This is an owner proposal,
not a change to settled decisions or permission to implement it.

Basis: #250's hunt and three journal reviews (round 1: `8bc0cfc6f`, round 2:
`e157f9b01`, round 3: `a0ffc82d5`), implementation `660aa612b`, and parent #243.
D180/D183/D248 and `contracts/wire.md`, “Account canvas layout”, already provide
ordered intents, snapshots and permanent idempotence receipts. D243 is the
binary-size rule; **issue #243**, rather than D243, delivered server-held layout.
D245 requires device cleanup. D259 budgets terminal reconnect, not the lifetime
of an unconfirmed layout edit.

## Choice and cost

Estimates below are production TypeScript for the replacement path, excluding
retained reducers, server store and tests; they are planning estimates, not
measurements. All durable options still need failed-storage behavior and a
sign-out barrier for *every* private writer, including the drawing cache.

| Shape | Crash/close loss | Sign-out privacy | Complexity estimate | Support and performance |
| --- | --- | --- | --- | --- |
| One writing tab / BroadcastChannel leader / SharedWorker | Memory-only owner loses queued work; durability needs a journal anyway | Requires fencing an old owner and its successors; messages alone are insufficient | 350–600 lines, plus durable storage if required | Safari 17 has these APIs; suspension/owner loss and private-context partitioning still need handling. Election/handoff adds latency. |
| Per-tab durable journal; server merges | Completed successful writes survive reload; quota/eviction still lose work; abandoned keys need discovery | Separating keys prevents overwrite, not writes after sign-out; sessionStorage also needs peer revocation | 250–450 lines plus cleanup/barrier | Storage widely supported, but synchronous and ephemeral in private modes. Per-entry writes avoid full-history serialization. |
| Generation token written before cleanup; checked by writers | Depends on underlying journal | **Insufficient alone:** check, peer sign-out, write still recreates data. Needs an atomic transaction/lock and startup bound to the original authenticated lifetime | 100–180 extra lines atop storage | Web Locks supported at Safari 17 floor; unavailable/rejected storage or locks must disable persistence. Coordination can queue startup/input. |
| **Per-tab memory only; server merges** | **Unconfirmed edits may be lost; confirmed edits restored** | **No layout storage writer exists to resurrect data**; server revokes authentication; peers discard memory on revocation | **160–240 lines** | Existing WebSocket path; no worker/lock/storage dependency. Zero layout storage calls during edits, flush or reconnect. |

Safari shipped BroadcastChannel/Web Locks in
[15.4](https://webkit.org/blog/12445/new-webkit-features-in-safari-15-4/) and
SharedWorker in [16.0](https://webkit.org/blog/13152/webkit-features-in-safari-16-0/).
Availability is not durability: [Web Storage is synchronous and private-mode
data is temporary](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API).
Actual iPhone/PWA/private-mode qualification remains required; none of these
sources proves background execution or reliable unload delivery.

## Ownership, confirmation and sign-out

1. **Each tab owns its live intents.** Subscribe once, paint immediately and send
   semantic operations (existing four-call pipeline). Peers write directly to the
   server; nobody adopts another queue. Keep placeholders local until resolved;
   cancelling a parent rebuilds only its unsent dependent suffix.
2. **Only receipts/events confirm identities.** Retry identical
   `{op_id,base_revision,intent}`. A receipt above canonical retains the overlay;
   one at/below canonical prunes it. Notify on projection changes. After reconnect,
   hide uncertain sent overlays over the snapshot and retry unchanged requests.
   Matching snapshot values cannot prove identity. Retain uncertainty until
   receipt/event, definitive refusal or explicit discard, without blocking
   independent edits. Never expire work after 50 ms. Refusal rolls back its overlay;
   uncertainty must not claim rollback of a possibly committed request. “Saved”
   means every edit is confirmed and represented by canonical state; a capture
   promise means local acceptance only.
3. **Recovery never waits for layout confirmation to draw or type.** Reuse the
   warm screen within D259's 16 ms (8 ms at 120 Hz), resume typing within RTT +
   50 ms; D267 allows four RTTs + 50 ms for fresh links. Request the first gap/
   withdrawal snapshot immediately, then coalesce jittered same-ID retries. Let
   an outstanding snapshot finish before replacement, with a bounded response
   watchdog. Pause offline; resume on welcome/visibility; cancel on disposal.
   Show pending state immediately and one neutral delayed recovery notice,
   including offline-at-capture/no-RTT cases with a finite fallback.
4. **Zero new private layout/drawing/identity cache writes**, including storage,
   service-worker responses and IndexedDB. Keep static app-shell caching. Cold
   offline startup says “Connect to load your layout”; warm offline tabs retain
   their drawing and edits. This changes existing offline behavior (owner question).
5. **Sign-out revokes, then forgets.** Freeze initiating-tab edits during existing
   logout; failure preserves signed-in state and queue. Success deletes this
   browser session and publishes revocation (`auth/sessions.rs`), then teardown
   drops memory/callbacks/timers and sweeps legacy account keys. Peers stop on
   authenticated revocation and revalidate before resuming after suspension.
   BroadcastChannel only accelerates notification. New stores require server
   authentication; callbacks stay bound to the original session lifetime across
   later sign-in. Suspended/offline peers cannot instantly forget RAM, but write
   **zero layout bytes**. Verify the server's queued-call/logout ordering: already
   admitted commits may finish, later admission must fail. Do not promise that a
   browser marker cancels an in-flight call or erases server-held layout.

## Failure cases

Every hunt/review finding is listed; round-2 source-loss sequences are separate.
“Removed” describes the new path, not unchanged old durability tests passing.

| Finding | Outcome and reason under this proposal |
| --- | --- |
| Hunt 1: tab overwrites offline peer journal | No shared queue; live A retains edits. Discarding A loses unconfirmed work under the explicit new contract. |
| Hunt 2: stale sent edit paints over newer snapshot | Uncertain sent overlay stays hidden until its receipt/event locates it. |
| Hunt 3: red toast on each brief drop | Persistent pending state; one neutral delayed notice, definitive refusals remain errors. |
| Hunt 4: repeated Subscribe on slow reconnect | One outstanding snapshot, response watchdog, same-ID bounded retries. |
| Hunt 5: gap waits 250–375 ms before resync | First replacement requested immediately; backoff applies to subsequent retries. |
| R1: adopter deletes a live page's newer write | Removed: no adoption or peer-key deletion. |
| R1: failed replacement deletes sole source | Removed from live path; legacy source retained until confirmed import/export decision. |
| R1: dropping unresolved parent loses resolved child | No foreign placeholders; preserve same-tab resolved child by rebuilding only unsent dependencies. |
| R1: stale unresolved duplicate suppresses completed birth | No persisted duplicate selection; one tab owns birth completion. |
| R1: held receipt changes projection without notification | Receipt transition explicitly publishes a changed projection. |
| R1: live peer recreates signed-out journal | Zero layout persistence; revoked session cannot restart a queue under later login. |
| R1: known receipt 2 replayed over canonical 3 | Prune confirmed identities at/below canonical before projection. |
| R2: concurrent first tabs invalidate each other's lifetime | No shared lifetime creation; independent authenticated stores. |
| R2: sign-out between check and write | No private layout storage write to race with cleanup. |
| R2: unreadable source omitted then retired | No live retirement; migration read failure never authorizes deletion. |
| R2: 33+33 columns exceed 64; omitted source deleted | Server bounds refuse individual invalid intents; no peer union/retirement. Legacy oversized imports retained for export. |
| R2: receiptless edit held through 100 snapshots | Explicit “Not saved” uncertainty with identical retry; no silent success or immortal hidden durable record. |
| R2: failed cleanup leaves 21 generations | No new generations; legacy cleanup failure is reported and retried outside interaction. |
| R2: full-history flush 23.4–38.6 ms at 8192 entries | No serialization/flush. Projection/queue CPU still needs measurement. |
| R2: failed initial marker bypasses peer sign-out | No marker or persistence fallback; server authentication gates live work. |
| R2: completed capture lost before 300 ms flush | Explicitly accepted **only while Not saved**. Confirmed edits recover from server after abrupt stop. |
| R3-01: no-Web-Locks fallback recreates account key | No fallback writer; locks unavailable changes nothing. |
| R3-02: startup queued after sign-out creates replacement lifetime | No startup storage transaction; require current server authentication, invalidate old callbacks. |
| R3-03: cleanup refusal causes 8195 reads per one-entry flush | Zero layout storage reads/writes per live edit or flush, regardless of leftover keys. |

## Replacement and qualification

Against `660aa612b`, delete `storage-journal.ts` (205 lines),
`storage-lifetime.ts` (45), `layout-storage-lock.ts` (14), and about 90 cache merge/
serialization/recovered-ID lines. Replace about 70 storage scheduling/startup
lines in `server-store.ts`, 40 lifetime/key lines in `account-storage.ts`, and 40
offline drawing/identity reader/writer lines. **About 500 lines removed/replaced,
80–140 added; net 360–420 fewer.** Keep intent reducers, reconciliation, the
in-memory queue and server receipts. No new dependency, engine or snapshot field.
Against `origin/dev`, unmerged R3 storage modules are avoided, not deleted.

**Cutover:** old bundles can still write localStorage after logout. Require all
old tabs/PWA instances closed/reopened before claiming zero writers; server
version checks cannot fence old JavaScript storage calls. Legacy layout/import
sources stay read-only until existing `initialize` confirmation (wire contract)
or explicit export/discard. Never silently adopt journals from unshipped branches
or delete unreadable/unconfirmed imports. Sign-out still sweeps them; report
refused cleanup without claiming successful erasure. Transitional cleanup is
separate from the steady-state guarantee.

**Tests:** retain hunt's stale-overlay test; R1 held-notification/covered-receipt
cases; identity, duplicate-event, refusal, late-epoch, placeholder dependency,
account-isolation and teardown controls. Recast storage-specific R1/R2/R3 cases
as zero-layout-write assertions, removing obsolete key/lock setup expectations;
leave originals on their review branches. Replace unconfirmed crash-survival
with explicit advertised loss and confirmed-state recovery tests. Keep native
recovered-ID receipt compatibility coverage. Reuse `review-sync-p3s` notice
regressions (`5916174ee`) and six lifecycle controls; follow D267's four RTTs.

Add real two/three-tab delayed-notification/suspended-startup tests; sign-out
versus late receipt/reference completion, reload and re-login; queued apply versus
logout; failed logout; absent/throwing/recovered storage; uncertainty after 50 ms;
legacy import/refused cleanup/old-client cutover. Use production Chromium,
Firefox, WebKit and iPhone PWA, normal/private modes; attach screenshots for owner
review. No private-mode qualification is claimed by this plan.

**Performance gates:** locked 4-vCPU perf VM, 1/10/60 windows, three tabs,
8192/32768 queued intents: hot capture/rebase/reconnect and typing during recovery.
Count zero live storage operations independently; require layout tasks <=16 ms
and D259/D267 without waiting for receipts. Keep projection incremental; coalesce
only adjacent unsent same-field changes. Bound queue memory by measured bytes
with explicit backpressure, never silent eviction; report per-tab memory ×3/×10.
Prior R3 save/flush maxima were 12.2/2.3 ms on `573dc412e`; R3-03 measured counts,
not time. This plan claims no new latency. Run full fast, D243 same-recipe stripped
size comparison and unchanged transfer caps before implementation handoff.

## Owner questions (recommended answers)

1. **Accept losing unconfirmed layout edits on tab loss? Yes.** Renaming offline
   shows “Not saved”; iOS discarding that tab restores the last server name.
   A confirmed rename survives. Terminal sessions and their content are unaffected.
   This explicitly narrows #250's prior no-edit-loss brief; if rejected, choose a
   separately designed per-tab durable store with an atomic sign-out barrier.
2. **Accept no cold offline private drawing, plus closing old tabs at cutover?
   Yes.** A warm disconnected canvas remains visible; reopening offline asks for
   a connection. Reopening online restores the server layout. This needs an
   explicit owner clarification of D245's fast-drawing expectation; D259's warm
   reconnect budgets remain unchanged. Until those answers, retain current product
   behavior and treat this document only as a design recommendation.
