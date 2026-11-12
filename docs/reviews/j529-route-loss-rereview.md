# J529 route-loss re-review (#483)

Verdict: **REQUEST CHANGES** on `j485b-mesh-dns-route-loss-review-fixes` at
`c51c91fe67be9a1c5bd4d043c0415835d9c2c479`.

## Findings

1. **P2: failed DNS cleanup retains a stale success cache.**
   `dns_integration.rs:214–230` short-circuits identical cached records, but
   invalidates the previous install only after its removal succeeds. The
   NetworkManager removal first empties the marked file, then reloads DNS.
   A failed reload leaves the old install cached over an empty durable file.
   Returning to the old suffix snapshot silently returns `Ok(())` without
   retrying or restoring forwarding rules. The independent regression
   `review_j529_failed_cleanup_does_not_cache_previous_success` fails on that
   unexpected success, exit 101. Invalidate the success shortcut when resolver
   mutation starts or fails, while retaining safe cleanup ownership.
   Issue finding 92383; receipt `dns-failed-cleanup.log` attached there.

2. **P2: route repair writes through an unrelated replacement link.**
   The deletion listener records a proven interface index, but
   `wireguard.rs:726` resolves `infraternal0` by name again for the repair.
   Rename the owned link to `j529-owned`, create an unrelated dummy link named
   `infraternal0`, and remove the peer route from the original link. The worker
   installs `10.254.0.2/32 proto 250` through the unrelated dummy. Exclusive
   creation protects an existing destination, not the identity of the link.
   `review_j529_repair_does_not_follow_a_reused_interface_name` fails on that
   foreign-interface write, exit 101. Bind repair writes to the proven link
   identity and refuse a replacement.
   Issue finding 92384; receipt `interface-reuse.log` attached there.

## Scope and verification

All builds and test runs used compute01, build-slot, nice -n10, one job target,
`CARGO_BUILD_JOBS=4`, and a private 0700 TMPDIR. Resolver mutations used private
filesystem mounts. Routing and daemon fixtures used disposable user, network,
mount and PID namespaces. No production or mesh-staging access, shared live
mesh mutation, deployment, target-branch push, or issue closure.

The original fixes remain verified within these limits:

- Fixed root-owned resolver candidates include protected Nix profiles; canonical
  executable and ancestor checks reject replaceable paths. No PATH search is
  used. Missing discovery reports the tool and candidate list. Nix discovery
  and missing-tool/identical-snapshot retry regressions each pass 1/1.
- Fresh-process marked dnsmasq cleanup passes 1/1. Successful cleanup can run
  twice; unrelated and unmarked files survive. A failed reload retains an empty
  marker for retry. Finding 1 concerns the separate in-memory success shortcut.
- Ten existing DNS units pass, including exact DNS-only NetworkManager reload
  arguments (`general reload dns-full`) and ownership/rendering checks.
- J485's red-first route assertion against pre-fix source
  `3086ef47019c795f1c7675436544dd9eb2b27e30` fails on protocol `static`, exit 101.
  Current original ownership/retirement and J519 restart regressions each pass
  1/1, verifying protocol 250 and preservation of foreign routes. The reviewer
  also stops the new repair worker before deleting routes in the restart
  fixture, so reconstruction must come from restore rather than a live repair;
  the strengthened case passes 1/1 (`restart-after-worker-stop.log`).
- J519's original configured-link networkd fixture without a live repair
  worker still loses both protocol-250 routes, expected exit 1. The current
  live-node repair/foreign-route regression passes 1/1 on systemd 257.13.
- Three changed-file reloads with one peer preserve both routes. Each reload
  emits two deletes and two adds, with no self-sustaining churn observed.
  Three reloads with 256 peers preserve all 512 accepted routes. The larger
  run's text event capture is incomplete; its inventory assertions are the
  evidence for convergence, not its event counts for latency or churn.
- The original Nix NetworkManager 1.58.1 fixture again deletes both static
  routes under the old cleanup reapply, preserves protocol-250 routes, and
  preserves them under DNS-only reload. `NM_ROUTE_SURVIVAL_PASS`, exit 0.
  The garbage-collected test dependency was restored from the repository's
  locked nixpkgs input before this successful rerun.

## Event-driven repair and recovery gap

The worker blocks on netlink and a cancellation stream with an infinite
`poll` timeout. It has no polling timer and reacts only to deletions, not its
own route additions. The one-peer repeated reload test shows one repair per
external deletion, rather than an autonomous reload loop.

There is **no finite worst-case recovery bound** in this implementation.
Scheduling and the route-state mutex delay handling; a failed add is warned
without retry. A listener error exits the worker, and only a subsequent `up`
checks for a finished worker. There is no event-loss resynchronization path.
The successful 256-peer run is not proof of overflow/error recovery.

The original measurement stamps notifications when an `ip monitor` reader
consumes text, not when the kernel deletes or adds a route. Buffered output
can compress that interval. The author's 5/1,078 microseconds and this review's
1,758/16 microseconds are observer samples, not worst-case kernel outage
measurements. No performance-budget acceptance is claimed.

Before another patch round, state the ownership and partial-failure invariants
explicitly: the same proven link must receive the repair; mutated resolver
state must not use an old success shortcut. Also decide how listener loss
reconciles the complete accepted inventory. Do not treat larger buffers or a
single-peer timing sample as a correctness proof.

## Reproduction

Run on compute01 through build-slot and nice -n10, within the Nix development
shell, with a private TMPDIR and a job-specific CARGO_TARGET_DIR:

```sh
bash scripts/review-j519-dns-regressions review_j529_failed_cleanup_does_not_cache_previous_success
unshare -Urnmpf --mount-proc cargo test --locked -j4 -p infraternal-plugin-mesh --test restart_route_ownership --no-default-features --features agent,server,relay,test-support review_j529_repair_does_not_follow_a_reused_interface_name -- --ignored --exact --nocapture
J529_PEERS=1 bash scripts/review-j519-networkd-route-repair review_j529_networkd_reload_recovers_all_peers
J529_PEERS=256 bash scripts/review-j519-networkd-route-repair review_j529_networkd_reload_recovers_all_peers
```

The first two deliberately fail on the reviewed implementation. The latter
two exercise three changed-file reloads each. Generous timeouts are hang bounds,
not functional assertions about speed.

## Receipts and gate

Raw logs and command runners are retained outside the checkout under:

- compute01: `/home/claude/.cache/codex-scratch/j529/evidence/`
- control: `/home/kayg/.cache/codex-scratch/j529/evidence/`

Selected receipts are attached to #483. The full disk initially blocked the
launcher and later held the corrective route build at build-slot's disk floor.
No other jobs' files or host configuration were changed. Initial route green
attempts incorrectly reused the red binary from the shared Cargo target;
those zero-test/stale-line results were invalidated and retained under
`invalidated-cache-reuse/`. Cleaning the mesh package and rebuilding produced
all current route results cited above. The discovery tests had a separate
feature fingerprint and each actually ran its named current test.

The reviewer-specific brief forbids quick/fast reruns. The author's full gate
from #483 comment 92306 was inspected: every Rust table row is PASS and the
runner ends `VERIFY_FAST_EXIT=0`. The complete author gate and runner logs are
retained with the evidence. No reviewer full-gate pass is claimed.
