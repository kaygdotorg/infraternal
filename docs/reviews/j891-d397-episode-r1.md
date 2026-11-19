<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D397 receive queue episode review, round 1 (#260, J891)

**Verdict FIX.** A backward realtime step can carry deferred signals across a
drain shorter than one observation interval.

The product was reviewed at `fef180bc1513a9382a3e4c244644a5373d813969`
after merging dev `982ecf15343716c6eedc64f08d250d37e2f36059` into the
author's head. It pins the mirrored controller
`08a9cdcc1da0c430ac241cc2eb639a7acc46f61e`. Apply
[j891-d397-episode-regressions.patch](j891-d397-episode-regressions.patch) in
the fork to run the three independent tests.

## P2. A short drain can keep deferred signals after a backward realtime step

The test establishes a standing queue and earns four deferred signals by
passing four 216-byte exempt packets at actual signal deadlines. It then
drains the peer's queue. The next packet arrives 6.9 ms after the previous
dequeue. The next ten 1,400-byte Not-ECT packets dequeue across 90 µs and have
fresh receive stamps with an age of 3 ms. Each replay uses a new warmed
controller and its own fresh-controller control.

| Realtime step during the drain | Warm drops | Fresh drops |
| --- | ---: | ---: |
| Stable clock | 0/10 | 0/10 |
| +1 hour | 0/10 | 0/10 |
| −1 hour | 4/10 | 0/10 |
| −7 ms | 4/10 | 0/10 |

`gotatun/src/aqm.rs:367–375` requires agreement between the monotonic gap
and the receive timestamp's comparison to the previous wall clock. After a
backward step the new receive stamp sorts before the previous dequeue wall
time. The monotonic gap is shorter than 10 ms, so the expiry rule also does
not clear the old evidence. The new run inherits the previous run's deferred
signals before it can establish a new episode. In the −7 ms case, the resumed
dequeue wall time is still 2.9 ms ahead of the previous dequeue wall time.

Clear the episode and deferred signals when a valid age puts the arrival
after the previous dequeue on the monotonic timeline but the wall comparison
disagrees. Keep the two-clock agreement for immediate byte-credit renewal.
A test-only candidate keeps the original drain test and adds an episode reset
when the monotonic gap exceeds the valid age while elapsed realtime does not.
It passes all 247 fork tests (ten ignored) and reproduces 3,523 signals per
100,000 fresh-stamped packets under stable and stepped realtime, for both
Not-ECT and ECT. All four mutations fail via assertions, covering drain
recognition, evidence expiration, overdue rebasing and equality at the
catch-up boundary.

The actual fork library fails by assertion on the independent red test.
The other two tests check strictly future scheduling at the exact catch-up
boundary and saturating timing arithmetic with zero and huge configuration
values. The unmodified fork library passes 244 tests with ten ignored.
Logs live on dev-02 under
`/home/claude/.cache/codex-scratch/j891/evidence/`, including
`independent.log`, `short-step-original.log`, `clock-disagreement-candidate.log`,
`fork-followup-run.log` and `fork-lib.log`. Product and native Mac gate receipts
are tracked on #260.
