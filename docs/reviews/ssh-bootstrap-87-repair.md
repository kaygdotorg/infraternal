<!-- Records the independent SSH provisioning repair regressions, measured limits and review evidence for #87. -->
# SSH host provisioning repair round (#87)

Base `d0290f6e`; merged `dev` at `7d6df447` in `5c428697`.
The final head and exact gate output are recorded on issue #87.
The eight review regressions are repaired in separate gated commits. Every
reported red run precedes its corresponding production fix.

| Review | Repair | Red / green evidence |
| --- | --- | --- |
| R01 P1 | Drop the unfinished manual module export; retain committed-source completeness test | archived tracked source 0/1; source 1/1 |
| R02 P1 | A refused owned service stop preserves artifacts and linger for retry | 0/1 0.11 s; installer 12/12 0.42 s |
| R06 P1 | Pending host confirmation stays under logout, expiry and disconnect lifetime | 0/1 2.63 s; bootstrap API 7/7 4.89 s |
| R07 P1 | Retain KnownHostsCommand; dynamic trust refuses file-only first-contact and pin bypass | real review 0/1 0.27 s → 1/1 0.33 s; real trust 2/2 4.11 s |
| R03 P2 | Retire the owned group before reaping its naturally exited leader | exact review 0/1 0.02 s; bounded oracle 0/1 1.01 s → process 4/4 0.30 s |
| R04 P2 | Clear linger intent after an acknowledged refusal or no-change result; retain it on interruption | review 0/1 0.05 s; no-change0/1 0.06 s → installer 15/15 0.93 s |
| R05 P2 | Bind fresh cleanup to a protected receipt outside its removed stage | review 0/1 0.21 s; four restart/admission cases 0/4 0.11 s; linked owner 0/1 0.11 s → installer 23/23 2.82 s |
| R08 P2 | Make SSH removable from both CLI and server dependency graphs and runtime paths | actual review 0/1 0.25 s → both graph closures pass; no-default all-target check 38.92 s, 13 test-result rows, strict clippy 12.06 s, CLI build 42.61 s |

The R03 review assertion originally checked immediately after asynchronous
SIGKILL delivery. The retained oracle uses the existing cancellation test's
one-second termination bound. It still fails on the original code. Production
completion has no added sleep or polling timer.

## Parser evidence

The exact production public-policy parser and workspace-locked dependencies
ran through coverage-enabled ASan cargo-fuzz: 914,448 executions in 46 s,
2612 counters, final cov=666 / ft=2276, RSS 476 MiB, max_len=65537, zero crashes.
Seeds include active/disabled command policy, duplicates, control bytes and the
size limit. A preliminary ASan run without coverage instrumentation is excluded.

## Performance evidence

Eight concurrent production helper calls, 800 commands/run; current-thread
Tokio debug controller, 8-core infraternal-dev, CPUWeight=10000, shared load
24.86–28.38. This relative pilot is not full provisioning acceptance.

| Case | Before p50/p99 | After p50/p99 | Controller memory |
| --- | --- | --- | --- |
| Normal exit, two alternating pairs |16.805–18.749 /75.195–96.883ms |18.001–18.229 /62.692–64.504ms | both 1 thread; RSS 4060–4104 /4120–4176KiB |
| Pipes close before leader exit |45.298 /128.476ms |48.666 /138.391ms | both 1 thread; RSS 4144 /4136KiB |

Natural exit must be acknowledged before group retirement to preserve leader
status and prevent signalling a reused identity. A measured blocking-pool
candidate retained 10 threads and 4308KiB RSS at the same eight-helper limit;
the repair uses existing asynchronous SIGCHLD instead.

## Merge integration and visual evidence

The dev merge exceeded the deferred tracer transfer budget: gzip 51871/51200,
Brotli 45276/45056 bytes. Deferring the existing details reader and formatter at
its popover boundary restores gzip 51023/51200 and Brotli 44612/45056.
The existing live subscription remains eager. Existing details browser tests
pass 4/4. Real production-build screenshots with public mock data:
`evidence/ssh-bootstrap/repair-round/screenshots/details-desktop.png` (1440x900),
`details-phone.png` (393x852). Visual quality requires independent review.

## Scope and remaining acceptance

The repaired code enrolls a node into an existing trusted invitation; it never
creates a server. The production default remote runtime still lacks real
join/facts/terminal integration and a signed-release catalog. Synthetic manager,
CLI and readiness fixtures prove recovery behavior, not a live remote install.
Full phase latency, whole-server scale and production readiness remain
unproven. No real SSH host was contacted and no real host key was accepted.

## Reviewer checklist

- Whole-batch validation and bounded admission remain before any host mutation.
- Origin, owner, live session and confirmation proof remain at the publication boundary.
- Dynamic native trust is retained; first-contact and pin paths cannot bypass it.
- Stop refusals retain artifacts; interrupted linger state stays recoverable.
- Cleanup receipts bind the original directory identity and refuse links, tampering,
  writable parents, unrelated directories and committed installations.
- Helper cancellation and natural exit retire owned descendants; parser fuzzing
  uses the actual coverage-enabled production parser.
- Cargo feature removal is checked independently for the CLI and server.
- AGPL declarations, transfer budgets and both stripped static binary budgets pass.
- Plugin shutdown is tested for queued hosts, interrupted control, real helpers,
  idle sockets, blocked writes and confirmations; scale evidence is below.
- Production remote enrollment and whole-server acceptance remain unproven;
  production screenshot quality still requires independent review.

## Resumable cleanup boundary

A fresh public receipt is stored beside the installation directory before its
transaction stage is deleted. It records host, transaction and the original
device/inode identity; it contains no login material. Restart tests cover stage,
owner and base deletion. An older attempt that already lost its only ownership
proof cannot safely be inferred to be fresh rather than committed; it requires
operator review. Blind deletion of an unowned directory remains refused.

## Plugin boundary

The shared API and metadata are additive draft interfaces. They reference the
owning serialized shapes without selecting a new schema or adapter engine.
SSH declares ordered action instructions, defaults, an existing-server
prerequisite, and permission to enable only the infraternal agent component.
No public CLI command is added; the generic skill/adapter generator remains #10
work. Existing wire request shapes remain compatible.

The SSH backend implements the shared `Plugin` controller. Disable closes
admission, cancels registered batches, and waits for host attempts and
confirmations through their cleanup. Interrupted shutdown stays closed;
re-enabling drains old leases and never resumes cancelled batches. Construction
starts no background task or timer. Six actual controller cases pass in 0.01 s,
including a real native helper and 100 queued targets.

The trusted server adapter holds a lease through socket teardown and admission
permit release. Off interrupts idle sockets, pending confirmation lookups,
stalled sends and Settings key lookups. Off refuses new admission and returns
uncached unavailable key responses; other server authentication stays valid.
Ten actual API cases pass in 6.95 s. Both CLI and server pass their complete
no-default test suite and strict all-target clippy after this integration.

Two alternating actual workspace-binary scale pairs, debug current-thread,
CPUWeight=10000, 8-core infraternal-dev, load 10.68/10.20/10.17:

| 1,000 targets / 10 batches | Before | After |
| --- | --- | --- |
| Backend concurrency peak | 8 | 8 |
| Elapsed |56 /49ms |65 /95ms |
| Baseline /held RSS, pair 1 |4424 /7904KiB |4864 /8600KiB |
| Baseline /held RSS, pair 2 |4556 /8108KiB |4808 /8544KiB |
| Held queue delta |3480 /3552KiB |3736 /3736KiB |

The measured additional held memory is 184–256KiB per 1,000 targets
(~0.18–0.26KiB/target). At the declared 1,600-target maximum, the queue estimate is
~5.84MiB, an increment of ~0.29–0.40MiB. Fixed binary/fixture RSS differs. Elapsed
time increased in this pilot; the accounting buys explicit refusal and
acknowledged retirement without an idle worker or timer. These controlled
unavailable-backend numbers exclude full-server and live-installation budgets.
Raw logs: `evidence/ssh-bootstrap/repair-round/plugin-lifecycle-paired-scale.log`.

## Commit and gate record

| Step | Commit | Full fast gate |
| --- | --- | --- |
| R01 missing module |599c3cf4 |r01-recheck-fast.log |
| dev integration |5c428697 |merge-recheck-fast.log |
| R02 stop refusal |1d99f6c3 |r02-fast.log |
| R06 confirmation lifetime |77f5eefc |r06-fast.log |
| R07 configured trust |9239c052 |r07-fast.log |
| R03 helper lifetime |14b70d8e |r03-fast.log |
| R04 linger intent |5bc14bca |r04-fast.log |
| R05 resumable cleanup |230fe3e4 |r05-recheck-fast.log |
| R08 build removal |4dd4fd7f |r08-fast.log |
| Shared plugin interface |9fb6a2f0 |plugin-api-recheck-fast.log |
| Shared API dependencies |5c34de1a |plugin-deps-fast.log |
| SSH declarations |dff31f78 |plugin-manifest-fast.log |
| SSH controller |063e75b6 |plugin-controller-fast.log |
| Server adapter |1c84f91a |plugin-adapter-fast.log |
| Funded restart oracle |487ef1ef |restart-credit-fast.log |

Every listed completed gate exits 0. Logs are under
`evidence/ssh-bootstrap/repair-round/`; issue #87 retains each head and its
verbatim gate summary. No load-sensitive exception has been used.


The final source build is stripped and static on both targets (`PT_INTERP`
absent): x86_64 **16,577,392 / 16,783,792 bytes**; aarch64
**13,942,912 / 14,143,720 bytes** (actual / maximum).

Final documentation gate: `evidence/ssh-bootstrap/repair-round/final-fast.log`.

## Verification-oracle repair

The first documentation gate failed the daemon restart test at iteration 22/24
in 38.19 s; the unchanged targeted rerun failed at iteration 1/24 in 11.79 s.
Both received the whole replay but left the final 17 input bytes unacknowledged,
then reported the intentional terminal queue close. Host load reached
34.03 / 24.24 / 16.01. This is outside the allowed #118 exceptions and was not
waived.

Each attachment already grants 1 MiB of output credit, more than its at-most
512 KiB restart replay and 17-byte fence. The oracle unnecessarily refunded
64 KiB chunks behind the forwarded replay, competing in the eight-command
admission queue. The repair consumes the funded window without refunds only
for that restart drain. Exact payload/fence, complete input acknowledgments,
errors, deadlines and the separate saturation oracle remain unchanged.
Production code is unchanged. Targeted restart and saturation cases pass in
40.41 s and 35.95 s. Their failing and passing logs remain in the evidence
folder; the separately gated harness commit is `487ef1ef`.
