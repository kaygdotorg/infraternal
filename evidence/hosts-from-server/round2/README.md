<!-- Round 2 regression, adapter, transfer and VM measurement evidence for #194. -->
# Round 2: admitted hosts

R2 is repaired in `1ba38b50`: the client reads every bounded server page, including
10,001 offline admissions (79 pages), without a total-host cutoff. Publication
remains atomic; duplicate IDs, malformed cursors, superseded generations and
socket loss remain guarded. The server's account-scoped authoritative ledger and
128-row / 60 KiB page bounds are unchanged.

R3 is repaired in `bca017fa`: palette dispatch and Settings navigation load on
selection. Inventory and current palette rows remain available independently of
that chunk. Existing D188 limits are unchanged. The imported fixed public metadata
regression passes at deferred gzip 50,736 / 51,200 and Brotli 44,801 / 45,056 bytes.
Ordinary head metadata in the TypeScript milestone passes at gzip 50,735 and
Brotli 44,886 (170 bytes margin). Critical JavaScript, every on-demand chunk and
fonts pass. `transfer-metadata-gate.log` is the actual fixed-metadata gate output.

R1 is designer work, as instructed by the repair brief. No surface or style was
built. `6207c15a` proves the toolbar's existing `SessionService` exposes offline
admission, connectivity/removal notifications and UUID opening. The same API is
documented in `contracts/remote-host-inventory.md` and on #194. The imported
`hosts-new-window-review.spec.ts` remains a failing UI regression for designers;
it is not represented as passing.

The independent offline-open/reconnect/withdrawal browser regression passes.
`769a1b3e` also repairs the original fixture's single-session interference using
an offline refusal and waits for the new subscription and completed empty reply.
Fresh storage, offline labels, UUID routing, reconnect without duplicates and
removal while the palette stays open pass. Settings/About and the macOS lock action
also pass after dispatch is split. Functional test durations in the raw logs are
build-host diagnostics, never performance evidence.

The author checklist was run: one account-ledger source; no new dependency,
transport or authority model; item/byte bounded pages; complete publication;
welcome/refusal/disposal fencing; UUID routing; shared SessionService; no designer
UI; unchanged budgets; owned fixtures and processes; no credential searches.

`review-red.log` records R2 and R3 failing before repairs. `inventory-tests.log`,
`adapter-tests.log`, `transfer-tests.log`, browser logs and `ts-fast.log` retain
checks. The TypeScript milestone passes 188 tracer tests and 36 protocol tests.
The parallel native milestone fails three unchanged CLI process deadlines; they
are outside #118 exemptions, so no exemption was used. The raw milestone is
retained and a complete serial final gate follows it.

VM measurements use the prebuilt x86 static server, real PTYs and fresh browser
contexts at fixed 300 ms RTT, under `flock -w 3600 /var/lock/perf-bench.lock` on
`infraternal-perf-test` (the named 4-vCPU / 7-GB target). Builds and artifact copies
occur outside the lock, and the lock is released between runs. The frontend
baseline is `efac27a598027a09abd008df952629a3cb549de5`; the candidate production
bundle was built at `769a1b3e` after the R2/R3 code fixes. That first artifact precedes the
selection repair below; the final artifact is built at `d18da979`. Server SHA-256 is
`54a774d4b7799718c336df9ea849bd5e6d60c212026d42e0bebda91c09e2b098`.

| Hosts / order | Samples per variant | Baseline median / max (ms) | Candidate median / max (ms) | Candidate inventory before first glyph |
| --- | --- | --- | --- | --- |
| 1,000 / baseline first | 12 | 1,369 / 1,569.5 | 1,555.7 / 2,400.8 | 0/12 |
| 10,000 / baseline first | 6 | 1,339.1 / 1,601.7 | 1,361.6 / 2,414.2 | 0/6 |
| 1,000 / candidate first | 12 | 1,552.2 / 2,416.7 | 1,379.9 / 2,415.7 | 0/12 |

The final admitted host appears in every candidate trial. Raw JSON retains every
sample and each run's before/after load averages. The reverse run also retains
existing public mount/client/attach/paint timestamps. The direction of the
1,000-host median difference flips with run order; slow client initialization
occurs in both variants before terminal attachment and inventory. These small
samples support the structural/request-order guarantee (inventory starts after
the first glyph), not an exact zero-cost or statistically established p99 claim.
No slow sample is discarded.

The newly built x86 static binary is 22,512,464 bytes, exactly the prior branch
artifact size. Its frozen limit remains 16,404,816. The original dev baseline was
already 22,464,880; round 2 changes no native source and raises no limit. This
inherited static gate failure is retained rather than called green.

The later author check found and repaired a delayed window-selection race from the
R3 split (`d18da979`): split/new/close now retain the event-time window and reject
closed/replaced records. `action-target-red.log` contains three failing-before
cases; the repair passes those plus closed-selection cases, 35 focused tests,
strict TS and three production browser checks. Fixed metadata now passes at
44,811 / 45,056 deferred Brotli; the final production artifact passes at 44,834
(222 bytes margin). Final artifact measurements are retained separately below.
The ARM static binary is 19,935,768 / 13,817,816 bytes, also exactly the prior
branch artifact size; its budget remains unchanged. The milestone retains all
three CLI deadline failures and both inherited size failures.

Final artifact `d18da979`, same native server, six fresh contexts per variant:

| Hosts | Baseline median / max (ms) | Candidate median / max (ms) | Candidate inventory before first glyph |
| --- | --- | --- | --- |
| 1,000 | 1,565.6 / 2,423.3 | 1,558.7 / 1,626.3 | 0/6 |
| 10,000 | 1,413.1 / 2,461.1 | 1,583 / 2,456.7 | 0/6 |

`sign-in-final1000.json` and `sign-in-final10000.json` retain all samples, phase
marks and load. At 10,000, the candidate median is higher in this small sample;
both variants again have slow client initialization before attachment and
inventory. This is not represented as equal overall latency. The structural
first-glyph guarantee is independently maintained: inventory code/RPC start only
after the visible glyph, with 0/42 candidate trials asking earlier across all
runs. Every candidate finds the final host. All VM fixtures/artifacts are removed
and the shared lock released. No sample is dropped or budget raised.

The first serial branch-head full gate (`e06f5f50`) also failed the unchanged
`server_setup_terminal_echo_and_resume_preserve_offsets_once`: unexpected
WebSocket close (`auth/tests.rs:1731`). Server library: 415 pass, 1 fail, 45
ignored. The same binary failed once in isolation and passed its next exact run.
No #118 exemption is used. `serial-head-fast.log`, `echo-isolated.log` and
`echo-backtrace.log` preserve these outputs. Final TypeScript head validation
passes 191 tracer and 36 protocol tests; deferred Brotli 44,822 / 45,056 (234
bytes margin). A complete two-thread head gate is run next, keeping the serial
failure rather than masking it with the isolated pass.
