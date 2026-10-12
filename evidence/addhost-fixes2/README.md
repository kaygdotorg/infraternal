<!-- Records reviewed continuation evidence for host provisioning #169. -->
# Host provisioning continuation

The initial R1 fresh-target batch on the breakit2 test branch reached Done on
7/10 targets; the three readiness failures occurred after upload, join and
start at 4,144, 4,490 and 4,754 ms. Later, ordinary `b4ae9e22` and frozen
pre-fix controls both reached Done 10/10 in the same measurement window, so
those samples do not establish a production failure rate. After the drain
repair, 10/10 fresh supported targets reached Done. The delayed-credit live
regression fails before the repair and passes after it; the socket regression
also reproduces on `b4ae9e22`.

Per-step timings (milliseconds, range of ten samples; detailed load and machine
records in each log). Network discovery refusal is expected before key sign-in.

| Setup step | b4ae9e22 | Frozen pre-fix | Drain repair |
| --- | --- | --- | --- |
| network_discovery | 116.337–172.841 | 118.097–171.324 | 100.332–160.512 |
| key_sign_in | 167.301–207.047 | 171.068–267.897 | 143.945–201.025 |
| check | 119.194–164.251 | 94.489–215.418 | 70.096–106.806 |
| upload | 307.621–1778.055 | 615.057–1313.084 | 303.577–920.620 |
| join | 104.917–567.107 | 103.587–681.248 | 92.918–204.910 |
| install | 80.001–116.852 | 91.869–125.496 | 58.662–136.822 |
| start | 217.573–317.025 | 243.170–362.184 | 153.156–257.324 |
| linger | 36.421–62.103 | 38.712–80.857 | 25.605–50.599 |
| commit | 23.078–66.415 | 23.178–63.246 | 16.969–28.427 |


## Repair coverage

The original breakit2 behavior findings below were present on `b4ae9e22`.
For R1, the delayed-credit ordering reproducer failed on that baseline even
though ordinary fresh-target controls were 10/10 in one measurement window;
neither sample is a production failure-rate estimate. Later review-only
regressions and the primary-retirement race are identified as follow-ups, not
as baseline defects.

| Finding | Fix commit(s) | Existing regression test(s) | On `b4ae9e22`? | Before → after evidence |
| --- | --- | --- | --- | --- |
| R1 | `677ca2f9`, `4955b966`, `61edf2d4` | `ownership_eof_does_not_discard_private_terminal_output`; live `breakit2_live_ssh_install_join_and_terminal` | Yes: delayed-credit output was lost before readiness; ordinary fresh controls were 10/10 in a later window | Before: first fresh batch 7/10 Done, with three readiness failures at 4,144–4,754 ms; b4 socket test 0/1 in 0.00 s; frozen live ordering run failed Done at 4,449 ms. After: socket test 1/1 in 0.07 s and fresh readiness 10/10 in 3.08–4.36 s. Per-setup-step ranges are below. |
| T1 | `e4827f10` | `breakit2_rollback_preserves_foreign_launcher_new`; `breakit2_rollback_preserves_foreign_unit_new` | Yes: rollback removed both foreign `.new` paths | Before 0/2 in 0.26 s; after 32 passed, 0 failed, 2 ignored in 1.16 s. |
| S1 | `554fe436`, `66ed0d63`, `de1d74a2` | `breakit2_unpublished_invitation_retires_durable_authority`; `cancelled_invitation_after_commit_retires_its_host_record` | Yes: refused address persistence left an extra live host record. The cancellation follow-up covers a later publication boundary. | Before 0/1 in 0.13 s; after S1 bootstrap suite 30 passed, 0 failed, 3 ignored in 22.46 s. The later cancellation case was red 0/1 in 0.09 s and its suite passed 32/0/3 ignored in 14.87 s. |
| S2 | `11a673e6` | `breakit2_concurrent_same_destination_issues_only_one_invitation` | Yes: eight concurrent requests received eight identities | Before 0/1 in 0.12 s; after one host-bound attempt and seven “already being added” results; bootstrap suite 31 passed, 0 failed, 2 ignored in 18.43 s. |
| T2 | `72672e9b` | `breakit2_stage_refuses_parent_that_cannot_be_rolled_back` | Yes: staging admitted a parent rollback later refused | Before 0/1 in 0.12 s; after 33 passed, 0 failed, 1 ignored in 2.12 s. |
| T3 | `d2661eb5`, `a17ccb21` | `breakit2_interrupted_lock_creation_allows_cleanup_and_retry`; `interrupted_acquisition_cleanup_receipt_can_resume` | Yes: an interrupted lock creation could not be authenticated for cleanup | Before 0/1 in 0.04 s; recovery follow-up red 0/1 in 0.24 s; after install suites 34 passed in 3.89 s and 39 passed in 2.28 s. |
| T4 | `eb047f72` | `full_stage_frees_payload_before_allocating_a_cleanup_receipt` | Yes: the tiny-disk rollback case failed | Before 0/1 in 0.12 s (`baseline-tiny-disk.log`); after 35 install tests passed in 1.92 s; the final full-home cleanup assertion passed. |
| H1 | `e5fd4c6d` | `shell_startup_refusal_names_an_interactive_only_remedy`; existing real-SSH startup-profile probe | Yes: seven startup profiles prevented the requested check script from running | Before guidance test 0/1 in 0.00 s and 7 profiles failed before `CHECK_SCRIPT`; after guidance suite 2 passed, 0 failed, 1 ignored in 0.05 s. Exit, shell replacement and non-returning startup remain target-side boundaries and have no successful setup-step duration. |
| A1 | `06fef9d9`, `865b6c82` | `breakit2 an explicit port on a listed host survives chip resolution`; `listed host plus port retains its saved user in the serialized destination` | Yes: the explicit port was discarded | Before address assertions 0/2; after source suites 47/0 and 51/0. This local input step emits no provisioning event timing. |
| A2 | `1d13d872` | `breakit2 malformed bracketed IPv6 waits for correction` | Yes: malformed bracketed IPv6 was accepted as a chip | Before address assertions 0/2; after source suite 48/0. This local input step emits no provisioning event timing. |
| H2 | `b11368e9` | `breakit2_no_systemd_names_the_required_manager` | Yes: the unsupported-init refusal omitted the required init manager | Before guidance test 0/1 in 0.00 s; after probe suite 3/3 in 0.17 s and model suite 5/5. |
| Payload reuse | `af5fa4e2` | `retry_reuses_verified_payload_after_owned_rollback`; `retry_resends_payload_when_cache_content_changes`; `payload_reuse_never_adopts_a_foreign_cache_directory` | Yes: a retry sent two complete payloads | Before cache regressions 0/2 in 0.45 s and 40,129,888 bytes in two uploads (691.076 + 656.308 ms); after cache suite 38/0 in 1.70 s and one accepted file input, with 130.617 ms local / 600.886 ms delayed reuse and 178.824 / 624.644 ms lookup in the final proof. |

The before/after test durations above come from the saved breakit2 red and
green runs. End-to-end setup-step measurements are separate: the tables below
show `b4ae9e22` against the final repaired flow and do not attribute a latency
change to one individual fix. A1 and A2 run before provisioning starts, so
there is no backend setup-step event to time.

### Setup-step timing cross-reference

Milliseconds, ten-run ranges (phase rows also include p50). These are the
workflow-level measurements in the final fresh proof; they provide the
before/after setup-step context for each finding.

| Finding | Relevant setup step | `b4ae9e22` | Final repaired flow |
| --- | --- | --- | --- |
| R1 | readiness and commit phase | 101–217 (p50 133.5) | 97–539 (p50 164.0) |
| T1, T2, T3 | install | 80.001–116.852 | 87.026–201.050 |
| S1, S2 | commit | 23.078–66.415 | 26.292–161.596 |
| T4 | install; rollback has a separate pass/fail assertion | 80.001–116.852 | 87.026–201.050 |
| H1, H2 | check for supported profiles | 119.194–164.251 | 113.388–1066.597 |
| A1, A2 | typed-target validation before provisioning | n/a | n/a |
| Payload reuse | payload lookup / upload | absent / 307.621–1778.055 | 19.898–128.368 / 729.131–6822.204 |

Review regressions: `s1-cancel-before.log` proves a committed but unacknowledged
host record needed early cleanup ownership; `t3-recovery-before.log` proves an
interrupted journal removal needed receipt-bound recovery;
`a1-user-before.log` covers listed-account serialization.
The independent review cleared all three at `865b6c82`; see
`review-findings.txt` and `review-cleared.txt`.

## Scale and review limits

The actual SQLite admission path ran with 1,600 pending host attempts and
100 groups of eight simultaneous requests (800 total), under CPUWeight=10000
on infraternal-dev, 12 measured online CPUs, load 65.47 / 49.17 / 40.98.
Group completion p50/p99: 20.954 / 122.871 ms. The map had capacity 1,792;
Attempt is 128 bytes (229,376 bytes at that capacity), destination string
capacity total 91,200 bytes. Controller RSS rose from 27,540 to 28,428 KiB
(888 KiB). `s2-scale.log` records these measurements. SSH is a read-only test
boundary here; this is not a 1,600-installed-daemon measurement.

Author checklist: bounded admission precedes mutation; owner/session proof
remains at publication; native trust remains strict; no server is created;
cleanup refuses foreign files, links and changed ownership; cache stores only
the public payload and is bounded to one file per installation mode;
interrupted cleanup preserves evidence for retry; added API is additive.
No new engine or dependency was chosen. SSH retains its plugin feature/runtime
boundary. Parser fuzzing and final gate results are recorded below.

The production browser run at `865b6c82` passed 27/27 in 6.4 minutes, including
phone-viewport coverage. `captures/failure-details.png` is a production-build
capture for independent visual review. This is not physical-iPhone or Safari
proof, and the author does not judge its visual quality.


## Live measurements before the primary retirement repair

Baseline is b4ae9e22; final sample here is 865b6c82, 10/10 fresh runs.
Milliseconds, ranges of ten runs. Discovery refusal precedes key sign-in.

| Setup step | Baseline | 865b6c82 |
| --- | --- | --- |
| network_discovery | 116.337–172.841 | 117.543–263.198 |
| key_sign_in | 167.301–207.047 | 171.469–238.304 |
| check | 119.194–164.251 | 117.366–221.974 |
| payload_lookup | absent | 20.161–36.468 |
| upload | 307.621–1778.055 | 578.436–1201.136 |
| join | 104.917–567.107 | 108.927–166.671 |
| install | 80.001–116.852 | 83.916–246.030 |
| start | 217.573–317.025 | 211.713–383.084 |
| linger | 36.421–62.103 | 40.233–71.802 |
| commit | 23.078–66.415 | 27.430–46.877 |

Baseline retry uploaded 20,064,944 bytes twice (40,129,888 total); upload
times 691.076 and 656.308 ms. At 865b6c82, delayed-150 retry uploaded
20,107,152 bytes once, then verified reuse took 449.165 ms (lookup 517.898
ms); the batch completed. The local retry also sent no second file input,
but failed readiness; `final-retry-local.log` remains part of the evidence.
The reviewed second-attachment retirement window is a possible mechanism,
not a proven attribution of that sample. `final-tiny-disk.log` passes the
real full-home cleanup assertion.


Independent visual review of `captures/failure-details.png`: the visible
failure heading, explanation, next step and Retry fit without clipping or
overlap; no obvious layout defect. Details is collapsed and this is a desktop
capture, so it does not verify expanded readiness labels, mobile layout,
contrast, target sizes or accessibility semantics. The source readiness label
is `Check terminal readiness`; its socket decoding regression passes separately.


## Primary retirement repair

Regression `a5e2cc63` fails on the prior source (0/1); repair `61edf2d4`
keeps the primary stream until marker plus matching authenticated status-zero
exit, skips the second writer on success, and clears its owned coordinates
before authorization awaits. Independent source review found no blocking
issues (`review-retirement.txt`). Existing failure and cancellation recovery
remain. Provisioning tests: 33 pass, 3 opt-in ignored; strict server clippy and
fmt pass. Observer `01f5a067` mirrors the proof only in opt-in diagnostics;
normal measurements delegate to the production path.

The frozen payload is 20,108,048 bytes (`retirement-payload.json`). Both local
and delayed-150 retries complete. Each sends one accepted file input and then
zero additional file-input bytes: 20,108,048 total instead of 40,216,096 for
two sends of this payload. Reuse itself takes 130.617 ms locally and 600.886 ms
on the delayed link; lookup takes 178.824 / 624.644 ms respectively. Initial
loads are 113.73 / 107.94 / 91.96 and 104.82 / 106.45 / 91.98, 12 CPUs.
The earlier local retry failure remains archived and is not retrospectively
attributed to this race. These are observed samples, not controlled speedup
estimates. The avoided bytes follow directly from accepted file-input counts.


Final fresh proof: 10/10 on `01f5a067`; opt-in delayed-credit proof 1/1.
Per-step milliseconds, ranges of ten samples. Phase rows use adjacent public
events; readiness phase includes final commit and authorization.

| Setup step | b4ae9e22 | Primary retirement repair |
| --- | --- | --- |
| network_discovery | 116.337–172.841 | 147.592–2976.640 |
| key_sign_in | 167.301–207.047 | 189.247–11980.198 |
| check | 119.194–164.251 | 113.388–1066.597 |
| payload_lookup | absent | 19.898–128.368 |
| upload | 307.621–1778.055 | 729.131–6822.204 |
| join | 104.917–567.107 | 162.479–2742.695 |
| install | 80.001–116.852 | 87.026–201.050 |
| start | 217.573–317.025 | 290.938–466.242 |
| linger | 36.421–62.103 | 42.449–161.470 |
| commit | 23.078–66.415 | 26.292–161.596 |
| check phase | 420–516 (p50 454.5) | 550–15367 (p50 752.5) |
| installation phase | 2627–4794 (p50 3501.5) | 3278–11420 (p50 8282.5) |
| authenticated facts phase | 55–84 (p50 62.5) | 19–122 (p50 31.0) |
| readiness and commit phase | 101–217 (p50 133.5) | 97–539 (p50 164.0) |


## Gate environment and TypeScript

The full TypeScript gate passes in `final-ts-fast-serial.log`, including
compiler, production build, transfer budgets and 36 protocol tests (34,462
assertions, 5.44 seconds). The first differential attempt hit the unchanged
30-second limit while its `cargo run` shared the debug build directory with
native compilation; the serial repeat changes neither source nor deadline.
`final-ts-fast.log` retains that failure.

The first workspace milestone used a fixture path of 109 bytes and failed
its existing Unix socket bound. The next run inherited umask002, producing
an own-scratch mode0775 test image; the existing restart image validator
correctly refused it and its test waited for a valid request. Only that owned
process was stopped. Executable permissions inside the job target were
corrected, the job directory made private, and the gate rerun with umask022
and the shorter owned state root. These are environment corrections, not
source changes or waived test rows. `milestone-fast.log` and
`retirement-fast.log` preserve both attempts.


## Completion replay

The final requested browser replay used `TRACER_TEST_PORT=4272` on source head
`2a57316e`: the 27 tests in `apps/tracer/test/addhost-wizard.spec.ts` passed.
Its full transcript is `browser-27.log`.

Focused current-source regressions also passed: R1 socket drain 1/1 in 0.07 s,
S1/S2 durable authority 2/2 in 1.21 s, SSH install and payload reuse 39/39 in
13.69 s, H1/H2 probe 3/3 in 0.23 s, and address selection 3/3. Their
transcripts are `r1-native-final.log`,
`authority-native-final.log`, `ssh-install-native.log`, `ssh-probe-native.log`
and `address-source.log`. Baseline red replays against `b4ae9e22` are in
`baseline-r1.log`, `baseline-s1.log`, `baseline-s2.log`,
`baseline-install.log` and `baseline-h2.log`; the H1 startup-profile result and
T4 tiny-disk result remain documented from their original live fixture runs.
