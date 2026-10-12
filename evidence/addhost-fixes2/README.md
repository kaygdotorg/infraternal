<!-- Records reviewed continuation evidence for host provisioning #169. -->
# Host provisioning continuation

R1: 10/10 fresh supported-target runs reached Done after the drain repair.
The ordinary baseline and frozen pre-fix samples also reached Done 10/10 in
this load window; these samples do not estimate a production failure rate.
The delayed-credit live regression fails before the repair and passes after it.
The real socket regression reproduces the mechanism on b4ae9e22.

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

All cases below existed on `b4ae9e22`: the baseline logs retain the same
contract tests and assertion failures. The added review regressions apply to
this lane's intermediate code; they are not attributed to that baseline.

| Case | Baseline evidence | Repair evidence / remaining boundary |
| --- | --- | --- |
| R1 | `baseline-ordering-red.log`; normal fresh samples 10/10 | Daemon drain, decoder readiness option, and primary retirement tracking; final live samples below |
| T1 | `baseline-install-red.log`: both foreign suffix tests fail | Owned stage replacement and journal; foreign launcher and unit suffixes preserved |
| S1 | `baseline-authority-red.log`: two live records instead of one | Address, invitation and host record share a SQLite transaction; cancellation ownership registered before commit |
| S2 | `baseline-authority-red.log`: eight admissions instead of one | Destination reserved before awaits and checked within the writer transaction; one record, seven “already being added” results |
| T2 | `baseline-install-red.log`: unsafe parent admitted | Same private-parent check before mutation and rollback; existing permissions unchanged |
| T3 | `baseline-install-red.log`: empty interrupted lock unrecoverable | Exact acquisition journal; interrupted receipt recovery retires only that journal |
| T4 | `baseline-tiny-disk.log`: rollback fails | Staged payload removed before cleanup receipt allocation; real full-home refusal cleans owned files |
| H1 | `baseline-startup-red.log`, `baseline-startup-red-fresh.log`: seven startup profiles fail | Actionable refusal added. Startup that exits, replaces or waits before the requested command remains target-side; no client-only repair proven |
| A1 | `baseline-address-red.log`: explicit port discarded | Typed port retained; listed account retained in serialized destination |
| A2 | `baseline-address-red.log`: malformed IPv6 accepted | Browser-native address validation; chip remains editable |
| H2 | `baseline-init-red.log`: missing init guidance | Canonical unsupported-init record gives systemd requirement and SSH-only next step |
| Retry | `baseline-retry.log`: payload sent twice | One private, marked, hash-verified cache; reuse rehashes staged hardlink, changed bytes resend, foreign cache refused |

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
