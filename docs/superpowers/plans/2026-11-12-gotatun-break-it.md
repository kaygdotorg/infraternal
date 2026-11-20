# GotaTun In-App Break-It Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete a repeatable Linux and macOS break-it suite for the in-app GotaTun data plane, with recovery, stalled-byte, latency, resource, and manual-intervention evidence for every requested case.

**Architecture:** Keep the Linux product-node pair in disposable network namespaces on compute01 and the Mac pair on `.6 ↔ .7` under the shared Mac lock. The suite drives real infraternal mesh nodes, reports coordinator-fixture boundaries explicitly, captures queue events against the host monotonic clock, and samples product and scheduler counters. Product fixes stay separate from harness fixes and from J485b, J502b, J510, J511, and J525 work.

**Tech Stack:** Rust, GotaTun, Python, Linux network namespaces and netem, macOS `lockf` and dummynet, `build-slot`, `/mnt/build`, and the J88c x86 perf kit.

**Spec:** J526 request in #260 and #483; J516 loaded-latency finding and follow-up instructions.

## Handover status (2026-11-13)

- The Linux suite and real server-restart row are committed on `j526-gotatun-break-it`.
- The stale Linux owner-proof failure has a red/green regression. The fix is pushed as `d1110d125`; the focused namespace run passed 1/1.
- The full matrix still needs a fresh run on the rebased head. Prior rows are stale; endpoint and NAT recovery remain open and overlap J502b/J510.
- The 3,600-second queue-depth soak, backup01 scheduler window, Mac runner and Mac cases, and `scripts/verify fast` are not complete.
- The post-rebase `scripts/verify quick` never acquired a compute01 slot and was canceled at handover; no test ran in that invocation.

## Global Constraints

- Measure performance and latency before changing behavior; every regression needs measured justification.
- Keep production fixes small, atomic, and red-first; coordinate overlapping files before changing them.
- Use `scripts/verify fast` on compute01 before completion and quote its output.
- Keep evidence outside the checkout under `$HOME/.cache/codex-scratch/J526/evidence/`.
- Use only `/mnt/build/targets/J526` for Rust targets on compute01.
- Do not use prod for mutation or take backup01/Mac locks outside the assigned turn; release each shared lock within 20 minutes.
- Never disturb Lume's session, keychain, or TCC database.

## Review Focus

- A changed peer IP or NAT port can leave a TCP transfer stalled after probes recover; compare product fixes with J510 before editing.
- A crypto queue can remain shallow while scheduler or lock waits create latency spikes; correlate queue samples, scheduler counters, and probe samples on monotonic time.
- A retiring key can be rejected after the local identity has rotated; test the complete apply path and payload integrity, not only chunk staging.
- Coordinator restart and config churn can leave the live node on a stale version; identify whether a row restarts the production server or only the schema fixture.
- Mac sleep/wake can disturb the shared Lume session; run only after J524 releases the lock and only when the session remains safe.

---

### Task 1: Trace and close key-retirement failure

**Files:** `crates/plugins/mesh/src/node.rs`, `crates/plugins/mesh/src/node_actions.rs`, `scripts/gotatun_break_it/linux_matrix.py`, `scripts/test_gotatun_fault_suite.py`.

**Interfaces:** Reuse the `rekey-under-load` and `rekey-timer-expiry-under-load` cases and the instrumented GotaTun binary; keep queue/lock internals owned by J525 out of the product diff.

- [ ] **Step 1: Write a failing complete-apply regression** for a key rotation whose final same-authority delta retires the predecessor while one TCP flow is active. Assert node version advances, peer traffic hashes match, and no bytes remain unverified.
- [ ] **Step 2: Run the test against the unmodified product** and preserve the refusal, queue trace, and probe evidence.
- [ ] **Step 3: Trace the refusal through parsing, staged config, route/policy application, and GotaTun apply** before changing the implementation.
- [ ] **Step 4: Implement the smallest product fix** that makes the complete apply succeed; leave crypto queue and completion-lock files untouched.
- [ ] **Step 5: Run both rekey cases with queue depth sampling** and preserve per-agent logs, recovery, stalled bytes, and p99.
- [ ] **Step 6: Commit and push the product fix atomically** with the test and why the rejected alternatives were not used.

### Task 2: Finish Linux namespace coverage and scope server restart

**Files:** `scripts/gotatun_break_it/linux_matrix.py`, `scripts/gotatun_break_it/app_fixture.py`, `scripts/gotatun_break_it/report.py`, `scripts/test_gotatun_fault_suite.py`, and the suite README.

- [ ] **Step 1: Add a red regression** proving the server-restart row restarts the real infraternal server process while an already-configured data-plane flow continues; keep the coordinator database and agent state explicit.
- [ ] **Step 2: Run the regression red** and record the exact process and traffic outcome.
- [ ] **Step 3: Extend the fixture only as needed** to restart the product server and preserve the coordinator state; retain the existing fixture-only row under a precise name if the real-process case is distinct.
- [ ] **Step 4: Run the Linux matrix** for endpoint and NAT rebinding; 1%, 5%, and 20% loss; reordering and duplication; link down/up; both rekey cases; infraternal agent and real server restart; peer add/remove churn; MTU change mid-flow; and 50/200 simulated peers.
- [ ] **Step 5: Record recovery time, stalled/unverified bytes, p99 during recovery, integrity, and manual-fix status** for every row; coordinate endpoint and MTU fixes with J510 and J502b.
- [ ] **Step 6: Commit and push the server-restart coverage separately** from any product fix.

### Task 3: Reproduce the 594 ms loaded-latency stall

**Files:** `scripts/gotatun_break_it/loaded_latency_soak.py`, `scripts/gotatun_break_it/mesh_ix_soak.py`, `scripts/gotatun_break_it/long_soak.py`, `scripts/gotatun_break_it/run_loaded_latency_window.sh`, and suite documentation.

- [ ] **Step 1: Run one continuous 3,600-second single-flow soak** in compute01 namespaces through `build-slot`, using the queue-depth diagnostic binary, one 800 Mbit/s shaped flow, monotonic probes, per-thread scheduler counters, GotaTun counters, RSS, descriptors, threads, and CPU samples.
- [ ] **Step 2: Preserve queue and scheduler samples on the same monotonic timeline** and report p99/max latency, probes above 100 ms, payload integrity, and resource drift.
- [ ] **Step 3: When the backup01 turn returns, capture a bounded TID-filtered `perf sched` window** with the J88c x86 kit, queue samples, and GotaTun counters; release the lock within 20 minutes.
- [ ] **Step 4: If the 594 ms stall is captured, add a failing regression first, trace the trigger, then fix only the owned product path** and rerun the correlated window.

### Task 4: Build and run the macOS product matrix after J524

**Files:** `scripts/gotatun_break_it/` Mac runner and README; use the J421 networking and dummynet notes as operational references.

- [ ] **Step 1: Add red tests for the Mac runner's cleanup and case reporting** before invoking the real `.6 ↔ .7` product nodes.
- [ ] **Step 2: After J524 releases the lock, run endpoint/NAT changes; loss, reordering, duplication; link down/up; key rotation; agent and server restart; peer churn; MTU changes; 50/200 peers; and a one-to-two-hour soak.** Run sleep/wake only if it will not disturb Lume's session.
- [ ] **Step 3: Record recovery, stalled bytes, recovery p99, resource drift, and manual-fix status** for each case; release the Mac lock promptly.
- [ ] **Step 4: Compare Mac rotation support with D166 and D352** and label any deliberately skipped behavior with its reason.

### Task 5: Gate, coordinate, and report

- [ ] **Step 1: Recheck overlapping J485b, J502b, J510, J511, and J525 heads** and avoid duplicating their product changes.
- [ ] **Step 2: Run `scripts/verify fast` on compute01** after rebasing the J526 branch on current `origin/dev`.
- [ ] **Step 3: Push only J526 commits and post the evidence and gate output on #260 and #483.** Do not close either issue.
- [ ] **Step 4: Prepare the Linux and Mac per-case table** with recovery time, stalled bytes, p99 during recovery, manual-fix result, fixed branches/heads, and suite invocation.
