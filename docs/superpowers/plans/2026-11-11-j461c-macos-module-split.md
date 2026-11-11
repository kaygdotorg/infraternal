# macOS Mesh Send Path Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the oversized macOS mesh node module by responsibility without changing behavior or test code, then complete J461c's Mac measurements.

**Architecture:** Keep node orchestration and durable state in `macos_node.rs`. Move utun packet framing and GotaTun adapters into `macos_node/utun_io.rs`, and route plus endpoint-derived MTU logic into `macos_node/route_mtu.rs`. Keep the existing test module byte-for-byte unchanged and re-export the moved private interfaces only within the parent module.

**Tech Stack:** Rust, Tokio, GotaTun, macOS utun and route utilities.

**Spec:** `DECISIONS.md` (D378, D381) and issue #260.

## Global Constraints

- No behavior or test changes; preserve the current private interfaces at the node module boundary.
- The repository artifact limit for `crates/plugins/mesh/src/macos_node.rs` is 200,000 bytes.
- Run `scripts/verify fast` on compute01 and quote its complete output.
- Run the Mac matrix under `lockf -k /tmp/mac-bench.lock`, with three counterbalanced windows for all four cells against Tailscale and NetBird, then collect the after-profile.
- Keep raw evidence outside the checkout under `~/.cache/codex-scratch/j461c/evidence/` and attach selected evidence to #260.

## Review Focus

- IPv4 and IPv6 utun send framing: existing mesh unit tests and the Mac data-path harness.
- Malformed, mismatched and over-MTU receive frames: existing utun parser tests.
- Route ownership, deletion and interface validation: existing route and `valid_utun_name` tests.
- Endpoint-derived route MTU refresh and rollback ordering: existing MTU tests and the Mac matrix.
- Existing test definitions remain unchanged: compare the full `tests` module against the base revision.

## Tasks

### Task 1: Split the utun data path

**Files:**
- Create: `crates/plugins/mesh/src/macos_node/utun_io.rs`
- Modify: `crates/plugins/mesh/src/macos_node.rs`

- [ ] Move utun setup, send/receive adapters, and frame parsing into `utun_io.rs` with a module doc comment.
- [ ] Keep existing unit tests in `macos_node.rs`; add only the visibility and doc comments needed at the parent-module boundary.
- [ ] Confirm the existing tests block is byte-for-byte identical to the base revision.

### Task 2: Split route and MTU ownership

**Files:**
- Create: `crates/plugins/mesh/src/macos_node/route_mtu.rs`
- Modify: `crates/plugins/mesh/src/macos_node.rs`

- [ ] Move route commands, peer route selection, endpoint MTU probing and route validation into `route_mtu.rs`.
- [ ] Keep the node-facing private interfaces available through the parent module without changing call behavior.
- [ ] Confirm `macos_node.rs` is below 200,000 bytes and existing tests remain byte-for-byte identical.

### Task 3: Run the repository gate

**Files:** none.

- [ ] Run `scripts/verify fast` on compute01 with one job target directory, then remove that target directory.
- [ ] Record the complete output and resulting artifact-size measurements on #260.

### Task 4: Complete J461c measurements

**Files:** evidence outside the checkout.

- [ ] Under the Mac lock, run three counterbalanced LAN windows for `mac-tx` and `mac-rx` at 1 and 8 flows against GotaTun, Tailscale and NetBird.
- [ ] Capture the `lan-mac-tx-8f` after-profile, aggregate all windows, and compare the full cell table to J461b.
- [ ] Attach the table and profile evidence to #260, then post the final head SHA and gate output.
