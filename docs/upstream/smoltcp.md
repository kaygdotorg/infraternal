<!-- Draft upstream PRs for infraternal's smoltcp loss-recovery patches (#146, J1193). -->
# smoltcp: upstream PR drafts (NewReno partial-ACK and SACK sender recovery)

**Job:** J1193 · **Status:** rebased and CI-verified drafts, **not submitted** · **Submitter:** the owner (kayg).
We never open upstream PRs from a job. Everything below is a draft and technical brief for the owner to review.

- **Upstream repository:** `https://github.com/smoltcp-rs/smoltcp`
- **Upstream `main` base:** `7de37764f793ad70c44096d746f9f8715496709b` (2026-11-24)
- **Source patches in infraternal:** `origin/j1042-macos-userspace-fallback` commits `426a0dac7` (patch `0002`, NewReno partial-ACK) and `ce702753b` (patch `0003`, SACK sender recovery); patch `0001` (`bb1e73d28`) is already merged upstream as PR `#1211`.
- **License:** `0BSD` (`LICENSE-0BSD.txt` in smoltcp).
- **Tracking issue:** `#146` (macOS no-admin userspace fallback, D228 M5).

---

## 1. Upstream contribution policy blocker (read before submitting)

Upstream `CONTRIBUTING.txt` adopts the **NLnetLabs LLM policy** (`https://nlnetlabs.nl/llm-policy/`), and commit `53cf534` (PR `#1247`, merged 2026-11-12) added `.github/PULL_REQUEST_TEMPLATE.md` with a mandatory checkbox:

```markdown
- I have not included any LLM generated content in this PR, including code, comments, and descriptions.
- I understand these changes in full and will be able to respond to review comments.
- My change is accurately described in the commit message.
- My contribution is tested and working as described.
- [ ] I have read and followed all of the above requirements.
```

> PRs without a completed checkbox will be closed.

Because the original vendored patches (`426a0dac7`, `ce702753b`) were written by Claude Opus 5.5 (J1042) and this rebase/draft was prepared by Gemini 4 Neon (J1193), **these commits and PR descriptions cannot be submitted verbatim while checking that box honestly.**

Options for the owner:
1. **Rewrite by hand from the design spec** (recommended if submitting upstream): use the RFC references, invariants, and test cases below as a specification, write the implementation, comments, and PR text yourself, and submit cleanly under upstream's policy.
2. **Ask maintainers first:** open an issue/discussion on `smoltcp-rs/smoltcp` (e.g. commenting on `#256` for SACK) asking whether human-reviewed AI-assisted patches are accepted despite the template wording.
3. **Keep vendored only:** retain `vendor/smoltcp-patches/0002` and `0003` in infraternal and skip upstream submission.

---

## 2. Rebased branches and SHAs

Both branches are rebased onto upstream `main` (`7de37764f793ad70c44096d746f9f8715496709b`).
One rebase adaptation was required for upstream PR `#1216` (`bd424c8`, "tcp: Retry fast retransmissions if emitting it fails"): `pending_fast_retransmit`, `rexmit_credit`, `high_rxt`, and Karn's `rtte.on_retransmit()` are now committed **after** `emit(...)` succeeds, so a failed `emit` retries the recovery retransmission on the next dispatch (covered by a new unit test).

| Order | Branch | Base | Head SHA | Commits | Summary |
|---|---|---|---|---:|---|
| 1 | `tcp-newreno-recovery` | `7de37764f793ad70c44096d746f9f8715496709b` (`main`) | `982bf925853066ae0f1450ed3545cb0cc1957177` | 1 | Opt-in RFC 6582 NewReno partial-ACK retransmission |
| 2 | `tcp-sack-recovery` | `tcp-newreno-recovery` | `65884de972e9bb46c92250bcbe256e0a03495df0` | 1 (+1 from PR 1) | Opt-in RFC 2018 / RFC 6675-style sender-side SACK recovery |

**Note on Forgejo fork:** no `kayg/smoltcp` or `kayg/smoltcp-fork` repository exists on `git.kayg.org` yet, and the job's Forgejo token lacks `write:user` scope to create repositories. Both rebased branches (plus `main`) are exported to a git bundle and `git format-patch` series under `~/.cache/codex-scratch/j1193/evidence/` on `hd01` (`smoltcp-j1193-branches.bundle`, `0001-*.patch`, `0002-*.patch`; clone at `~/.cache/codex-scratch/j1193/smoltcp`). Once `kayg/smoltcp-fork` exists on Forgejo, push with:

```bash
git -C ~/.cache/codex-scratch/j1193/smoltcp push ssh://git@o2.vpn.kayg.org:2222/kayg/smoltcp-fork.git \
  main tcp-newreno-recovery tcp-sack-recovery
```

**Note on stacking:** PR 2 (`tcp-sack-recovery`) builds on PR 1's recovery-episode machinery (`recovery_point`, `high_rxt`, `rexmit_credit`, `next_hole`, `tracks_recovery`, `end_recovery`, `grant_rexmit`). Submit PR 1 first, then rebase PR 2 onto `main` once PR 1 merges (or open PR 2 as a draft noting it depends on PR 1).

---

## 3. PR 1 draft: `tcp: add opt-in NewReno partial-ACK retransmission`

**Branch:** `tcp-newreno-recovery` (on `main`)
**Files changed:** `src/socket/tcp.rs`, `CHANGELOG.md`

### Draft PR title

`tcp: add opt-in NewReno partial-ACK retransmission (RFC 6582)`

### Draft PR body

#### Problem

smoltcp currently implements RFC 5681 fast retransmit: after three duplicate ACKs, it retransmits the single segment at `SND.UNA`. When more than one segment is lost in the same flight:

1. The first retransmission fills the first hole, and the receiver sends a *partial ACK* that advances `SND.UNA` to the second lost segment.
2. Because `ack_number` advanced, smoltcp resets `local_rx_dup_acks` to 0.
3. If the transmit window or send buffer is full, no new segments can leave to generate three more duplicate ACKs.
4. Recovery stalls until the retransmission timer expires (≥ 1 s by default) and falls back to go-back-N retransmission of the entire window.

In a userspace TCP/IP workload over a 1% random-loss link (1280-byte MTU, 256 KiB buffers), this reduced smoltcp sender throughput to **0.007 Gbit/s** versus **0.155–0.193 Gbit/s** for the OS kernel TCP stack. Adding RFC 6582 partial-ACK retransmission (together with a 200 ms `min_rto` via `#1211`) restored sender throughput to **0.190 Gbit/s** on the same link.

#### Change

Add an opt-in per-socket setting `Socket::set_newreno_recovery(&mut self, enabled: bool)` and getter `Socket::newreno_recovery(&self) -> bool` (default: `false`, preserving existing RFC 5681 behaviour):

- **Recovery episode (RFC 6582 §3.2 step 2):** when fast retransmit starts and recovery tracking is enabled, record `recovery_point = Some(self.remote_last_seq)` (RFC 6582 `recover`), initialise `high_rxt = self.local_seq_no`, and zero `rexmit_credit`.
- **Duplicate ACKs during recovery (RFC 6582 §3.2 step 4):** while `recovery_point.is_some()`, additional duplicate ACKs do not restart fast retransmit.
- **Partial ACKs (RFC 6582 §3.2 step 3):** when a fresh ACK arrives with `ack_number < recover` and `ack_len > 0`, grant one retransmission credit (capped at `MAX_REXMIT_CREDIT = 8` to bound bursts). `dispatch` immediately retransmits one segment at `local_seq_no` (bounded by `recover` and `tx_buffer.len()`), at most once per range (`high_rxt`), and notifies `rtte.on_retransmit()` per Karn's algorithm (RFC 6298).
- **Exiting recovery:** a full ACK (`ack_number >= recover`), an RTO (go-back-N), or `Socket::reset()` clears `recovery_point` and `rexmit_credit`.
- **Failed emit retry (preserving `#1216`):** `pending_fast_retransmit`, `rexmit_credit`, `high_rxt`, and `rtte.on_retransmit()` are updated only after `emit(...)` succeeds.
- **Scope:** changes only *which* segments are retransmitted and *when*; congestion window calculations are untouched.

#### RFC references

- **RFC 5681** — TCP Congestion Control (baseline fast retransmit)
- **RFC 6582** — The NewReno Modification to TCP's Fast Recovery Algorithm (§3.2 steps 2, 3, and 4)
- **RFC 6298** — Computing TCP's Retransmission Timer (Karn's algorithm: do not sample RTT on retransmissions)

#### Tests

Added 7 unit tests in `src/socket/tcp.rs`:
- `test_newreno_partial_ack_retransmits_next_segment` (checks both `false` and `true`)
- `test_newreno_full_ack_ends_recovery`
- `test_newreno_resends_each_hole_once`
- `test_newreno_rto_ends_recovery`
- `test_newreno_duplicates_in_recovery_do_not_restart_fast_retransmit`
- `test_newreno_recovery_retransmit_retries_after_failed_emit`
- `test_newreno_is_off_by_default`

#### Changelog entry

```markdown
- tcp: add opt-in NewReno partial-ACK retransmission (`set_newreno_recovery`/`newreno_recovery`).
```

---

## 4. PR 2 draft: `tcp: add opt-in sender-side SACK loss recovery`

**Branch:** `tcp-sack-recovery` (stacked on `tcp-newreno-recovery`)
**Files changed:** `src/socket/tcp.rs`, `CHANGELOG.md`
**Upstream issue:** `#256` (SACK support; receiver-side SACK emission is already in smoltcp, sender-side recovery was not)

### Draft PR title

`tcp: add opt-in sender-side SACK loss recovery (RFC 2018 / RFC 6675)`

### Draft PR body

#### Problem

smoltcp already negotiates `SACK Permitted` during the handshake and emits SACK blocks as a receiver, but as a sender it ignores incoming SACK blocks (`repr.sack_ranges`). Even with NewReno partial-ACK recovery, recovering *k* lost segments in one window still takes *k* round trips because the sender learns about each hole only when the partial ACK for the previous retransmission returns.

On the same userspace TCP/IP test link (1280-byte MTU, 256 KiB buffers, 200 ms `min_rto`):
- **1% random loss:** 0.226 Gbit/s with SACK recovery vs 0.190 Gbit/s with NewReno alone (kernel baseline: 0.155 Gbit/s).
- **2% random loss:** 0.120 Gbit/s with SACK recovery vs 0.081 Gbit/s with NewReno alone (kernel baseline: 0.075 Gbit/s).

#### Change

Add an opt-in per-socket setting `Socket::set_sack_recovery(&mut self, enabled: bool)` and getter `Socket::sack_recovery(&self) -> bool` (default: `false`; depends on PR 1's recovery episode):

- **Allocation-free scoreboard (`SCOREBOARD_LEN = 4`):** when `sack_recovery && remote_has_sack`, `update_scoreboard` clips incoming SACK blocks to `[ack, remote_last_seq)` (dropping D-SACK blocks below `ack` per RFC 2883 and blocks above `SND.NXT`), sorts and merges touching/overlapping ranges into a fixed 4-entry array. If more than 4 disjoint ranges exist, the lowest 4 are kept so high holes are conservatively left for partial ACKs or RTO rather than erroneously retransmitted.
- **Duplicate ACK detection with SACK:** an ACK carrying newly SACKed bytes counts as a duplicate ACK even when it also updates the advertised window.
- **Hole selection and packet conservation (RFC 6675-style):** during fast recovery, each incoming duplicate or partial ACK grants one retransmission credit (capped at `MAX_REXMIT_CREDIT = 8`). `next_hole` returns the first unSACKed range at or above `high_rxt.max(local_seq_no)` that lies strictly *below* a SACKed block and within `recovery_point` — data above the highest SACKed byte is never retransmitted as lost.
- **Receiver reneging (RFC 2018 §8):** an RTO clears the scoreboard (as does `Socket::reset()` or disabling `set_sack_recovery(false)`).
- **Fallback and scope:** if the remote did not advertise SACK Permitted, `set_sack_recovery(true)` falls back to NewReno partial-ACK recovery (via `tracks_recovery()`). Congestion window calculations are untouched.

#### RFC references

- **RFC 2018** — TCP Selective Acknowledgment Options (§4 SACK option format & scoreboard semantics, §8 receiver reneging on RTO)
- **RFC 2883** — An Extension to the Selective Acknowledgement (SACK) Option for TCP (D-SACK blocks below `SND.UNA` ignored)
- **RFC 6582** — The NewReno Modification to TCP's Fast Recovery Algorithm (recovery episode)
- **RFC 6675** — A Conservative Loss Recovery Algorithm Based on Selective Acknowledgment (SACK) for TCP (`HighRxt`, packet conservation, hole retransmission below highest SACKed byte)

#### Tests

Added 9 unit tests in `src/socket/tcp.rs`:
- `test_sack_new_blocks_count_as_duplicate_despite_window_change`
- `test_sack_partial_ack_resends_the_next_hole`
- `test_sack_hole_goes_out_on_a_later_duplicate`
- `test_sack_never_resends_above_the_highest_sacked_byte`
- `test_sack_rto_clears_the_scoreboard`
- `test_sack_recovery_needs_a_sack_capable_remote`
- `test_sack_scoreboard_merges_and_clips`
- `test_sack_scoreboard_keeps_the_lowest_ranges`
- `test_sack_is_off_by_default`

#### Changelog entry

```markdown
- tcp: add opt-in sender-side SACK loss recovery (`set_sack_recovery`/`sack_recovery`).
```

---

## 5. Local CI verification

Verified on `infraternal-dev-02-std` (aarch64, `rustc 1.98.1`, `cargo 1.98.1`, through `build-slot` with `CARGO_INCREMENTAL=0`) against upstream's `ci.sh` matrix. Raw logs are saved on `hd01` under `~/.cache/codex-scratch/j1193/evidence/ci-newreno.log` and `ci-sack.log` and attached to `#146`.

| Check (from `ci.sh` / `.github/workflows/`) | `tcp-newreno-recovery` (`982bf92`) | `tcp-sack-recovery` (`65884de`) |
|---|---|---|
| `cargo fmt -- --check` | PASS | PASS |
| `cargo clippy --tests --examples` (`-D warnings`, Rust 1.98.1)* | PASS (0 warnings in touched code) | PASS (0 warnings in touched code) |
| `check_unused` (`--cfg ci_forbid_unused --deny unused --deny irrefutable_let_patterns`) | PASS | PASS |
| `FEATURES_CHECK` (4 `no_std` / `defmt` / `alloc` configs) + `--examples` | PASS (4/4 + examples) | PASS (4/4 + examples) |
| `FEATURES_TEST` (all 23 feature combinations) | PASS (23/23) | PASS (23/23) |
| — `default` | 692 unit + 7 doc passed | 701 unit + 7 doc passed |
| — `default,socket-tcp-reno,socket-tcp-cubic` | 715 unit + 7 doc passed | 724 unit + 7 doc passed |
| `netsim` (`cargo test --release --features _netsim netsim`) | PASS (2 passed) | PASS (2 passed) |

\* Upstream `ci.sh` runs `clippy` on MSRV `1.91.0`. On Rust `1.98.1`, three pre-existing upstream lints fire in untouched code (`clippy::needless-late-init` on `is_keep_alive` in `src/socket/tcp.rs`, `clippy::chunks-exact-to-as-chunks` in `src/wire/dhcpv4.rs`, `clippy::unnecessary-unwrap` in `src/wire/ieee802154.rs`). Allowing those three lints verified zero warnings across all added/modified lines and tests.
