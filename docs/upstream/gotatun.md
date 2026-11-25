<!-- Which of infraternal's GotaTun fork patches can go upstream, in what order, and how we keep them current (#260, J1141). -->
# GotaTun: what can go upstream, and how

**Job:** J1141 · **Status:** research and drafts only · **Submitter:** the owner (kayg). Nothing here has been
posted. We open no upstream issue, discussion or pull request (PR) from a job: upstream requires a person behind every
submission, and everything below is a draft for that person to read, understand and edit.

Fork: `github.com/kaygdotorg/gotatun` (Forgejo `kayg/gotatun-fork`), pin `e6efb96`. Upstream: `github.com/mullvad/gotatun`,
release 0.10.3 (`e95ba96`, 2026-11-09), `main` at `5454dac` (2026-11-18; only `CONTRIBUTING.md` and the README
differ from 0.10.3). The fork is `e95ba96` plus **126 commits** (125 plus one merge), +33,019 / −816 lines in 74 files.
This page was written from the fork and upstream state on 2026-11-24.

## 1. Summary

1. **Four small groups are real upstream candidates today** and are cheap: a one-line build fix (G01), a receive-error fix
   that upstream's `main` still has (G02), a confirmed-endpoint field (G03), and two memory trims (G05). G01 and G02 are bug
   fixes; the others are small features and want a short discussion first.
2. **Upstream already has open work for three of our big features.** PR #170 (Linux UDP GSO sends, open since July), PR #10
   (TUN TSO, open since August 2025) and PR #220 (`Tunn::next_timer_deadline`, open since 2026-11-06). Our versions are
   supersets of #170/#10 (we ported both, see commit messages) and overlap #220. We should **comment on those PRs with our
   evidence and offer review and tests** instead of opening competing PRs.
3. **The big features (parallel crypto with inline runs, AQM, GRO zero-copy, per-peer deadline queue, handshake backlog) need
   a discussion first**, not a PR. They are 400 to 9,000 lines each, they sit on one another (see §3), and upstream
   closed an unrequested 1,000-line PR on 2026-11-11 (#227) for exactly this.
4. **Some of our work cannot go upstream as is:** macOS `sendmsg_x`/`recvmsg_x` use private system calls (G22; upstream's
   client ships through app stores), and the harness and bench knobs are infraternal-specific (G23).
5. **Evidence gap, important:** every #260 number we have compares the fork with *an older fork pin*, with kernel
   WireGuard or with wireguard-go. We have **no head-to-head of stock upstream 0.10.3 against the fork** with the current
   kit. Upstream will ask for it first, so it is step 0 (§6). Until it exists, every "+x%" below is "against our previous pin".
6. **Fair comparison (J1199, 2026-11-25):** on the cross-VM perf pairing, like for like, GotaTun beats wireguard-go on
   throughput and CPU per Gbit in every cell, but **has not beaten kernel WireGuard**. The kernel has lower loaded latency in every cell that resolves and is 18–23% faster
   when the small VM receives 8 flows (§3.1). No upstream text may claim otherwise.
7. **Process finding:** the pin `e6efb96` contains a merge commit (`c4813b5`), and `scripts/gotatun-upstream-sync` refuses a
   series with merges (exit 2). The next sync fails until the series is linearised. I tested it: flattening the 125 non-merge
   commits onto `e95ba96` gives a tree **identical** to `e6efb96`, and that linear series rebases onto upstream `main`
   with no conflicts (scratch test, nothing pushed). See §7.

## 2. What upstream asks for

From `CONTRIBUTING.md` on `main` (commit `7a0de6b`, 2026-11-18) and upstream practice:

- **Features, refactors and major changes:** look at the existing discussions, or open one in the *Ideas* category, before
  writing code. **Bug fixes:** comment on the issue or open a bug report; a PR is fine.
- **A human behind every submission** (PRs, issues, security advisories). Regardless of tooling, a person must understand
  all of it and answer questions. Submissions with no human in the loop are closed at once.
- **MPL-2.0.** Everything we submit is licensed MPL-2.0 and we must be the author. Our fork files are MPL-2.0 already (the
  fork's `LICENSE`); the infraternal repository is AGPL-3.0-only, so **never copy code from infraternal into a submission**.
  Only fork code moves. Our commits carry `Co-Authored-By:` trailers naming AI tools. The owner decides how to disclose assistance in
  submitted commits (upstream does not ban tools, it bans unattended AI).
- **Style:** Mullvad's coding guidelines (`github.com/mullvad/coding-guidelines`). Each PR adds a `CHANGELOG.md` entry
  under *Unreleased* (what 0.10.x PRs do). CI: rustfmt, clippy, `typos`, `cargo-semver-checks`, `cargo-shear`, licence
  headers, nix check, tests on Linux, macOS, Windows, and a RISC-V clippy run.
- **Security-flavoured findings:** upstream's `SECURITY.md` asks for a private GitHub advisory, not a public issue.

What the record shows about how they treat outside work:

| Item | What happened | Lesson |
|---|---|---|
| #227 (Windows ICMP receive errors, 6 commits, +992/−59) | Closed in one comment the same day: looks LLM-generated, 1k lines the author has "not proven to understand". They invited smaller focused PRs and promised to pick them up "if you show that you would be willing to fix any remarks". | Small PRs, a human who answers in the thread. |
| #219 / `fix/tai64n-epoch` (handshake timestamp epoch, tiny) | Taken into 0.10.3 within days. | Small, well-argued, correctness-visible fixes land fast. |
| #170 (Linux UDP GSO sends, +757/−27, one commit) | Open since 2026-07-18. A maintainer (`hulthe`) asked on 2026-09-01 for the benchmark to be shared: "Is this test open source?" No answer yet. | **They want a reproducible benchmark.** That is the harness in §6. |
| #10 (TUN TSO, by maintainer `hulthe`, 2025-08) | Open for 15 months. | Offload work is wanted but unfinished. Our hardened version could unblock it. |
| #220 (`next_timer_deadline`, by an outside author) | Open, no comments. | Overlaps our G16. Do not duplicate it. |

Also relevant, read-only: upstream has branches `os-threads` (one commit, 2026-06-26, "Use OS threads instead of tokio
tasks"), `handle-incoming-peer-lock` (2026-07-31, "Release peer lock asap in handle_incoming"), `optimize-pool` (13 commits,
stale since February) and `dial9`. The maintainers are exploring threading and peer-lock hold time themselves; a
discussion about our parallel crypto should ask about those branches first, not assume they are dead. Open issues
that touch our areas: #226 (Windows receive loop exits on `WSAECONNRESET`; the same class as G02), #230 (UAPI `set` on an
existing peer drops its live session, relevant to G04), #228 (preshared key in `Debug` output, unrelated).

## 3. Classification

Classes:

- **BUG** a defect in upstream code. Upstreamable as a PR (after confirming it on `main`).
- **PERF** a performance feature. Needs a discussion and benchmark evidence.
- **PLAT** a platform fix or feature (macOS, Linux kernel interfaces).
- **API** a small additive public API. Discussion first (public surface, semver).
- **LOCAL-BENCH** bench-only knobs, diagnostics, harness. Keep local.
- **LOCAL** infraternal-specific. Keep local.

"Applies to `main`" says what happens when the group's commits are cherry-picked alone onto upstream `main` (`5454dac`):
*clean* means `git cherry-pick` succeeded; *N hunks* is the number of conflicting hunks; *needs G..* means the commit builds on
other groups in the series. This tests text only. **Nothing was compiled**: compile, clippy and tests on a build VM are
part of preparing each submission (§5). Size is insertions plus deletions summed over the group's commits (tests and
comments included).

| Group | What | Commits | Size (+/−) | Class | Applies to `main` | Depends on | Risk | Evidence we have |
|---|---|---:|---|---|---|---|---|---|
| **G01** | `gotatun-crypto` workspace dependency with `default-features = false`, so `device,ring` really excludes `aws-lc-rs` (`bba3dcf`) | 1 | +1/−1 | **BUG** | clean | none | Very low. Cargo feature unification only. | D289 check: `cargo tree` for `device,ring` lists no `aws-lc-rs` with the fix. Upstream `main`'s `gotatun-crypto` has `default = ["aws-lc-rs"]` and the workspace entry has default features, so a `ring`-only dependent still builds `aws-lc-rs`. To confirm on a build VM. |
| **G02** | One bad frame no longer stops a traffic direction: only a gone TUN or socket is fatal; `EBADF` fatal on every Unix (`01c29f4`, `11dc4e9`, `a557b50`) | 3 | +264/−15 | **BUG** | 1 hunk each in `device/mod.rs` and `tun/mod.rs`; `is_fatal_tun_error` lives in `tun/buffer.rs` upstream | none in principle; `01c29f4` also edits our batch receive, re-express it | Medium: behaviour change on error paths. | **Confirmed on `main`:** `tun/buffer.rs` `is_fatal_tun_error` still treats `InvalidData`/`InvalidInput` as "TUN device was deleted" and breaks the read loop. Our #260 comment 77025 (J143 P2-1) found that one raw IPv6 packet with a lying extension-header length from a process with `CAP_NET_RAW` stops the direction for good. Tests were written first (a bad frame then a good one, both buffered paths). See §4.1 about reporting it. |
| **G03** | `Endpoint::confirmed` / `Stats::confirmed_endpoint`: the address of the last packet that proved key possession (`8c118e8`) | 1 | +138/−4 | **API** (small) | 3 hunks in `peer_state.rs` | none upstream; our parallel-decrypt hook is a separate line | Low. One compare per decrypted packet, store only when the source moves. | Test pins that a replayed initiation moves `addr` but not `confirmed`. infraternal reads it to stop an unauthenticated sender choosing a peer's path MTU (#489). Hot-path cost measured only as A/B/B/A inside infraternal, no separate number. |
| **G04** | Network-change API: `Device::rehandshake` (new initiation over an active session), `Device::request_keepalives`, announce on the live session during a rekey, plus tests incl. 1,000- and 4,096-peer measurements (11 commits, one is the merge `c4813b5`) | 11 | +545/−68 | **API** | `rehandshake`: 2 hunks; `request_keepalives`: 7 hunks, builds on G12/G16 hooks | `force_handshake` (upstream #199, merged) | Medium: new public API, timer-path change. | #515: without `rehandshake`, NAT rebind recovery was bimodal 20/65 s. #260 J561: 15.2 s of loss after an endpoint IP change against a 300 ms budget. The 1,000-peer test checks idle peers send nothing. |
| **G05** | Per-peer memory: session ring allocated after the first handshake (`10f9f2c`), compact route list instead of a per-peer trie (`c6fd62c`) | 2 | +154/−34 | **PERF** (small) | clean, clean | none | Low. | Commit messages: eight 1,128-byte session slots per idle peer, and about 1.76 KiB inline plus 4.6 KiB of trie freelist per peer. `research/mesh-engines` measured 20,017 B incremental RSS per GotaTun peer at 1,000 peers (wireguard-go 37,614 B); the split by commit is not measured. **Needs a before/after on stock.** |
| **G06** | Idle release: return packet buffers and receive pages to the OS when a link goes idle (`87471cc`) | 1 | +260/−21 | **PERF** | 2 files conflict (`device/mod.rs`, `socket/linux.rs`) | pool in `gotatun-packet` | Medium: touches the memory allocator behaviour; D331. | After load GotaTun kept 7 to 22 MiB resident per endpoint for good; nothing came back after 120 s idle. Mostly useful for long-lived small devices. |
| **G07** | `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` past `rmem_max` when privileged (`2441d08`) | 1 | +116/−9 | **PLAT** | 1 hunk in `socket/mod.rs` | upstream #135 (configurable buffers, merged) | Low. | Under load GotaTun lost 5 to 16% of loaded RTT probes at 1 and 8 flows; the CLI asks for 7 MiB, the kernel capped it. Later full-stack holds (J1129) show 0 lost probes, but they include many other changes, so the effect of this commit alone is not isolated. |
| **G08** | Linux TUN offload: `IFF_VNET_HDR` TSO, UDP-L4/USO segmentation, GRO-style coalescing of ordered packets, checksum validation of GSO frames, TCP segment storage reuse, 8-byte-wide checksum sum, plus fixes (9 commits) | 9 | +5,228/−149 | **PERF** | `79eadab` clean alone, the rest build on it | **#10** | High. Parses kernel-supplied metadata; the draft's unchecked parsing is why we rewrote it. | J741 A/B showed no regression after the rebase. J1129: +10 to +21% Gbit/s with the GRO/TUN-write work (G17 sits on this). The checksum change removed about 4% of samples on the sending side (J393c profile). |
| **G09** | Linux TUN transmit ring 1,024 packets (`2b56d27`) | 1 | +132/−1 | **PERF** (small) | 1 hunk (touches TSO code) | G08 (file layout) | Low. | The TUN-side drop was 0.06 to 0.13% at 1 flow and 1.3 to 1.5% at 8 flows; the paired hold (J88e) showed the drops and lost probes gone. Only for devices GotaTun creates. |
| **G10** | Linux UDP GSO sends with plain `sendmmsg` fallback on `EIO`, GRO receive split by returned length, batch cap 64, tests (`872a511`, `65ddbfa`, `3a2e3a4`, `f767914`) | 4 | +986/−60 | **PERF** | `872a511` clean alone; `65ddbfa` 2 hunks, `3a2e3a4` 4 hunks (need `buffer.rs` changes of G12) | **#170** | Medium. | Commit message says `872a511` is a port of #170 onto 0.10.2 with the receive split added. #170's author reports +148 to +157% TCP in a private guardrail setup; ours is in the J872 kit. |
| **G11** | Linux: pass the socket receiver straight to `handle_incoming`, no second worker and channel (`1485210`) | 1 | +140/−115 | **PERF** | clean | none | Medium: changes where receive buffering happens. | "The profile found queue residence and worker crossings"; loaded p99 lower, 8-flow throughput within variance (R4b). **Needs stock A/B.** |
| **G12** | Parallel crypto pipeline: ordered per-peer slot reservation, bounded worker pool, in-order release, workers started on first handoff, mutex-free wake queue, stall and shutdown fixes, tests (25 commits) | 25 | +9,087/−1,188 | **PERF** (large) | `c26e975` 4 files conflict | none | **High.** Core data path, ordering, shutdown. | 15 of the 25 commits are fixes for ordering, stall and shutdown bugs found by our own break-it tests and reviews (rekey under load, drain across rekeys, panic or task failure failing the device). Throughput effect is part of the whole-stack rows in §3.1; per-commit numbers are in the #260 comments, not in the commit messages. |
| **G13** | Inline crypto policy: runs up to 48 packets stay inline on Linux (macOS 16 receive) (`ff7785c`, `523465c`, `40e22d3`, `b2cb26a`, `cd9ab06`) | 5 | +107/−18 | **PERF** | needs G12 | G12 | Medium: a tuning policy. | J1121 on the 6-vCPU perf VM, ECN, CUBIC and BBR, 1 and 8 flows, 83 s: pool size 2/3/4/6 within 1% throughput; no handoff at all −24 to −35% throughput; inline limit 32/48: throughput and p99 unchanged, futex per Gbit −12 to −30%, crypto wakes −20 to −40%, CPU per Gbit −1 to −2%. J1120: the pool woke 14,700 times a second for about 70 µs of work per wake. |
| **G14** | Receive-side CoDel with ECN marking (`aqm.rs`), sparse-flow rules, clock-step and padding fixes (11 commits) | 11 | +3,689/−441 | **PERF** (large) | `983aa30` 4 files conflict | G12 (ordered delivery point), Linux `SO_TIMESTAMPNS` | **High.** Marks packets, owns a state machine, three review rounds (J881, J891). | Cubic 8-flow loaded p99 22.4 ms → 6.16 ms, +4.7% Gbit/s, −2.7% CPU per Gbit (backup01, D397). `GOTATUN_AQM=ecn\|drop\|off`. |
| **G15** | Handshake "under load" decided by backlog, not 100 messages per source per second (`5757403`) | 1 | +507/−89 | **PERF** + security-relevant | 2 files conflict | G12 (receive task shape), touches `rate_limiter.rs` | **High.** Changes DoS posture. | Table B, 1,000 peers behind one address: all up in **0.3 s vs 5.7 s** before (wireguard-go 0.5 s, kernel 0.3 s). Flood, 256 source addresses at 20,000/s: engine CPU 172 vs 1,026 ms/s and the real peer gets in at 5 s instead of never. Known downside: one-address flood delays other new handshakes by one 5 s retry (kernel WireGuard behaves the same). |
| **G16** | Per-peer deadline queue: `Tunn::next_timer_deadline`, timer min-heap on a 250 ms grid, safety sweep (`3881c70`, `bd6eaeb`) | 2 | +1,300/−119 | **PERF** | 3 files conflict | **#220** (overlap); `rate_limiter` lazy reset | Medium. Timer logic, but a 48-script old-vs-new property test must give identical logs. | At 4,096 idle peers the 250 ms poll cost 125 wakeups/s and 7.7 ms CPU/s (wireguard-go 6.3 and 0.0). `bd6eaeb` fixed a 2.5 to 4.6% throughput loss that the first version caused (event clock read per packet stamp). |
| **G17** | UDP GRO datagrams cut in place from a 128 KiB chunk, no per-segment copy; merge queued TUN runs into one write (`30a1544`, `e6efb96`) | 2 | +382/−80 | **PERF** | 2 files conflict | G08, G06 (pool `count_taken`) | Medium-high: pool and buffer lifetime. | J1129: **+10 to +21% Gbit/s, 9 to 14% less CPU per Gbit, loaded p99 flat or lower**; against our own previous pin on backup01 (see §3.1). The copy was 2.5% of engine cycles. |
| **G18** | Receive and send priority: replies jump ahead of bulk, small datagrams overtake queued send runs, hand the packet task every queued datagram (`d77cbf5`…) | 7 | +759/−32 | **PERF** | `udp/buffer.rs` 4 hunks | G12 | Medium. | Loaded-latency work from J720/J728; no isolated number in the commit messages. |
| **G19** | macOS utun and UDP queue bounds (512 packets, 128 receive, utun max pending) | 4 | +222/−10 | **PLAT** | needs `device/mod.rs` | none upstream | Low. | Sizes were chosen from queue-depth samples on the Mac VM and `mba`; no isolated before/after is in the commit messages. |
| **G20** | macOS connected per-endpoint send sockets: safe across network changes, port-takeover audit, refused connected send falls back to `sendto` (covers **`EPIPE`** from a shut-down pool socket and macOS **Local Network** privacy refusals), `SIGUSR1` network-change signal (22 commits) | 22 | +4,075/−660 | **PLAT** (large) | needs `socket/mod.rs` changes | none | **High.** Socket ownership and security (`SO_REUSEPORT` window). | J744: Mac send 1.9 µs per datagram instead of 14.5 µs. Cause of the late fixes: `EPIPE` on a LAN peer while `sendto` on the wildcard socket worked (J1108; the macOS Local Network grant was missing for an `sshd`-started process). Path errors (`EADDRNOTAVAIL`, `ENETUNREACH`, `ENETDOWN`, `EHOSTUNREACH`) drop the connected socket and fall back to `sendto`. There is no AWDL-specific code in the range. |
| **G21** | macOS dual-stack bind as one socket per family (`177f3bd`, `f135c7e`, `987cfdb`) | 3 | +420/−130 | **PLAT** | needs G20 | none | Medium. | Tests written first; verified on Mac VM 26.5.2. |
| **G22** | macOS `sendmsg_x`/`recvmsg_x` batching via runtime `dlsym` (`04ff48c`, `ac1d1d7`) | 2 | +2,036/−326 | **PLAT** | needs G20 | G20 | **Blocker for upstream:** private (undocumented) system calls. | J1036 on the M1 `mba`, macOS 27.2.1: all calls ×1.34 to 1.45 over connected sends alone. The owner's own note says "we are not shipping to the app store". Upstream's client does. |
| **G23** | Bench and diagnostics: the R4b overlay (4,719 lines), queue-depth sampler, bench knobs (`GOTATUN_BENCH_*`, `GOTATUN_DIAG_*`) | 6 | +5,249/−90 | **LOCAL-BENCH** | n/a | | | Keep local. Environment-variable knobs read at run time are not something to ask upstream for. |
| **G24** | `gotatun-cli` disables transparent huge pages at start (`68a4a7c`) | 1 | +68/−0 | **LOCAL** | clean | none | Low. | RSS footprint of the product's CLI. Could be offered as an opt-in flag later; no evidence of value for upstream's users. |

The per-commit list of all 126 commits and the group each belongs to is in the appendix.

### 3.1 Honest read of the evidence

- The performance rows (G13, G14, G15, G16, G17) were measured by infraternal's own kit on one perf VM
  (`backup01`, CPUs 0 to 5, ECN, 83 s windows), against *our previous pin*, kernel WireGuard and wireguard-go. They are real
  and careful (paired holds, empty machine diffs), but they were never run against `e95ba96`.
- **We have not beaten kernel WireGuard** (owner correction, 2026-11-25). The like-for-like engine comparison (J1199,
  [research/fair-bench/summary.md](../../research/fair-bench/summary.md)) is cross-VM on the backup01 perf pairing. It
  runs `gotatun-cli` at pin `e87fef91`, wireguard-go and kernel WireGuard, all configured with `wg set`, MTU 1390, the
  same nft guard table and no CPU pinning, and measures latency with a TCP round-trip probe instead of ping. Two paired
  holds; the A/A floor is 0.2–1.3% on Gbit/s. Against kernel WireGuard, the kernel has lower loaded round-trip latency
  in every cell that resolves (p99 −19 to −82%), and moves 18–23% more at 8 flows when the 2-core VM receives (4.15
  against 3.50 Gbit/s). Forward at 8 flows the two are level within 1%. GotaTun is ahead only in single-flow cells
  (forward CUBIC +23%; reverse BBR, where kernel WireGuard stays at 1.18 Gbit/s for a reason not yet investigated).
- **Against wireguard-go, GotaTun is ahead on throughput and CPU in every cell of that pairing:** 1.4–1.8× the throughput at about half the
  CPU per Gbit, with lower loaded latency in 14 of 16 p50/p99 cells, 0.5 against 8.7 idle wakeups/s, and 34 against 147
  MiB RSS for both nodes. That is one pairing and one LAN hop. Upstream will want their own fixture.
- The older single-host table (J1129, both ends in network namespaces on one 6-vCPU VM, CUBIC, Gbit/s at 1 / 8
  flows: kernel 2.52 / 2.51, wireguard-go 6.72 / 6.58, GotaTun `e6efb96` 6.19 / 6.14) must not be quoted as a
  comparison with kernel WireGuard. On one VM, kernel WireGuard's crypto runs in softirq on the same CPUs as both
  endpoints and iperf3, and cannot be pinned the way the userspace engines were. Its 2.5 Gbit/s there is a fixture
  limit, and the cross-VM rows above contradict it. In that table wireguard-go was also ahead of GotaTun. Its idle
  RSS (11–18 MiB against 67–130 MiB) agrees with the cross-VM rows.
- Stock GotaTun 0.10.3 on that kit is **unmeasured**. The fork's early baseline (before the TUN offload work) was far below these
  rows, so the stack as a whole is probably a large gain, but the discussion must not say a number we have not measured.

## 4. Upstreamable groups, one by one

### 4.1 G01 and G02: bug fixes

**G01.** One line in the workspace `Cargo.toml`. Cherry-picks cleanly onto `main`. The fix and its evidence (`cargo tree -e
features -i aws-lc-rs --no-default-features --features device,ring` is empty) fit one PR. Ask: does upstream want `ring`-only
builds to avoid `aws-lc-rs` (upstream's #122 added both backends and made `aws-lc-rs` the default, so this looks intended).
Needs: `CHANGELOG.md` entry under *Unreleased → Fixed*.

**G02.** The bug exists on `main` today (§3 table). Prepare a fresh patch on `main` instead of cherry-picking
`01c29f4`, because that commit also edits our batch receive:

1. `is_fatal_tun_error`: drop `InvalidData` and `InvalidInput` from the fatal list; keep `NotFound`, `UnexpectedEof`,
   `BrokenPipe`, Linux `EBADF`/`EBADFD`/`ENODEV`, Windows EOF.
2. Make `EBADF` fatal on every Unix (a closed utun descriptor was treated as "one bad frame" on macOS, and the reader never
   stopped: gate failure in the macOS test on the Mac VM).
3. A frame the TUN refuses on send is dropped and counted, not a reason to stop the send task.
4. Tests: a bad frame then a good one through `BufferedIpRecv`; `EBADF` still stops it.

Two ways to report it; **the owner chooses**: (a) a normal bug report plus a small PR, because the trigger needs
`CAP_NET_RAW` or write access to the TUN on the same host, which is not a trust boundary on most deployments; or (b) a
private advisory per upstream's `SECURITY.md`, because the effect is a persistent denial of service of one direction by one
malformed packet. My recommendation: (a), written as a robustness bug, and mention the trigger. If the owner or upstream
prefers (b), nothing else changes.
Related: do **not** include the UDP side (`handle_incoming` stopping on any `recv_many_from` error, and our Windows
`ConnectionReset` skip). Upstream #226 and the closed #227 cover it; the right move is a short comment on #226 pointing at the
one-line `SIO_UDP_CONNRESET` idea, left to the person who filed it.

### 4.2 G03 to G05: small additive features

All three want a one-paragraph discussion post each, or one combined *Ideas* post listing them, then separate PRs.

- **G03 confirmed endpoint.** Argument: `Endpoint::addr` moves on an accepted handshake initiation, which proves nothing
  about the source address (a captured initiation not yet seen by the responder can be replayed from anywhere). Kernel
  WireGuard has the same property, so upstream may say "not our problem"; the field is additive and costs one compare per
  decrypted packet.
- **G04 network-change API.** `rehandshake` and `request_keepalives` answer one use case: the host knows its network changed
  and wants the peer to learn the new path now rather than at the next keepalive (about 15 s). Mullvad's app has the same
  situation on every network switch. Overlap: #199 `force_handshake` (merged; it is a no-op while a session is younger
  than 120 s) and #230 (UAPI `set` drops the live session). A discussion should open with the measured loss (15.2 s) and
  ask whether they prefer these two methods or one `Device::network_changed()`.
- **G05 per-peer memory.** Two small PRs with before/after bytes per peer on stock (to measure, §6). Mullvad runs few
  peers, so the value is lower for them; keep them last.

### 4.3 G08, G10: offload work that already has upstream PRs

- **G10 (UDP GSO).** Comment on #170 with the J872 kit (once §6 exists as a public script) and offer our tests: loopback checks
  that compare payload *contents and order*, not just counts, and the `EIO` fallback test. Do not open a second PR. If #170 stalls, ask
  whether a maintainer wants a rebased copy of `872a511` instead.
- **G08 (TUN TSO).** #10 is a 15-month-old draft. Comment with the specific defects we found in its metadata parsing (unchecked
  header parsing and a panic path; a `gso_size` TODO that treated virtio `gso_size` as a full packet length) and offer the
  hardened port (`79eadab`) as a replacement, with USO (`9001341`) and checksum validation (`b70333b`) as follow-ups.
  Dependencies after G08 (G09, G17 and parts of G12) are not offered until G08 is accepted.

## 5. Order of submissions

Principle: the cheapest, clearest first, so a first PR proves a person is behind the work and builds trust. Each step starts
only after the previous one is merged or answered. Before every submission: rebase on current `main`, run upstream's CI
steps on a build VM (rustfmt, clippy `-D warnings`, `typos`, tests with `ring` and with all features), add the `CHANGELOG.md`
entry, and reread the diff.

| Step | Submission | Form | Size | Gate to start |
|---|---|---|---|---|
| 0 | Stock-vs-fork measurements with the harness (§6) | internal | | none; needed before steps 3 and later |
| 1 | **G01** ring-only build fix | PR | 1 line | confirm on a build VM |
| 2 | **G02** receive-error fix | issue then PR (or advisory, §4.1) | about 250 lines with tests | step 1 answered |
| 3 | Comment on **#170** (GSO) and **#10** (TSO) with evidence and offer | comment | | step 0 done |
| 4 | **G03** confirmed endpoint | discussion then PR | 138 lines | step 2 merged |
| 5 | **G04** `rehandshake` / `request_keepalives` | discussion then PR | about 300 lines | step 4 |
| 6 | **G07** buffer force, **G09** TUN ring | small PRs, each with a number | 116 + 132 lines | step 0 numbers |
| 7 | Comment on **#220** (deadline) offering our property test; then **G16** as a discussion | discussion | 1,300 lines | #220 answered |
| 8 | **G17** GRO zero-copy (depends on G08 landing) | discussion | 382 lines | G08 merged |
| 9 | **G15** handshake backlog | discussion, security-careful | 507 lines | discussion about rate limiting open |
| 10 | **G12/G13** parallel crypto and inline runs | discussion only; maybe never a PR | 9,000 lines | maintainers' interest, after upstream's `os-threads`/`handle-incoming-peer-lock` direction is known |
| 11 | **G14** AQM | discussion only | 3,700 lines | needs G12 |
| 12 | **G05**, **G06** memory | small PRs | 154 and 260 lines | step 0 numbers |

Never offered: G19 to G22 (macOS socket stack) until the owner decides how to handle the private calls; G23, G24 stay local.
macOS items that could go earlier on their own are the `EBADF` part of G02 and, later, a *minimal* "refused connected send
falls back to `sendto`" if upstream ever adds connected sockets (it has none).

## 6. The shared benchmark harness

### 6.1 What upstream needs

Upstream asked for it already (#170, 2026-09-01: "Is this test open source?"). Our J872 head-to-head kit (`research/head-to-head`,
about 8,000 lines of shell and Python) cannot be shown: it is built for a pinned perf VM,
cpuset audit, `perf-lock`, NetBird, Tailscale and our product's agent fixtures. They need something they can read in an
afternoon and run on any Linux box.

**Proposal: `gotatun-netns-bench`**, one directory, three files, no dependencies beyond tools every distribution has.

```
bench/
  README.md        what it measures, what it does not, how to read the numbers
  run.sh           the whole run, bash + iproute2 + iperf3 + ping + wireguard-tools
  summarize.py     python3 stdlib only: per-run CSV in, table out (median, min, max, A/B delta)
```

**Topology** (everything inside two private network namespaces and one veth pair; nothing touches the host network
namespace, no route to any uplink, so it also satisfies our rule that no test sends to fake addresses from the host):

```
 ns gt-a                                          ns gt-b
 ┌──────────────────────┐  veth a0 ─ b0 (underlay)  ┌──────────────────────┐
 │ gotatun-cli  -> gt0  │ ───────────────────────── │ gotatun-cli  -> gt0  │
 │ 10.77.0.1 (tunnel)   │   optional netem delay    │ 10.77.0.2 (tunnel)   │
 └──────────────────────┘   / loss on a0 and b0     └──────────────────────┘
```

The ranges `10.77.0.0/24` (tunnel) and `10.78.0.0/24` (underlay) exist **only inside the namespaces**. The script refuses to
run if a veth end is in the root namespace, and removes both namespaces in a `trap` on exit.

**Arms.** `--arm NAME=/path/to/gotatun-cli` repeated; `--arm kernel` uses `ip link add type wireguard` in the same namespaces
as a control. Binaries are given by path so upstream can compare `main` against a PR head built the same way.

**Measurements** (the numbers our #260 tables use, reduced to what a script can do anywhere):

| Metric | How |
|---|---|
| Throughput, 1 and 8 flows | `iperf3 -c … -P N -t 30 -J`, receiver-side bits per second |
| Loaded latency p50/p99 | while iperf3 runs, `ping -i 0.01 -s 64` for 20 s from a third process; percentile computed in `summarize.py`; probes lost reported |
| CPU per Gbit | `/proc/<pid>/stat` utime+stime ticks of each `gotatun-cli` over the iperf3 window divided by transferred bits; kernel arm reports nothing here (softirq is not per process) and says so |
| Memory | `VmHWM` and `VmRSS` of `gotatun-cli` after load and 5 s after idle |
| Idle wakeups | `/proc/<pid>/status` `voluntary_ctxt_switches` delta over 10 s idle |
| Handshake time to first reply (optional) | first `ping -c1 -W` success after peer configuration |
| WAN profile (optional) | `tc netem delay 99ms` on both veth ends (198 ms RTT), optional `loss 2%` |

**Method rules that make numbers comparable** (these come from what broke our own comparisons):

1. Alternate arms **A B B A** for N holds (default 3); report per-hold values and a paired delta, not one mean.
2. Run an **A/A** series first and print the noise floor; the summary marks any delta inside it as "no difference".
3. Pin the two `gotatun-cli` processes and the iperf3 server/client to separate CPU sets (`taskset`), refuse to run if fewer than
   4 CPUs are online, and print the CPU model, kernel, governor and `rmem_max` in the header.
4. Print every sysctl and link offload setting the run depends on (`ethtool -k` for the veth ends); do not change them
   without `--tune`, and when `--tune` is used restore them in the same `trap`.
5. Never claim an absolute number from a shared CI runner. The README says so in its first paragraph: the output is for
   *relative* comparison on a quiet machine.

### 6.2 What it takes to build

| Piece | Work |
|---|---|
| Namespace/veth/netem plumbing with a safe `trap` and root-namespace refusal | about 80 lines bash; we have the pattern in `research/head-to-head/kit/lib/common.sh`, written fresh and short |
| Key setup and peer config for `gotatun-cli` | `wg genkey`/`wg set` against the UAPI socket in each namespace (`/var/run/wireguard/gt0.sock`), about 40 lines. Our `kit/lib/gotatun_uapi.py` shows the UAPI text protocol if `wg` is not wanted |
| iperf3 and ping drivers, percentile and paired-delta summary | about 80 lines bash, about 120 lines Python (stdlib) |
| `/proc` CPU and RSS sampling | about 40 lines |
| A/A noise-floor logic and ABBA scheduling | about 60 lines |
| README with limits, and a worked example output | half a day |
| Validation: run on two unlike machines (our `backup01` and a laptop), compare to the J872 kit on the same binaries, record where they disagree | one to two days, mostly waiting on quiet-machine holds |

Estimate: **3 to 4 days of work, about 450 lines**, none of it product code. Build and validate on a build VM; run the
validation holds on `backup01` under `perf-run` (only the orchestrator uses the perf VMs).

**Where it could live.** Upstream's CI cannot gate on throughput (shared runners are noisy), so the best home is a directory
`bench/` in their repository or a gist plus a link from the discussion; the owner asks in the same discussion as step 3 of §5
which they prefer. Licence: MPL-2.0 for anything in their repository.

**What it does not reproduce:** the J872 kit's cpuset audit, `perf-lock`, the machine-diff-must-be-empty check, DAITA, the
multi-peer scale rows, and the macOS rows. Those stay ours; the README says our own tables use the larger kit and where it is.

**Step 0 deliverable:** with this harness, run three arms on the same machine: stock `e95ba96`, the fork pin, and kernel
WireGuard, 1 and 8 flows, CUBIC. That table replaces §3.1's caveat and decides how each discussion is worded. If the harness
disagrees with J872 on direction, find out why before posting anything.

## 7. Keeping our patches current

The repository already has a process: `docs/operations/gotatun-fork.md` and `scripts/gotatun-upstream-sync`
(`sync --check`, `sync`, `test`). J741 wrote it, with sync branches `infraternal/upstream-YYYYMMDD`, rerere, a
no-merge rule and the perf A/B gate. I propose keeping it and changing four things.

### 7.1 Fix what is broken now: linearise the pin

The script exits 2 on the current pin because of the merge `c4813b5`. I checked it: `git rebase --onto e95ba96 e95ba96
<pin>` (which drops the merge) gives 125 linear commits with a **tree identical to `e6efb96`**, and rebasing those
onto `upstream/main` (`5454dac`) succeeds with no conflict. So a linearised pin needs **no re-measurement** if
`git diff e6efb96 <new>` is empty, which is a one-command check, and the new pin bump is a hash change only.
The job that does it should: create `infraternal/upstream-<date>` with `--onto upstream/main`, assert the tree differs from
`e6efb96` only in `CONTRIBUTING.md` and `README.md`, then bump the pin, `Cargo.lock`, `nix/package.nix` `outputHashes` and
`THIRD_PARTY_NOTICES.md` together (the four places listed in the fork doc).

### 7.2 Weekly check, not daily

Upstream moved only three documentation commits in the 15 days since 0.10.3, and the sync costs a gate and a perf A/B. A
weekly read-only check is enough, plus an extra check **when an upstream release or a PR that touches our files appears**.

Proposed script `scripts/gotatun-upstream-watch` (read-only; `gh api` and `git fetch` only; never pushes, never comments):

1. Fetch `upstream`. Print `git log --oneline pin_base..upstream/main` and which of our files they touch (the existing `sync
   --check` already does this; reuse it).
2. List upstream PRs and issues **opened or updated since the last run** (`gh api repos/mullvad/gotatun/issues?since=…`),
   and flag those whose title or changed files match a table of keywords per group (`gso`, `gro`, `tso`, `vnet`, `timer`,
   `deadline`, `handshake`, `rate limit`, `macos`, `udp`, `recv`, `fatal`), printing `G10: PR #170 updated`.
3. Check whether any of our upstream-candidate commits became **empty** after a rebase onto upstream (the existing script
   reports "commits upstream made empty"): that means upstream took it, and the group moves out of our series.
4. Write one line to `docs/operations/gotatun-upstream-log.md` (date, upstream SHA, new items, result) so the history is in
   the repository. The orchestrator runs it from a weekly job, opens a #260 comment when anything is flagged, and starts the
   rebase job only when upstream changed files in the series.

State between runs is one file, `~/.cache/gotatun-watch/last.json` (last seen timestamp and upstream SHA), not committed.

### 7.3 Order the series so candidates come first

Today the series is in the order work happened. After linearising, **reorder it once** (a scripted `git rebase -i` todo
file generated from the group list, applied with `GIT_SEQUENCE_EDITOR`) into:

1. upstream candidates (G01, G02, G03, G04, G05, then G07, G09),
2. features that other groups need (G08, G10, G06),
3. the big features in dependency order (G12, G13, G11, G17, G16, G15, G14, G18),
4. platform stacks (G19 to G22),
5. local and bench (G23, G24) last, as the fork doc already asks.

Candidates first means that when upstream merges one of them, `git rebase` on the next sync drops that commit as already
applied or empty (the script reports it), and the rest of the stack does not move. The reorder must be proved: the final tree
must equal the pre-reorder tree (`git diff` empty), and each commit still builds (`cargo check --locked --workspace
--all-targets --all-features` per commit on a build VM, which the fork doc already requires). Groups that depend on each
other in text (G13 on G12, G09 on G08) keep their order. The reorder is a one-time job that costs conflicts; do it together
with 7.1 on the first sync branch.

Record the group of each commit with a trailer, `Series-Group: G12`, **added only on the new sync branch** (sync branches are
never rewritten once pushed, so this is the moment to add it). The sync and watch scripts then read groups from the
trailers; the group table in this document stays the human description.

### 7.4 Re-pin rules and the upstream-merged case

- A sync branch is never rewritten once pushed (existing rule). A new sync branch starts from the pin.
- When upstream merges a group (or our PR is accepted in a different form), the next sync **skips** our commits for it
  (`git rebase --skip`), the commit message of the next kept commit says so (existing rule), and we adopt upstream's version
  of the API even if it differs from ours; the product follows with a small change.
- Weekly job outputs are comments on #260 with the old and new upstream SHA, the range-diff of the series, and the
  conflict list. A re-pin needs the existing gate (`scripts/verify fast`, native Mac tests under the lock) and the perf A/B
  from the fork doc, with the run order counterbalanced.
- When upstream starts a competing implementation of a large group (G12, G14, G16), stop carrying our version forward
  beyond one sync and write it up for the owner: carrying 9,000 lines against a moving upstream is the real cost.

## 8. Questions for the owner

1. **How to disclose AI assistance** in submissions? Upstream's rule is that a human understands and answers for every line,
   not that tools are banned. Recommendation: submit under the owner's name, describe the tooling in one sentence in the first
   comment, and write each PR description yourself from the commit message. Strip `Co-Authored-By` trailers only if upstream asks.
2. **G02 as a public bug report or a private advisory?** Recommendation: public bug report (needs `CAP_NET_RAW` or TUN write
   access on the same host).
3. **Should the harness (§6) be built before any performance discussion?** Recommendation: yes. #170 has waited since
   September for a benchmark; do not repeat that.
4. **Who answers upstream?** Someone has to read the thread for months. If the owner does not want that load, post only G01 and G02
   and the comments on #170, #10 and #220, and stop there.
5. **macOS private calls (G22).** Recommendation: never offer; keep `sendmsg_x` local behind the fork's runtime gates.
6. **Linearise and reorder the pin** (§7.1 and §7.3) as the next job, before the next upstream sync. Recommendation: yes; it
   needs no new measurement if the tree is unchanged.

## 9. Draft discussion posts

These are drafts for the owner. They are written in the first person of the person who will submit them, they quote only
numbers we have, and each says what we did not measure. **Do not post a draft that still contains `[to measure]` markers.**
Post in <https://github.com/mullvad/gotatun/discussions/new?category=ideas>.

### 9.1 Draft: running small crypto runs inline, and a bounded worker pool for large ones

> **Title:** Idea: ordered per-peer crypto batches, with small runs staying inline
>
> **Context.** In 0.10.3 each device runs encryption on the outgoing task and decryption on the incoming task, one packet at a time
> in order. We carry a patch series that adds a bounded worker pool: per peer, a contiguous run of ready packets takes
> sequence slots up front, workers seal or open them, and results are released strictly in slot order, so a peer's packets never
> reorder. Idle peers cost no thread and no timer.
>
> **What we found.** On a 6-vCPU Linux VM (two network namespaces, ECN on, 83 s windows, CUBIC and BBR, 1 and 8 flows), the
> pool woke about 14,700 times a second for about 70 µs of work per wake. We then swept the hand-off size: waking the pool for small runs
> cost futex traffic, and handing none cost 24 to 35% of throughput because the task stops reading the socket while it
> seals. Keeping runs of up to 48 packets inline and sending only full 64-packet chunks to workers left throughput and loaded
> p99 within run-to-run noise, cut futex calls per Gbit by 12 to 30% and CPU per Gbit by 1 to 2%.
>
> **What we do not know.** Whether this helps your clients (few peers, mobile CPUs): all our numbers come from a server-like VM.
> On the harness below (backup01, quiet: a 6-vCPU VM held by one job, two namespaces, 2 CPUs per engine, 3 paired holds, 20 s runs),
> our whole pin against stock 0.10.3 gives 5.30 to 5.60 Gbit/s against 2.24 to 2.50 (+123 to +146%) and 64 to 66% less CPU per Gbit
> in all four cells (CUBIC and BBR, 1 and 8 flows). That compares two builds, not one patch: we have not measured the pool alone
> against stock.
>
> **Questions.** (1) Is there an intended direction for parallel crypto? We saw the `os-threads` and `handle-incoming-peer-lock`
> branches. (2) If a worker pool is welcome, would you want it behind a cargo feature first? (3) Would you review a design note
> before a patch? The code is about 9,000 lines with tests, so we do not plan a PR unless you want one.
>
> Benchmark harness and raw results: [link to be added].

### 9.2 Draft: UDP GRO datagrams without the copy

> **Title:** Idea: cut UDP GRO receive buffers in place instead of copying each segment
>
> **Context.** With UDP GRO on, `recvmmsg` returns up to 64 KiB holding many segments. The current code copies every segment
> into a pool packet before decrypting (a `TODO` in `udp/socket/linux.rs` already says "consider splitting the iov backing
> buffer into multiple BytesMut"). In our profile the copy was 2.5% of engine cycles, the largest userspace copy on the receive
> path.
>
> **What we did.** Each receive slot reads into the rest of a 128 KiB chunk and the received bytes are cut into `BytesMut` views of
> that chunk. Decryption already runs in place, so the bytes are written once, by the kernel. A slot takes a new chunk when
> less than one message (64 KiB) is left; a retired chunk returns whole when its last packet is dropped, so steady receiving reuses
> the same memory. At most 128 retired chunks wait. The kernel builds non-TCP GRO packets only below 64 KiB, so a message
> always fits.
>
> **Result on our kit.** Together with a change that writes whole runs to the TUN (see below), at 1 and 8 flows: +10 to +21%
> Gbit/s, 9 to 14% less CPU per Gbit, loaded p99 flat or lower, no lost probes (CUBIC 1 flow 5.46 → 6.19 Gbit/s, 8 flows 5.29 → 6.14,
> measured against our previous pin). Against stock 0.10.3 on the harness below (backup01, quiet), our whole pin gives
> 5.52 and 5.60 Gbit/s against 2.50 and 2.31 at CUBIC 1 and 8 flows; that is every patch together, not the receive path alone.
>
> **Cost.** The packet pool no longer sees these packets, so an idle detector needs a count of taken buffers; the pool grows
> a counter. Chunks can hold memory while any packet from them is alive.
>
> **Questions.** Do you want this before or after TUN TSO (#10) lands, since the write side depends on it? Is a pool counter
> acceptable in `gotatun-packet`?

### 9.3 Draft: receive-side queue control (CoDel with ECN)

> **Title:** Idea: mark ECN on congested receive queues, using the kernel's receive time
>
> **Context.** A TUN device orphans packets, so TCP Small Queues never limits flows through a userspace tunnel, and senders'
> windows stand as queue on the receiving side: the UDP socket backlog plus decrypt-and-order. On our VM, CUBIC with 8
> flows had loaded p99 22.4 ms.
>
> **What we did.** The Linux UDP socket asks for `SO_TIMESTAMPNS`; each received packet keeps its kernel receive time through
> ordered delivery. At delivery, a per-peer CoDel controller (RFC 8289) judges the time from kernel receive to TUN write. In
> ECN mode it sets CE on ECN-capable inner packets (RFC 3168, IPv4 checksum updated per RFC 1624) and drops others; sparse
> flows are exempt and a signal goes to a queue-heavy flow. Targets are 1 ms / 10 ms rather than RFC 8289's 5 / 100 ms,
> because one receive batch alone spends about 2.5 ms. Switch: `ecn | drop | off`.
>
> **Result.** CUBIC, 8 flows: loaded p99 22.4 ms → 6.16 ms, +4.7% Gbit/s, −2.7% CPU per Gbit. Review rounds
> found clock-step, padding and accounting bugs, now fixed with tests.
>
> **What we do not know.** Behaviour on mobile, Windows and macOS (no kernel receive stamps there, so the bound is off), and the
> effect of queue control alone on stock 0.10.3. On the harness below (backup01, quiet; TCP round trip under load, not ping), CUBIC
> with 8 flows has loaded p99 6.58 ms on stock and 4.37 ms on our whole pin (-34.7%, outside the 4.2% A/A floor) while Gbit/s
> goes from 2.31 to 5.60. Stock is not queue-bound on that VM, so this is not the 22.4 ms case above. One cell went the other
> way: BBR with 1 flow has p99 1.62 ms on stock and 2.85 ms on the pin (+75%, floor 8.1%), at 2.3 times the throughput.
> It adds about 3,700 lines.
>
> **Questions.** Is queue control in scope for the library, or should it sit with the application? Would you want only the
> measurement (receive age) exposed as a hook, leaving the policy outside?

### 9.4 Draft: per-peer timer deadlines (coordinate with #220)

> **Comment on #220 first (draft):** "Thanks for this. We carry a similar function, `Tunn::next_timer_deadline`, which mirrors
> `update_timers` branch by branch, plus a device-level scheduler that sleeps until the earliest deadline. We have a
> differential test you may find useful: 48 seeded 20-minute scripts with 10 to 50% loss and outages up to 130 s, run
> through the 250 ms poll and through the deadline driver, which must give identical logs. We can share it if you want it
> against your version. We do not want to duplicate your PR."
>
> **Then, in discussion (only if #220's author agrees):** "Device scheduler on top of `next_timer_deadline`." The device timer
> task visits every peer every 250 ms. At 4,096 idle peers we measured 125 wakeups/s and 7.7 ms CPU/s (wireguard-go: 6.3 and 0.0).
> Ours keeps a min-heap of deadlines on the same 250 ms grid (so timers fire within one tick of due, as now), sleeps at most 1 s
> because the WireGuard clock keeps running through system sleep, and sweeps every peer every 10 s as a check that counts
> any peer whose reported deadline was too late (the counter must stay zero). Cost to avoid: our first version read the boot-time clock for every
> packet stamp and lost 2.5 to 4.6% throughput; it now reads once per run of packets. Mullvad clients have few peers; this
> is mostly for server-style use, so tell us if it is out of scope.

### 9.5 Draft: handshake "under load" from the queue, not a per-source count

> **Title:** Idea: decide "under load" by handshake backlog, as the WireGuard paper describes
>
> **Context.** The rate limiter counts every MAC1-valid initiation and response per source address and demands MAC2 after
> 100 per second. Our own responses to our initiations count too. A node restarting with 1,000 peers behind one NAT or relay
> got 100 sessions up and a cookie for the other 900, so they waited for the 5 s retry: all 1,000 up after 5.7 s on our VM
> (wireguard-go 0.5 s, kernel 0.3 s). The per-address count is also no defence against a flood from many addresses.
>
> **What we did.** The receive task owns a queue of MAC1-valid handshake messages (1,024 entries, about 180 KiB, no pool buffers
> held; full means drop). It serves the queue after each turn's data for at most 1 ms. The device is under load while the
> queue is an eighth full, and for one second after (as kernel WireGuard and wireguard-go do). The per-source map and its lock in
> every peer's timer visit go away. Data goes first, so a handshake storm cannot hold every peer's packets behind key agreements.
>
> **Result.** 1,000 peers behind one address: all up in 0.3 s (was 5.7 s). Flood of 20,000 MAC1-valid initiations per second
> from 256 addresses: engine CPU 172 ms/s against 1,026 ms/s (a full core), and a real peer starts after one retry
> instead of never. **Known cost:** a flood from one address that outruns the receive task now delays every new handshake by one 5 s
> retry, where the old count isolated that address; kernel WireGuard and wireguard-go behave the same way.
>
> **Questions.** Is the 128-message threshold (about 13 ms of key agreement in one task) right for your clients? Given the earlier
> advisory (GHSA-m2rr-7rr7-vmp7), would you want a security review of the design before code? We will not open a PR until
> you say so.

## Appendix: every fork commit and its group

Commits in `git log e95ba96..e6efb96` order within each group. 125 commits plus the merge `c4813b5` (G04).

| Group | Commit | Subject |
|---|---|---|
| G01 | `bba3dcf` | fix: a ring-only gotatun build no longer pulls in aws-lc-rs (#260, D289) |
| G02 | `01c29f4` | fix: drop undecodable packets instead of stopping a traffic direction (#260) |
| G02 | `11dc4e9` | fix: treat a closed TUN descriptor as device-gone on macOS too (#260) |
| G02 | `a557b50` | docs: say why ENODEV from a UDP socket is fatal (#260, J466 P3-B) |
| G03 | `8c118e8` | feat(device): report a confirmed peer endpoint (infraternal #489, J549 P1) |
| G04 | `1ae1fb8` | feat: Device::rehandshake sends a new initiation over an active session (#515, J604) |
| G04 | `8bfb2e5` | test: advance mock time for active-session rehandshake (#545) |
| G04 | `1490618` | Announce on the live session while a rekey is in flight (#483) |
| G04 | `4917100` | feat(device): let the owner request an immediate keepalive to every peer (#260, J561) |
| G04 | `2e54414` | test(device): a requested keepalive must not handshake an idle peer (infraternal #483, J633) |
| G04 | `adf7ff3` | fix(device): request keepalives only from peers with a live session (infraternal #483, J633) |
| G04 | `f5a6531` | test(device): drop two unused `mut` bindings so clippy -D warnings passes (infraternal #483) |
| G04 | `c382ef8` | test(device): observe the 1,000-peer requested keepalive by Bob's roam (infraternal #483) |
| G04 | `1f194e6` | test(device): fail the 1,000-peer keepalive test when idle peers send (infraternal #483) |
| G04 | `b52f1ef` | test(device): measure request_keepalives at 1,000 and 4,096 peers (infraternal #483, D393) |
| G04 | `c4813b5` | Combine Linux announcements and macOS send pools with the rehandshake test fix (#483) |
| G05 | `10f9f2c` | perf: allocate peer session ring after handshake (#260) |
| G05 | `c6fd62c` | perf: replace peer route trie with compact list (#260) |
| G06 | `87471cc` | perf: release packet buffers and receive pages when a link goes idle (#260) |
| G07 | `2441d08` | perf: force UDP socket buffers past rmem_max on Linux (#260) |
| G08 | `79eadab` | feat: add Linux TUN vnet-header TSO support (#260) |
| G08 | `9001341` | feat: segment UDP-L4 TUN frames when USO is enabled (#260) |
| G08 | `51c8fe4` | feat: coalesce ordered packets on Linux TUN (#260) |
| G08 | `b70333b` | fix: validate TUN GSO checksums before forwarding (#260) |
| G08 | `7df9305` | perf(tun): reuse TCP segment storage for transport data (#260) |
| G08 | `6a156e9` | #260: sum checksums 8 bytes at a time instead of one word at a time |
| G08 | `60b656c` | fix: keep the TUN virtio-header flag Linux-only (#260) |
| G08 | `abb772d` | fix: import IntoBytes on every OS for the raw TUN write (#260) |
| G08 | `95187b4` | chore: remove redundant Linux TUN return (#260) |
| G09 | `2b56d27` | perf: raise the Linux TUN transmit ring to 1,024 packets (#260) |
| G10 | `872a511` | feat: Linux UDP GSO sends and bounded GRO receive splitting (#260) |
| G10 | `65ddbfa` | perf: cap Linux UDP message batches at 64, alone on the pin (#260, J579) |
| G10 | `3a2e3a4` | fix(udp/buffer): no receive-queue depth probe in Linux test builds (#260, J827) |
| G10 | `f767914` | test: a burst over two UDP batches arrives whole and in order (#260, J588) |
| G11 | `1485210` | perf: bypass Linux UDP receive worker (#260) |
| G12 | `c26e975` | feat: process crypto in ordered peer batches (#260) |
| G12 | `3b99658` | perf: dispatch deep peer backlogs to crypto workers (#260) |
| G12 | `2f4d805` | fix: preserve per-run ordered delivery callbacks (#260) |
| G12 | `77caa54` | fix: keep shallow peer crypto inline during contention (#260) |
| G12 | `1291545` | fix: find and remove ordered-receive stalls in the parallel pipeline (#260) |
| G12 | `03a44d5` | fix: release device guard before incoming drains (#260) |
| G12 | `0565a1b` | fix: defer timer output at full peer capacity (#260) |
| G12 | `f3c357b` | fix: shut down crypto workers when owner drops (#260) |
| G12 | `0231023` | fix: take the async device lock out of every running packet task (#260) |
| G12 | `0c8609c` | fix: hold handshake-flush exclusion until the drained run owns its slots (#260) |
| G12 | `38cf5c9` | perf: start a connection's crypto workers on the first handoff (#260) |
| G12 | `4076dda` | #260: hand bulk-sized crypto runs to the workers without waiting for a backlog |
| G12 | `435418a` | test: a rekey under sustained traffic must not stall a receive path (#260) |
| G12 | `5e26149` | fix: drain the handshake queue only from the TUN task (#260) |
| G12 | `d278adc` | test: assert the receive task never drains across rekeys (#260) |
| G12 | `7716973` | test: J433's handshake-during-drain regression and simultaneous-start stress (#260) |
| G12 | `dbf19d5` | fix: reserve the receive task's control slot under peer state (#260) |
| G12 | `c12f540` | fix: a packet-task panic or pipeline failure now fails the device (#260) |
| G12 | `60f9d83` | fix: send nothing to a peer removed between route lookup and its lock (#260) |
| G12 | `2e39995` | fix: count and report handshake-queue drops; assert none across rekeys (#260) |
| G12 | `1359ad5` | test: the rekey flood waits for its rekeys and treats gaps as a hang check (#260) |
| G12 | `f0ad192` | fix: a drain requested before peer removal sends nothing (#260, J466 P3-A) |
| G12 | `5311c2c` | Wake crypto workers from a bounded mutex-free queue (#260) |
| G12 | `a33f3d9` | Rotate idle crypto worker wake priority (#260) |
| G12 | `6db3b51` | Withdraw the coalesced ready signal when a worker takes the last run (#260, J1010) |
| G13 | `ff7785c` | test(crypto): small receive runs stay inline under a limit (red) (#260, J744) |
| G13 | `523465c` | perf(crypto): keep small receive runs inline behind a bench switch (#260, J744) |
| G13 | `40e22d3` | perf(crypto): small receive runs stay inline by default on macOS (#260, J763) |
| G13 | `b2cb26a` | Keep crypto runs of up to 48 packets inline on Linux (#260, J1121) |
| G13 | `cd9ab06` | test: drop a needless ok() before expect() in the J1010 wake test (#260, J1121) |
| G14 | `983aa30` | feat(aqm): the receive-side queue bound ships on, ECN first (infraternal D397, #260) |
| G14 | `288f993` | feat(aqm): a due signal skips sparse flows and goes to a queue-heavy one (infraternal #260, J747) |
| G14 | `4a6c8ab` | fix(aqm): pass implausible receive ages and reset stale signal debt (#260) |
| G14 | `e3d4a99` | fix(aqm): bound sparse exemptions by aggregate small-packet bytes (#260, D397) |
| G14 | `abc97d5` | fix(aqm): bill authenticated padding before IP length trimming (#260, D397) |
| G14 | `08a9cdc` | fix(aqm): start congestion episodes from current queue evidence (#260, D397) |
| G14 | `e94546d` | fix(aqm): expire deferred signals across a backward clock step (#260, D397) |
| G14 | `be70cc0` | style(aqm): format the short-drain regression assertion (#260) |
| G14 | `800259d` | fix(aqm): expire deferred signals across a forward clock step (#260, D397) |
| G14 | `5eea3d1` | test(aqm): retain the fixed-run-order fairness diagnostic (#260, D397) |
| G14 | `c4abd7f` | fix(aqm): spread bulk CE marks within ordered receive runs (#260, D397) |
| G15 | `5757403` | Decide "under load" by the handshake backlog, not by 100 messages per source (#260, J1112) |
| G16 | `3881c70` | Wake the timer task only for peers with a timer due (#260, J1111) |
| G16 | `bd6eaeb` | Read the timer event clock once per packet run, not per stamp (#260, J1111) |
| G17 | `30a1544` | Receive UDP GRO datagrams without copying them (#260, J1129) |
| G17 | `e6efb96` | Merge TUN runs that are already queued into one write run (#260, J1129) |
| G18 | `d77cbf5` | test: replies jump ahead of bulk in the TUN read-ahead and UDP receive (red) (#260, J720) |
| G18 | `31775c1` | perf: replies jump ahead of bulk in the TUN read-ahead and UDP receive (#260, J720) |
| G18 | `7fed605` | test(udp): small datagrams overtake queued send runs (red) (#260, J720) |
| G18 | `5a91838` | perf(udp): small datagrams overtake queued send runs (#260, J720) |
| G18 | `9564196` | test(udp): a send-turn budget lets other tasks run between datagrams (red) (#260, J728) |
| G18 | `d663f4d` | test(udp): pin batch hand-over from the buffered receive queue (red) (#260) |
| G18 | `161ecd5` | perf(udp): hand the packet task every queued datagram at once (#260) |
| G19 | `a233146` | perf: cap macOS TUN channels and UDP receive buffer at 512 packets (#260) |
| G19 | `8129065` | perf(macos): hold 128 received datagrams, not 512, before decryption (#260) |
| G19 | `1c18175` | test(macos): pin a utun max-pending-packets setter (red) (#260, J673) |
| G19 | `e204cfe` | perf(macos): let a utun queue more than one packet for its reader (#260, J673) |
| G20 | `d0bacbb` | test(udp/macos): connected per-endpoint sends keep both directions working (red) (#260, J744) |
| G20 | `5ee0715` | perf(udp/macos): send through connected per-endpoint sockets (bench switch) (#260, J744) |
| G20 | `ef0a9e4` | test(udp/macos): connected sends on by default and hardened for network changes (red) (#260, J763) |
| G20 | `b5d1edf` | perf(udp/macos): connected per-endpoint sends on by default, safe across network changes (#260, J763) |
| G20 | `87ae319` | feat(cli/macos): SIGUSR1 tells the device the network changed (#260, J763) |
| G20 | `5ecec93` | test(udp/macos): a network change reconnects while the receiver runs (red) (#260, J763) |
| G20 | `fd796b9` | fix(udp/macos): removing a connected socket closes it at once (#260, J763) |
| G20 | `5bd8b75` | test(udp/macos): keepalives and handshake responses reconnect their endpoint (red) (#260, J789) |
| G20 | `fdc9118` | fix(udp/macos): keepalives and handshake replies leave through sendto and reconnect (#260, J789) |
| G20 | `52ebd5b` | test(udp/macos): pin the connected-send rules that J789's mutants survived (#260, J789) |
| G20 | `8d0dad0` | style(udp/macos): rustfmt the files J744 and J763 touched (#260, J789) |
| G20 | `f0a6f4f` | test(udp/macos): connected sends are off by default (red) (#260, J789) |
| G20 | `ec11fc0` | fix(udp/macos): connected sends off by default until the port cannot be taken over (#260, J789) |
| G20 | `26ad4be` | test(udp/macos): a port another process bound first is never shared (red) (#260, J827) |
| G20 | `cc09ffc` | fix(udp/macos): refuse a port another socket held before our bind, connected sends off (#260, J827) |
| G20 | `78c0fc1` | docs(udp/macos): ensure_alone checks once at bind; it does not cover the socket's life (#260, J826) |
| G20 | `eefc913` | test(udp/macos): a_free_port_binds no longer races the squatter test for its port (#260, J826) |
| G20 | `88b970e` | Restore opt-in Mac connected sends with startup pools for each family (#260) |
| G20 | `4e20c3d` | feat(macos): the socket factory takes its owner's connected-send choice (#260, J1108) |
| G20 | `3660129` | fix(macos): a refused connected send falls back to sendto, and a defunct pool socket is retired (#260, #554, J |
| G20 | `2982c3b` | fix(macos): batched sends on a failing pool socket fall back once per run (#260, #554, J1108) |
| G20 | `617eb92` | fix(macos): the port audit notices that macOS 27 hides other processes' sockets (#260, J1108) |
| G21 | `177f3bd` | test(udp/macos): a dual-stack bind is one socket per family (red) (#260, J834) |
| G21 | `f135c7e` | fix(udp/macos): bind a dual-stack port as one socket per family (#260, J834) |
| G21 | `987cfdb` | fix(udp/macos): the per-family pair needs no socket-list audit (#260, J834) |
| G22 | `04ff48c` | proto(macos): batch UDP sends and receives with sendmsg_x/recvmsg_x behind GOTATUN_J1023_BATCH (#554, #260, J1 |
| G22 | `ac1d1d7` | feat(macos): batch UDP through sendmsg_x/recvmsg_x where it is measured faster (#554, #260, J1036) |
| G23 | `c9a91d5` | perf: D348 pinned R4b harness overlay (#260) |
| G23 | `49dd3a4` | perf: read pipeline diagnostic switches once (#260) |
| G23 | `c1d1476` | bench(diag): queue-depth sampler and capacity overrides for the Mac pipeline (#260, J687) |
| G23 | `7db407b` | bench: GOTATUN_BENCH_UDP_RX_BATCH overrides the receive hand-over batch (#260, J687) |
| G23 | `c163dea` | bench: crypto worker count, transmit inline limit and worker placement knobs (#260, J1121) |
| G23 | `8936888` | perf(udp): bench switch for a send-turn budget, the reply-leg poll point (#260, J728) |
| G24 | `68a4a7c` | perf: disable THP on Linux CLI startup (#260) |
