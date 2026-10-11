<!-- Session shim implementation, local measurements and reviewer handoff for #16. -->
# S1 session shim evidence (#16)

Historical Alacritty implementation and measurements. DECISIONS 94 replaces its
terminal-state engine; see [the Ghostty migration evidence](S1-VT-GHOSTTY.md)
for the current serializer, byte budget, build and release comparisons (#22).
The retained-Exited/ExitAck lifetime evidence below is historical: owner brief
#151 now retires a dead shell's shim after ordered exit delivery, or within one
second without a data viewer. See [the current shim contract](../contracts/shim.md)
and [the session bounds evidence](perf/session-bounds/README.md). Detached live
shells still survive under D178.

Branch `lane-shim`, base `386acfd3dc6255c7f58f98b4f114d5d7326292ad`.
Implements DECISIONS 5, 12, 13, 17, 40 and 41 without changing a decision or
frozen v1 frame. Linux implementation; macOS remains S2.

`infraternal __shim --session <32 hex digits> --uid <uid>` owns one login shell.
The infraternal agent starts this internal command in its own transient systemd
scope. On other init systems it passes `--detach` for double fork and setsid.
The systemd scope and the agent unit's KillMode belong to the launcher/installer.
Default socket state follows contract §3; `--state`, geometry and ring capacity
are local launcher parameters. Shell environment is constructed from the target
account, with TERM/PATH and an optional local ZDOTDIR profile location. Groups
are resolved before fork; the slave is owned by the target uid with mode 0600; groups, gid and uid are dropped before home traversal
and exec. Input is retained across connection replacement and disconnect.

## Frozen framing interpretation recorded on #16

Hello identifies the **shim** pid and captures current head/start offsets.
Attach records capability negotiation (shim caps are zero). ReadFrom or
SnapshotRequest establishes delivery; PTY reads pause until then. Replay and
live output share one cursor. Requests take effect after any partly written
frame completes; multiple unserviced cursor requests select the latest cursor.
Future ReadFrom offsets, wrong directions, invalid payloads and unknown types
close the peer, leaving the shell intact. Snapshots trim the oldest tail rows to
fit the frame. A screen that itself cannot fit gets Error(1) without killing its
shell. Exited follows PTY drain and is retransmitted after reattach until ExitAck.

Every frame has golden bytes. Decoder storage is bounded before allocation.
One bounded outgoing frame, one bounded pending-input queue and kernel socket
buffers apply attached backpressure. Detached output keeps flowing into the
lazy 8 MiB byte-offset ring and VT state. Replacement first authenticates the
new socket, then drops the old socket. Directories reject symlinks and incorrect
ownership/modes; existing sockets are never stolen by another startup.

## VT comparison

Local Linux release measurements at 200×60; these are host measurements, not
results from the pinned perf VM. Raw parser workload: the same 10,060-line
ASCII buffer repeated 100 times. RSS includes allocator retention and parser
screen storage; it is measured as the process's increase over startup.

| Candidate | Raw parsing | RSS increase for 10,000 lines | Repaint evidence |
| --- | ---: | ---: | --- |
| alacritty_terminal 0.25.1 | 58.63 MB/s | 47,988 KiB | Custom serializer passes vim/htop/less screen, cell colors/flags, cursor, modes, and continuations |
| vt100 0.16.2 | 42.51 MB/s | 63,704 KiB | Built-in formatter paints vim and its cursor, but loses alternate mode and fails continuation |
| libghostty-vt 0.2.2 | 138.26 MB/s | 19,672 KiB (10,001 lines) | Available formatter fails cursor on all three fixtures, htop repaint, and all continuations |

Ghostty is a usable safe Rust binding, but requires the pinned Zig 0.15.2;
Zig 0.16.0 fails its build-version check. Its pinned C implementation counts
scrollback **bytes**, although the C/Rust options docs say lines. The comparison
uses a 64 MiB history budget, measures RSS immediately after the first buffer,
then runs throughput (ending at 38,799 retained lines). Its formatter comparison
requests VT, modes, cursor, style, scrolling region, tabs, character sets and
keyboard state, and includes a primary-screen canary before entering alternate
screen. These are formatter results, not a claim that Ghostty's parser is wrong.

Alacritty wins over vt100 on throughput and memory and supplies the public cell,
cursor and mode data needed for a correct repaint. Its custom serializer retains
both screen buffers, a bounded scrollback tail, styles/colors/hyperlinks, saved
and live cursors, pending wrap, margins/origin, input modes, tabs, character sets
and current keyboard flags. A bounded VTE observer preserves incomplete CSI,
UTF-8 and control-string prefixes across snapshot boundaries. Printable ASCII
in ground state skips that second parser. Entering alternate screen copies only
256 history rows and the primary screen, avoiding a full 10,000-line clone.

Captured real programs and their continuation bytes live in
`crates/infraternal-shim/tests/fixtures/`; `capture.py` regenerates them.
Htop is restricted to PID 1 so fixtures do not capture arbitrary process argv.
The socket integration drives real vim, forces ring wrap, repaints a fresh VT,
compares every visible cell and cursor against an independent VT fed the raw output,
then exits vim and verifies subsequent shell output and retained exit status.

## Budgets and security

Final release measurements (same host, 2026-10-06):

```text
Input decode -> real PTY write: n=10000 p50=2.118 us p99=4.777 us
Snapshot 200x60 + 256-line tail: p50=0.426 ms p99=0.669 ms bytes=74157
shim VT including observer: 57.35 MB/s, 10,000-line retention
static shim idle RSS: 1136 KiB (1.109 MiB); 80x24; default 8 MiB ring allocated lazily; 10,000-line scrollback limit
```

The input measurement starts when complete frame bytes reach the decoder and
ends after successful writes to a real PTY; it excludes socket scheduling and
shell echo. The snapshot measurement includes repaint allocation and the
scrollback tail. The idle measurement uses the actual x86_64 static binary,
after login startup, and measures the shim alone. The ring grows only when used;
these fresh idle numbers do not describe a full ring or full scrollback.

Rootful canary output:

```text
PTY slave: uid=1001, mode=0600
rootful shell: real/effective/saved/fs uid=['1001', '1001', '1001', '1001']; supplementary groups=['27', '1001']; root group absent
SO_PEERCRED: uid 65534 connected but received no Hello; authenticated root connection retained
Exited(0) -> ExitAck: shim exited and socket removed
```

The credential probe temporarily permits traversal in only its test directories
to prove SO_PEERCRED independently of filesystem permissions, then restores
0700/0600. Unsafe is denied at the crate boundary and forbidden in every data
module; the five unsafe sites are confined to `src/pty.rs` with SAFETY comments.
A second reviewer must audit those sites as required by contract §6; this lane
provides the implementation and evidence, not an independent review of itself.

## Verification and reproduction

Seven real socket tests exercise login, echo, resize, exact replay after a drop,
ring wrap/vim, replacement, malformed frame limits, disallowed signals, attached
backpressure/detached progress, retained Exited/ExitAck, launcher SIGKILL, and
systemd scope survival after stopping the parent service. The systemd test skips
with an explicit reason if there is no user manager; it ran and passed here.
Unit tests cover every frame, fragmentation, coalescing, exact length limits,
ring wrap, full-screen continuations, margins, tabs, character sets and incomplete
VT prefixes. Performance tests are explicitly ignored in normal debug runs.

```sh
cargo test -p infraternal --test shim -- --nocapture
ZDOTDIR="$PWD/crates/infraternal/tests/profile" \
  cargo test --release -p infraternal-shim --lib -- --ignored --nocapture --test-threads=1
cargo run --release -p infraternal-shim --example vt_compare -- vt100
cargo run --release -p infraternal-shim --example vt_compare -- alacritty
nix shell nixpkgs#zig_0_15 -c cargo run --release -p infraternal-shim \
  --features bench-ghostty --example vt_compare -- ghostty
python3 crates/infraternal-shim/tests/idle.py
sudo -n python3 crates/infraternal-shim/tests/security.py \
  target/x86_64-unknown-linux-musl/release/infraternal "$(id -u)"
nix shell nixpkgs#binutils nixpkgs#file -c scripts/verify fast
```

Run `vt_compare <candidate> <fixture.vt>` for fixture/continuation comparisons.
Ghostty is opt-in and is absent from the production binary. The test harness's
LLVM/NCSA license is permissive and AGPL-compatible; cargo-deny explicitly allows
it without exceptions to the advisory/source/wildcard policy.

The ASan/libFuzzer decoder run completed **3,470,294 executions in 611 seconds**,
no crash, coverage 434, features 1,244, final corpus 296 inputs / 64 KiB. See
`fuzz/README.md` for reproduction (fuzz-only LTO override). Raw local gate,
benchmark, comparison, security and fuzz logs are retained under `target/shim-*`.

## Independent review repairs (2026-10-06)

The reviewed implementation is preserved as `lane-shim-v1` at
`7c879a47e508a32452571d2bb5d750a10311b718`. The lane is reconstructed from
`s1-base` as separate dependency, production module, test, fuzz, benchmark and
documentation commits. Every commit runs
`nix shell nixpkgs#binutils nixpkgs#file -c scripts/verify fast`; complete local
outputs are under `target/history-gates/`. The commit list and final verbatim
output are recorded on Forgejo #16. No decision or frozen frame changes.

The snapshot regression first fails at visible cell 0:7 (`A` becomes a space),
as recorded in `target/fix-vt-red.log`. The observer previously interpreted
47/1047 as alternate-screen transitions although pinned Alacritty/vte ignores
those modes. It now observes only runtime-supported 1049; ignored modes no
longer select a stale primary grid for repaint. This preserves runtime behavior,
rather than adding or normalizing terminal modes. Tests in
`crates/infraternal-shim/tests/unit/terminal.rs` cover 47, 1047 and 1049, each
with ordinary and nested switches. Each of the six cases compares all 12,000
visible cells, styles, modes, palette and cursor immediately after repaint and
again after continuation/return to the primary screen. Existing full-screen,
charset, margins and unfinished-parser tests remain.

The public detach reproduction initially reports ENOENT for fd0 after closing
stdin following Rust startup (`target/review-detach-fd0.log`, `target/fix-detach-red.log`). Detach duplicates
its /dev/null source with F_DUPFD_CLOEXEC to a fresh fd above stderr, transfers
ownership exactly once to File, then calls safe nix standard-descriptor dup2
wrappers. Dropping that source cannot close redirected fd0/1/2. The standalone
`examples/detach_probe.rs` is deliberately single-threaded; the threaded test
harness launches it in a subprocess. `tests/detach.rs` verifies all seven
combinations of closed standard descriptors. The result reader waits for a
complete line so it cannot confuse a partial write with a failed redirection.

Raw chdir is replaced with nix's CStr wrapper, which uses the preallocated
pointer after fork. The reviewed TIOCSWINSZ block remains: its master ownership
and valid Winsize pointer are unchanged, and adding a production rustix
dependency solely to replace a sound ioctl is unnecessary. There are still
five unsafe boundaries: pre_exec, resize, two forks and transfer of the fresh
F_DUPFD_CLOEXEC descriptor into File. The new transfer's SAFETY comment states
its unique ownership and fd-range invariant.

Review evidence for exactly-once boundary replay, twenty replacement races,
decoder bounds, credentials, fd inheritance and socket permissions remains
at the reviewer's cited paths. The current gate reruns real socket lifecycle,
backpressure, replay, vim repaint, malformed input and survival tests. Separate
user-scope survival proves stopping the parent service leaves the scope alive;
it does not prove the rootful installer/restart path. Stale socket removal is
still the infraternal agent's responsibility. Custom --state parent directories
must be trusted launcher choices. The prior fuzz campaign is historical evidence,
not a campaign rerun by this repair job; the decoder has not changed.

An initial budget run overlapped compilation and ran benchmark tests in parallel:
its snapshot p99 was 12.672 ms (`target/fix-budgets.log`). The subsequent serial
run after those builds passed: input p99 16.002 us, snapshot p99 1.213 ms, parser
53.41 MB/s, fresh idle RSS 1124 KiB (`target/fix-budgets-serial.log`,
`target/fix-idle.log`). Keep the loaded-host result visible rather than calling
the local measurements pinned-perf-VM evidence. Final measurements after the
history rewrite are recorded below and on #16.

Final serial release measurements after reconstruction:

```text
test session::measurements::budgets::input_to_pty_write ... Input decode -> real PTY write: n=10000 p50=2.118 us p99=4.777 us
ok
test terminal::measurements::budgets::snapshot_200x60 ... Snapshot 200x60 + 256-line tail: p50=0.426 ms p99=0.669 ms bytes=74157
ok
test terminal::measurements::throughput::measured_parser ... shim VT including observer: 57.35 MB/s, 10,000-line retention
ok
static shim idle RSS: 1136 KiB (1.109 MiB); 80x24; default 8 MiB ring allocated lazily; 10,000-line scrollback limit
```

Complete measurement logs: `target/final-budgets.log`, `target/final-idle.log`.
The rootful canary was rerun successfully in `target/final-security.log`: slave
uid 1001/mode 0600, all UID slots 1001, supplementary groups 27/1001 with no root
group, uid65534 peer refused without replacing the authenticated peer, and
Exited(0)/ExitAck removed the socket.

Static binaries have no PT_INTERP. Against the independent same-compiler base
build, the complete lane delta is:

| musl target | s1-base bytes | repaired lane bytes | delta bytes |
| --- | ---: | ---: | ---: |
| x86_64 | 705624 | 1025208 | +319584 (+45.29%) |
| aarch64 | 607880 | 875968 | +268088 (+44.10%) |

Relative to reviewed lane-shim-v1 this is +288 bytes on x86_64 and +424 bytes on
aarch64. The complete lane includes PTY, codec, ring, VT, pump and CLI; these
deltas do not isolate a parser library. The final lockfile equals the reviewed
lockfile; dependency commits introduce their own resolved graph incrementally.
