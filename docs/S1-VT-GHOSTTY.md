<!-- Ghostty VT migration, C API gaps, reproducible measurements and review evidence for #22. -->
# Shim terminal state: libghostty-vt (#22)

> Raw verification logs and captures were removed under D262. Fresh receipts belong under
> `$HOME/.cache/codex-scratch/vt-ghostty/evidence/`; create output directories before direct
> shell redirections and point `VT_CAPTURE_DIR` inside that external directory.

Owner DECISIONS 94 replaces the Alacritty terminal-state engine. This checkout's
`DECISIONS.md` ends at 86; 94 is supplied by the owner's job and recorded on #22.
This document supplements the historical [S1 shim comparison](S1-SHIM.md).
DECISIONS 7, 13, 20, 40 and 41 still apply. Frozen v1 frame layouts remain
unchanged; an additive recovery capability is documented below.

## Build and production dependencies

`scripts/build-vt` builds the MIT-licensed, minisign-verified libghostty-vt
1.0.1 source and dependency archives. `scripts/libghostty-vt.sha256` pins both
archives and their signatures; `nix/package.nix` consumes the same inputs.
Zig is exactly 0.17.0, supplied by the development shell or the existing
architecture-specific checksum-verified `scripts/auth-toolchain` download.
Both the VT archive and vendored C dependencies use the same Zig. The shim
remains AGPL-3.0-only. Rust `libghostty-vt` 0.2.2 is retained only for the
optional historical `bench-ghostty` comparison; production uses our audited
C boundary directly. The 1.0.1 compatibility review and qualification are
tracked on #508 (J537); historical measurements below retain their original
source and toolchain context.

Native builds explicitly select `x86_64-linux-musl` or `aarch64-linux-musl`,
baseline CPU, and ReleaseFast; development uses ReleaseSafe. A content-keyed
cache under `target/vt-tools` covers the pinned source, adapter, build recipe,
target and optimization. Installation is locked so Cargo feature/test builds
cannot observe a partial archive. `build.rs` links the static archive.
Both final executables are stripped static PIE with no `PT_INTERP`.

| Static executable | Alacritty baseline | Ghostty | Increase |
| --- | ---: | ---: | ---: |
| x86_64 musl | 9,908,192 bytes | 11,421,456 bytes | 1,513,264 bytes (15.27%) |
| aarch64 musl | 8,327,168 bytes | 9,560,376 bytes | 1,233,208 bytes (14.81%) |

The actual starting HEAD was `e72589e346fe1707299f64676367cc5668c9d1c3`, one
commit after the requested `947d68f` base. Baseline copies are
`target/vt-ghostty/alacritty-{x86_64,aarch64}`. Default production Cargo edges
contain neither `alacritty_terminal` nor `vt100`; the optional `bench-vt`
feature preserves the comparison example. `bench-ghostty` additionally enables
the old Rust binding/formatter comparison. Those engines are absent from a
default build (`$HOME/.cache/codex-scratch/vt-ghostty/evidence/production-dependencies.log`).

## Snapshot state and the upstream API boundary

`src/terminal_native.rs` owns one opaque C terminal handle. Its audited unsafe
boundary covers creation, synchronous input, resize, serialization and free;
test-only queries compare cells and count history. It lends no grid references
to Rust and has no callbacks. Initialization errors propagate to the session
API; returned resize errors permanently retire the handle and reconstruct at
the last good size as documented in the third-review section below. Independent
review of that boundary is still required; these measurements are implementation evidence.

Release packaging follows the stripped final executable (D243, #189): only
`ReleaseFast` sets the native root module's `strip` flag. Native panic messages
and termination remain; raw-address stack fallback and external-symbol lookup
are unavailable in that build. Debug and `ReleaseSafe` keep their diagnostics.
This does not change frame-pointer settings, unwind-table settings, parser
checks, or Rust's `panic = "unwind"` task containment (D5).

The `session-image` feature selects a callback-free archive for executable
images, including the full CLI's session-payload fallback. It omits native
logging configuration exports and their unused formatters; it never reports
successful callback configuration while dropping callbacks. Ordinary archives retain the upstream logging exports
and behavior. Both modes use the same pinned terminal engine and Rust
initialization/resize error handling; mode and adapter source enter the native
cache key.

`native/snapshot.zig` reads Ghostty's actual screen/page/cell state. It streams
VT into the caller's bounded buffer and does not use the built-in terminal
formatter, clone history, or maintain a second terminal-state engine. It uses
the style formatter only for SGR encoding. Repaint constructs primary and
retained alternate screens with mode 47 so reconstruction does not destroy
DECSC state or clear the alternate screen as 1049 would. Subsequent original
47/1047/1049 transitions, including repeated switches, run in Ghostty normally.
Screen-switch mode bookkeeping is represented by that canonical construction;
synchronized-output mode 2026 is omitted to permit the repaint to display.

For representable states, the serializer preserves visible cells and a bounded
history tail, SGR flags,
16/256/RGB colors and palette overrides, hyperlinks and their row groups,
wide cells and stored graphemes, saved/live cursors and protection, pending
wrap, vertical/horizontal margins and origin, input modes, custom tabs,
charsets/single shifts, cursor shape/blink and the complete Kitty keyboard
flag ring. Saved origin positions are constructed against temporary full
margins before restoring the live region. Erased cells use ECH/CUF runs rather
than spaces because combining continuation distinguishes absence from text.
Grapheme clustering is disabled at cell boundaries and enabled while appending
each cell's stored combining/ZWJ sequence; the original mode is then restored.
Implicit hyperlink IDs are represented by stable `infraternal-implicit-N`
OSC 8 identifiers; explicit IDs and URIs are preserved.

The pinned public **C** API cannot expose all this state. Its grid references
address the active screen; it lacks inactive-screen iteration, per-screen saved
cursor state, cursor charset/protection/active hyperlink identity, tab stops,
scrolling margins, and the complete keyboard stack. Cell hyperlink lookup gives
the URI, not the explicit/implicit group identity. Active cursor coordinates,
pending wrap, modes and SGR are already queryable; visual cursor shape/blink is
available through the render API. These existing getters need no patch.

The smallest proposed upstream change is read-only C accessors: a screen key on
grid-reference lookup; sized live/saved cursor-state records with charset,
protection and hyperlink identity; margins/tab-stop/keyboard-stack queries;
and a grid-reference hyperlink-ID getter. These can expose the same existing
Zig fields this adapter reads, with references valid until terminal mutation.
Those getters cover observation, but the fidelity work below also needs
nonprinting setters for states the bounded VT painter cannot restore. Until
those APIs exist,
the adapter is compiled into the pinned library using two C exports, snapshot
and a read-only test oracle. Updating Ghostty requires reviewing this adapter
against the new fields and rerunning the fixtures.

The Rust VTE observer tracks only unfinished syntax. Ground ASCII/C0 other
than ESC bypasses it; Ghostty handles those bytes once. Inside sequences it
still sees execution/cancellation, and already-executed C0 is excluded from
CSI carry. The carry retains fragmented UTF-8, CSI and control strings up to
the frozen 1 MiB frame capacity. Exceeding that capacity rejects Snapshot
without corrupting runtime state; completing the sequence restores snapshots.
Snapshots always include both required visible screens and the complete carry.
The history tail starts at 256 rows and halves on frame overflow, down to zero,
bounding retries to nine. If visible state still cannot fit, Snapshot returns
an error rather than truncating cells or parser state.

## Scrollback budget and correctness evidence

The session limit is **17 MiB = 17,825,792 bytes** of Ghostty page storage.
This is not a line count or an exact bound on process RSS. At 200 columns with
`1234567890 abcdefghijklmnopqrstuvwxyz` CRLF output it retains about 10,000
history rows: calibration retained 10,063; subsequent page-pruning positions
retained 10,099–10,178. Width, styles, graphemes and page granularity change the
mapping. At 16 MiB the calibration retained 9,364 rows; 17 MiB gives the closest
mapping to the earlier 200×60/10,000-line comparison. The 8 MiB output replay
ring is an independent byte budget, allocated lazily.

All pre-existing vim, htop, less and continuation bytes remain unchanged.
The real vim socket integration still forces ring wrap and repaints a fresh VT.
The new frozen `tests/fixtures/unicode{,.continue}.vt` covers emoji ZWJ,
family emoji, CJK wide boundaries, combining characters, colors and hyperlinks.
Additional unit cases exercise nested alternate switches, saved origin after
margin changes, wrap-disabled combining continuation, keyboard ring rollover,
implicit links, long OSC/DCS/APC prefixes, oversized carry recovery, history
pruning and resize. The native oracle reads Ghostty cells independently of the
serializer, including text presence, widths, graphemes, styles, links, row wrap,
cursor, modes and palette; continuations expose retained hidden-screen state.

The historical red/green logs were removed under D262. The final unit result is
20 passed; performance tests are explicitly ignored by the ordinary test gate
and run separately below.

## Release measurements on this host

2026-10-06, Linux x86_64, eight CPUs, Intel Core i9-9900K; **not the pinned perf
VM**. Own builds completed before timing. Other worktrees may use this host;
there is no CPU isolation. Rates use decimal MB/s. Floods include real PTY,
shim, inherited socket, infraternal agent mux framing and output-credit return.
Each trial sends exactly 50 MiB plus completion/prompt overhead and keeps only
a bounded completion suffix. Three serial trials per binary:

| Flood | Alacritty median (range), MB/s | Ghostty median (range), MB/s |
| --- | ---: | ---: |
| LF | 6.350 (6.178–6.528) | 18.003 (17.369–18.071) |
| CRLF | 23.232 (20.770–25.712) | 21.210 (19.696–22.757) |
| Printable | 44.687 (44.141–45.966) | 80.232 (78.239–82.428) |

Every Ghostty trial exceeds DECISIONS 41's 10 MB/s target. LF is 2.84× and
printable 1.80× the contemporary baseline. CRLF median is 8.7% lower; ranges
overlap. The tradeoff is higher LF/printable throughput and much lower full
session memory, with every flood above the target. The review's 4–5.7 MiB/s LF
is consistent with the earlier loaded-host preview (4.160 MB/s) and contemporary
serial baseline (6.056 MiB/s median); do not substitute parser speed for floods.

| Measurement | Alacritty | Ghostty |
| --- | ---: | ---: |
| Current raw parser / Ghostty with carry | 67.33 MB/s | 145.01 MB/s |
| Terminal RSS growth at ~10,000 rows, 200×60 | 47,988 KiB | 19,160 KiB (10,001 rows) |
| Terminal RSS growth at full byte budget | — | 19,416 KiB (10,178 rows) |
| Static shim idle RSS, 200×60 | 4,248 KiB | 4,800 KiB |
| Static shim full history + 8 MiB ring RSS, 200×60 | 67,128 KiB | 33,116 KiB |
| Real shim socket Snapshot p99, 1,000 samples | 4.112 ms | 1.089 ms |
| Serializer Snapshot p99, 200×60 + 256-row tail | 0.669 ms (historical) | 0.917 ms |
| Direct Input decode→real PTY write p99, 10,000 samples | 4.777 µs (historical) | 17.417 µs |

The standalone terminal memory test allocates its emitter before baseline and
runs alone in a fresh process. The actual shim measurements include code pages,
native initialization and the output ring. Full shim RSS falls 50.7%; terminal
growth at 10,000 rows falls 60.1%. Idle shim RSS increases 552 KiB at 200×60.
The optional comparison example confirms the historical 47,988 KiB Alacritty
growth on this host and measures 67.33 MB/s parsing, versus its earlier 58.63
MB/s. Ghostty including carry is 2.15× that contemporary parser result.
The input implementation is unchanged by the engine switch apart from fallible
initialization/resize. Historical timings are not contemporary A/B latency
controls. Direct input remains below its 200 µs test threshold and serializer
p99 below 2 ms.

The real infraternal-agent verification passes 24/24 crash/replay cases, then
measures Input→PTY-write acknowledgement p99 **184.360 µs**, including delivery
and acknowledgement (an upper bound on write latency). Its credited 50 MiB
flood reaches 17.401 MiB/s; withholding output credit leaves peak infraternal
agent RSS at 4,024 KiB. This is below DECISIONS 41's 15 MB idle infraternal-agent
budget, but that result is not a substitute for pinned-VM verification.

The historical `tests/idle.py` standalone 80×24 canary's 4 MiB assertion fails
on **both** saved binaries here: Alacritty 5,748 KiB; Ghostty 4,724 KiB. Its
guard is unchanged. This supplemental failure remains visible in
`alacritty-idle-80x24.log` and `idle-final.log`; the exact fast gate and the
release parser/input/snapshot assertions pass. Do not describe every
historical supplemental canary as green.

## Reproduction and gate logs

Run from this worktree:

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl -c scripts/verify fast
ZDOTDIR="$PWD/crates/infraternal/tests/profile" nix shell nixpkgs#zig_0_15 -c cargo test --release -p infraternal-shim --lib --locked -- --ignored --nocapture --test-threads=1 --skip measured_terminal_rss
nix shell nixpkgs#zig_0_15 -c cargo test --release -p infraternal-shim --lib --locked measured_terminal_rss -- --ignored --nocapture --test-threads=1
python3 crates/infraternal-shim/tests/vt_flood.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 crates/infraternal-shim/tests/vt_memory.py --binary target/x86_64-unknown-linux-musl/release/infraternal
python3 scripts/verify-agent.py --binary target/x86_64-unknown-linux-musl/release/infraternal
nix shell nixpkgs#zig_0_15 -c cargo clippy -p infraternal-shim --all-targets --features bench-vt --locked -- -D warnings
```

The raw release measurements and per-commit fast-gate receipts were removed
under D262. Forgejo #22 records start/base, findings and final HEAD with
verbatim gate output. No issue is closed and no branch is pushed by this job.


## Snapshot fidelity follow-up (#22)

The differential oracle compares both allocated screens immediately after
replay and after shared continuations. It checks text and grapheme scalars,
wide/continuation flags, empty-cell attributes, SGR (including RGB and underline
style), protection, OSC 8 URI/group identity, row wrap/continuation flags,
live/saved cursor coordinates and attributes, cursor shape/visibility, active
screen, region/origin, tab stops, the terminal REP source, and each screen's pending wrap.
Continuation probes run REP first, print at the actual right margin, combine
characters, tab, restore the saved cursor, and newline at the region bottom.
They also switch screens to exercise retained inactive state.

Regression tests preceded their corresponding fixes. F1 compared with code
6,000,000 (REP source); painting the inactive screen first and active screen
last fixes the alternate-screen round trip. The cursor regression compared
with 3,000,000: CUP under origin mode clamps a cursor which was outside its
region before origin was enabled. Restoration now positions it with full
margins before reinstating the region. Edge regressions required independently
styled empty spacer heads, narrowed wide cells, wrapped graphemes and widened
variation-selector tails to retain their own metadata. Saved cursors are
constructed before painting because the saved margin cell can subsequently
change width. REP is reconstructed explicitly, and temporary wrap anchors
preserve live/saved pending wrap without leaving visible scratch cells.

The Rust corpus lives in `crates/infraternal-shim/tests/unit/snapshot_fidelity.rs`.
The normal fast gate runs 1,000 seeded cases; `scripts/verify nightly` runs
20,000 in release mode. Both use xorshift64 seed `0x22601006`, 24 valid tokens
per case, including screen switches, regions, origin, save/restore, tabs,
REP, erase, wrap, SGR, CJK, emoji, ZWJ and combining marks. Four tracked vim,
htop, less and Unicode captures replay their recorded continuations too.
`spikes/stress` is absent from the supplied checkout and its local history;
the loader will include it if restored, but this run covers zero stress files.

### Remaining restoration API gaps

Accepted snapshots must pass the full oracle; inability to construct a state
returns `io::ErrorKind::Unsupported`, never a knowingly divergent snapshot.
The C boundary reserves `usize::MAX` for this error, separate from zero for
buffer exhaustion. Rust checks the sentinel before interpreting a length;
Unsupported propagates immediately rather than retrying shorter history tails.
The original terminal is not mutated. A regression verifies rejection leaves
later REP output unchanged and that subsequent input can make it representable.

| State the bounded painter cannot reliably restore | Proposed upstream addition |
| --- | --- |
| Optional terminal REP source independent of grid/live/saved pending wrap, including no previous character | A nonprinting terminal previous-character getter/setter, with explicit null support |
| Live and saved cursor pending wrap when no safe paint anchor exists (including degenerate geometry and modified margin cells) | Sized per-screen live/saved cursor setters including absolute coordinates, attributes, origin, and pending wrap; no implicit printing or clamping |
| Visible boundary or orphaned row wrap/continuation flags after rows are overwritten/scrolled | Per-row wrap and continuation getters/setters independent of adjacent cell writes |
| Independently styled, linked or protected no-text interior cells which ordinary erase cannot reproduce | A nonprinting cell metadata setter retaining text absence, wide flags, style, protection and hyperlink group identity |

These additions should have native/WASM parity and explicit reference lifetime
rules. A versioned, bounded state export/import API would be an alternative
that covers the same invariants. This adapter already reads the underlying
fields; extra read-only C getters alone cannot solve restoration. The gaps are
in this bounded VT construction strategy, not a claim that every original
input stream is impossible to replay. Upstream setters and their client/wire
integration remain future work; this change keeps Ghostty and the frozen
Snapshot frame. The owner decides engine or protocol changes.

### Final corpus and performance evidence

The final smoke corpus has **990 faithful replays / 10 explicit API gaps**;
the nightly corpus has **19,864 faithful replays / 136 explicit API gaps**.
All accepted snapshots compare equal before and after the continuations.
The shim module reports **32 passed, 0 failed, 5 ignored** (four measurements
and the nightly corpus); nightly is separately executed, not skipped evidence.
No unsupported case is counted as a faithful replay.

Performance below is from the unisolated development box, not the pinned
performance VM. Flood uses the real PTY, shim, infraternal agent and credited
output socket, 50 MiB per pattern, with decimal MB/s. Snapshot is the release
serializer benchmark, 1,000 samples at 200×60 plus a 256-row history tail;
it is not socket Snapshot latency. The first post-change trial under saturated
C compilation measured p50 0.613 ms / p99 4.637 ms and failed the existing 2 ms
guard. Its log is retained as `after-snapshot.log`; the concurrent flood still
exceeded 10 MB/s (LF 11.189, CRLF 18.963, printable 64.846). Serial reruns after the saturation subsided (still an unisolated host)
are listed separately below rather than replacing that evidence.


| Measurement | Before (base d3c7194) | After (serial) |
| --- | ---: | ---: |
| LF flood, MB/s | 17.505 | 16.514 |
| CRLF flood, MB/s | 20.808 | 20.810 |
| Printable flood, MB/s | 74.784 | 77.715 |
| Serializer Snapshot p50, ms | 0.487 | 0.519–0.547 |
| Serializer Snapshot p99, ms | 1.034 | 1.023 / 1.051 / 1.191 |
| Snapshot bytes | 27,279 | 27,410 |

The extra restoration and metadata checks add about 6.6–12.3% to measured
serializer p50; they are justified by the red-then-green future-state and edge
regressions above. All three serial p99 trials pass the existing 2 ms guard,
and every flood (including the loaded-host run) exceeds DECISIONS 41's 10 MB/s
budget. One flood trial per pattern is not enough to claim a throughput
improvement or attribute LF's 5.7% difference to code; the input/parser path
was unchanged. These numbers are development-box evidence, not a guarantee
under arbitrary host contention.

Historical logs and the seeded diagnostic fixture were removed under D262.
Fresh logs and any temporary seeded cases belong in
`$HOME/.cache/codex-scratch/vt-ghostty/evidence/snapshot-fidelity/`; console
reads remain sanitized and restricted to summaries.

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast > $HOME/.cache/codex-scratch/vt-ghostty/evidence/snapshot-fidelity/final-docs-fast.log 2>&1
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify nightly > $HOME/.cache/codex-scratch/vt-ghostty/evidence/snapshot-fidelity/final-nightly.log 2>&1
nix shell nixpkgs#zig_0_15 -c cargo test --release -p infraternal-shim --lib snapshot_200x60 -- --ignored --nocapture --test-threads=1 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/snapshot-fidelity/after-snapshot-serial-1.log 2>&1
python3 crates/infraternal-shim/tests/vt_flood.py --binary target/x86_64-unknown-linux-musl/release/infraternal > $HOME/.cache/codex-scratch/vt-ghostty/evidence/snapshot-fidelity/after-flood-serial.log 2>&1
```

Forgejo #22 contains the final HEAD and verbatim final fast summary table.

 ## Second-review corrections (#26, supersedes earlier oracle claims)

The second review found accepted snapshots omitted saved DEC modes, semantic
prompt state, and the remembered ISO/DEC protection mode. The native oracle now
compares saved mode values; live charset, protection and hyperlink; complete
keyboard stacks for both screens; dynamic color defaults/overrides and palette
masks; retained-tail cell and row metadata; semantic rows/cells in the exported
extent and prompt/redraw fields. Independent continuation branches include
erase, saved-mode restore, keyboard pop, and shrink/grow resize. A source
rejected by the faithful path remains unchanged. Older history outside the
returned tail is intentionally omitted by the frozen v1 contract; its metadata
is outside the oracle scope, never certified equal. Semantic validation now
walks exactly the exported tail and both visible screens. Live semantic
screen/cursor/redraw fields remain mandatory regardless of tail length. An
isolated regression keeps input-semantic cells inside the tail Unsupported and
permits exact retained-tail replay when those cells are in omitted older rows.

Saved DEC modes and ISO/DEC protection modes are restored. Semantic prompt state
in the exported extent and live screen/cursor state is explicitly rejected:
printing VT cannot import arbitrary semantic cell/row metadata without
triggering actions. The pinned C constructor sets `shell_redraws_prompt=false`,
whereas RIS sets it true. Production initialization is unchanged; fresh-C states
with that default cannot be certified faithful. Canonical painter fixtures start
after RIS and their counts are reported separately from fresh-C fixtures. This
is a material construction gap, not a claim that these states are equal.

RIS also preserves prior viewer palette/dynamic overrides. Both painters now
reset overrides before restoring source colors. History construction excludes
padding rows and starts from neutral cursor/margins/styles after inactive-screen
restoration. The oracle compares every returned history row up to the 256-row
bound, using the active-cell field inventory; intentionally discarded older
history is outside this bounded repaint scope, not certified equal.

Additional minimized cases exposed transient single-shift charset mapping of REP
seeds, ISO protection retaining a temporary REP seed, wide mapped spaces,
protection inherited into an off-mode screen, and an inherited single shift
being accidentally stored in a reconstructed saved cursor. Identity-mapped
transient charsets and erasable REP scratch state fix the first two. Mapped wide
spaces and inherited off-mode protection are explicit bounded-painter
rejections. Nonprinting DECRC before cursor construction fixes the saved-shift
case, including a null terminal-global REP source. Exact VT could potentially
construct them; this adapter does not claim a universal impossibility.

Reconnect always asks for retained raw bytes first, including after returned
credit. Only a ring gap needs a repaint. Capability bit 2 negotiates additive
`SnapshotWithFlags` (0x1C), keeping the frozen 0x15 and leg-B Snapshot layouts.
An ordered `terminal.snapshot` JSON Event announces approximation before the
leg-B repaint. The bounded visible fallback may clip content and omit hidden
state, history, semantic state and oversized parser carry. The process metric
`infraternal_agent::daemon::approximate_snapshots_total()` counts successfully
written approximate repaints; it retains no terminal content. Detached
input/resize waits for an ordered InputState reply before its shim peer is
replaced, confirming acceptance/handling. Legacy Snapshot limits produce
`terminal.snapshot_unavailable` and park a live stream until credit/input/resize
retries recovery. They do not send Close or busy-loop.


### Second-review state inventory

| Previously unchecked item | Faithful Snapshot behavior and oracle |
| --- | --- |
| Saved DEC modes | Restore saved values separately from live values; compare the packed saved record and branch through DECRM. |
| Live charset and single shift | Restore all slots, GL/GR and the transient shift after painting; compare live/saved records. Mapped wide spaces and unsupported wrap/REP combinations explicitly reject. |
| Live protection and ISO/DEC mode | Restore live protection and remembered erase mode independently; compare both and branch through ECH. Protected state inherited into an off-mode screen explicitly rejects. |
| Live hyperlink | Restore URI and explicit/implicit group identity; compare identity, not pointers. |
| Both keyboard stacks | Restore complete eight-entry rings and indices; compare each screen and branch through pops on both. |
| Dynamic colors | Clear stale viewer overrides, then restore source palette/dynamic overrides; compare defaults, values and override masks. |
| Semantic content | Compare screen/cursor/redraw scalars plus cells/rows in the exported extent. Nondefault live semantics or exported semantic metadata explicitly reject. Older omitted history is outside the bounded fidelity scope. |

The real-engine wrapped-output and controlled `less` capture regression proves
retained replay through credit starvation, one ordered approximation notice on
a ring gap, and a live legacy limitation followed by faithful reset recovery.
The retained fixture has 2,160,005 printable characters after reset. The final
`less` recovery replays 1,203,378 retained bytes; its forced gap starts at
3,303,620 and emits approximation at head 11,692,228. Terminal server relay and
browser product are absent here, so this is shim/infraternal-agent E2E evidence.

## engine-level state export/import

Lossless recovery needs a versioned native/WASM state boundary rather than
additional printing tricks. Ghostty would need bounded, validated export and
transactional nonprinting import covering:

- Both screens and the required history extent: cell text absence, Unicode
  scalars/graphemes, width/spacer metadata, styles, protection, hyperlink group
  identity, row wrap/continuation and semantic row/cell content.
- Live and saved cursors, pending wrap, all charset slots and single shifts,
  sticky protected-area mode, live/saved/default DEC and ANSI modes, margins,
  tabs, mouse reporting/encoding derived state and complete keyboard stacks.
- Palette defaults, current values and override mask; dynamic color defaults
  and overrides; semantic prompt/redraw/clear-eol and interaction state; the
  exact REP source independently of printed cells.
- Incremental parser and UTF-8 state, partial OSC/DCS/APC strings and bounded
  carry; title, working directory, status/graphics state wherever enabled by
  the shared native and viewer configuration.

Import must set these values without printing cells, scrolling, copying cursors,
resetting semantic state, selecting sticky protection, or executing terminal
replies. Ownership and lifetime rules must prevent borrowed page pointers
escaping an engine operation. Unknown versions, invalid dimensions and resource
limits must fail atomically without changing the destination. Native and WASM
consumers need the same schema and continuation behavior. A genuinely complete
retained history may exceed the frozen 1 MiB frame; chunking/state transport
would need its own additive contract, while this job's bounded painter
intentionally includes only a tail. Getters alone are not an import API. The
owner decides whether to pursue this upstream; this job adds no foundational
engine choice or upstream promise.

## Second-review final corpus, performance and scale (#26)

The release nightly uses seed `0x22601006`, 24 operations per case, 25 original
or 45 expanded tokens, 12×5 initial geometry, and independent continuation and
shrink/grow resize branches for every accepted Snapshot. Expanded tokens include
saved modes, charsets, both protection modes, keyboard stacks, dynamic colors,
hyperlinks and semantic shell state. Rejected states are not faithful replays.
These synthetic counts are not a probability for a real application.

| 20,000-case context | Faithful | Rejected | Divergent |
| --- | ---: | ---: | ---: |
| Original, RIS | 19,864 | 136 | 0 |
| Expanded, RIS | 4,815 | 15,185 | 0 |
| Original, fresh C | 0 | 20,000 | 0 |
| Expanded, fresh C | 0 | 20,000 | 0 |

Final shim unit gate: **50 passed / 0 failed / 7 ignored**. The Snapshot measurement
and both nightlies were executed separately. Parser, direct-input and isolated
terminal-RSS unit measurements above are historical; the diagnostic-only
fixture test remains opt-in. Four tracked captures and their independent recorded
continuations pass; restored stress coverage is still zero. The real terminal
reconnect gate passes in debug and in the final static release binary.

2026-10-06, infraternal-dev, Linux 6.12.111+deb13-amd64, Intel Core i9-9900K,
eight CPUs. This is an unisolated development host, not the pinned perf VM.
Own native builds and corpus work completed before final serial measurements.
Three real PTY/shim/infraternal-agent credited trials per pattern, 50 MiB each,
explicitly require zero Snapshot substitutions and more than 10 decimal MB/s:

| Raw flood | Median, MB/s | Range, MB/s |
| --- | ---: | ---: |
| LF | 14.143 | 12.522–14.335 |
| CRLF | 16.585 | 16.508–18.434 |
| Printable | 71.948 | 71.900–73.600 |

Every trial has `snapshots=0` and passes the 10 MB/s budget. Starting load
averages were 3.40–3.71 / 4.31–4.35 / 5.55–5.57. These lower rates than the
historical single trials above cannot establish a causal throughput difference
without a contemporary control; the steady parser path did not change here.
They establish the actual credited raw-byte rate, not sequence advancement via
approximate repaint. Flood timing is single-session; simultaneous 128-session
output throughput is not certified by these trials.

| Snapshot measurement, full ~10k-row history at 200×60 | p50, ms | p99, ms | Samples |
| --- | ---: | ---: | ---: |
| Final serializer, 256-row tail (27,522 bytes) | 0.611 | 1.259 | 1,000 |
| Socket, default scheduling (23,581 bytes) | 0.729 | 3.375 | 1,000 |
| Socket repeat, client CPU 1 / shim CPU 2 | 0.645 | 1.673 | 1,000 |
| Serial socket requests over 128 full sessions | 0.844 | 1.526 | 128 |

Serializer p99 passes the unchanged 2 ms guard. Socket timing also includes
framing, allocation, scheduling, transfer and Python decode. The default
scheduling sample exceeds 2 ms; it is retained, not replaced by the repeat.
Affinity is not CPU isolation. Socket-repeat starting load was
3.66 / 4.32 / 5.53; the default sample started at 3.89 / 5.22 / 6.16.
These measurements do not guarantee a bound under arbitrary contention.

The first all-history validation measured serializer p50 **2.749 ms / p99
13.518 ms** and failed the 2 ms guard. A packed row reduction still failed
(p50 2.745 ms / p99 7.468 ms; affinity repeat 2.137 / 3.538 ms). Native-only
measurement isolated all-history validation plus visible painting at p50
1.688 ms with no exported tail. Validating the exported extent instead, as
permitted by frozen v1 history truncation, passed at p50 0.519 / p99 0.844 ms
before the final serial measurement. Live semantic state remains mandatory,
and the boundary regression rejects semantic cells inside the returned tail.
No threshold or production initialization was changed.

### Full resident state at the 128-session registry limit

Each real shim is 200×60, with its full 17 MiB page-storage budget and lazy
8 MiB replay ring filled by more than 9 MiB of CRLF output before timing.
Expected session count is 128, so the page/ring capacities alone are
128 × 25 MiB = **3,200 MiB**, plus native metadata, allocators and code pages.
Measured aggregate RSS includes shared pages more than once; PSS accounts for
sharing.

| Resident-state measurement | Result |
| --- | ---: |
| Full shim RSS per session, minimum–maximum | 31,016–33,576 KiB |
| Sum of 128 shim RSS values | 4,047,200 KiB |
| Sum of 128 shim PSS values | 3,555,936 KiB |
| Infraternal agent RSS with 128 sessions | 4,260 KiB |
| Simultaneous recovery, 10 bursts × 128 replies | p99 39.178 ms; maximum 39.389 ms |

The recovery burst passes decision 41's 300 ms budget; infraternal agent RSS
is below 15 MiB. Load was 3.89 / 5.22 / 6.16 initially and
4.85 / 5.27 / 6.13 after filling all sessions. A separate static shim socket
trial measured idle/full RSS 4,716 / 32,868 KiB; the affinity repeat measured
4,712 / 31,416 KiB. The historical 4 MiB idle shim canary remains a known
failure, previously reproduced on both engines; its threshold is unchanged.
This job does not claim that supplemental budget passed.

### Evidence, self-review and reproduction

Historical logs were removed under D262. Fresh output belongs in `$HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/`; raw terminal payloads and native diagnostics stay in files, while console reads select sanitized summaries.

- Ordering and final real reconnect: `run2-reconnect.log`,
  `detached-controls-fast.log`, `run2-bounded-final-reconnect.log`.
- Saved charset regression: `minimized-case-1027.vt`,
  `run2-saved-shift-red.log`, `run2-saved-shift-green.log`,
  `saved-shift-{test,fix}-fast.log`.
- Semantic extent and failed timing evidence: `run2-semantic-tail-{red,green}.log`,
  `run2-snapshot.log`, `run2-snapshot-reduction.log`,
  `run2-snapshot-affinity.log`, `run2-profile.log`,
  `run2-snapshot-bounded.log`, `semantic-tail-{test,fix}-fast.log`.
- Final nightly: `run2-final-nightly.log`, `run2-final-expanded-fresh-c.log`.
- Raw floods: `run2-raw-flood-{1,2,3}.log`, `run2-raw-flood-summary.json`.
- Final serializer/socket/scale: `run2-final-snapshot.log`,
  `run2-final-socket.log`, `run2-socket-affinity.log`, `run2-final-scale.log`.
- Parser fuzz from run 1: `fuzz-no-lto.log`, 1,110,160 ASan runs in 61 seconds,
  no failures, coverage 512 / features 1,364. Harness-only LTO was disabled;
  production profiles are unchanged. No parser changes followed this run.
- Final docs fast gate: `run2-final-docs-fast.log`.

Self-review checked capability intersection, v1 layouts and reserved flags,
bounded frame/carry/painter lengths, ordered notices and input-state replies,
source preservation on rejection, complete oracle fields and independent
continuations, FFI ownership/lifetimes, compatible licenses, and the measured
budgets above. This is the required implementation self-review; independent
FFI review and pinned perf-VM validation remain separate reviewer work.

The eight continuation commits each pass exact fast independently. #26 records
the base/head, findings, each completed step and final verbatim gate summary.
No push, deployment or issue closure is part of this job. Scratch build caches
are removed after the gate; fresh evidence logs belong under
`$HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/`, while build
binaries remain under the worktree target directory.

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-1.log 2>&1
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify nightly > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-2.log 2>&1
python3 scripts/verify-vt-reconnect.py --binary target/review-vt2-fixes/final-infraternal-x86_64 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-3.log 2>&1
python3 crates/infraternal-shim/tests/vt_flood.py --binary target/review-vt2-fixes/final-infraternal-x86_64 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-4.log 2>&1
python3 crates/infraternal-shim/tests/vt_memory.py --binary target/review-vt2-fixes/final-infraternal-x86_64 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-5.log 2>&1
python3 crates/infraternal-shim/tests/vt_scale.py --binary target/review-vt2-fixes/final-infraternal-x86_64 --sessions 128 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt2-fixes/reproduce-6.log 2>&1
```

## Third-review corrections T1–T3 (#26)

T1 now arms the existing 250 ms one-shot output-pause deadline whenever an
indivisible repaint exceeds available credit, including positive credit.
Expiry detaches the shim peer and preserves the delivered output cursor.
The required repaint cost survives detachment: unchanged or still insufficient
credit parks recovery rather than repeatedly serializing the same state.
Approximation notices are queued only after the repaint is credit-admitted;
the process counter increments only after the flagged frame reaches the socket.

T2 restores effective mouse event and format after boolean mode construction.
Those effective fields depend on the last-written mode, including false mode
writes. The painter emits a compatible final mode write or explicitly rejects
an unconstructible combination. The strict native oracle now compares both
fields independently of the booleans. Public C encoder continuations cover
1000, 1003+1006, and 1003 followed by 1000; all three pass.

T3: resize returns an error and the engine handle must not be reused. Rust
permanently removes native ownership on every returned resize error. Input,
queries, Snapshot, another resize, and Drop cannot call the retired handle.
A fresh engine is constructed at the last successful geometry. Exact replay
borrows both retained-ring fragments without a second 8 MiB allocation, but
requires origin coverage and no prior geometry change. Otherwise the engine
starts with a clean screen and retains approximate-recovery provenance.
The real PTY is restored to the last good size; the peer, input acknowledgments,
and subsequent PTY output remain usable. Pending output reads receive recovery;
control-only peers retain the ordered InputState fence before replacement.
A later peer requesting even the current head still receives the approximation
notice. Legacy peers retain their explicit limitation response.

### Transactional resize candidate for our fork (#37)

The pinned native implementation does not guarantee transactional resize.
The required upstream invariant is: any returned allocation error leaves both
screens, dimensions, tab stops, page ownership and cursor pins internally valid,
with input, queries, Snapshot and destruction safe at the old geometry.
Construction should prepare all replacement ownership before committing it.
This is a candidate for our fork, not a change to the selected engine or
owner decision 94.

Until that invariant exists, retired native allocations are held until shim
exit: invoking the native destructor would inspect the same invalid state.
Repeated refused resizes can therefore retain additional native memory;
ordinary page/ring budgets do not bound that accumulated retention.
The upstream C allocation probe still fails at four of twelve refusal points.
Our production ReleaseFast wrapper passes all twelve retirement probes and
the real-PTY refusal fixture. ReleaseSafe refusal points 4 and 5 encounter
native invalid-state checks before resize returns, so the wrapper cannot
establish its returned-error guarantee there. Native diagnostic logs were removed under D262.
This is an upstream limitation, not evidence of a transactional native engine.

### Reproduction and self-review

Historical evidence below was removed under D262. Fresh output belongs under
`$HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/`. Public probe
diagnostics and terminal bytes stay in files. The default fast gate includes all four
faithful/approximate × 1-byte/16-KiB credit probes, the public mouse encoder,
production allocator retirement, and five isolated real-PTY ordering cases.
Each fix had a failing regression before its implementation.

The four 20,000-case corpora have zero accepted divergence: RIS original
19,864 accepted / 136 rejected; RIS expanded 4,815 / 15,185; both fresh-C
runs 0 / 20,000. Rejection is explicit and does not prove representability.
Tracked vim/htop/less/Unicode captures pass their independent continuations.
Fresh real-program captures at 200×60 sampled every 64 bytes accept all
48 vim, 39 htop, and 34 less boundaries with zero divergence; each includes
recorded continuation plus independent future-output and resize branches.
The original reviewer credit probes complete in 120.9, 121.1 and 141.3 ms,
with zero premature notices or repaints. Final wrapped-output and real less
reconnect cases pass, including negotiated and legacy recovery.

Self-review checked unique non-Send native ownership and synchronous slice
lifetimes, no native call or destructor after returned resize errors, bounded
Snapshot lengths and sentinels, effective mouse fields and public encodings,
unchanged recovery cursor and one-shot deadline, parked serialization,
credit-admitted approximation ordering, retained provenance across peers,
geometry coverage, frozen v1 layouts, capability intersection, compatible
licenses, and the measurements below. No protocol parser changed; its existing
fuzz targets and the recorded second-review 1,110,160-run result remain valid.
`docs/PROCESS.md` is absent in this checkout; this records the applicable
review checks directly. Independent review remains separate from this work.

### Final latency, throughput and scale

Serial trials used an Intel Core i9-9900K at 3.60 GHz, eight exposed logical
CPUs, x86_64 Linux 6.12.111+deb13-amd64. This is the shared host, not a pinned
performance VM. Flood starting load averages ranged from
11.11 / 5.42 / 4.30 to 13.57 / 6.38 / 4.64; serializer/reconstruction started
at 13.57 / 6.61 / 4.73. Our measurements ran serially after our builds and
corpora, but other host work remained active. These trials establish current
budgets without establishing a causal performance delta from the previous
review's measurements. Simultaneous 128-session flood throughput is unmeasured.

| Real credited 50 MiB flood, three trials | Median MB/s | Range MB/s |
| --- | ---: | ---: |
| LF | 11.103 | 10.232–11.816 |
| CRLF | 14.649 | 11.957–15.523 |
| Printable | 37.189 | 34.557–43.643 |

All nine trials pass 10 MB/s, with zero Snapshot substitutions.

| 200×60 latency measurement | Samples | p50 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Serializer, full history + 256-row tail (27,535 bytes) | 1,000 | 0.613 | 1.066 |
| Real static shim socket Snapshot (23,594 bytes) | 1,000 | 0.675 | 3.288 |
| Serial socket Snapshots over 128 full sessions | 128 | 0.883 | 5.865 |
| Full origin-ring fresh-engine constructor/replay | 50 | 78.767 | 101.708 |
| Simultaneous socket recovery over 128 full sessions | 1,280 | — | 51.720 |

The serializer passes the unchanged 2 ms guard. Socket timing includes
scheduling, framing, transfer and Python decode; its 3.288 ms p99 is retained,
not described as passing that serializer-only budget. Full-ring reconstruction
uses 8,388,595 bytes per session, or **1,073,740,160 bytes across 128 sessions**.
Multiplying its per-unit p99 service time by 128 gives 13,018.624 ms of serialized
reconstruction work; this multiplication is capacity evidence, not a joint p99.
That test measures the same fresh-engine constructor/replay component while
old healthy handles permit cleanup. Actual native refusal and retirement have
separate allocator and PTY tests. It does not certify latency when all 128
sessions simultaneously require full native reconstruction.

The scale fixture fills both native history and the 8 MiB ring in every real
shim at 200×60 before timing. Expected count is 128: page/ring capacities alone
are 128 × 25 MiB = 3,200 MiB, excluding metadata and retired allocations.
Measured per-shim RSS is **30,944–35,956 KiB**, aggregate RSS **4,089,300 KiB**,
aggregate PSS **3,597,524 KiB**, and infraternal agent RSS **4,264 KiB**.
A separate static shim measures idle/full RSS **4,712 / 31,256 KiB**; the
historical supplemental 4 MiB idle canary remains unmet. Ten simultaneous
128-reply recovery bursts measure p99 **51.720 ms**, maximum **51.970 ms**,
passing decision 41's 300 ms guard. Existing-state Snapshot recovery uses
existing native state, unlike the full-ring rebuild component above. Scale
starting/ending load averages are 13.36 / 6.69 / 4.77 and
12.59 / 7.50 / 5.14. The retained-allocation limitation under repeated resize
refusal is not included in these ordinary resident-state totals.

Reproduction from this worktree (all command output must remain in files):

```sh
nix shell nixpkgs#binutils nixpkgs#file nixpkgs#gnumake nixpkgs#perl nixpkgs#zig_0_15 -c scripts/verify fast > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-fast.log 2>&1
nix shell nixpkgs#zig_0_15 -c cargo test --release --locked -p infraternal-shim --lib fidelity_seeded_nightly -- --ignored --nocapture --test-threads=1 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-original.log 2>&1
nix shell nixpkgs#zig_0_15 -c cargo test --release --locked -p infraternal-shim --lib fidelity_extended_nightly -- --ignored --nocapture --test-threads=1 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-expanded.log 2>&1
python3 scripts/verify-vt-reconnect.py --binary target/x86_64-unknown-linux-musl/release/infraternal > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-reconnect.log 2>&1
python3 crates/infraternal-shim/tests/vt_flood.py --binary target/x86_64-unknown-linux-musl/release/infraternal > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-flood.log 2>&1
nix shell nixpkgs#zig_0_15 -c cargo test --release --locked -p infraternal-shim --lib snapshot_200x60 -- --ignored --nocapture --test-threads=1 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-snapshot.log 2>&1
nix shell nixpkgs#zig_0_15 -c cargo test --release --locked -p infraternal-shim --lib measured_full_ring_reconstruction -- --ignored --nocapture --test-threads=1 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-reconstruction.log 2>&1
python3 crates/infraternal-shim/tests/vt_scale.py --binary target/x86_64-unknown-linux-musl/release/infraternal --sessions 128 > $HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/reproduce-scale.log 2>&1
```

Use `VT_SNAPSHOT_INITIAL=fresh-c` to reproduce constructor-context rejection
counts; both contexts' logs are `final-fidelity*-{RIS,fresh-c}.log`. Fresh capture bytes belong under `$HOME/.cache/codex-scratch/vt-ghostty/evidence/review-vt3-fixes/fresh-captures/`; the opt-in `fidelity_fresh_real_program_captures` test takes `VT_CAPTURE_DIR` and writes its summary to external scratch. Final benchmarks are `final-flood-{1,2,3}.log`,
`final-snapshot.log`, `final-reconstruction.log`, `final-socket-snapshot.log`
and `final-scale-128.log`; machine and per-trial load are recorded in
`final-machine.json` and `final-measurement-status.json`. Original reviewer
probes are `final-reviewer-credit*_probe.log`; public mouse and upstream
allocation diagnostics are in `t2-gate-public/` and `t3-upstream-native/`.
Final exact gate output is `final-docs-fast.log`. #26 records each atomic
commit and its gate; this job neither pushes nor deploys.
