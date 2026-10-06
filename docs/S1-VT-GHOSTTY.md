<!-- Ghostty VT migration, C API gaps, reproducible measurements and review evidence for #22. -->
# Shim terminal state: libghostty-vt (#22)

Owner DECISIONS 94 replaces the Alacritty terminal-state engine. This checkout's
`DECISIONS.md` ends at 86; 94 is supplied by the owner's job and recorded on #22.
This document supplements the historical [S1 shim comparison](S1-SHIM.md).
DECISIONS 7, 13, 20, 40 and 41 still apply. No frozen frame changes are needed.

## Build and production dependencies

`scripts/build-vt` builds the MIT-licensed Ghostty source used by Rust
`libghostty-vt` 0.2.2: commit
`a887df42c56f6de86c0fe6da9c4eeca37931e083`, archive SHA-256
`fb4b2f9ffa0af125983041fdbe4ef94d3fa79fb9f2d22b9c213c0e3847a866b6`.
Zig is exactly 0.15.2. Local verification obtains `nixpkgs#zig_0_15`; CI uses
the existing architecture-specific checksum-verified `scripts/auth-toolchain`
download. Both the VT archive and vendored C dependencies use the same Zig.
Zig package dependencies use upstream's content hashes. The shim remains
AGPL-3.0-only.

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
default build (`target/vt-ghostty/production-dependencies.log`).

## Snapshot state and the upstream API boundary

`src/terminal_native.rs` owns one opaque C terminal handle. Its audited unsafe
boundary covers creation, synchronous input, resize, serialization and free;
test-only queries compare cells and count history. It lends no grid references
to Rust and has no callbacks. Initialization and resize errors propagate through
the session API in separate commits. Independent review of that boundary is
still required; these measurements are implementation evidence.

`native/snapshot.zig` reads Ghostty's actual screen/page/cell state. It streams
VT into the caller's bounded buffer and does not use the built-in terminal
formatter, clone history, or maintain a second terminal-state engine. It uses
the style formatter only for SGR encoding. Repaint constructs primary and
retained alternate screens with mode 47 so reconstruction does not destroy
DECSC state or clear the alternate screen as 1049 would. Subsequent original
47/1047/1049 transitions, including repeated switches, run in Ghostty normally.
Screen-switch mode bookkeeping is represented by that canonical construction;
synchronized-output mode 2026 is omitted to permit the repaint to display.

The serializer preserves visible cells and a bounded history tail, SGR flags,
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
No upstream parser or formatter change is needed. Until those getters exist,
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

Red/green evidence lives in `target/vt-ghostty/`: `native-unicode-red.log` /
`native-unicode-green.log`, `saved-origin-red.log` /
`expanded-origin-tests.log`, and `expanded-wrap-red.log` /
`empty-cells-tests.log`. The final unit result is 20 passed; performance tests
are explicitly ignored by the ordinary test gate and run separately below.

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

Raw evidence under `target/vt-ghostty/`: `release-budgets.log`,
`terminal-rss-isolated.log`, `{alacritty,ghostty}-rss-serial.log`,
`alacritty-flood-serial{,-2,-3}.log`, `ghostty-flood-after-carry.log`,
`ghostty-flood-serial-{2,3}.log`, `flood-summary.json`, `real-agent-gate.log`,
`comparison-feature-gate.log`, `alacritty-comparison-current.log`, and
`history-preview.log`. Per-commit exact fast
logs are `toolchain-gate.log`, `init-api-gate.log`,
`native-module-gate-final.log`, `resize-api-gate.log`, `engine-gate.log`,
`snapshot-regressions-gate.log`, `carry-perf-gate.log`, `measurements-gate.log`,
and `docs-gate.log`. Forgejo #22 records start/base, findings and final HEAD with
verbatim gate output. No issue is closed and no branch is pushed by this job.
