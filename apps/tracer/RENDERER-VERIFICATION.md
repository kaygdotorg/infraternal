<!-- Role: records the pinned Ghostty source build and issue #36 browser, memory, and latency evidence. -->
# Tracer renderer verification (#36, D109)

## Source build and license

The tracer uses the ESM build from `ghostty-web` source commit
`835eb2749f640a139693bb64fd67de3c1b50a598` (upstream `main`, 2026-11-18). It includes
fix `bec9e162b137478fb032d7edf60a2f29a6e5f04b` from #180. The Ghostty core is the signed
libghostty-vt 1.0.2 release (2026-11-24), the same one the native shim builds from; the
page talks to it through our own `web-engine.zig` (`vendor/ghostty-web/README.md` says
why). Build tools are Bun 1.4.4 and Zig 0.17.1, as the development shell provides them.
`vendor/ghostty-web/build.sh` checks these exact versions, builds from the pinned,
signature-checked sources, and compares the output to `vendor/ghostty-web/SHA256SUMS`.

The checked-in ESM artifact is 1,080,280 B and embeds its WASM (as base64; the production
build cuts it out). The separately retained WASM is 702,460 B (204,967 B gzip at level 9);
its digest and the ESM and declaration digests are in the manifest. `scripts/verify fast`
verifies all three files. The source rebuild command is:

```sh
nix develop -c apps/tracer/vendor/ghostty-web/build.sh --check
```

The upstream `ghostty-web` and Ghostty VT source are MIT licensed. Their license
texts are in `vendor/ghostty-web/LICENSE` and `GHOSTTY-LICENSE`; the inventory
entry is in `THIRD_PARTY_NOTICES.md`. No upstream issue or pull request was sent.
Switch to an official release only after it contains #180 and the browser corpus
passes against it.

## App bundle

`src/main.ts` retains the dynamic `import("./terminal")`; authentication and
onboarding do not eagerly download the renderer. The deferred chunk contains
the local vendor import from `src/terminal.ts`.

Sizes below use the production build and Node `gzipSync` level 9. The baseline
is the pre-change 0.4.0 tracer build; the after values include the test-only
renderer counters used for these measurements.

| Bundle | 0.4.0 raw / gzip | Pinned build raw / gzip | Change raw / gzip |
|---|---:|---:|---:|
| Deferred renderer chunk | 662,832 / 191,545 B | 675,936 / 194,438 B | +13,104 / +2,893 B |
| All JavaScript chunks | 739,372 / 220,423 B | 752,635 / 223,663 B | +13,263 / +3,240 B |

The final `main.js` remains 76,699 B raw, and it imports the renderer chunk only
after sign-in.

## Chromium crash regressions

`test/renderer-regression.spec.ts` builds and serves the production app, uses
Chromium at the spike trigger grid (205×56), sends each exact payload through
the tracer wire client, checks that the browser stays alive, then requires the
canary marker to paint. The fixture route checks the payload byte count and
SHA-256 before sending it. The test manifest with all ten payload hashes is
`test/terminal-fixtures.ts`.

| Payload | Bytes | SHA-256 |
|---|---:|---|
| `minimal-combining-5679.bin` | 5,679 | `0047de6d657e0a1f69e16b9cdf8c6dc9343c98086c8b44df9276223f4bf3428f` |
| `behemoth-prefix-82541.bin` | 82,541 | `480f7026f1494e79fc62492439bf99c0449b6c4262cf641039ba3a94bc733741` |
| `mixed-prefix-82144.bin` | 82,144 | `9d3575c83d09f5129461dc3c4406b04add00c01f23a6999c3a4c2bb26b1dc192` |
| `binary-prefix-106342.bin` | 106,342 | `519b244ff5ec90ef21cd0eeb017ed2bfc6655afc9b14424029a183a4b826ceca` |
| `browser-text-binary-prefix-192253.bin` | 192,253 | `be3734effe07068d44594d261fbab86725528dd9cee1320880b89a58844fb55e` |
| `binary-one-esc-context.bin` | 192,253 | `7a07d190be76e63a521385fb69abf043e21b94aa73951ba340526d477951ce89` |
| `binary-no-esc-context.bin` | 192,253 | `bfc8c9fe72b76270cfb7c32ca576db69d21dd762b3845487c2c1667a29678434` |
| `behemoth.txt` | 50,000,000 | `e436d35a872e85acd7ea95431e365fe876147576e13d0438db0093647ccae06d` |
| `mixed.txt` | 20,000,000 | `29e8a2ca5d93956b9678ece3ba6ef2037c671d6fb423e9368ba00c42ff6e950f` |
| `binary.bin` | 20,000,000 | `c923c6d07a407ebc6a5003fe58ff94326c1834e0b34fc5567c9f46bc1c21f1f7` |

The final production Chromium gate passed all 14 browser tests in 2.0 minutes.
All seven reproducers and all three complete fixtures survived, and each
post-fixture canary painted. The 50 MB behemoth case completed in 24.2 seconds
in that run. The production terminal and latency screenshots are emitted under
`$HOME/.cache/codex-scratch/tracer-<pid>/evidence/playwright/` by `terminal.spec.ts`.

## Renderer memory

`test/renderer-memory.ts` builds the same production bundle, streams the
50,000,000-byte behemoth at 205×56, and samples the sum of Chromium renderer
`VmRSS` values every 75 ms. It also reads each page's `WebAssembly.Memory`
length and retained scrollback row count. Eight sessions used eight distinct
Chromium renderer processes.

Machine and load: Debian 13, kernel `6.12.111+deb13-amd64`, Intel i9-9900K at
3.60 GHz, 8 logical CPUs, 33,591,037,952 B RAM, Chromium 149.0.7827.55. Host load
average was 4.36/6.86/8.77 before the scenarios and 6.27/6.78/8.59 afterwards.
The measurements are local, with no memory or performance budget changes.

| Scenario | Sessions | Configured option | Retained rows/session | WASM memory/session | Peak renderer RSS total | Peak/session |
|---|---:|---:|---:|---:|---:|---:|
| Tracer default | 1 | 10,000 | 291 | 1,053,818,880 B (1,005 MiB) | 851,156,992 B (811.7 MiB) | 811.7 MiB |
| One-byte control | 1 | 1 | 291 | 1,053,818,880 B (1,005 MiB) | 847,368,192 B (808.1 MiB) | 808.1 MiB |
| Tracer default | 8 | 10,000 each | 291 each | 1,005–1,006 MiB | 6,818,861,056 B (6,502.9 MiB) | 812.9 MiB average |

The setting’s unit is easy to misread. The pinned web wrapper calls its option a
scrollback limit in lines, but its C patch passes the raw integer to Ghostty's
`Screen.max_scrollback`, which `ghostty/src/terminal/Screen.zig` documents in
bytes and rounds up to at least one page. The default value 10,000 therefore
retained one page (291 rows) in this fixture. A one-byte value retained the same
page and produced nearly identical WASM size and RSS.

An exploratory zero value was not a no-history control: the pinned C wrapper
maps zero to an effectively unlimited value. It retained 229,674 rows and grew
WASM memory to 1,054,343,168 B. The capped and unlimited runs both grew the WASM
buffer to about 1,005 MiB. This cap control shows that retained scrollback does
not account for the 1 GiB linear-memory high-water mark. The evidence points to
WASM allocation/page growth during the 50 MB write as the dominant source; that
is an inference from the cap comparison and memory counters, not a symbol-level
allocation trace. Renderer RSS stayed near 812 MiB per session in the measured
1- and 8-session runs.

Decision 41 budgets remain unchanged: keystroke-to-echo overhead below 5 ms
p99, reconnect below 300 ms without byte loss, PWA first paint below 1 s on a
mid-range phone, 60 fps at 10 MB/s output, and idle infraternal agent below
15 MB RSS. These local renderer runs do not prove the pinned perf-VM budgets.

## Unicode stream fidelity (#39)

Issue #38 reported that raw behemoth output lost emoji modifiers and grapheme
clusters which a native Snapshot retained. This was not reproducible on the
deployed `0c47cd4` tracer build. The relevant sample is
`👩🏽‍💻 👨‍👩‍👧‍👦 🧑🏾‍🚀 🇩🇪 🇺🇳`.

`test/unicode-fidelity.spec.ts` drives the production page through one raw
Output frame, a 16 KiB boundary inside the skin-tone UTF-8 scalar, a boundary
between the base emoji and modifier codepoints, and a Snapshot frame carrying
the same VT sample. All five clusters remain in Ghostty's grapheme buffer in
all four cases. The split payloads are 16,454 B (16,377 B ASCII prefix; seven
bytes of the first cluster remain in that Output frame) and 16,457 B (16,380 B
prefix; four bytes remain). The Snapshot control is a minimal protocol repaint,
not a separately exported native terminal state.

The production behemoth case in `test/renderer-regression.spec.ts` streams all
50,000,000 B as raw Output frames at 205×56. All five clusters remain present
after the final painted sequence. That run retained 291 rows and used
1,053,818,880 B of WASM memory; the test took 21.2 s on Debian 13, kernel
`6.12.111+deb13-amd64`, Intel i9-9900K, 8 logical CPUs, and 32 GiB RAM. This is
a correctness run, not a throughput measurement.

The earlier probe reader used the xterm-compatible `translateToString`, which
does not include Ghostty's separate grapheme buffer. `readGraphemeText()` now
reads the same `getGraphemeString()` values that the canvas renderer draws.
Frame chunking and the vendored Ghostty renderer therefore have no reproduced
loss in this deployed path; the original Snapshot-versus-raw difference remains
unconfirmed outside the #38 harness.

## Latency comparison

Both runs sent 500 sequential keys through the tracer probe on the same local
host and Chromium. The 0.4.0 package was temporarily selected only for its
baseline measurement; the tracked app continues to use the source pin.

| Renderer | p50 | p99 | Resume |
|---|---:|---:|---:|
| npm 0.4.0 | 14.90 ms | 16.40 ms | 78.70 ms |
| Source pin `5f0c6b7` | 14.90 ms | 15.70 ms | 77.60 ms |

Both runs painted 500/500 echoes and passed the unchanged local p99 <20 ms
check. The p99 difference was -0.70 ms and resume was -1.10 ms in these single
sequential samples; treat that as no measured regression, not a distributional
performance claim. The earlier 0.4.0 run on a heavily loaded host measured
19.80/49.40 ms p50/p99 and 103.00 ms resume, so it is not the paired comparison
used above.

## Renderer self-review

- [x] Source, Ghostty submodule, Bun, and Zig are pinned; a fresh source build
  reproduced the checked-in hashes, and the fast gate verifies all three.
- [x] Both MIT license texts and the repository inventory entry are present.
- [x] The app imports the local package through the existing deferred renderer
  import; production and gzip sizes are recorded above.
- [x] The 0.4.0 baseline failure at 205×56 is recorded on #36. All ten fixed
  payloads pass against the production build in Chromium and paint a canary.
- [x] RSS was sampled from renderer processes with default and one-byte
  scrollback controls, then across eight default sessions; no budgets changed.
- [x] The production run writes terminal and probe screenshots under
  `$HOME/.cache/codex-scratch/tracer-<pid>/evidence/playwright/`; historical files
  were removed under D262. Attach selected screenshots for external review; this
  checklist does not claim visual approval.

## Engine update: ghostty-web `835eb27` on Ghostty `e75f8956c` (#575, J1110, 2026-11-21)

The previous pin was ghostty-web `5f0c6b7` on Ghostty `5714ed07` (2025-12-01). Upstream
`main` has no library or build change since that pin, so the real update is the Ghostty
core: 662 first-parent commits newer (2026-03-13), built with the same Bun 1.4.2 and
Zig 0.15.2. Ghostty v1.4.0 (needs Zig 0.17, and a terminal C API that replaces the one
ghostty-web patches in) is not reachable without rewriting the WASM binding; that is a
foundational choice for the owner, not made here. Reproduce with
`build.sh --check` (verified bit-for-bit on compute01).

All numbers below are from `~/j1110-perf/` on the perf VM (under `perf-run`, alternating
old and new artifacts) unless noted; the harnesses and logs are attached to #575.

| Measure | Old (`5714ed07`) | New (`e75f8956c`) |
|---|---:|---:|
| `ghostty-vt.wasm` | 424,337 B (124,301 B gzip) | 470,694 B (136,634 B gzip), +10.9 % |
| WASM linear memory after the 50 MB behemoth (Chromium) | 1,053,818,880 B | 12,124,160 B |
| Same, 20 MB mixed / binary | 414,187,520 / 11,534,336 B | 14,680,064 / 11,534,336 B |
| Headless parse of the 50 MB behemoth, median of 2 | 1,794 ms | 1,615 ms (-10 %) |
| 20 MB mixed / 20 MB binary | 739 / 1,251 ms | 656 / 1,264 ms (-11 % / +1 %) |
| `write` 8 MB mixed, 64 KiB chunks (3 rounds) | 290-299 ms | 259-267 ms (-10 %) |
| `createTerminal`+`free` x300 | 72-104 ms | 58-59 ms |
| resize 80x24 to 205x56 and back, x200 | 166-177 ms | 189-195 ms (+11 %) |
| D375 `d375_render_10mbps` (unthrottled, 2 runs each) | 416.67 / 416.67 fps (gate 120) | 400.00 / 400.00 fps |
| Same row, write CPU for the 10 MB | 187 / 188 ms | 197 / 201 ms (+6 %) |

The WASM memory row is the large change: the old core grew linear memory to 1 GiB while
streaming the behemoth and never gave it back (renderer RSS about 750 MiB per session),
the new one stays at 11 MiB. The other D375 rows (first paint, returning sign-in, reconnect,
predicted glyph, own overhead, real echo) match the old artifact within the run-to-run
spread; their changes follow the proxy's measured round trip, not the engine.

What is worse: the wasm is 46 KB larger, the 10 MB/s render row is a consistent 4 % lower
(still 3.3 x its gate), and a resize costs 11 % more.

Correctness: the seven reproducers and three full fixtures pass in Node (headless
terminal, canary painted) and in Chromium (`test/renderer-regression.spec.ts`, 12/12).
Upstream's own 359 tests pass against both WASM files. A differential run of 23 inputs
(synthetic sequences, the ten fixtures) at 80x24 and 205x56 gives identical viewports and
cursors in 46 of 46 cases; 3 of them differ in their scrollback lines. The one dissected
(205x56, `binary-no-esc-context.bin`) is a single cell: U+06DD gets width 2 instead of 1. Of 167 further terminal and renderer Chromium specs, 166 pass;
`terminal-theme.spec.ts:209` (theme switch p99 10.6-13.1 ms against the 8.33 ms frame)
fails identically on the old artifact (10.6-11.2 ms, 3 of 3 runs).

## Engine update: the signed libghostty-vt 1.0.2 core in the browser (#575, J1165, 2026-11-25)

The Ghostty core moved from `e75f8956c` (2026-03-13) to the signed libghostty-vt 1.0.2
release (2026-11-24), the same source and dependency archives the native shim builds
from. J1110 left this open because the core's own terminal C API (since 2026-03-13) has
the names that upstream ghostty-web patches in, and the official API reads cells one by
one. `vendor/ghostty-web/web-engine.zig` is the answer: our own entry points
(`ghostty_web_*`) on top of the core's stream handler, with the one-call viewport read
kept. Everything else is in the vendor README. Upstream ghostty-web itself has no newer
commit or release than the pin.

Engine numbers, old (`5c0eab178`) against new, Bun 1.4.4 on dev-02 (a shared host; old and
new alternate; the log is `engine-ab-dev02.log` on #575):

| Measure | Old (March core) | New (1.0.2) |
|---|---:|---:|
| `ghostty-vt.wasm` | 470,694 B (136,736 gzip, 107,843 Brotli) | 702,900 B (205,143 gzip, 148,700 Brotli), +49 % / +38 % Brotli |
| WASM memory after the 50 MB behemoth / 20 MB mixed / 20 MB binary | 10.9 / 12.9 / 13.0 MiB | 4.0 / 4.0 / 4.2 MiB |
| Headless parse of the 50 MB behemoth | 741-761 ms | 115 ms |
| 20 MB mixed / 20 MB binary | 305-309 / 482-750 ms | 51-52 / 265 ms |
| `write` 8 MB mixed, 64 KiB chunks / 1 KiB chunks | 119 / 119 ms | 22 / 22 ms |
| `write`+`update`+`getViewport` per 4 KiB (8 MB) | 302-306 ms | 152-154 ms |
| `update`+`getViewport` on a static screen, x2000 | 153 ms | 125 ms |
| resize 80x24 to 205x56 and back, x200 | 94 ms | 26-28 ms |
| `createTerminal`+`free` x300 | 22.5-23.5 ms | 24.6-28.5 ms |
| scrollback line read x2000 / `isRowDirty` x56 x2000 | 0.8 / 0.17 ms | 1.3 / 0.21 ms |

The WASM is the one number that got worse for the person (a one-time, immutably cached
download, 41 KB more Brotli); the file stays outside the JavaScript budget (D188, #573).
`transfer-budget.ts` on this build: critical JavaScript 163,898 B gzip of 327,680 (143,060 B
Brotli of 273,408), deferred 60,572 of 61,440, largest on-demand chunk 18,838 of 20,480. The
features compiled out (`-Dvt-features=-all,+input_encode`) saved 250 KB.

D375 rows on dev-02 (the production build, unthrottled, `INFRATERNAL_LATENCY_PROFILE=1`,
two alternating runs each; `d375-dev02-*.log`): `d375_render_10mbps` 909 / 833 fps old,
3,333 / 3,333 fps new (gate 120; write CPU for 10 MB 96-103 ms to 10.6-11.1 ms; p99 frame
1.1-1.2 ms to 0.3 ms); first paint on a phone 93.8 / 90.8 ms old, 90.1 / 98.0 ms new
(gate 1,000); second-burst extra frames 0 both (gate 0). The rows that follow the
proxy's round trip are unchanged. `terminal.spec.ts:5` (the real-passkey latency probe)
fails the same way on both (`predictiveEcho().optedIn` is true where the scenario expects
false), so its rows are not in the table; the perf VM was busy for over two hours and its
rows are not part of this record.

Correctness: the seven reproducers and three full fixtures pass in Bun (headless, canary
painted); `renderer-regression.spec.ts` and `renderer-fresh-terminal.spec.ts` (the #180 and
#241 checks, which no longer have patches of ours) pass 12/12 in Chromium; of 216
terminal and renderer Chromium specs 211 pass. Four of the five that fail (`cursor-layer-skip`
:194, `terminal-links` :297, `terminal-theme` :209 and `terminal` :5) fail identically on
`5c0eab178`; the fifth is a flaky mouse drag in `terminal-selection-wrap` :65 that failed in
two of my new-artifact runs and in 2 of 16 repeats on the old artifact (16 of 16 passed on the
new one in the same repeat run). D307 holds: the engine answers DSR 5/6, DA1
and DA2 and nothing else, one reply per query in all 30 corpus forms, 515 splits and three
viewers (`terminal-query-property.test.ts`).

What changed in behaviour, because the core's own handler runs now: colour operations from
programs (OSC 4, 10, 11, 12 and their resets) are applied (the old handler ignored them),
with the page's theme as the default they reset to, so RIS or OSC 104 returns to the theme
(a first build returned to the core's built-in palette; `terminal-theme.spec.ts` found it);
scrollback pruning follows the core (whole pages; 80x24 keeps 846 rows of the first 3 MB
of the behemoth where the old core kept 992); stray ESC, C0 and invalid UTF-8 in binary
data are handled as the 2026 parser does, which moves the cursor and the viewport after
the binary fixtures (14 of 46 differential cases, all of them binary or large streams; the
synthetic sequences and the three small reproducers are identical). The browser and the
server run one engine revision now.
