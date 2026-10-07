<!-- Role: records the pinned Ghostty source build and issue #36 browser, memory, and latency evidence. -->
# Tracer renderer verification (#36, D109)

## Source build and license

The tracer uses the ESM build from `ghostty-web` source commit
`5f0c6b7720e5ac241208afe7a2335981ded1b486` (0.5.0-rc.0). It includes fix
`bec9e162b137478fb032d7edf60a2f29a6e5f04b` from #180. The embedded Ghostty
submodule is pinned to `5714ed07a1012573261b7b7e3ed2add9c1504496`. Build tools
are Bun 1.4.2 and Zig 0.15.2. `vendor/ghostty-web/build.sh` checks these exact
versions, builds from those immutable source revisions, and compares the output
to `vendor/ghostty-web/SHA256SUMS`.

The checked-in ESM artifact is 702,145 B (197,079 B gzip at level 9) and embeds
its WASM. The separately retained WASM is 423,939 B; its digest and the ESM and
declaration digests are in the manifest. `scripts/verify fast` verifies all
three files. The source rebuild command is:

```sh
nix shell nixpkgs#zig_0_15 -c apps/tracer/vendor/ghostty-web/build.sh --check
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
`test-results/` by `terminal.spec.ts`.

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
- [x] The production terminal and probe screenshots are available under
  `test-results/` for external review. This checklist records their presence;
  it does not claim visual approval.
