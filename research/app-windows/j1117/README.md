<!-- Role: how the tile-lane flicker proof and its before/after numbers are produced (J1117, #146 proposal C). -->
# Tile lane: flicker proof and before/after numbers (J1117, #146)

The owner approved the App Windows tile lane on 2026-11-21 "as long as you measure that there are no flickers". This folder
holds the measurement harness. Nothing here ships.

## What is measured

1. **Flicker.** `record.swift` drives the product's own capture pipeline (`SurfaceCapture`: mailbox, exact-pixel history,
   tile lane, hardware VideoToolbox encoder) with known pictures. It renders them with CoreText and hands them over
   through `receiveFrame`, the same handoff ScreenCaptureKit uses, so no capture permission is needed. It keeps every
   packet the pipeline sent and, in a second pass, every source picture (re-rendered and checked against a hash taken
   live). `replay-worker.ts` runs the product's real decode worker (`decode.worker.on-demand.ts`, unchanged) in a
   browser, feeds it those packets with the recorded timing, reads the canvas back after every painted unit (a whole
   video picture, or a whole tile update) and compares it with the source picture of that unit's capture stamp, in 16×16
   blocks. A block that matches an older source picture better than the expected one is **stale**. A painted picture
   whose source frame is older than the previous painted picture's is a **regression**.
   Modes: `realtime`, `jitter` (0–30 ms extra delay per unit, order kept, so units bunch up), `fast` (4× speed), and
   `swap`, the **negative control**: each tile that directly follows a video unit is delivered before it, like a viewer
   that ignored capture order. The harness must flag `swap`, which shows that its zeros mean something.
2. **Before/after on the Mac.** `record-base` (built from origin/dev's native sources) and `record-after` (this branch)
   play the same scenarios. `stages.py` reads the product's opt-in METRIC lines: capture → packet sent per lane, encoder
   time and bytes.
3. **Browser paint.** Mode `latency` draws on an ordinary GPU canvas with no readback and reports worker receive →
   painted per lane, plus the inflate and decode parts.

Scenarios (`record.swift`): `typing` (160 characters, 60 ms apart), `blink` (idle caret, 3 s), `scroll` (90 frames at
60 Hz), `mixed` (typing every 50 ms + 60 Hz spinner + 10 Hz clock + one-line scroll every 7th key), `burst` (30 times: a
scroll, then a key 3 ms later, so a tile arrives right behind a video frame that is still decoding).

## Running it

On a Mac (build there, never on the M1 `mba`; copy binaries to it):

```sh
N=crates/plugins/desktop/native
swiftc -O $N/CaptureState.swift $N/FrameDamage.swift $N/FramePixels.swift $N/LowDelaySPS.swift \
  $N/Encoder.swift $N/SurfaceCapture.swift research/app-windows/j1117/record.swift -o record-after
INFRATERNAL_DESKTOP_MEASURE=1 ./record-after run1 800 500 2> run1.stderr
python3 research/app-windows/j1117/stages.py run1 run1.stderr
```

Build `record-base` the same way from `git archive origin/dev crates/plugins/desktop/native`.

Bundle the replay worker (it imports the real worker), then serve the folder that holds `run1/`, `replay.html`,
`replay-worker.js` and `serve.py`:

```sh
cd apps/tracer && bun build ../../research/app-windows/j1117/replay-worker.ts --target browser --format esm --outfile replay-worker.js
python3 serve.py 8917 900 &
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --user-data-dir=$PWD/profile \
  "http://127.0.0.1:8917/replay.html?run=run1&browser=chrome&modes=realtime,jitter,fast,swap,latency"
```

Each mode's report lands in `reports/<browser>-<mode>.json`: a summary (painted pictures, stale blocks, regressions, lossy
blocks, paint latency, per-scenario counts), a verdict per painted picture, and the worker's counters.

## Limits

- The pictures are synthetic (text, caret, spinner, clock). Real apps draw more varied content; the ordering logic does
  not depend on content, but the byte counts do.
- The source rate is set by the recorder, not by an app's display link. Capture-to-callback time (ScreenCaptureKit) is
  not part of these numbers.
- The browser runs are on the Mac VM. Its headless decoder often supersedes 60 Hz scroll pictures, so pure scrolling
  paints only a few pictures; tile/video transitions are covered by `mixed` and `burst`.
