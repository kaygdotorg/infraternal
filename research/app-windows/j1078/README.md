<!-- Role: how to rebuild and rerun the J1078 App Windows latency probes (#146). -->
# J1078 App Windows latency probes

Measurement harnesses for the J1078 audit of App Windows latency (#146). They
are not product code and nothing in the product depends on them. The results
and the findings they support are in the J1078 report on #146.

## encode-probe (macOS)

Hardware encode latency with the session settings of
`crates/plugins/desktop/native/Encoder.swift`, against picture size, content,
input format, frames in flight and parallel sessions. It also times the
product's own `FramePixels.prepare`, a raw-tile fast lane, the settled sharp
refresh, and loss repair with long-term reference frames.

Build on a Mac that may build (the Mac VM, under its lock), then copy the
binary to the measurement Mac:

```sh
swiftc -O -swift-version 5 -o probe main.swift ../../../../crates/plugins/desktop/native/FramePixels.swift
./probe                      # size, variant, pipeline, parallel, history, tile
ONLY=refresh ./probe         # sharp refresh: keyframe against delta frames
ONLY=ltr ./probe             # repair after loss: keyframe against LTR refresh
ONLY=after ./probe           # first change after a refresh or an idle gap
ONLY=quality ./probe         # what the viewer sees: low-latency against real-time mode
ONLY=sparse ./probe          # typing-like frames that follow a gap, both modes
```

Every line that starts with `RESULT` is one measurement; `NOTE` lines report a
property the encoder refused.

## window-list-probe (macOS, needs the logged-in user's session)

Cost of the window-list reads made for each remote pointer event
(`Geometry.follow` and the occlusion check in `Input.swift`).

```sh
swiftc -O -swift-version 5 -o winprobe main.swift && ./winprobe
```

## browser-stall (Linux or macOS, headless Chromium and Node)

Shows that after a main-thread stall the queued socket messages run before the
decode worker's credit returns, so the handoff credit of
`apps/tracer/src/canvas/appwin/stream.ts` refuses frames.

```sh
./run.sh
```
