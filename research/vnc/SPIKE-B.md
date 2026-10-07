# S4 remote desktop spike, phase B

This report records a live Apple Screen Sharing session and two browser
subscriber encodings for issue #35. It does not choose an encoding or a
foundational engine. The spike remains on branch `spike-vnc` and is not for
merge.

## Authentication and RFB session

| Item | Observation |
| --- | --- |
| Apple RFB banner | `RFB 003.889`; the server offered security types `30, 33, 36, 31, 32, 35` in that order. |
| Authentication | Type 30 succeeded against the VM. The client replied `RFB 003.008`; AES-128-ECB credential encryption produced a successful authenticated ServerInit. The CBC-with-zero-IV description was not tried after ECB worked, and types 33/35/36 were not surveyed. |
| Record protection | The `0x44f` rekey supplied the session key and IV. Subsequent RFB records used persistent AES-CBC state and SHA-1 integrity tags. |
| Server pixel format | 32 bits per pixel, 24-bit depth, little-endian, true colour; maxima 255/255/255 and shifts 16/8/0. |
| Client pixel format | Same 32/24 little-endian true-colour format. |
| Remote desktop | `calternal`, 5004×2652 pixels. No display-layout configuration was sent, so the shared VM's display settings were left alone. |
| First RFB image | 3.419 s after starting the final release holder. The initial Zlib rectangle was 6,746,778 bytes. |

The holder offered Raw (0), CopyRect (1), Zlib (6), RichCursor (-239),
DesktopSize (-223), PointerPos (-232), and Apple DisplayLayout (1105),
VendorKeysym (1107), KeyboardInputSource (1109), and DeviceInfo (1110).
RFB has no SetEncodings acceptance reply, so the wire evidence is what macOS
actually emitted:

| Encoding received | Name | Observation |
| ---: | --- | --- |
| 6 | Zlib | Used for the initial image and framebuffer updates. |
| -239 | RichCursor | Cursor shape data. |
| -223 | DesktopSize | Reported the 5004×2652 desktop. |
| 1105 | Apple DisplayLayout (0x451) | Sent during the initial session setup. |
| 1107 | Apple VendorKeysym (0x453) | Sent as Apple metadata. |
| 1109 | Apple KeyboardInputSource (0x455) | Sent as Apple metadata. |
| 1110 | Apple DeviceInfo (0x456) | Sent as Apple metadata. |

macOS did not send Raw, CopyRect, or PointerPos in this session. Therefore
unused offered encodings cannot be called rejected; the server exposes no
acceptance acknowledgement. The decoder also recognizes Apple CachedCursor
Image (1104), but it was not observed on this connection.

## Holder and browser

The release holder owns one authenticated RFB connection, retains the live
framebuffer, and requests incremental updates at a maximum 20 Hz after each
server response. It listens on loopback HTTP `127.0.0.1:17832` and WebSocket
`127.0.0.1:17831`. Each subscriber gets a full image/keyframe before updates;
closing either browser subscriber left the RFB TCP connection established.

The browser scales to a 1280×800 canvas. JPEG uses changed rectangles and
`createImageBitmap`; H.264 uses `VideoDecoder` with
`optimizeForLatency: true`. Pointer and keyboard events go from WebSocket to
the retained RFB writer. In Chromium 153.0.8010.12 (Playwright 1.63.0), both
`VideoDecoder` and `createImageBitmap` were available and both paths drew the
live desktop.

## Measurement setup

| Machine | Hardware and software | Load/context |
| --- | --- | --- |
| Dev box `infraternal-dev` | Intel Core i9-9900K at 3.60 GHz, 8 logical CPUs, 32.8 GB RAM | Shared host, not the pinned performance VM. At the follow-up load sample, averages were 9.63/14.31/13.25 and several Rust compiler jobs were visible. Treat timing as exploratory. |
| macOS VM `calternal@10.69.69.21` | VirtualMac2,1, macOS 27.0 (26A428), 4 vCPU, 8 GiB | Read-only follow-up `uptime` showed 0.53/0.71/0.83. No settings or software were changed. |
| Network | NetBird SSH local forward, dev box to VM | 20 pings: 0% loss; min/avg/max 151.001/152.111/157.374 ms (mdev 1.353 ms). |
| Browser load | Chromium headless on the dev box; one holder session and one browser at a time | 200 sequential pointer inputs per encoding. Each JSON capture contained 200 unique sequence samples, 1–200. |

The timing starts at the browser's WebSocket send and ends when the changed
canvas frame is drawn. Holder timestamps split RFB arrival, scaling, and
encoding; browser timestamps split WebSocket delivery, decode, and draw.
Browser `performance.now()` measures the total. The staged Unix-clock values
use millisecond browser timestamps and are approximate to about 1 ms.

The benchmark change was a small holder-side pointer marker. macOS sent no
PointerPos updates, and RFB has no input acknowledgement. The holder draws the
marker only after an RFB server message carries the sent input sequence; it is
not a browser-optimistic echo. This is a server-update round-trip proxy to a
canvas change, not the native macOS cursor, proof that the OS processed the
pointer, or camera-measured photon latency. Keyboard forwarding is implemented
but these 200-event runs used pointer inputs.

## Input-to-canvas latency

Each cell is p50/p99 in milliseconds. The total covers all steps; stage
percentiles are calculated independently and should not be added together.

| Stage | JPEG changed rectangles | H.264 keyframes |
| --- | ---: | ---: |
| Samples | 200 | 200 |
| Total send-to-draw | 382.1 / 1031.9 | 703.9 / 952.9 |
| RFB update arrival | 360.2 / 1019.1 | 374.3 / 611.3 |
| Framebuffer scale | 10.5 / 42.2 | 17.9 / 56.8 |
| Encode | 1.0 / 10.6 | 286.3 / 479.8 |
| WebSocket delivery | 0.6 / 14.5 | 2.4 / 16.8 |
| Browser decode | 1.6 / 12.7 | 10.3 / 33.8 |
| Canvas draw | 0.1 / 0.5 | 5.6 / 19.6 |
| Subscriber join to first draw | 243.9 | 530.4 |
| Subscriber bytes during run | 506,067 B | 14,506,228 B |
| Mean subscriber rate during run | 6.3 kB/s | 102.2 kB/s |
| Run duration | 80.12 s | 141.91 s |

The H.264 prototype starts a new `ffmpeg`/libx264 process for every frame and
emits each frame as an IDR keyframe. Its median encode stage was 286.3 ms
(p99 479.8 ms); it also sent about 28.7 times as many bytes as JPEG in these
pointer-marker runs. This measures the current process-per-frame prototype,
not a persistent encoder. JPEG's median total was dominated by RFB update
arrival; H.264 added the process startup and encode time. The runs were
sequential input probes, not a 30 fps animation test.

## Update cadence, traffic, CPU, and memory

| State | macOS framebuffer updates | RFB traffic | Holder process-tree resources |
| --- | ---: | ---: | --- |
| Idle, no subscriber, first 15 s sample | 4 updates / 15 s (0.27/s) | 37,024 B received, about 2,468 B/s; 136 B sent | — |
| Idle, no subscriber, later 20 s sample | 0 updates / 20 s | 306 B received total; 0 B sent | 0.0% CPU ticks observed in either 10 s window; 82,708 KiB RSS |
| JPEG pointer run | 24–28 updates / 10 s (2.4–2.8/s) | 0.65–1.29 MB received per 10 s window | 2.6–3.5% CPU; 82,704 KiB peak RSS |
| H.264 pointer run | 12–16 updates / 10 s (1.2–1.6/s) | 0.09–0.80 MB received per 10 s window | 8.1–9.8% CPU in full active windows; 165,432 KiB peak holder-plus-ffmpeg RSS |

CPU and RSS were sampled from the holder and visible child processes every
20 ms. H.264's largest sampled ffmpeg child was 49,212 KiB. Short-lived child
processes can fall between samples, so the H.264 process-tree CPU/RSS peaks
are lower bounds. No subscriber was connected during the idle samples; after
both subscribers closed, the holder remained connected and received 238 bytes
in a later 15 s window with no framebuffer update.

For scale context, `docs/PROCESS.md` uses 50 sessions as an example. It is not
an S4 forecast: at 50 sessions, measured JPEG holder RSS scales to about
3.94 GiB and its sampled CPU to about 1.6 logical cores. The active H.264
holder-plus-child peak scales to about 7.89 GiB and 4.4 logical cores. The
expected S4 session count still needs an owner value.

## Caveats and real-iPhone pass

- No iPhone or Safari device was available. The browser evidence is headless
  Chromium only. This holder binds HTTP and WebSocket to loopback, so an iPhone
  also needs an owner-approved reachable page and secure WebSocket path.
- A real-iPhone pass must record the exact iPhone model, iOS build, and Safari
  version; confirm `VideoDecoder`, the H.264 profile, `optimizeForLatency`,
  and `createImageBitmap` support; and rerun 200 touch and hardware-keyboard
  events per encoding over the intended network path.
- That pass must capture RTT, jitter, and loss; join-to-first draw; p50/p99
  input-to-canvas and stage times (RFB arrival, scale/encode, transport,
  decode, draw); dropped frames and frame rate; and idle/active bytes per
  second. Record device CPU, holder CPU/RSS, battery/thermal behavior during
  at least a 10-minute active run.
- Measure actual touch/key-to-photon latency with a high-speed camera or
  photodiode. Browser timestamps alone stop at canvas drawing. Also check
  touch mapping, keyboard appearance, device-pixel ratio, safe areas,
  orientation, resize, background/resume, and reconnect behavior.
- The dev box was shared and above its 8-CPU load capacity in a follow-up
  sample. These timings are not a performance-budget result; the repository
  process requires budget measurements on the pinned performance VM.
- Type-30 credential and record key buffers are zeroized, but `num-bigint`
  temporary DH values do not promise zeroization. That remains a crypto
  review item before any production use.

## Owner grill questions

1. What active desktop-session count and CPU/RSS budgets should the next
   measurement use? The 50-session figures above are only scale context.
2. Should the next H.264 measurement use one persistent ffmpeg encoder, and
   should any x264 binding candidate be measured alongside it? This spike did
   not choose an encoder; current process-per-frame H.264 measured 286.3 ms
   median encode time and 48.1 MiB maximum sampled ffmpeg RSS per session.
3. Which repeatable visible macOS surface should the next input pass use so
   it can measure a real remote pixel change as well as the RFB-update proxy?
4. Should a later test be allowed to change the shared VM's display mode, or
   should the holder continue scaling the existing 5004×2652 desktop?
5. Which reachable HTTPS/WSS path should an iPhone subscriber use, given that
   the spike holder currently binds only to loopback?
6. Which DH implementation and memory-wiping requirement should own the
   temporary-value review? This spike does not select a crypto library.

## Checks and artifacts

- `cargo test --manifest-path spikes/vnc/Cargo.toml`: 10 passed.
- `cargo clippy --manifest-path spikes/vnc/Cargo.toml --all-targets`: passed
  with existing dead-code and style warnings; no lint errors.
- `cargo fuzz`: Apple record 891,239 cases, RFB message 60,769 cases, and
  type-30 auth 443 cases; no crash found in these short runs.
- Parser review caught a claimed 1 MiB compressed Zlib body for a 1×1
  rectangle allocating before EOF. The regression assertion failed before the
  new output-relative bound and passed after it.
- Release holder plus Chromium smoke run: JPEG and H.264 both rendered the
  live desktop and left the RFB session up after disconnect.
- The requested repository gate `scripts/verify fast` is absent from this
  worktree; its exact attempted output is recorded in the final issue comment.
