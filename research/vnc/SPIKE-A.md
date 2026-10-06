<!-- Role: records phase A Apple Screen Sharing auth findings and local codec measurements without selecting an implementation. -->

# S4 remote desktop spike, phase A

**Issue:** kayg/infraternal#35  
**Branch/base:** `spike-vnc` from `main` at `b66edda`  
**Date:** 2026-10-06  
**Decision scope:** DECISIONS 104–107. This report measures options and asks the owner to resolve open questions; it does not choose an authentication type, codec, or library.

## Findings for the owner

- The macOS 27 Screen Sharing server answered `RFB 003.889` and offered security types in wire order `30, 33, 36, 31, 32, 35`. The Rust probe echoed the exact version and parsed that list. A separate probe selected type 30 and closed without reading the challenge or sending authentication bytes. No account credentials were available or used. RFB password type 2 was not offered.
- Public protocol material describes types 30, 33, 35 and 36, but not 31 or 32. Type 30 has a material discrepancy: an Apple-protocol reverse-engineering write-up describes CBC with a zero IV for its credential block; noVNC and TigerVNC encrypt that block with AES in ECB form. The type-30 exchange was not attempted, so compatibility with this macOS 27 server is unresolved.
- At 1280×800, the tested 4:2:0 H.264 CRF 30 stream used 4,910 B/frame and measured 136.9 ms for the illustrative input-to-photon sum. WebP q75 and JPEG q75 changed-rectangle paths both modeled near 161 ms, with different encode, bandwidth and text-quality trade-offs. Lossless changed-rectangle paths preserved exact pixels but modeled at 301–371 ms at 10 Mbit/s.
- At 4096×2170, H.264 4:2:0 CRF 30 modeled at 245.8 ms, while Chromium decode plus canvas draw alone took 106.8 ms p50. That service time exceeds the 66.7 ms interval of the normalized 15 fps stream, so a client-side backlog is plausible. The browser measurements used desktop Chromium, not Safari on iPhone.
- No VideoToolbox result is available: `ffmpeg` was absent on the Mac VM. No software was installed there.

## 1. Authentication survey

### Probe behavior and live result

The standalone Rust client is in [`spikes/vnc/src/main.rs`](../../spikes/vnc/src/main.rs). `inspect HOST PORT` reads the 12-byte RFB banner, echoes the exact `RFB 003.889\n` bytes, and reads the one-byte count and offered type list. It handles a zero-count failure list with a 64 KiB reason-length bound. `select HOST PORT TYPE` verifies the server offered the requested byte, sends only that byte, then exits. Neither mode reads nor answers the selected authentication exchange.

The SSH-forwarded connection to `127.0.0.1:15900` returned banner `RFB 003.889` and `[30, 33, 36, 31, 32, 35]`. Selecting 30 was followed immediately by client close. This confirms the version echo, list framing and security-type selection only. It does not confirm a DH challenge, credential format, authentication result, or post-authentication encryption.

### Offered types

IANA assigns the whole 30–36 range to Apple Inc.; it does not document each type. The mapping below comes from an unofficial reverse-engineering write-up and open-client source, not an Apple protocol specification. That write-up has its own stated revision gaps, especially for types 30 and 35.

| Type | Protocol evidence and owner inputs | Open implementation evidence reviewed |
|---:|---|---|
| **30** | Diffie–Hellman: server sends generator, modulus and server public value; client returns its public value and an encrypted fixed-size username/password block. The write-up describes MD5 of the DH shared value as the AES-128 key and AES-CBC with zero IV for the credential block. It requires a Screen Sharing account username and password, each no longer than 63 UTF-8 bytes plus a NUL in a 64-byte field; remaining bytes are random padding. The protocol material does not require Keychain access; the client must obtain credentials through a safe owner-approved path. | noVNC implements an ARD/DH handler and requests username/password. TigerVNC implements Apple DH and requests credentials. LibVNCClient lists Apple ARD type 30 and gates it on obtaining credentials. Both noVNC and TigerVNC use AES block encryption in ECB form for the 128-byte credential buffer, which conflicts with the write-up's CBC description. Their version handling caps/normalizes RFB versions above 3.8 to 3.8; whether the target accepts that response was not tested. |
| **33** | RSA1 identity envelope followed by SRP-6a challenge/proof. The server can provide an RSA public key; the client then needs a trust policy for that key as well as the target account username and password. The reverse-engineering write-up describes salt, group, server public value, iteration count and client/server SRP proofs. | No type-33 handler was found in the current noVNC or TigerVNC sources reviewed. LibVNCClient support is proposed in open PR #698, not merged. |
| **35** | Kerberos GSS-API exchange with GSS tokens. The write-up describes AP-REQ/AP-REP framing and says the server consumes an already established/imported GSS context; details of the server-side GSS service remain a revision gap. Owner input likely includes a Kerberos principal, realm, service principal and how the holder obtains a usable ticket/context (for example a ticket cache or keytab). Confirm the exact credential source before implementation. | No type-35 handler was found in the current noVNC or TigerVNC sources reviewed. LibVNCClient support is proposed in open PR #698, not merged. |
| **36** | Direct SRP-6a. It uses a clear identity envelope followed by the SRP challenge/proof, without type 33's RSA envelope. It requires the account username and password; the write-up says the initial username envelope is unencrypted. | No type-36 handler was found in the current noVNC or TigerVNC sources reviewed. LibVNCClient support is proposed in open PR #698, not merged. |
| **31** | Apple-assigned number; no per-type exchange, credential requirement or key exchange was found in IANA, the reviewed Apple-protocol write-up, or the reviewed client sources. Do not infer its meaning from adjacent values. | No handler found in noVNC, TigerVNC or current LibVNCClient support list. |
| **32** | Apple-assigned number; no per-type exchange, credential requirement or key exchange was found in IANA, the reviewed Apple-protocol write-up, or the reviewed client sources. Do not infer its meaning from adjacent values. | No handler found in noVNC, TigerVNC or current LibVNCClient support list. |

The protocol mapping and AES discrepancy are based on the [Apple VNC reverse-engineering write-up](https://github.com/renegadelink/iShareScreen/blob/main/docs/apple_vnc_rfc.md), which is not an Apple publication; IANA's [RFB security-type registry](https://www.iana.org/assignments/rfb) only attributes 30–36 to Apple. The client comparison uses [noVNC's RFB implementation](https://github.com/novnc/noVNC/blob/master/core/rfb.js), [TigerVNC's DH implementation](https://raw.githubusercontent.com/TigerVNC/tigervnc/master/common/rfb/CSecurityDH.cxx) and [version negotiation](https://raw.githubusercontent.com/TigerVNC/tigervnc/master/common/rfb/CConnection.cxx), [LibVNCClient's support matrix](https://github.com/LibVNC/libvncserver/blob/master/README.md), and its [open type-33/35/36 proposal](https://github.com/LibVNC/libvncserver/pull/698). Sources were reviewed on 2026-10-06.

### Owner inputs needed before an authenticated follow-up

1. Select a test macOS account with Screen Sharing access and provide its username and password through an owner-approved secret channel. Do not put the password in an issue comment, repository, log, shell argument or command line. No credential file was opened or passed to a process for this phase.
2. Confirm whether a Keychain-backed credential provider is desired. The reviewed wire descriptions call for account credentials; they do not establish a Keychain requirement.
3. Resolve the type-30 AES-CBC versus AES-ECB discrepancy with an authoritative Apple reference or an owner-approved authenticated test account and target capture. Also confirm whether replying with RFB 3.8 is accepted by this `003.889` server.
4. Provide a protocol source or capture for types 31 and 32 if they must be supported.
5. For type 33, set the RSA server-key trust/pinning policy. For type 35, identify the principal, realm, service name and ticket/context source. For type 36, decide whether its clear username envelope is acceptable.

## 2. Screen-content corpus

The source is the shared VM `calternal@10.69.69.21`, macOS 27.0 build `26A428`, arm64, 4 vCPUs and 8 GiB RAM. Its load average was 0.45, 0.72 and 0.76 at the protocol inspection sample. The VM was shared with another project. No system settings or software were changed. The temporary Terminal window was closed and Notes was restored to the foreground after capture.

The capture used the existing desktop. Six idle stills were spaced about one second apart. Eight Terminal stills and a four-second `screencapture -v -V4` clip captured generated scrolling `frame-N` lines. Eight window-position stills and a four-second clip captured AppleScript window-bounds changes. Those changes show window movement; they are not real pointer drag samples. Video capture worked through SSH in this headless run.

| Scene | Stills | Video frames / duration | Still raster | Video raster |
|---|---:|---:|---:|---:|
| Idle | 6 | 27 / 4.00 s | 5004×2652 | 4096×2170 |
| Terminal scroll | 8 | 51 / 4.02 s | 5004×2652 | 4096×2170 |
| Window movement | 8 | 45 / 4.00 s | 5004×2652 | 4096×2170 |

The corpus has 27 files (22 PNGs, 3 movies and 2 timing CSVs), 146,739,237 bytes total. The repository contains only the checksummed [corpus manifest](SPIKE-A-CORPUS-MANIFEST.md); the capture data remains at `$HOME/.cache/codex-scratch/spike-vnc/corpus/`. The manifest records each file's size and SHA-256.

## 3. Measurement setup and method

### Machines and load

| Work | Machine and software | Load average at start → end |
|---|---|---|
| Capture / protocol inspection | macOS 27.0 arm64 VM, 4 vCPUs, 8 GiB; no FFmpeg installed | VM inspection sample: 0.45 / 0.72 / 0.76 |
| Rectangle encode | Linux 6.12.111 KVM, Intel Core i9-9900K @ 3.60 GHz, 8 logical CPUs; Rust 1.99.0 | 1/5/15-minute averages: 1.41/2.70/2.91 → 2.03/2.58/2.84 |
| Rectangle decode/composite | Same Linux host; Google Chrome for Testing 153.0.8010.12, headless | 1/5/15-minute averages: 0.70/1.37/2.24 → 1.17/1.43/2.23 |
| H.264 encode | Same Linux host; FFmpeg 9.0.1 with libx264 | 2.27/2.59/2.60 → 4.94/3.54/2.94 |
| H.264 decode/draw | Same Linux host and Chrome | 0.58/1.73/2.48 → 0.96/1.71/2.44 |

These are host measurements, not measurements on the Mac holder or an iPhone. The H.264 browser runner asked WebCodecs to prefer software; the browser does not expose the implementation it actually used. The rectangle decoders were WASM for QOI, Zstandard and LZ4; JPEG and WebP used `createImageBitmap`. Canvas timings use `OffscreenCanvas` in headless Chromium and do not include a physical display, GPU scanout or iOS scheduling.

### Changed rectangles

[`spikes/vnc/src/bench.rs`](../../spikes/vnc/src/bench.rs) downsamples stills to 1280×800 with Lanczos3 and aspect-preserving black letterbox, or uses the 5004×2652 still raster. It exact-diffs RGBA pixels against the previous still, crops one bounding rectangle, then encodes it. The first image of each scene is a full-frame keyframe. Per-frame encode time includes exact diff, crop and codec, with each codec called three times and the last result stored. Input decode and 1280×800 resampling are outside the timed region.

The compared outputs are zstd level 1, LZ4 block, QOI, JPEG q75/q85/q90 and lossy WebP q75/q85/q90. Browser decode uses the exact emitted payloads and then composites each rectangle into an offscreen framebuffer. The LZ4 length needed by its WASM API is added in memory for decode; that four-byte length and transport headers are not included in wire bytes. No no-change frames occurred in the 22 still samples.

The holder-side p50 is the median across 22 frame samples; p99 uses nearest-rank and is the worst sample for this set. Browser decode/composite uses 66 samples per codec (three repeats for each of 22 frames); its nearest-rank p99 is also the worst sample. Terminal PSNR is the mean over eight terminal stills and an ROI covering the terminal text. Lossless decoders are exact; the Rust PSNR helper caps an exact score at 120 dB. Rectangle `KiB/s` is total encoded bytes divided by the declared 23 seconds across the still sequences. This is about 0.96 still updates/s; it is not a live VNC bitrate. At another cadence, multiply the mean bytes/frame by that update rate.

### H.264 video

[`research/vnc/benchmark/h264.py`](benchmark/h264.py) pads each captured movie to its intended four-second duration, concatenates the three clips, scales/letterboxes to 1280×800 or 4096×2170, then normalizes to 15 fps. Each case has 180 frames over 12 seconds. It tests libx264 `ultrafast` + `zerolatency`, no B-frames, 30-frame key interval, CRF 23/30 or CBR 4 Mbit/s at 1280×800 and 20 Mbit/s at 4096×2170, in yuv420p and yuv444p. The output is Annex-B with access-unit delimiters and repeated parameter sets.

`encode CPU` is FFmpeg `-benchmark_all` user+system time from the paired send/receive callbacks per frame. `encode wall` is elapsed time from the same callbacks. CPU time can exceed wall time when FFmpeg uses multiple threads. Three impossible `UINT64_MAX` clock pairs in 4:4:4 1280×800 cases were excluded and counted; all other samples were kept. p50 is the median over valid samples and p99 uses nearest rank. Terminal quality is FFmpeg SSIM over the terminal ROI; the table gives mean/min over 180 frames. Chromium used WebCodecs `VideoDecoder` with `optimizeForLatency` and measured submit-to-output callback time plus `drawImage`. Every case reported support and produced all 180 output frames.

The requested Mac VideoToolbox comparison could not run: `command -v ffmpeg` found no FFmpeg on the VM. No install was attempted.

## 4. Measurements

### Changed-rectangle results

The estimated input-to-photon column uses the budget assumptions in the next section. Browser timing is decode plus composite, not physical presentation.

| Size | Codec | Encode ms p50/p99 | Mean B/frame | Observed KiB/s | Chromium decode ms p50/p99 | Canvas composite ms p50/p99 | Terminal PSNR mean | Estimated input-to-photon p50 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1280×800 | zstd-l1 | 3.41/5.92 | 253,520 | 236.8 | 2.2/8.2 | 0.2/0.8 | ≥120 dB, lossless | 314.2 ms |
| 1280×800 | lz4-block-fast | 3.15/5.33 | 325,435 | 304.0 | 1.8/5.0 | 0.2/0.6 | ≥120 dB, lossless | 371.1 ms |
| 1280×800 | qoi | 3.66/5.26 | 234,352 | 218.9 | 4.2/9.3 | 0.2/0.6 | ≥120 dB, lossless | 301.1 ms |
| 1280×800 | jpeg-q75 | 13.76/24.22 | 48,948 | 45.7 | 3.1/5.9 | 0.0/6.9 | 40.23 dB | 161.6 ms |
| 1280×800 | jpeg-q85 | 13.52/25.45 | 60,844 | 56.8 | 3.4/12.4 | 0.0/8.0 | 43.71 dB | 171.2 ms |
| 1280×800 | jpeg-q90 | 13.48/27.96 | 72,411 | 67.6 | 3.3/9.4 | 0.0/8.3 | 46.57 dB | 180.3 ms |
| 1280×800 | webp-q75 | 34.61/61.70 | 20,950 | 19.6 | 4.0/8.9 | 0.0/7.8 | 42.39 dB | 161.0 ms |
| 1280×800 | webp-q85 | 31.96/73.45 | 28,743 | 26.8 | 4.4/10.2 | 0.0/6.3 | 45.29 dB | 165.0 ms |
| 1280×800 | webp-q90 | 31.41/68.78 | 35,249 | 32.9 | 4.3/10.0 | 0.0/6.7 | 46.79 dB | 169.5 ms |
| 5004×2652 | zstd-l1 | 51.25/171.76 | 2,818,318 | 2,632.6 | 25.6/59.4 | 4.2/7.7 | ≥120 dB, lossless | 2,441.3 ms |
| 5004×2652 | lz4-block-fast | 45.74/91.55 | 3,854,288 | 3,600.3 | 21.2/96.3 | 4.1/10.2 | ≥120 dB, lossless | 3,260.1 ms |
| 5004×2652 | qoi | 40.77/63.27 | 2,249,981 | 2,101.7 | 47.3/181.8 | 4.0/8.5 | ≥120 dB, lossless | 1,997.7 ms |
| 5004×2652 | jpeg-q75 | 206.43/353.46 | 422,393 | 394.6 | 24.4/48.6 | 4.1/8.7 | 43.82 dB | 678.4 ms |
| 5004×2652 | jpeg-q85 | 225.53/356.85 | 497,572 | 464.8 | 25.5/48.2 | 4.3/8.5 | 47.02 dB | 759.0 ms |
| 5004×2652 | jpeg-q90 | 213.58/432.82 | 572,018 | 534.3 | 26.5/49.4 | 3.8/9.3 | 49.59 dB | 807.1 ms |
| 5004×2652 | webp-q75 | 481.44/854.34 | 128,536 | 120.1 | 28.8/63.2 | 3.9/9.1 | 45.35 dB | 722.6 ms |
| 5004×2652 | webp-q85 | 467.65/876.57 | 171,056 | 159.8 | 31.2/62.5 | 3.9/10.5 | 47.67 dB | 745.2 ms |
| 5004×2652 | webp-q90 | 482.12/913.35 | 211,019 | 197.1 | 34.2/68.1 | 4.2/8.7 | 48.82 dB | 794.9 ms |

### H.264 results

Stream rates below use the 12-second, 15 fps encoded video. The bitstream profile strings observed from the SPS were `avc1.42C020` / `avc1.42C033` for yuv420p and `avc1.F40020` / `avc1.F40033` for yuv444p. In particular, the 1280 yuv420p output was Constrained Baseline despite requesting `-profile:v high`.

| Size | Format | Rate mode | Encode CPU ms p50/p99 | Encode wall ms p50/p99 | Mean B/frame | kB/s | Chromium decode ms p50/p99 | Canvas draw ms p50/p99 | Terminal SSIM mean/min | Estimated input-to-photon p50 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1280×800 | yuv420p | CRF 23 | 10.61/55.98 | 1.90/8.15 | 8,256 | 123.8 | 20.9/27.6 | 4.0/5.9 | 0.999558/0.996194 | 139.0 ms |
| 1280×800 | yuv420p | CRF 30 | 10.91/58.15 | 1.79/7.45 | 4,910 | 73.6 | 21.4/28.6 | 4.2/6.5 | 0.999072/0.995984 | 136.9 ms |
| 1280×800 | yuv420p | CBR 4 Mbps | 14.09/49.16 | 2.17/6.86 | 32,778 | 491.7 | 22.4/26.3 | 4.0/5.7 | 0.999843/0.996475 | 160.4 ms |
| 1280×800 | yuv444p | CRF 23 | 21.64/69.20 | 2.93/9.30 | 9,279 | 139.2 | 19.5/27.6 | 3.3/4.9 | 0.999476/0.997718 | 138.8 ms |
| 1280×800 | yuv444p | CRF 30 | 18.19/71.11 | 2.61/8.99 | 5,486 | 82.3 | 18.9/22.8 | 3.4/5.8 | 0.999026/0.997315 | 134.9 ms |
| 1280×800 | yuv444p | CBR 4 Mbps | 22.41/84.98 | 3.27/10.13 | 32,778 | 491.7 | 21.8/30.0 | 3.6/5.3 | 0.999808/0.998109 | 160.5 ms |
| 4096×2170 | yuv420p | CRF 23 | 111.32/201.65 | 15.70/27.43 | 47,044 | 705.7 | 96.6/134.4 | 19.9/28.8 | 0.999727/0.996158 | 275.4 ms |
| 4096×2170 | yuv420p | CRF 30 | 102.76/197.81 | 14.08/26.90 | 24,106 | 361.6 | 88.4/99.4 | 18.4/24.2 | 0.999411/0.995882 | 245.8 ms |
| 4096×2170 | yuv420p | CBR 20 Mbps | 110.06/208.01 | 15.98/25.43 | 163,889 | 2,458.3 | 93.6/118.8 | 19.0/24.4 | 0.999881/0.996355 | 365.3 ms |
| 4096×2170 | yuv444p | CRF 23 | 161.07/304.13 | 22.16/38.41 | 53,605 | 804.1 | 101.6/129.1 | 19.1/25.0 | 0.999721/0.997845 | 291.3 ms |
| 4096×2170 | yuv444p | CRF 30 | 152.04/292.95 | 21.17/37.51 | 26,546 | 398.2 | 101.7/109.3 | 19.0/23.7 | 0.999449/0.997591 | 268.7 ms |
| 4096×2170 | yuv444p | CBR 20 Mbps | 173.20/318.72 | 24.03/46.71 | 164,263 | 2,463.9 | 105.3/127.9 | 19.0/23.9 | 0.999891/0.998100 | 385.3 ms |

## 5. Illustrative latency budget

No real input or network path was exercised. The estimated p50 column in both tables is a serial sum under these assumptions:

| Stage | Assumption |
|---|---:|
| Input client → holder | 20 ms one way |
| Target input dispatch and paint | 8.3 ms, half a 60 Hz interval |
| Wait until next captured frame | 49 ms, half the measured source-video interval (123 frames / 12.02 s ≈ 10.2 fps) |
| Holder encode | Measured p50 wall time for the row |
| Holder → client serialization | Mean row bytes/frame × 8 / 10 Mbit/s |
| Holder → client network | 20 ms one way |
| Browser decode and canvas | Measured p50 decode plus composite/draw for the row |
| Wait for display scanout | 8.3 ms, half a 60 Hz interval |

The common assumed cost is 105.6 ms; each row adds its measured encode, serialization, decode and canvas values. This does not include input injection queues, capture scheduling beyond the half-frame estimate, transport framing, retransmission, jitter, codec recovery/keyframe wait or frame queues. It is a comparison model, not measured latency. At 10 Mbit/s, a 48,948-byte JPEG q75 update takes about 39.2 ms to serialize; a 20,950-byte WebP q75 update takes about 16.8 ms; a 4,910-byte H.264 CRF 30 frame takes about 3.9 ms. A 234,352-byte QOI update takes about 187.5 ms.

## 6. Ranked shortlist for owner review

Ranked by which alternatives look most useful to take into real-phone and real-network measurements next. This is not an implementation or codec selection.

1. **1280×800 H.264 4:2:0 CRF 30 / CRF 23.** The CRF 30 row measured 4,910 B/frame, 1.79 ms p50 encode wall, SSIM 0.999072 mean / 0.995984 minimum and a modeled 136.9 ms p50. It has the smallest 1280×800 video payload in this matrix. Browser decode and canvas add 25.6 ms p50. Check Safari/iPhone profile support, battery and text quality on a physical device before weighing this against rectangles. At native size, the same format's decode+draw p50 is 106.8 ms, above the 15 fps frame interval.
2. **1280×800 JPEG q75 or WebP q75 changed rectangles.** Their modeled p50 values are close (161.6 and 161.0 ms). JPEG takes 13.76 ms p50 holder time and scores 40.23 dB terminal PSNR; WebP takes 34.61 ms, sends fewer bytes (20,950 vs 48,948) and scores 42.39 dB. Which has lower end-to-end latency depends on available bandwidth and holder CPU. q85/q90 improve terminal PSNR but increase bytes/frame.
3. **1280×800 lossless QOI, zstd or LZ4 changed rectangles.** These preserve exact pixels and encode in 3.15–3.66 ms p50. QOI had the smallest lossless payload (234,352 B/frame); LZ4 had the fastest browser decode (1.8 ms p50) but sent 325,435 B/frame; zstd decoded in 2.2 ms and sent 253,520 B/frame. On the illustrative 10 Mbit/s path, their modeled totals are 301–371 ms.
4. **Native-size transfer.** H.264 reduces bytes substantially, but measured desktop Chromium decode plus draw is 106.8–124.3 ms p50 in the 4:2:0/4:4:4 cases. Changed-rectangle JPEG/WebP holder encode is 206–482 ms p50, while lossless updates send 2.2–3.9 MB/frame. Ask whether a phone needs native pixels or should receive a scaled representation before investing in this path.

## 7. Caveats and owner grill questions

- The corpus has only 22 still samples and three four-second clips from one Mac. Its “window drag” is scripted window repositioning. There is no real pointer-driven drag, large application mix, resize or long-running session.
- Still captures are 5004×2652; clips are 4096×2170. H.264 uses the clip raster and pads its tail to four seconds. Still resampling time is excluded from rectangle holder timing.
- The encode host is an 8-core Intel Linux VM, not the arm64 Mac or production holder. Load varied across runs. The measured per-frame CPU/wall costs do not establish session capacity. A decoded RGBA framebuffer alone is 3.91 MiB at 1280×800 or 50.6 MiB at 5004×2652, before previous-frame, codec and transport buffers. Expected concurrent sessions per holder are not specified, so multiply those floors by the chosen scale only after the owner sets it.
- No iPhone model, real Safari version, radio/network profile, RTT, throughput, packet loss, battery, thermal state or GPU path was measured. The desktop decoder asked for software, but WebCodecs cannot confirm the selected implementation. Canvas calls are not photon measurements.
- Lossy quality is one Terminal ROI: PSNR for still rectangles and SSIM for video. These values do not replace visual review on an iPhone. No production UI was changed, so there are no UI screenshots for review.
- No credentials were available. The probe intentionally stopped before reading or answering any authentication challenge. Do not treat an offered type as proven interoperable.

Questions for the owner:

1. Which non-admin macOS account may be used for a later authenticated protocol capture, and how should its secret be provisioned without placing it in chat, issue text, repository, log or argv? Is a Keychain-backed source expected?
2. Can Apple or an owner-held capture resolve type 30's AES mode and whether a 3.8 client version reply works with this 3.889 server?
3. Are types 31 and 32 required? If so, what documentation or reference implementation identifies their protocol?
4. For types 33, 35 and 36, what RSA key trust policy, Kerberos principal/realm/service and ticket source, and direct-SRP username exposure are acceptable?
5. Which iPhone models, one/four-pane concurrency, network RTT/throughput/loss and target input-to-photon budget define the phone test? What is the expected concurrent session count per holder?
6. Must a phone receive the full native 5004×2652 framebuffer, or should the holder scale it to the subscriber's viewport?

## 8. Author review and gates

The phase A self-review found no area-specific checklist file in the worktree, so the author checklist was applied directly: the RFB reader bounds its failure reason and closes before auth; no credential bytes or corpus payloads are committed; all 27 corpus manifest sizes and hashes matched the scratch files; temporary benchmark outputs remain outside the repository; report rates and p99 sample sizes state their cadence and limits; modules start with role comments; the Rust package and browser benchmark package declare AGPL-3.0-only; dependency license metadata offers AGPL-compatible terms; and no architecture choice is made. `scripts/verify fast` is not a spike gate.

Requested Rust gates from the worktree root (build target kept outside the repository):

```text
$ CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/spike-vnc/target" cargo build --manifest-path spikes/vnc/Cargo.toml
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.11s

$ CARGO_TARGET_DIR="$HOME/.cache/codex-scratch/spike-vnc/target" cargo clippy --manifest-path spikes/vnc/Cargo.toml --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
```

The saved corpus and machine-readable measurements are at the scratch paths above; the repository retains only the manifest, spike runners and this report.
