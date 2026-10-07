# S4 remote desktop spike, phase C

This phase attributes the long RFB wait from phase B, measures additional encodings and Apple scaling, and replaces process-per-frame H.264 with a persistent x264 pipe. It remains an exploratory spike on branch **spike-vnc**; it does not choose a production codec, transport, or foundational library. Findings are for issue #35 and decisions 104–107, especially D107's lowest-latency target.

## Summary

- The NetBird/SSH path contributes about **159 ms p50** before desktop work: 20 fresh TCP opens and RFB banners had 158.706 ms p50; 20 ICMP probes averaged 154.747 ms with no loss. The RFB update wait in phase B was 360–374 ms p50, so there was another roughly 200 ms in the old request/capture/update path.
- Keeping four incremental requests outstanding did not make the display fresher. Reply intervals were 153.709/782.951 ms p50/p99 and request ages reached 614.866/938.921 ms. A single outstanding request issued after each reply avoids that stale queue, but cannot beat the path and server's update pace.
- Standard ContinuousUpdates (-313 / server message 150) and Fence (-312 / message 248) produced no streaming or echo evidence. Apple's reverse-engineered AutoFramebufferUpdate (client message 0x09) produced only three full updates in 10 seconds in the tested run. This is not an Apple-published protocol description.
- macOS emitted ZRLE, Apple's 1000–1002/1011 still-image encodings when offered, and Zlib/Raw in other profiles. It did not emit Tight, Hextile, TRLE, or CopyRect in the tested profiles. “Not observed” is the limit: RFB SetEncodings has no acceptance acknowledgement.
- Apple's ScaleFactor 0.5 cut full-frame bytes by 69.9% and measured decode/conversion CPU by 63.4%, while leaving the VM's display settings alone.
- A persistent x264 pipe reduced encode p50 from the phase B process-per-frame 286.3 ms to 16.3 ms in the final input run. With 200 events per path, the RFB-update-to-canvas proxy measured JPEG 172.5/246.0 ms and H.264 189.2/269.1 ms p50/p99.
- Those input numbers are not true macOS input-to-photon latency. The probe draws its marker after a server reply, and an outstanding full-screen request can satisfy the follow-up probe. A real visible app change and a camera/photodiode measurement are still needed to say whether the phase B capture-pacing gap was closed.

## Setup and measurement limits

The remote Mac remained calternal@10.69.69.21, RFB 3.889, 5004×2652, 4 vCPU / 8 GiB. No display setting or system software was changed. Traffic used the NetBird SSH local forward from 127.0.0.1:15900 to remote localhost:5900. Credentials came from the configured environment file and were not written to files, arguments, or logs.

The client measured 20 fresh TCP connect-to-RFB-banner samples through the forward and 20 simultaneous ICMP pings. This estimates the empty-path network round trip; it is not an isolated RFB request/reply because the server banner is sent as part of connection setup. The measured FBU request-to-update samples are not clean RTT samples: macOS can defer or coalesce framebuffer updates, and with multiple requests the response need not correspond to the oldest request. I exclude the single-request “RTT” readings from the encoding runs for that reason.

The holder's 1×1 nonincremental request-after-input mode leaves its normal full-screen incremental request active. It can elicit a small response promptly, but the next update may satisfy either request. The mode is useful for a repeatable browser marker round trip; it does not prove that macOS applied the input or repainted the underlying application.

The final browser runs used Chromium 153.0.8010.12 / Playwright 1.63.0 on infraternal-dev (8 logical CPUs, 32.8 GB RAM). There were 200 sequential pointer events per encoding. The host was shared and loaded: sampled load averages were 11.72/6.97/5.91 while compiler jobs were active. Treat timing as exploratory, not a budget result. Stage percentiles are computed independently and must not be added together.

## 1. Network RTT, update pacing, and request strategy

| Measurement | Samples | Result |
| --- | ---: | ---: |
| ICMP through NetBird route | 20 | min/avg/max 151.199/154.747/187.133 ms; 0% loss; mdev 7.489 ms |
| TCP open + RFB banner through SSH forward | 20 | min/p50/mean/p99/max 153.372/158.706/162.894/237.899/237.899 ms |
| Four outstanding 1×1 incremental FBUs | 4 | update interval p50/p99 153.709/782.951 ms; request age p50/p99 614.866/938.921 ms |
| poll50, one request replenished after each reply | 6 s | 5 server updates; measured full-screen update intervals p50/p99 865.279/2859.359 ms in an idle capture |

The fresh TCP and ICMP results agree within 4 ms at the median/mean, so most of the roughly 150 ms baseline is the routed network round trip. It is not reasonable to attribute the full phase B 360–374 ms update-arrival stage to the network. Under phase B's normal interaction probe, the remainder was about 200 ms beyond the route baseline. The phase C forced small-response probe brought RFB arrival to around the path RTT, but changed the measurement semantics as described above.

The queue-depth test shows why “always outstanding” is not automatically lower latency: macOS returned updates at its own cadence while old requests accumulated. Request-after-receive prevents a deep stale queue. It still waits for the routed round trip and for a server update. At 50 ms polling the 6 s idle run still returned only five updates; client polling did not force macOS to capture at 20 Hz.

The queue-depth and poll50 figures came from separate idle runs, not a controlled same-state A/B. Damage and server capture timing differed, so the interval values show pacing and queue-age behavior, not a measured latency win for one request policy.

The standard RFB registry defines ContinuousUpdates pseudo-encoding -313 and server message 150, plus Fence pseudo-encoding -312 and message 248. The client sent the ContinuousUpdates enable message and Fence request, but observed no continuous stream and no Fence echo. Apple's unofficial reverse-engineered protocol write-up describes AutoFramebufferUpdate client message 0x09, sent after a nonincremental FBU. That path yielded three full updates over 10 s and no explicit acknowledgement in this run. The [IANA RFB registry](https://www.iana.org/assignments/rfb) defines the standard message and encoding numbers; Apple's behavior here follows the [unofficial reverse-engineered Apple RFB notes](https://github.com/renegadelink/iShareScreen/blob/main/docs/apple_vnc_rfc.md), which are not an Apple specification.

## 2. Encoding results

The client offered each candidate with Raw and CopyRect fallbacks, then recorded encodings macOS actually sent. “Decode CPU” below is specifically the local work measured; where tile parsing or the Apple image decoder was unavailable, it is not a complete decode cost.

| Encoding sent by macOS | Full 5004×2652 update bytes | Local decode CPU | Notes |
| --- | ---: | ---: | --- |
| ZRLE (16) | p50/p99 3,992,385/4,006,430 B | deflate-only 31.578/31.641 ms | Inflated 39,815,142 B; no ZRLE tile reconstruction in this parser. |
| Apple low quality (1000) | p50/p99 128,241/128,249 B | inflate-only 1.430/1.556 ms | Inflated 1,660,152 B; not a full pixel decoder. |
| Apple medium quality (1001) | p50/p99 352,452/352,464 B | inflate-only 4.049/5.895 ms | Inflated 6,635,304 B; not a full pixel decoder. |
| Apple high-quality RGB565 (1002) | p50/p99 1,716,205/1,716,234 B | inflate-only 19.098/20.277 ms | Inflated 26,541,216 B; not a full pixel decoder. |
| Apple MVS / “high performance” (1011) | 213,069–306,229 B observed | unavailable | The reverse-engineered format's DCT/MVS decoder was not implemented. A 0×0 table/init rectangle was 145 B. |
| Zlib (6) | p50/p99 5,065,408/5,065,419 B | decode + pixel conversion 67.004/69.129 ms | Existing phase B path; see scaling section. |
| Raw (0) | 53,082,444 B in the tested full rectangle | no compression decode | Sent as fallback in the Tight/Hextile/TRLE and CopyRect trials. |

Apple 1000–1002 are registered encodings and the reverse-engineered notes describe low/medium/high still-image variants. Encoding 1011 is described there as MVS, associated with Apple's high-performance mode. Apple lists broader server encodings in the IANA registry, but neither [noVNC's encoding constants](https://github.com/novnc/noVNC/blob/master/core/encodings.js) nor [LibVNCServer's documented encoding support](https://github.com/LibVNC/libvncserver/blob/master/README.md) advertises a decoder for these Apple image formats. This spike only measured compressed payloads and bounded inflate work; it did not establish visual quality or full decode throughput, so these byte counts are not enough to select a production format.

Tight (7), Hextile (5), and TRLE (15) were offered with Raw fallback; macOS sent full Raw rectangles in those runs. CopyRect was offered during a static view and a 30-second Terminal jot 100 plus PageUp/PageDown scroll, but no CopyRect rectangle appeared. The dynamic run emitted Raw rectangles including 1758×996 and 516×54, as well as full 53,082,444-byte rectangles. This means those encodings were not observed for these profiles, not that the server rejects them in every state.

## 3. Resolution and pixel cost

The Apple ScaleFactor request at 0.5 kept the ServerInit desktop at 5004×2652 but the retained framebuffer stabilized at 2502×1326. The VM's display settings were untouched.

| Retained framebuffer | Full Zlib bytes p50/p99 | Inflate + pixel conversion CPU p50/p99 |
| --- | ---: | ---: |
| 5004×2652 | 5,065,408 / 5,065,419 B | 67.004 / 69.129 ms |
| 2502×1326 via ScaleFactor 0.5 | 1,525,880 / 1,526,114 B | 24.546 / 29.054 ms |

The half-size path used 69.9% fewer bytes and 63.4% less median local decode/conversion CPU. This is a server-side scaled framebuffer request, not a VM mode change. Apple ScaleFactor and AutoFramebufferUpdate are described by reverse engineering, not a public Apple protocol spec. The consumer-facing [Screens compression documentation](https://help.edovia.com/en/screens-5/features/images-quality/) says its remote Mac compression choice asks Screen Sharing for a half-size image without changing the remote display resolution. [Jump Desktop's performance notes](https://docs.jumpdesktop.com/viewer/performance/codecs/) likewise call out total pixel count and Retina scaling as performance factors.

No separate ROI request was identified or measured. Standard incremental FBU rectangles ask for updates over a framebuffer region, but did not give a demonstrated way to make macOS capture only a chosen application region. Holder-side cropping/downscaling remains possible, but still requires receiving and processing the source update; the measured ScaleFactor path is better evidence for reducing work before delivery.

## 4. Persistent x264 path

The H.264 holder now keeps one FFmpeg/libx264 process open per H.264 WebSocket subscriber. The measured session had one subscriber, so it used one persistent encoder; the holder does not yet share that encoder across multiple browser subscribers on the same retained RFB session. It scales to 1280×800, feeds RGBA frames through a persistent pipe, and encodes yuv420p using ultrafast + zerolatency, CRF 26, baseline level 3.1, no B-frames, no scene-cut keyframes, repeated headers, and a very long GOP. Chromium's WebCodecs decoded the first frame and subsequent P-frames. In the final run, all 200 event frames were P-frames; the join image from the smoke run was 73,036 B.

| H.264 event run stage | p50 / p99 |
| --- | ---: |
| Total send-to-canvas draw | 189.2 / 269.1 ms |
| RFB update arrival | 156.4 / 198.9 ms |
| Scale | 9.5 / 34.4 ms |
| Persistent x264 encode | 16.3 / 41.1 ms |
| WebSocket delivery | 0.7 / 8.4 ms |
| Browser decode | 1.3 / 8.9 ms |
| Canvas draw | 5.8 / 15.8 ms |
| Event payload bytes | 174 / 12,046 B |

The final JPEG run used the same 1280×800 output scale and input probe:

| JPEG event run stage | p50 / p99 |
| --- | ---: |
| Total send-to-canvas draw | 172.5 / 246.0 ms |
| RFB update arrival | 150.4 / 184.7 ms |
| Scale | 16.0 / 46.5 ms |
| JPEG encode | 1.9 / 11.1 ms |
| WebSocket delivery | 1.3 / 11.9 ms |
| Browser decode | 2.2 / 12.0 ms |
| Canvas draw | 0.0 / 0.2 ms |
| Event payload bytes | 799 / 5,919 B |

Each path completed 200/200 pointer samples, one browser subscriber at a time. The JPEG changed-bounds diff scans the frame; the H.264 path skips that scan and sends the full scaled frame into the encoder. The H.264 pipe removed the 286.3 ms p50 process-per-frame cost from phase B, but in this proxy run JPEG remained 16.7 ms faster at p50 and 23.1 ms faster at p99. H.264 used fewer bytes at p50 but more at p99; this marker workload is not representative of video motion.

A separate short active sample recorded maximum sampled RSS of 75,812 KiB for the FFmpeg process and 69,020 KiB for the holder; FFmpeg peak sampled CPU was 37.5% and holder 3.5%. Sampling was every 100 ms and misses short peaks. The FFmpeg process is per browser subscriber; the holder's memory includes more than one framebuffer and this single-process sample is not a per-session capacity benchmark. For scale, 50 concurrent FFmpeg children at 75,812 KiB each alone would total about 3.61 GiB; measure real concurrent sessions before using that as a budget.

The Annex-B pipe currently separates access units after a 3 ms quiet interval. If FFmpeg delivers parts of one access unit with a gap longer than that, the holder could split a frame incorrectly. The configured million-frame key interval is finite, not truly “IDR only on join or loss”; there is no explicit keyframe request after a detected browser/network loss. Those are follow-up requirements before relying on long sessions or recovery behavior.

## 5. Input-to-canvas and keyboard probe

The runs measured a holder marker after an RFB server reply, not a changed application pixel. A pointer-only movement does not reliably change the captured desktop in this server profile, so phase C sends a 1×1 nonincremental FBU after the input while leaving the normal full-screen incremental request active. The following update triggers the server marker. That makes a repeatable 200-event proxy possible, but it can use a response already in flight and has no acknowledgement that the macOS event was applied.

The two 200-event stage tables above are the final pair after the H.264 diff-scan optimization. Both ran on the shared, overloaded dev box, one encoding after the other. Independent stage percentiles can exceed the total relationships due to independent samples/timestamps and must not be summed.

A Terminal was already open on the Mac. Typing p and Backspace produced visible server updates measured at 317 ms and 218 ms for the same proxy. This is a two-event smoke check only; it is not a keyboard p50/p99 measurement.

## 6. Floor, remaining gap, and owner questions

The measured network baseline is 158.706 ms p50. Adding one 60 Hz display interval (16.667 ms, an assumed cadence rather than a measured VM refresh rate) gives a rough **175.4 ms p50 path-plus-frame floor**. The best proxy, JPEG at 172.5 ms p50, is effectively at that estimate within a few milliseconds of measurement and proxy noise. H.264 is 13.8 ms above it at p50. The JPEG p99 is still 70.6 ms above that p50 floor.

This only describes the holder marker after an RFB reply. It does not establish true input-to-visible-Mac-content latency. Phase B's 360–374 ms p50 RFB arrival stage was reduced in this test by changing to a forced 1×1 post-input response. It remains unknown how much delay is Apple event dispatch, WindowServer capture/pacing, queued damage, or the path when a real app changes pixels. To close that gap, the next experiment needs a deterministic visible macOS surface that changes in response to each input, a causal server-response correlation, and camera or photodiode capture. If actual updates remain slower than the roughly 159 ms path, the useful target is an Apple push mode with proven semantics or a closer/lower-jitter route—not deeper request pipelining.

Questions for the owner:

1. What user-visible macOS surface and input should define the next real input-to-pixel measurement, and is a high-speed camera/photodiode pass in scope?
2. Should the prototype use Apple AutoFramebufferUpdate 0x09 as a candidate push path, given three full updates in 10 seconds here but no explicit acknowledgement?
3. What session count and per-session CPU/RSS limits should the next scale test use? The single-subscriber RSS sample is only context.
4. Should one encoder be shared across browser subscribers on a retained RFB session? The current one-subscriber measurement uses one encoder, but joining another subscriber needs a defined IDR and decoder-resync policy.
5. Which codec path should be compared next under representative motion on a real iPhone? This spike does not choose between JPEG, Apple image encodings, or H.264.

## Checks and review

- Rust crate tests after the final implementation change: 12 passed.
- Release holder build: passed with existing dead-code warnings.
- Touched Rust source formatting check (rustfmt edition 2024, skip_children=true): passed. Whole-crate cargo fmt --check still reports existing formatting differences in untouched apple_record.rs and bench.rs; they were left alone.
- Chromium real-engine browser runs: 200/200 pointer events each for final JPEG and persistent H.264; browser rendered both paths.
- The updated RFB parser has bounded lengths and two new unit assertions; a nightly cargo-fuzz run of rfb_message completed 92,532 executions in 11 s with no crash.
- No production UI changed; no iPhone/Safari screenshot review applies to this spike.
- The spike package declares AGPL-3.0-only; no dependencies or foundational-engine choices were added.
- Web sources were reviewed on 2026-10-06.
- No scripts/verify executable exists in this worktree. The required scripts/verify fast attempt and exact output are recorded in the final issue comment.
