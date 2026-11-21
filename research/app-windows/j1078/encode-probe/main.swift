/// J1078 measurement probe (not product code): hardware H.264/HEVC encode latency with the
/// production session settings of crates/plugins/desktop/native/Encoder.swift, against picture
/// size, content, input format, in-flight depth and parallel sessions; plus the per-frame cost of
/// the production FramePixels.prepare (compiled from the repo file) and of a raw-tile fast lane.
import Compression
import CoreMedia
import CoreVideo
import Foundation
import IOSurface
import VideoToolbox

/// The machine's tick-to-nanosecond ratio, read once.
var timebase = mach_timebase_info_data_t(); mach_timebase_info(&timebase)
/// Milliseconds for a `mach_absolute_time` span.
func ms(_ ticks: UInt64) -> Double { Double(ticks) * Double(timebase.numer) / Double(timebase.denom) / 1e6 }
/// The monotonic clock in ticks.
func now() -> UInt64 { mach_absolute_time() }
/// Nearest-rank percentile of `values` (unsorted); NaN when empty.
func pct(_ values: [Double], _ p: Double) -> Double {
    guard !values.isEmpty else { return .nan }
    let s = values.sorted(); return s[min(s.count - 1, Int((Double(s.count) * p).rounded(.down)))]
}
/// Three decimals.
func f(_ v: Double) -> String { String(format: "%.3f", v) }
/// True for the short run (QUICK set): fewer sizes and frames.
let quick = ProcessInfo.processInfo.environment["QUICK"] != nil
/// The sections named in ONLY, comma separated; nil runs the default set.
let only = ProcessInfo.processInfo.environment["ONLY"]

/// Deterministic xorshift, so every run and every arm sees the same pictures.
struct RNG { var s: UInt64; mutating func next() -> UInt64 { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s } }

/// A UI-like BGRA picture: a toolbar gradient and rows of glyph-like dark marks on white.
func basePicture(_ w: Int, _ h: Int) -> [UInt8] {
    var p = [UInt8](repeating: 255, count: w * h * 4); var r = RNG(s: 0x9E3779B97F4A7C15)
    for y in 0..<min(64, h) { for x in 0..<w { let i = (y * w + x) * 4; p[i] = UInt8(200 + (x * 40 / w)); p[i+1] = UInt8(205 + y / 2); p[i+2] = 210 } }
    var y = 80
    while y + 14 < h {
        var x = 16
        while x + 10 < w - 16 {
            let gw = 5 + Int(r.next() % 5)
            if r.next() % 6 != 0 {
                for gy in 0..<12 { for gx in 0..<gw where r.next() % 3 != 0 {
                    let v = UInt8(r.next() % 120); let i = ((y + gy) * w + x + gx) * 4; p[i] = v; p[i+1] = v; p[i+2] = v
                } }
            }
            x += gw + 2
        }
        y += 20
    }
    return p
}
/// An IOSurface-backed pixel buffer of `format`, as the capture framework hands out.
func buffer(_ w: Int, _ h: Int, _ format: OSType = kCVPixelFormatType_32BGRA) -> CVPixelBuffer {
    var out: CVPixelBuffer?
    let attrs = [kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary
    precondition(CVPixelBufferCreate(kCFAllocatorDefault, w, h, format, attrs, &out) == kCVReturnSuccess)
    return out!
}
/// Copies rows into `pixel`; `rows` returns the source of each row.
func fill(_ pixel: CVPixelBuffer, _ w: Int, _ h: Int, rows: (Int) -> UnsafeRawPointer) {
    CVPixelBufferLockBaseAddress(pixel, []); let base = CVPixelBufferGetBaseAddress(pixel)!; let stride = CVPixelBufferGetBytesPerRow(pixel)
    for row in 0..<h { base.advanced(by: row * stride).copyMemory(from: rows(row), byteCount: w * 4) }
    CVPixelBufferUnlockBaseAddress(pixel, [])
}
/// `count` frames. typing: one more glyph-sized mark per frame. scroll: text area moves up 8 px per frame.
func frames(_ w: Int, _ h: Int, scenario: String, count: Int) -> [CVPixelBuffer] {
    var base = basePicture(w, h); var out: [CVPixelBuffer] = []; var r = RNG(s: 42)
    for k in 0..<count {
        let pixel = buffer(w, h)
        if scenario == "typing" {
            let gx = 16 + (k * 9) % max(1, w - 64), gy = min(h - 16, 80 + 20 * ((h - 100) / 40))
            for yy in 0..<12 { for xx in 0..<7 where r.next() % 3 != 0 { let i = ((gy + yy) * w + gx + xx) * 4; base[i] = 20; base[i+1] = 20; base[i+2] = 20 } }
            base.withUnsafeBytes { b in fill(pixel, w, h) { b.baseAddress!.advanced(by: $0 * w * 4) } }
        } else {
            let top = min(80, h), span = h - top, shift = (k * 8) % max(1, span)
            base.withUnsafeBytes { b in fill(pixel, w, h) { row in
                row < top ? b.baseAddress!.advanced(by: row * w * 4) : b.baseAddress!.advanced(by: (top + (row - top + shift) % span) * w * 4)
            } }
        }
        out.append(pixel)
    }
    return out
}
/// The same pictures converted to another pixel format (for the 420v/420f arms).
func converted(_ source: [CVPixelBuffer], _ w: Int, _ h: Int, _ format: OSType) -> [CVPixelBuffer] {
    var transfer: VTPixelTransferSession?; VTPixelTransferSessionCreate(allocator: nil, pixelTransferSessionOut: &transfer)
    return source.map { let d = buffer(w, h, format); precondition(VTPixelTransferSessionTransferImage(transfer!, from: $0, to: d) == noErr); return d }
}
/// Horizontal band `index` of `n` cut from each picture (for the split-encoder arms).
func band(_ source: [CVPixelBuffer], _ w: Int, _ h: Int, index: Int, of n: Int) -> [CVPixelBuffer] {
    let bh = (h / n) & ~1
    return source.map { s in
        let d = buffer(w, bh); CVPixelBufferLockBaseAddress(s, .readOnly)
        let base = CVPixelBufferGetBaseAddress(s)!, stride = CVPixelBufferGetBytesPerRow(s)
        fill(d, w, bh) { UnsafeRawPointer(base.advanced(by: (index * bh + $0) * stride)) }
        CVPixelBufferUnlockBaseAddress(s, .readOnly); return d
    }
}

/// One session configuration under test: codec, rate-control mode, cadence and extra properties.
struct Variant {
    /// The label, codec, rate-control mode and frame rate of the variant.
    var name = "prod"; var hevc = false; var lowLatency = true; var fps = 120
    /// Extra session properties set after the production ones.
    var extra: [(String, CFTypeRef)] = []
}
/// The session of Encoder.configure (same properties, same order), plus a variant's extras.
func session(_ w: Int, _ h: Int, _ v: Variant) -> VTCompressionSession? {
    var spec: [String: Any] = [kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String: true]
    if v.lowLatency { spec[kVTVideoEncoderSpecification_EnableLowLatencyRateControl as String] = true }
    var s: VTCompressionSession?
    let created = VTCompressionSessionCreate(allocator: kCFAllocatorDefault, width: Int32(w), height: Int32(h), codecType: v.hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264,
        encoderSpecification: spec as CFDictionary, imageBufferAttributes: nil, compressedDataAllocator: nil, outputCallback: nil, refcon: nil, compressionSessionOut: &s)
    guard created == noErr, let s else { print("NOTE create_failed variant=\(v.name) size=\(w)x\(h) status=\(created)"); return nil }
    func set(_ k: CFString, _ value: CFTypeRef) { let st = VTSessionSetProperty(s, key: k, value: value); if st != noErr { print("NOTE property=\(k) status=\(st) variant=\(v.name)") } }
    set(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
    set(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
    set(kVTCompressionPropertyKey_ColorPrimaries, kCVImageBufferColorPrimaries_ITU_R_709_2)
    set(kVTCompressionPropertyKey_TransferFunction, kCVImageBufferTransferFunction_sRGB)
    set(kVTCompressionPropertyKey_YCbCrMatrix, kCVImageBufferYCbCrMatrix_ITU_R_709_2)
    set(kVTCompressionPropertyKey_MaxKeyFrameInterval, NSNumber(value: Int32.max))
    set(kVTCompressionPropertyKey_ExpectedFrameRate, NSNumber(value: v.fps))
    set(kVTCompressionPropertyKey_AverageBitRate, NSNumber(value: max(500_000, w * h * 3)))
    for (k, value) in v.extra { set(k as CFString, value) }
    guard VTCompressionSessionPrepareToEncodeFrames(s) == noErr else { print("NOTE prepare_failed variant=\(v.name)"); return nil }
    return s
}

/// Collected latencies, bytes and drops of one run; `lock` guards callback writes.
final class Tally { let lock = NSLock(); var latency: [Double] = []; var bytes: [Int] = []; var drops = 0; var last: UInt64 = 0; var keys = 0 }
/// Submits one frame and calls `done` with the callback time, bytes and whether it was dropped.
func submit(_ s: VTCompressionSession, _ pixel: CVPixelBuffer, index: Int, fps: Int, key: Bool = false, _ done: @escaping (UInt64, Int, Bool) -> Void) {
    let options = key ? [kVTEncodeFrameOptionKey_ForceKeyFrame as String: true] as CFDictionary : nil
    let st = VTCompressionSessionEncodeFrame(s, imageBuffer: pixel, presentationTimeStamp: CMTime(value: Int64(index), timescale: Int32(fps)), duration: CMTime(value: 1, timescale: Int32(fps)), frameProperties: options, infoFlagsOut: nil) { status, flags, sample in
        let t = now(); let dropped = status != noErr || flags.contains(.frameDropped) || sample == nil
        done(t, sample.map { CMSampleBufferGetTotalSampleSize($0) } ?? 0, dropped)
    }
    if st != noErr { done(now(), 0, true) }
}
/// Sleeps until the absolute tick `deadline`.
func sleepUntil(_ deadline: UInt64) { let n = now(); if deadline > n { mach_wait_until(deadline) } }
/// Ticks per source frame at a frame rate.
let tickNs = { (fps: Int) -> UInt64 in UInt64(1e9 / Double(fps) * Double(timebase.denom) / Double(timebase.numer)) }

/// One frame in flight, as production does: submit, wait for the callback, then the next source tick.
func runSync(_ sessions: [VTCompressionSession], _ inputs: [[CVPixelBuffer]], fps: Int, count: Int, warm: Int) -> Tally {
    let tally = Tally(); let interval = tickNs(fps); var next = now()
    for i in 0..<(count + warm) {
        sleepUntil(next); let t0 = now(); next = max(t0, next) + interval
        let group = DispatchGroup(); var worst: UInt64 = t0; var total = 0; var dropped = false; let l = NSLock()
        for (n, s) in sessions.enumerated() {
            group.enter()
            submit(s, inputs[n][i % inputs[n].count], index: i, fps: fps, key: i == 0) { t, b, d in l.lock(); worst = max(worst, t); total += b; dropped = dropped || d; l.unlock(); group.leave() }
        }
        group.wait()
        if i >= warm { if dropped { tally.drops += 1 } else { tally.latency.append(ms(worst - t0)); tally.bytes.append(total) } }
    }
    return tally
}
/// Submit on the source cadence without waiting, so several frames may be inside the encoder.
func runPipelined(_ s: VTCompressionSession, _ input: [CVPixelBuffer], fps: Int, count: Int, warm: Int) -> (Tally, Double) {
    let tally = Tally(); let interval = tickNs(fps); var next = now(); var first: UInt64 = 0
    for i in 0..<(count + warm) {
        sleepUntil(next); let t0 = now(); next += interval; if i == warm { first = t0 }
        submit(s, input[i % input.count], index: i, fps: fps, key: i == 0) { t, b, d in
            tally.lock.lock(); if i >= warm { if d { tally.drops += 1 } else { tally.latency.append(ms(t - t0)); tally.bytes.append(b); tally.last = max(tally.last, t) } }; tally.lock.unlock()
        }
    }
    VTCompressionSessionCompleteFrames(s, untilPresentationTimeStamp: .invalid)
    let seconds = ms(tally.last - first) / 1000
    return (tally, Double(tally.latency.count) / max(seconds, 1e-9))
}
/// Prints one RESULT line for a run.
func report(_ kind: String, _ label: String, _ w: Int, _ h: Int, _ scenario: String, _ t: Tally, extra: String = "") {
    let mean = t.bytes.isEmpty ? 0 : t.bytes.reduce(0, +) / t.bytes.count
    print("RESULT kind=\(kind) variant=\(label) size=\(w)x\(h) mp=\(f(Double(w * h) / 1e6)) scenario=\(scenario) n=\(t.latency.count) drops=\(t.drops) p50_ms=\(f(pct(t.latency, 0.5))) p95_ms=\(f(pct(t.latency, 0.95))) min_ms=\(f(t.latency.min() ?? .nan)) mean_bytes=\(mean)\(extra)")
    fflush(stdout)
}
/// True when the section is in ONLY, or ONLY is unset.
func want(_ section: String) -> Bool { only == nil || only!.split(separator: ",").contains(Substring(section)) }

/// Timed frames, warm-up frames, and distinct pictures per run.
let N = quick ? 40 : 160, WARM = quick ? 10 : 30, FRAMES = 12
/// The hardware model name (hw.model), for the log header.
var host = [CChar](repeating: 0, count: 256); var hostSize = 256; sysctlbyname("hw.model", &host, &hostSize, nil, 0)
print("INFO model=\(String(cString: host)) os=\(ProcessInfo.processInfo.operatingSystemVersionString) cores=\(ProcessInfo.processInfo.activeProcessorCount) n=\(N) warm=\(WARM) thermal=\(ProcessInfo.processInfo.thermalState.rawValue) low_power=\(ProcessInfo.processInfo.isLowPowerModeEnabled)")

// Experiment 0: encode latency against megapixels, production settings, one frame in flight.
if want("size") {
    for (w, h) in quick ? [(640, 400), (1520, 1026)] : [(320, 200), (640, 400), (960, 600), (1280, 800), (1520, 1026), (1920, 1200), (2560, 1600)] {
        for scenario in ["typing", "scroll"] { autoreleasepool {
            let input = frames(w, h, scenario: scenario, count: FRAMES)
            for fps in [120, 60] {
                guard let s = session(w, h, Variant(fps: fps)) else { continue }
                report("size", "prod_fps\(fps)", w, h, scenario, runSync([s], [input], fps: fps, count: N, warm: WARM))
                VTCompressionSessionInvalidate(s)
            }
        } }
    }
}
// Settings and input-format variants at the measured fixture size.
/// The fixture window size the variant rows use (1.56 MP).
let W = 1520, H = 1026
if want("variant") {
    let variants: [Variant] = [
        Variant(name: "prod"),
        Variant(name: "max_frame_delay_0", extra: [(kVTCompressionPropertyKey_MaxFrameDelayCount as String, NSNumber(value: 0))]),
        Variant(name: "speed_over_quality", extra: [(kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality as String, kCFBooleanTrue)]),
        Variant(name: "no_power_efficiency", extra: [(kVTCompressionPropertyKey_MaximizePowerEfficiency as String, kCFBooleanFalse)]),
        Variant(name: "max_realtime_rate_120", extra: [("MaximumRealTimeFrameRate", NSNumber(value: 120))]),
        Variant(name: "reference_count_1", extra: [("ReferenceBufferCount", NSNumber(value: 1))]),
        Variant(name: "baseline_profile", extra: [(kVTCompressionPropertyKey_ProfileLevel as String, kVTProfileLevel_H264_Baseline_AutoLevel)]),
        Variant(name: "classic_realtime", lowLatency: false, extra: [(kVTCompressionPropertyKey_MaxFrameDelayCount as String, NSNumber(value: 0))]),
        Variant(name: "hevc_low_latency", hevc: true),
        Variant(name: "hevc_classic", hevc: true, lowLatency: false, extra: [(kVTCompressionPropertyKey_MaxFrameDelayCount as String, NSNumber(value: 0))]),
    ]
    for scenario in ["typing", "scroll"] { autoreleasepool {
        let input = frames(W, H, scenario: scenario, count: FRAMES)
        for v in variants { if let s = session(W, H, v) { report("variant", v.name, W, H, scenario, runSync([s], [input], fps: 120, count: N, warm: WARM)); VTCompressionSessionInvalidate(s) } }
        for (name, format) in [("input_420v", kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange), ("input_420f", kCVPixelFormatType_420YpCbCr8BiPlanarFullRange)] {
            let planar = converted(input, W, H, format)
            if let s = session(W, H, Variant(name: name)) { report("variant", name, W, H, scenario, runSync([s], [planar], fps: 120, count: N, warm: WARM)); VTCompressionSessionInvalidate(s) }
        }
    } }
}
// More than one frame inside the encoder: does 120 fps hold, and what does a frame wait?
if want("pipeline") {
    for (w, h) in quick ? [(1520, 1026)] : [(1520, 1026), (2560, 1600)] { for scenario in ["typing", "scroll"] { autoreleasepool {
        let input = frames(w, h, scenario: scenario, count: FRAMES)
        if let s = session(w, h, Variant()) {
            let sync = runSync([s], [input], fps: 120, count: N, warm: WARM)
            let span = sync.latency.reduce(0, +) / 1000
            report("pipeline", "sync_back_to_back", w, h, scenario, sync, extra: " ceiling_fps=\(f(Double(sync.latency.count) / span))")
            VTCompressionSessionInvalidate(s)
        }
        if let s = session(w, h, Variant()) {
            let (t, fps) = runPipelined(s, input, fps: 120, count: N * 2, warm: WARM)
            report("pipeline", "pipelined_120", w, h, scenario, t, extra: " achieved_fps=\(f(fps))")
            VTCompressionSessionInvalidate(s)
        }
    } } }
}
// Parallel sessions: horizontal bands of one window, and several whole windows at once.
if want("parallel") {
    for scenario in ["typing", "scroll"] { autoreleasepool {
        let input = frames(W, H, scenario: scenario, count: FRAMES)
        for n in [1, 2, 4] {
            let bh = (H / n) & ~1; let inputs = (0..<n).map { band(input, W, H, index: $0, of: n) }
            let sessions = (0..<n).compactMap { _ in session(W, bh, Variant()) }
            if sessions.count == n { report("bands", "bands_\(n)", W, bh * n, scenario, runSync(sessions, inputs, fps: 120, count: N, warm: WARM)) }
            sessions.forEach { VTCompressionSessionInvalidate($0) }
        }
        for n in quick ? [2] : [2, 4, 8] {
            let sessions = (0..<n).compactMap { _ in session(W, H, Variant()) }
            if sessions.count == n { report("windows", "windows_\(n)", W, H, scenario, runSync(sessions, Array(repeating: input, count: n), fps: 120, count: N, warm: WARM)) }
            else { print("NOTE windows_\(n) sessions_created=\(sessions.count)") }
            sessions.forEach { VTCompressionSessionInvalidate($0) }
        }
    } }
}
// The production exact-pixel history (FramePixels.prepare from the repo), per frame, before encode.
if want("history") {
    for (w, h) in [(1520, 1026), (2560, 1600)] { autoreleasepool {
        for (label, scenario) in [("small_change", "typing"), ("full_change", "scroll")] {
            let input = frames(w, h, scenario: scenario, count: FRAMES); let history = FramePixels(); var times: [Double] = []
            _ = history.prepare(input[0]); history.delivered()
            for i in 1..<(N + 1) { let t0 = now(); _ = history.prepare(input[i % input.count]); times.append(ms(now() - t0)); history.delivered() }
            print("RESULT kind=history case=\(label) size=\(w)x\(h) mb=\(f(Double(w * h * 4) / 1e6)) n=\(times.count) p50_ms=\(f(pct(times, 0.5))) p95_ms=\(f(pct(times, 0.95)))")
        }
        let input = frames(w, h, scenario: "typing", count: 2); let twin = buffer(w, h)
        CVPixelBufferLockBaseAddress(input[0], .readOnly); let b = CVPixelBufferGetBaseAddress(input[0])!, st = CVPixelBufferGetBytesPerRow(input[0])
        fill(twin, w, h) { UnsafeRawPointer(b.advanced(by: $0 * st)) }; CVPixelBufferUnlockBaseAddress(input[0], .readOnly)
        let history = FramePixels(); var times: [Double] = []; _ = history.prepare(input[0]); history.delivered()
        for i in 0..<N { let t0 = now(); let changed = history.prepare(i % 2 == 0 ? twin : input[0]); times.append(ms(now() - t0)); precondition(!changed); history.delivered() }
        print("RESULT kind=history case=identical size=\(w)x\(h) mb=\(f(Double(w * h * 4) / 1e6)) n=\(times.count) p50_ms=\(f(pct(times, 0.5))) p95_ms=\(f(pct(times, 0.95)))")
    } }
}
// Raw-tile fast lane: cut a changed rectangle out of the surface and deflate it.
if want("tile") {
    let input = frames(W, H, scenario: "typing", count: 2)[1]
    for (label, tw, th) in [("glyph_32x40", 32, 40), ("word_240x40", 240, 40), ("line_1488x40", 1488, 40), ("block_800x400", 800, 400)] {
        var times: [Double] = []; var size = 0; var tile = [UInt8](repeating: 0, count: tw * th * 4); var out = [UInt8](repeating: 0, count: tw * th * 4 + 4096)
        for _ in 0..<N {
            let t0 = now(); CVPixelBufferLockBaseAddress(input, .readOnly)
            let base = CVPixelBufferGetBaseAddress(input)!, stride = CVPixelBufferGetBytesPerRow(input)
            tile.withUnsafeMutableBytes { d in for row in 0..<th { d.baseAddress!.advanced(by: row * tw * 4).copyMemory(from: base.advanced(by: (H - 80 - th + row) * stride + 16 * 4), byteCount: tw * 4) } }
            CVPixelBufferUnlockBaseAddress(input, .readOnly)
            size = compression_encode_buffer(&out, out.count, tile, tile.count, nil, COMPRESSION_ZLIB)
            times.append(ms(now() - t0))
        }
        print("RESULT kind=tile case=\(label) raw_bytes=\(tw * th * 4) deflate_bytes=\(size) n=\(times.count) p50_ms=\(f(pct(times, 0.5))) p95_ms=\(f(pct(times, 0.95)))")
    }
}

// Settled sharp refresh: a forced keyframe at 4x the bit rate (production) against re-encoding the
// same settled picture as ordinary delta frames. Every sample is decoded; quality is PSNR against
// the source pixels, so both arms pay the same colour conversion.
/// Encodes one picture and waits for it; nil when the encoder dropped it.
func encodeOne(_ s: VTCompressionSession, _ pixel: CVPixelBuffer, index: Int, key: Bool) -> CMSampleBuffer? {
    let done = DispatchSemaphore(value: 0); var out: CMSampleBuffer?
    let options = key ? [kVTEncodeFrameOptionKey_ForceKeyFrame as String: true] as CFDictionary : nil
    let st = VTCompressionSessionEncodeFrame(s, imageBuffer: pixel, presentationTimeStamp: CMTime(value: Int64(index), timescale: 120), duration: CMTime(value: 1, timescale: 120), frameProperties: options, infoFlagsOut: nil) { status, flags, sample in
        if status == noErr, !flags.contains(.frameDropped) { out = sample }; done.signal()
    }
    if st != noErr { return nil }; done.wait(); return out
}
/// A VideoToolbox decoder producing BGRA, for scoring.
final class Decoder {
    /// The decoding session, made from the first sample's format.
    var session: VTDecompressionSession?
    /// Decodes one sample synchronously; nil when it cannot.
    func decode(_ sample: CMSampleBuffer) -> CVPixelBuffer? {
        if session == nil, let format = CMSampleBufferGetFormatDescription(sample) {
            let attrs = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA] as CFDictionary
            VTDecompressionSessionCreate(allocator: nil, formatDescription: format, decoderSpecification: nil, imageBufferAttributes: attrs, outputCallback: nil, decompressionSessionOut: &session)
        }
        guard let session else { return nil }
        var picture: CVPixelBuffer?
        VTDecompressionSessionDecodeFrame(session, sampleBuffer: sample, flags: [], infoFlagsOut: nil) { _, _, image, _, _ in picture = image }
        VTDecompressionSessionWaitForAsynchronousFrames(session)
        return picture
    }
}
/// PSNR in dB over the RGB channels of two BGRA pictures (99 when identical).
func psnr(_ a: CVPixelBuffer, _ b: CVPixelBuffer, _ w: Int, _ h: Int) -> Double {
    CVPixelBufferLockBaseAddress(a, .readOnly); CVPixelBufferLockBaseAddress(b, .readOnly)
    defer { CVPixelBufferUnlockBaseAddress(a, .readOnly); CVPixelBufferUnlockBaseAddress(b, .readOnly) }
    let pa = CVPixelBufferGetBaseAddress(a)!.assumingMemoryBound(to: UInt8.self), pb = CVPixelBufferGetBaseAddress(b)!.assumingMemoryBound(to: UInt8.self)
    let sa = CVPixelBufferGetBytesPerRow(a), sb = CVPixelBufferGetBytesPerRow(b); var sum: Double = 0
    for y in 0..<h { var row: UInt64 = 0; for x in 0..<(w * 4) where x % 4 != 3 { let d = Int(pa[y * sa + x]) - Int(pb[y * sb + x]); row += UInt64(d * d) }; sum += Double(row) }
    let mse = sum / Double(w * h * 3); return mse == 0 ? 99 : 10 * log10(255 * 255 / mse)
}
if only?.contains("refresh") == true {
    for (w, h) in [(656, 422), (1520, 1026)] { for scenario in ["scroll", "typing"] { autoreleasepool {
        let input = frames(w, h, scenario: scenario, count: FRAMES); let rate = max(500_000, w * h * 3)
        func prefix() -> (VTCompressionSession, Decoder, Int, Double, Int)? {
            guard let s = session(w, h, Variant()) else { return nil }
            let d = Decoder(); var index = 0; var last = 0.0; var bytes = 0; var count = 0
            for i in 0..<60 {
                guard let sample = encodeOne(s, input[i % input.count], index: index, key: i == 0) else { index += 1; continue }
                index += 1; if i > 0 { bytes += CMSampleBufferGetTotalSampleSize(sample); count += 1 }
                if let picture = d.decode(sample) { last = psnr(picture, input[i % input.count], w, h) }
                usleep(8000)
            }
            return (s, d, index, last, count == 0 ? 0 : bytes / count)
        }
        let settled = input[59 % input.count]
        if let (s, d, index, before, delta) = prefix() {
            VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: rate * 4))
            if let sample = encodeOne(s, settled, index: index, key: true), let picture = d.decode(sample) {
                print("RESULT kind=refresh arm=keyframe_4x size=\(w)x\(h) scenario=\(scenario) psnr_before=\(f(before)) mean_delta_bytes=\(delta) bytes=\(CMSampleBufferGetTotalSampleSize(sample)) psnr_after=\(f(psnr(picture, settled, w, h)))")
            } else { print("NOTE refresh keyframe dropped size=\(w)x\(h) scenario=\(scenario)") }
            VTCompressionSessionInvalidate(s)
        }
        for (arm, factor) in [("delta_4x", 4), ("delta_1x", 1)] {
            guard let (s, d, start, before, _) = prefix() else { continue }
            if factor != 1 { VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: rate * factor)) }
            var total = 0; var line = "RESULT kind=refresh arm=\(arm) size=\(w)x\(h) scenario=\(scenario) psnr_before=\(f(before))"
            for k in 1...8 {
                usleep(8000)
                guard let sample = encodeOne(s, settled, index: start + k, key: false) else { line += " k\(k)=dropped"; continue }
                total += CMSampleBufferGetTotalSampleSize(sample)
                if let picture = d.decode(sample) { line += " k\(k)_bytes_total=\(total) k\(k)_psnr=\(f(psnr(picture, settled, w, h)))" }
            }
            print(line); VTCompressionSessionInvalidate(s)
        }
    } } }
}

// Loss repair without a keyframe: long-term reference frames of the low-latency encoder.
// The viewer loses three delta frames; the repair is either a forced keyframe (production) or a
// refresh that references the last acknowledged long-term frame. Both are decoded and checked.
/// The long-term-reference acknowledgement token a sample carries, if any.
func ltrToken(_ sample: CMSampleBuffer) -> NSNumber? {
    guard let all = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[CFString: Any]], let first = all.first else { return nil }
    return first[kVTSampleAttachmentKey_RequireLTRAcknowledgementToken] as? NSNumber
}
if only?.contains("ltr") == true {
    for (w, h) in [(656, 422), (1520, 1026)] { for scenario in ["typing", "scroll"] { for arm in ["keyframe", "ltr_refresh"] { autoreleasepool {
        let input = frames(w, h, scenario: scenario, count: FRAMES)
        guard let s = session(w, h, Variant(extra: [(kVTCompressionPropertyKey_EnableLTR as String, kCFBooleanTrue)])) else { return }
        let d = Decoder(); var token: NSNumber?; var tokens = 0; var deltaBytes = 0; var deltas = 0
        for i in 0..<40 {
            guard let sample = encodeOne(s, input[i % input.count], index: i, key: i == 0) else { continue }
            if let t = ltrToken(sample) { tokens += 1; if i < 36 { token = t } }
            if i > 0 { deltaBytes += CMSampleBufferGetTotalSampleSize(sample); deltas += 1 }
            if i < 37 { _ = d.decode(sample) }   // frames 37, 38, 39 never reach the viewer
            usleep(8000)
        }
        var options: [String: Any] = [:]
        if arm == "keyframe" { options[kVTEncodeFrameOptionKey_ForceKeyFrame as String] = true }
        else { options[kVTEncodeFrameOptionKey_ForceLTRRefresh as String] = true; if let token { options[kVTEncodeFrameOptionKey_AcknowledgedLTRTokens as String] = [token] } }
        let done = DispatchSemaphore(value: 0); var repair: CMSampleBuffer?; let picture = input[40 % input.count]; let t0 = now(); var t1 = t0
        VTCompressionSessionEncodeFrame(s, imageBuffer: picture, presentationTimeStamp: CMTime(value: 40, timescale: 120), duration: CMTime(value: 1, timescale: 120), frameProperties: options as CFDictionary, infoFlagsOut: nil) { status, flags, sample in
            t1 = now(); if status == noErr, !flags.contains(.frameDropped) { repair = sample }; done.signal()
        }
        done.wait()
        guard let repair else { print("NOTE ltr arm=\(arm) repair frame dropped size=\(w)x\(h) scenario=\(scenario)"); return }
        let sync = (CMSampleBufferGetSampleAttachmentsArray(repair, createIfNecessary: false) as? [[CFString: Any]])?.first?[kCMSampleAttachmentKey_NotSync] as? Bool != true
        let decoded = d.decode(repair)
        var after = Double.nan
        if let next = encodeOne(s, input[41 % input.count], index: 41, key: false), let p = d.decode(next) { after = psnr(p, input[41 % input.count], w, h) }
        print("RESULT kind=ltr arm=\(arm) size=\(w)x\(h) scenario=\(scenario) ltr_tokens_seen=\(tokens) acknowledged=\(token != nil) mean_delta_bytes=\(deltas == 0 ? 0 : deltaBytes / deltas) repair_bytes=\(CMSampleBufferGetTotalSampleSize(repair)) repair_is_keyframe=\(sync) repair_encode_ms=\(f(ms(t1 - t0))) repair_psnr=\(decoded.map { f(psnr($0, picture, w, h)) } ?? "decode_failed") next_delta_psnr=\(f(after))")
        VTCompressionSessionInvalidate(s)
    } } } }
}

// After the settled sharp refresh (a forced keyframe at 4x the bit rate, then the rate restored, as
// SurfaceCapture.drain does), is the next changed picture encoded or dropped by rate control?
if only?.contains("after") == true {
    for (w, h) in [(656, 422), (1520, 1026)] { for refresh in ["keyframe_4x", "none"] { for waitMs in [20, 100, 300, 1000] { autoreleasepool {
        let input = frames(w, h, scenario: "typing", count: FRAMES); let rate = max(500_000, w * h * 3)
        var dropped = 0, encoded = 0, refreshBytes = 0, refreshDropped = 0; var latency: [Double] = []; let trials = quick ? 2 : 4
        for _ in 0..<trials {
            guard let s = session(w, h, Variant()) else { continue }
            var index = 0
            for i in 0..<60 { _ = encodeOne(s, input[i % input.count], index: index, key: i == 0); index += 1; usleep(8000) }
            usleep(250_000)   // the picture settles
            if refresh == "keyframe_4x" {
                VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: rate * 4))
                var sample = encodeOne(s, input[59 % input.count], index: index, key: true); index += 1
                var tries = 0
                while sample == nil && tries < 30 { refreshDropped += 1; usleep(8333); sample = encodeOne(s, input[59 % input.count], index: index, key: true); index += 1; tries += 1 }
                refreshBytes = sample.map { CMSampleBufferGetTotalSampleSize($0) } ?? 0
                VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: rate))
            }
            usleep(UInt32(waitMs * 1000))
            index += max(1, waitMs * 120 / 1000)
            let t0 = now()
            if encodeOne(s, input[60 % input.count], index: index, key: false) != nil { encoded += 1; latency.append(ms(now() - t0)) } else { dropped += 1 }
            VTCompressionSessionInvalidate(s)
        }
        print("RESULT kind=after_refresh size=\(w)x\(h) refresh=\(refresh) wait_ms=\(waitMs) trials=\(trials) next_change_dropped=\(dropped) next_change_encoded=\(encoded) encode_p50_ms=\(f(pct(latency, 0.5))) refresh_bytes=\(refreshBytes) refresh_attempts_dropped=\(refreshDropped)")
    } } } }
}

// What the viewer sees per source tick, low-latency rate control against the ordinary real-time
// mode: a dropped frame leaves the previous picture on screen, and that is what is scored.
if only?.contains("quality") == true {
    let classic = Variant(name: "classic_realtime", lowLatency: false)
    for (w, h) in [(656, 422), (1520, 1026)] { for scenario in ["typing", "scroll"] { for fps in [120, 60] { for v in [Variant(name: "prod"), classic] { autoreleasepool {
        var variant = v; variant.fps = fps
        let input = frames(w, h, scenario: scenario, count: FRAMES)
        guard let s = session(w, h, variant) else { return }
        let d = Decoder(); var shown: CVPixelBuffer?; var shownScore: [Double] = []; var encodedScore: [Double] = []; var bytes = 0; var drops = 0; var latency: [Double] = []
        let interval = tickNs(fps); var next = now(); let total = quick ? 40 : 150
        for i in 0..<total {
            sleepUntil(next); next = max(now(), next) + interval
            let t0 = now(); let sample = encodeOne(s, input[i % input.count], index: i, key: i == 0)
            if let sample { if i >= 30 { latency.append(ms(now() - t0)); bytes += CMSampleBufferGetTotalSampleSize(sample) }
                if let picture = d.decode(sample) { shown = picture; if i >= 30 { encodedScore.append(psnr(picture, input[i % input.count], w, h)) } } }
            else if i >= 30 { drops += 1 }
            if i >= 30, let shown { shownScore.append(psnr(shown, input[i % input.count], w, h)) }
            next = max(now(), next)
        }
        let seconds = Double(total - 30) / Double(fps)
        print("RESULT kind=quality variant=\(v.name) size=\(w)x\(h) scenario=\(scenario) cadence_fps=\(fps) frames=\(total - 30) drops=\(drops) encode_p50_ms=\(f(pct(latency, 0.5))) kbit_s=\(f(Double(bytes) * 8 / 1000 / seconds)) budget_kbit_s=\(max(500_000, w * h * 3) / 1000) psnr_encoded_mean=\(f(encodedScore.reduce(0, +) / Double(max(1, encodedScore.count)))) psnr_shown_mean=\(f(shownScore.reduce(0, +) / Double(max(1, shownScore.count)))) psnr_shown_p05=\(f(pct(shownScore, 0.05)))")
        fflush(stdout); VTCompressionSessionInvalidate(s)
    } } } } }
}

// Typing is sparse: one changed picture, then a gap. Encode time of a frame that follows a gap,
// for the low-latency mode and the ordinary real-time mode.
if only?.contains("sparse") == true {
    for (w, h) in [(656, 422), (1520, 1026)] { for v in [Variant(name: "prod"), Variant(name: "classic_realtime", lowLatency: false)] { autoreleasepool {
        let input = frames(w, h, scenario: "typing", count: FRAMES)
        guard let s = session(w, h, v) else { return }
        var index = 0
        for i in 0..<30 { _ = encodeOne(s, input[i % input.count], index: index, key: i == 0); index += 1; usleep(8000) }
        for gap in quick ? [8, 150] : [8, 50, 150, 500, 1000, 2000] {
            var latency: [Double] = []; var drops = 0; var bytes = 0
            for k in 0..<(quick ? 4 : 8) {
                usleep(UInt32(gap * 1000)); index += max(1, gap * 120 / 1000)
                let t0 = now()
                if let sample = encodeOne(s, input[(30 + k + gap) % input.count], index: index, key: false) { latency.append(ms(now() - t0)); bytes += CMSampleBufferGetTotalSampleSize(sample) } else { drops += 1 }
            }
            print("RESULT kind=sparse variant=\(v.name) size=\(w)x\(h) gap_ms=\(gap) n=\(latency.count) drops=\(drops) p50_ms=\(f(pct(latency, 0.5))) max_ms=\(f(latency.max() ?? .nan)) mean_bytes=\(latency.isEmpty ? 0 : bytes / latency.count)")
            fflush(stdout)
        }
        VTCompressionSessionInvalidate(s)
    } } }
}
print("DONE")
