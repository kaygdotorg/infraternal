// J1115 measurement probe (not product code): which VideoToolbox rate-control mode and data-rate
// cap the App Windows encoder should use, and how the settled sharp refresh should be sent (#146).
//
// It builds the same session as crates/plugins/desktop/native/Encoder.swift in both modes:
// "lowlat" (EnableLowLatencyRateControl, the mode before J1115) and "realtime" (the ordinary
// real-time mode), the latter with and without DataRateLimits caps. Every encoded sample is kept
// and decoded after the timed loop, so scoring never disturbs the source cadence. A dropped frame
// leaves the previous decoded picture on screen, and that is what "shown" PSNR scores.
//
// Sections (ONLY=a,b to pick; default all):
//   mode     steady 120/60 Hz typing and scrolling: encode p50/p95/p99, drops, kbit/s, worst frame
//   sparse   one typed change after a gap: encode time and bytes
//   refine   after a pause: forced keyframe at 4x (before J1115) against delta passes at 2x/4x,
//            after typing, after scrolling, and after a lone motion keyframe ("static")
// Lines that start with RESULT are measurements; NOTE lines report a property the encoder refused.
import CoreMedia
import CoreVideo
import Foundation
import VideoToolbox

var timebase = mach_timebase_info_data_t(); mach_timebase_info(&timebase)
/// Milliseconds for a `mach_absolute_time` span.
func ms(_ ticks: UInt64) -> Double { Double(ticks) * Double(timebase.numer) / Double(timebase.denom) / 1e6 }
/// The monotonic clock in ticks.
func now() -> UInt64 { mach_absolute_time() }
/// Ticks per source frame at `fps`.
func tick(_ fps: Int) -> UInt64 { UInt64(1e9 / Double(fps) * Double(timebase.denom) / Double(timebase.numer)) }
/// Nearest-rank percentile of `values` (unsorted); NaN when empty.
func pct(_ values: [Double], _ p: Double) -> Double {
    guard !values.isEmpty else { return .nan }
    let s = values.sorted(); return s[min(s.count - 1, Int((Double(s.count) * p).rounded(.down)))]
}
/// Three decimals.
func f(_ v: Double) -> String { String(format: "%.3f", v) }
let env = ProcessInfo.processInfo.environment
let quick = env["QUICK"] != nil
/// True when the section was asked for (or no section was named).
func want(_ section: String) -> Bool { env["ONLY"].map { $0.split(separator: ",").contains(Substring(section)) } ?? true }

/// Deterministic xorshift so every run and every arm sees the same pictures.
struct RNG { var s: UInt64; mutating func next() -> UInt64 { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s } }
/// A UI-like BGRA picture: a toolbar gradient and rows of glyph-like dark marks on white (as J1078).
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
            x += gw + 2 + (r.next() % 9 == 0 ? 8 : 0)
        }
        y += 20
    }
    return p
}
/// An IOSurface-backed pixel buffer, as the capture framework hands out.
func buffer(_ w: Int, _ h: Int) -> CVPixelBuffer {
    var out: CVPixelBuffer?
    precondition(CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, [kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary, &out) == kCVReturnSuccess)
    return out!
}
/// Copies rows into `pixel`; `rows` returns the source of each row.
func fill(_ pixel: CVPixelBuffer, _ w: Int, _ h: Int, rows: (Int) -> UnsafeRawPointer) {
    CVPixelBufferLockBaseAddress(pixel, []); let base = CVPixelBufferGetBaseAddress(pixel)!; let stride = CVPixelBufferGetBytesPerRow(pixel)
    for row in 0..<h { base.advanced(by: row * stride).copyMemory(from: rows(row), byteCount: w * 4) }
    CVPixelBufferUnlockBaseAddress(pixel, [])
}
/// A deterministic picture sequence, made on demand into a ring of three buffers so a long run
/// never holds more than three pictures (a 4 MP sequence would otherwise need gigabytes).
/// typing: one more glyph-sized mark per picture, left to right along text lines. scroll: the
/// text area moves up 8 px per picture. Two sources with the same arguments yield the same
/// pictures, which is how scoring regenerates what was encoded. A returned buffer stays valid
/// until two more pictures have been taken.
final class Source {
    let w: Int, h: Int, scenario: String
    private var base: [UInt8]; private var r = RNG(s: 42); private var k = 0
    private let ring: [CVPixelBuffer]
    init(_ w: Int, _ h: Int, _ scenario: String) {
        self.w = w; self.h = h; self.scenario = scenario; base = basePicture(w, h)
        ring = (0..<3).map { _ in buffer(w, h) }
    }
    /// The next picture of the sequence.
    func next() -> CVPixelBuffer {
        let pixel = ring[k % 3]
        if scenario == "typing" {
            let perLine = max(1, (w - 64) / 9)
            let gx = 16 + (k % perLine) * 9, gy = min(h - 16, 80 + 20 * ((h - 100) / 40) + 20 * (k / perLine))
            for yy in 0..<12 { for xx in 0..<7 where r.next() % 3 != 0 { let i = ((gy + yy) * w + gx + xx) * 4; base[i] = 20; base[i+1] = 20; base[i+2] = 20 } }
            base.withUnsafeBytes { b in fill(pixel, w, h) { b.baseAddress!.advanced(by: $0 * w * 4) } }
        } else {
            let top = min(80, h), span = h - top, shift = (k * 8) % max(1, span)
            base.withUnsafeBytes { b in fill(pixel, w, h) { row in
                row < top ? b.baseAddress!.advanced(by: row * w * 4) : b.baseAddress!.advanced(by: (top + (row - top + shift) % span) * w * 4)
            } }
        }
        k += 1
        return pixel
    }
}

/// One encoder configuration under test. `cap` is DataRateLimits as (multiple of the average
/// bytes per second, window seconds) pairs; empty means no cap.
struct Arm { var name: String; var lowLatency: Bool; var cap: [(Double, Double)] = [] }
/// The product's motion budget for a picture size, in bits per second (Encoder.configure).
func budget(_ w: Int, _ h: Int) -> Int { max(500_000, w * h * 3) }
/// DataRateLimits for `arm` at `bitsPerSecond`: alternating byte counts and window seconds.
func limits(_ arm: Arm, _ bitsPerSecond: Int) -> CFArray {
    arm.cap.flatMap { [NSNumber(value: Double(bitsPerSecond) / 8 * $0.0 * $0.1), NSNumber(value: $0.1)] } as CFArray
}
/// The session of Encoder.configure (same properties, same order) for `arm`.
func session(_ w: Int, _ h: Int, _ arm: Arm, fps: Int) -> VTCompressionSession? {
    var spec: [String: Any] = [kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String: true]
    if arm.lowLatency { spec[kVTVideoEncoderSpecification_EnableLowLatencyRateControl as String] = true }
    var s: VTCompressionSession?
    let created = VTCompressionSessionCreate(allocator: kCFAllocatorDefault, width: Int32(w), height: Int32(h), codecType: kCMVideoCodecType_H264,
        encoderSpecification: spec as CFDictionary, imageBufferAttributes: nil, compressedDataAllocator: nil, outputCallback: nil, refcon: nil, compressionSessionOut: &s)
    guard created == noErr, let s else { print("NOTE create_failed arm=\(arm.name) size=\(w)x\(h) status=\(created)"); return nil }
    func set(_ k: CFString, _ value: CFTypeRef) { let st = VTSessionSetProperty(s, key: k, value: value); if st != noErr { print("NOTE property=\(k) status=\(st) arm=\(arm.name)") } }
    set(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
    set(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
    set(kVTCompressionPropertyKey_ColorPrimaries, kCVImageBufferColorPrimaries_ITU_R_709_2)
    set(kVTCompressionPropertyKey_TransferFunction, kCVImageBufferTransferFunction_sRGB)
    set(kVTCompressionPropertyKey_YCbCrMatrix, kCVImageBufferYCbCrMatrix_ITU_R_709_2)
    set(kVTCompressionPropertyKey_MaxKeyFrameInterval, NSNumber(value: Int32.max))
    set(kVTCompressionPropertyKey_ExpectedFrameRate, NSNumber(value: fps))
    set(kVTCompressionPropertyKey_AverageBitRate, NSNumber(value: budget(w, h)))
    if !arm.cap.isEmpty { set(kVTCompressionPropertyKey_DataRateLimits, limits(arm, budget(w, h))) }
    guard VTCompressionSessionPrepareToEncodeFrames(s) == noErr else { print("NOTE prepare_failed arm=\(arm.name)"); return nil }
    return s
}
/// Sets the average rate (and the cap scaled with it), as the product does per frame.
func rate(_ s: VTCompressionSession, _ arm: Arm, _ bitsPerSecond: Int) {
    VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: bitsPerSecond))
    if !arm.cap.isEmpty { VTSessionSetProperty(s, key: kVTCompressionPropertyKey_DataRateLimits, value: limits(arm, bitsPerSecond)) }
}
/// Encodes one picture with one frame in flight, as production does; returns the sample (nil when
/// dropped) and the time from submit to callback. Timestamps follow the real clock, as in Encoder.
func encode(_ s: VTCompressionSession, _ pixel: CVPixelBuffer, key: Bool, fps: Int) -> (CMSampleBuffer?, Double) {
    let done = DispatchSemaphore(value: 0); var out: CMSampleBuffer?
    let options = key ? [kVTEncodeFrameOptionKey_ForceKeyFrame as String: true] as CFDictionary : nil
    let t0 = now(); var t1 = t0
    let pts = CMTime(value: Int64(ms(t0) * 1e6), timescale: 1_000_000_000)
    let st = VTCompressionSessionEncodeFrame(s, imageBuffer: pixel, presentationTimeStamp: pts, duration: CMTime(value: 1, timescale: Int32(fps)), frameProperties: options, infoFlagsOut: nil) { status, flags, sample in
        t1 = now(); if status == noErr, !flags.contains(.frameDropped) { out = sample }; done.signal()
    }
    if st != noErr { return (nil, 0) }
    done.wait(); return (out, ms(t1 - t0))
}
/// A software-visible VideoToolbox decoder producing BGRA, for scoring.
final class Decoder {
    var session: VTDecompressionSession?
    /// Decodes one sample synchronously; nil when it cannot.
    func decode(_ sample: CMSampleBuffer) -> CVPixelBuffer? {
        if session == nil, let format = CMSampleBufferGetFormatDescription(sample) {
            VTDecompressionSessionCreate(allocator: nil, formatDescription: format, decoderSpecification: nil, imageBufferAttributes: [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA] as CFDictionary, outputCallback: nil, decompressionSessionOut: &session)
        }
        guard let session else { return nil }
        var picture: CVPixelBuffer?
        VTDecompressionSessionDecodeFrame(session, sampleBuffer: sample, flags: [], infoFlagsOut: nil) { _, _, image, _, _ in picture = image }
        VTDecompressionSessionWaitForAsynchronousFrames(session)
        return picture
    }
    deinit { if let session { VTDecompressionSessionInvalidate(session) } }
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
/// Bytes of a sample.
func size(_ s: CMSampleBuffer) -> Int { CMSampleBufferGetTotalSampleSize(s) }
/// Sleeps until the absolute tick `deadline`.
func sleepUntil(_ deadline: UInt64) { if deadline > now() { mach_wait_until(deadline) } }

let arms: [Arm] = [
    Arm(name: "lowlat", lowLatency: true),
    Arm(name: "realtime", lowLatency: false),
    Arm(name: "realtime_cap1s_1.5x", lowLatency: false, cap: [(1.5, 1)]),
    Arm(name: "realtime_cap1s_1x", lowLatency: false, cap: [(1.0, 1)]),
    Arm(name: "realtime_cap1s_1.5x_100ms_3x", lowLatency: false, cap: [(1.5, 1), (3.0, 0.1)]),
]
let chosen = env["ARMS"].map { names in arms.filter { names.split(separator: ",").contains(Substring($0.name)) } } ?? arms
var host = [CChar](repeating: 0, count: 256); var hostSize = 256; sysctlbyname("hw.model", &host, &hostSize, nil, 0)
print("INFO model=\(String(cString: host)) os=\(ProcessInfo.processInfo.operatingSystemVersionString) cores=\(ProcessInfo.processInfo.activeProcessorCount) thermal=\(ProcessInfo.processInfo.thermalState.rawValue) low_power=\(ProcessInfo.processInfo.isLowPowerModeEnabled) arms=\(chosen.map(\.name).joined(separator: ","))")
let sizes = quick ? [(1520, 1026)] : [(656, 422), (1520, 1026), (2560, 1600)]
let FRAMES = 160, WARM = 30

// Steady cadence: one source picture per tick, one frame in flight.
if want("mode") {
    for (w, h) in sizes { for scenario in ["typing", "scroll"] { autoreleasepool {
        for fps in [120, 60] { for arm in chosen { autoreleasepool {
            let source = Source(w, h, scenario)
            guard let s = session(w, h, arm, fps: fps) else { return }
            var samples: [CMSampleBuffer?] = []; var latency: [Double] = []
            var next = now(); let interval = tick(fps); let total = (quick ? 60 : FRAMES) + WARM
            for i in 0..<total {
                sleepUntil(next); next = max(now(), next) + interval
                let (sample, took) = encode(s, source.next(), key: i == 0, fps: fps)
                samples.append(sample)
                if i >= WARM, sample != nil { latency.append(took) }
            }
            VTCompressionSessionInvalidate(s)
            // Score after timing. The warm-up frames are decoded too (they hold the keyframe the
            // later deltas reference) but only the timed frames are counted.
            let d = Decoder(); let truth = Source(w, h, scenario); var shown: CVPixelBuffer?; var shownScore: [Double] = []; var bytes = 0; var worst = 0; var drops = 0
            for (k, sample) in samples.enumerated() {
                let picture = truth.next()
                if let sample, let p = d.decode(sample) { shown = p }
                guard k >= WARM else { continue }
                if let sample { bytes += size(sample); worst = max(worst, size(sample)) } else { drops += 1 }
                if let shown { shownScore.append(psnr(shown, picture, w, h)) }
            }
            let counted = samples.count - WARM, seconds = Double(counted) / Double(fps)
            print("RESULT kind=mode arm=\(arm.name) size=\(w)x\(h) scenario=\(scenario) fps=\(fps) frames=\(counted) drops=\(drops) p50_ms=\(f(pct(latency, 0.5))) p95_ms=\(f(pct(latency, 0.95))) p99_ms=\(f(pct(latency, 0.99))) kbit_s=\(f(Double(bytes) * 8 / 1000 / seconds)) budget_kbit_s=\(budget(w, h) / 1000) worst_frame_bytes=\(worst) psnr_shown_mean=\(f(shownScore.reduce(0, +) / Double(max(1, shownScore.count)))) psnr_shown_p05=\(f(pct(shownScore, 0.05)))")
            fflush(stdout)
        } } }
    } } }
}

// Typing is sparse: one changed picture, then a gap. Time and bytes of the frame after the gap.
if want("sparse") {
    for (w, h) in sizes.filter({ $0.0 < 2000 }) { for arm in chosen { autoreleasepool {
        let source = Source(w, h, "typing")
        guard let s = session(w, h, arm, fps: 120) else { return }
        for i in 0..<30 { _ = encode(s, source.next(), key: i == 0, fps: 120); usleep(8333) }
        for gap in quick ? [150] : [50, 150, 500, 1000, 2000] {
            var latency: [Double] = []; var drops = 0; var bytes: [Int] = []
            for _ in 0..<(quick ? 4 : 8) {
                usleep(UInt32(gap * 1000))
                let (sample, took) = encode(s, source.next(), key: false, fps: 120)
                if let sample { latency.append(took); bytes.append(size(sample)) } else { drops += 1 }
            }
            print("RESULT kind=sparse arm=\(arm.name) size=\(w)x\(h) gap_ms=\(gap) n=\(latency.count) drops=\(drops) p50_ms=\(f(pct(latency, 0.5))) max_ms=\(f(latency.max() ?? .nan)) mean_bytes=\(bytes.isEmpty ? 0 : bytes.reduce(0, +) / bytes.count) max_bytes=\(bytes.max() ?? 0)")
            fflush(stdout)
        }
        VTCompressionSessionInvalidate(s)
    } } }
}

// After a pause: what the settled picture costs to sharpen. The prefix is 60 pictures of typing
// (small changes) or scrolling (heavy motion) at 120 Hz, or one keyframe at the motion budget; then the picture holds still for 250 ms
// and is sent again either as one forced keyframe at 4x the rate (the refresh before J1115) or as
// up to 8 delta passes at 4x, one per source tick. Every pass is decoded and scored.
if want("refine") {
    for (w, h) in sizes.filter({ $0.0 < 2000 }) { for scenario in ["typing", "scroll", "static"] { for arm in chosen { for plan in ["keyframe_4x", "delta_4x", "delta_2x"] { autoreleasepool {
        // static: one keyframe at the motion budget and nothing else (startup, resize, repair).
        let source = Source(w, h, scenario == "static" ? "typing" : scenario)
        let prefix = scenario == "static" ? 1 : 60
        guard let s = session(w, h, arm, fps: 120) else { return }
        let d = Decoder(); var next = now(); var before = Double.nan; var prefixBytes = 0
        var settled = source.next()
        for i in 0..<prefix {
            sleepUntil(next); next = max(now(), next) + tick(120)
            if i > 0 { settled = source.next() }
            let (sample, _) = encode(s, settled, key: i == 0, fps: 120)
            if let sample { if i > 0 { prefixBytes += size(sample) }; if let p = d.decode(sample), i == prefix - 1 { before = psnr(p, settled, w, h) } }
        }
        usleep(250_000)
        let factor = plan == "delta_2x" ? 2 : 4
        rate(s, arm, budget(w, h) * factor)
        var line = "RESULT kind=refine arm=\(arm.name) plan=\(plan) size=\(w)x\(h) scenario=\(scenario) prefix_bytes=\(prefixBytes) psnr_before=\(f(before))"
        var total = 0; var encodeMs: [Double] = []
        for k in 1...(plan == "keyframe_4x" ? 1 : 8) {
            let (sample, took) = encode(s, settled, key: plan == "keyframe_4x", fps: 120)
            guard let sample else { line += " k\(k)=dropped"; usleep(8333); continue }
            total += size(sample); encodeMs.append(took)
            let score = d.decode(sample).map { psnr($0, settled, w, h) } ?? .nan
            line += " k\(k)_bytes=\(total) k\(k)_psnr=\(f(score))"
            usleep(8333)
        }
        rate(s, arm, budget(w, h))
        line += " encode_p50_ms=\(f(pct(encodeMs, 0.5)))"
        if scenario == "typing" {
            // The next typed letter after the refinement: is it encoded, and how big is it?
            let (after, afterMs) = encode(s, source.next(), key: false, fps: 120)
            line += " next_change_bytes=\(after.map(size) ?? -1) next_change_ms=\(f(afterMs))"
        }
        print(line); fflush(stdout)
        VTCompressionSessionInvalidate(s)
    } } } } }
}
print("DONE")
