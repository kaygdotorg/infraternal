/// Role: measure-only inventory of this Mac's VideoToolbox encoders and the cost of each codec/profile on real window pixels [D204,#146].
///
/// Facts for the owner's encoder grill; it chooses nothing. It captures nothing
/// either (no Screen Recording use): frames are built from a decoded PNG of a
/// real captured window, tiled to the requested size. Each configuration uses
/// the companion's production session settings (native/Encoder.swift: low-latency
/// rate control, real time, no reordering, no periodic IDR, w*h*3 bit/s) and
/// changes only codec and profile. One frame is in flight, paced at 60 Hz, like
/// the live path. Prints one JSON object per line.
///
/// Build: swiftc -O encoder-matrix.swift -o encoder-matrix
/// Run:   ./encoder-matrix window.png [WIDTHxHEIGHT ...]
import CoreMedia
import CoreVideo
import Foundation
import ImageIO
import VideoToolbox

func emit(_ value: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    print(String(data: data, encoding: .utf8)!)
}

func fourcc(_ code: UInt32) -> String {
    String(bytes: [24, 16, 8, 0].map { UInt8((code >> $0) & 0xff) }, encoding: .ascii) ?? String(code)
}

func nowNs() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }

func cpuSeconds() -> Double {
    var usage = rusage(); getrusage(RUSAGE_SELF, &usage)
    return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6
}

/// CPU seconds of the out-of-process encoder service(s), where VideoToolbox runs.
func serviceSeconds() -> Double {
    let ps = Process(); ps.executableURL = URL(fileURLWithPath: "/bin/ps")
    // -c prints executable names only; read to EOF before waiting so a full
    // pipe can never block ps (an earlier wait-first version deadlocked).
    ps.arguments = ["-axco", "time=,comm="]
    let pipe = Pipe(); ps.standardOutput = pipe
    try! ps.run()
    let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    ps.waitUntilExit()
    var total = 0.0
    for line in text.split(separator: "\n") where line.hasSuffix("VTEncoderXPCService") {
        let time = line.split(separator: " ", omittingEmptySubsequences: true)[0]
        total += time.split(separator: ":").reduce(0.0) { $0 * 60 + (Double($1) ?? 0) }
    }
    return total
}

setvbuf(stdout, nil, _IOLBF, 0)

// 1. Inventory: every encoder VideoToolbox lists, with its own flags.
var list: CFArray?
VTCopyVideoEncoderList(nil, &list)
for entry in (list as? [[String: Any]]) ?? [] {
    var row: [String: Any] = [:]
    for (key, value) in entry {
        if key == kVTVideoEncoderList_CodecType as String, let code = value as? UInt32 { row[key] = fourcc(code) }
        else if let value = value as? String { row[key] = value }
        else if let value = value as? NSNumber { row[key] = value }
    }
    emit(["kind": "encoder"].merging(row) { a, _ in a })
}

// 2. Source pixels: a real decoded window picture, tiled to each size.
let arguments = CommandLine.arguments
guard arguments.count >= 2, let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: arguments[1]) as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { fatalError("usage: encoder-matrix window.png [WxH ...]") }
let sizes: [(Int, Int)] = arguments.count > 2 ? arguments[2...].map {
    let parts = $0.split(separator: "x").map { Int($0)! }; return (parts[0], parts[1])
} : [(image.width, image.height)]

func canvas(_ width: Int, _ height: Int) -> [UInt8] {
    // Twice the height so scrolling can take any window of it.
    var bytes = [UInt8](repeating: 255, count: width * height * 2 * 4)
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    bytes.withUnsafeMutableBytes { raw in
        let context = CGContext(data: raw.baseAddress, width: width, height: height * 2, bitsPerComponent: 8, bytesPerRow: width * 4,
                                space: space, bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)!
        var y = 0
        while y < height * 2 { var x = 0; while x < width { context.draw(image, in: CGRect(x: x, y: y, width: image.width, height: image.height)); x += image.width }; y += image.height }
    }
    return bytes
}

final class Box { let done = DispatchSemaphore(value: 0); var bytes = 0; var key = false; var status: OSStatus = 0; var dropped = false; var at: UInt64 = 0 }
let callback: VTCompressionOutputCallback = { _, ref, status, flags, sample in
    let box = Unmanaged<Box>.fromOpaque(ref!).takeUnretainedValue()
    box.at = nowNs(); box.status = status; box.dropped = flags.contains(.frameDropped)
    if let sample, let block = CMSampleBufferGetDataBuffer(sample) {
        box.bytes = CMBlockBufferGetDataLength(block)
        let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[CFString: Any]]
        box.key = attachments?.first?[kCMSampleAttachmentKey_NotSync] as? Bool != true
    }
    box.done.signal()
}

func pct(_ values: [Double], _ q: Double) -> Double {
    guard !values.isEmpty else { return -1 }
    let sorted = values.sorted(); return sorted[max(0, min(sorted.count - 1, Int((q * Double(sorted.count)).rounded(.up)) - 1))]
}

struct Config { let name: String; let codec: CMVideoCodecType; let profile: CFString?; let requireHardware: Bool; var lowLatency = true }
var configs = [
    Config(name: "h264-baseline", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_Baseline_AutoLevel, requireHardware: true),
    Config(name: "h264-constrained-baseline", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel, requireHardware: true),
    Config(name: "h264-main", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_Main_AutoLevel, requireHardware: true),
    Config(name: "h264-high", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_High_AutoLevel, requireHardware: true),
    Config(name: "h264-constrained-high", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_ConstrainedHigh_AutoLevel, requireHardware: true),
    Config(name: "h264-default(production)", codec: kCMVideoCodecType_H264, profile: nil, requireHardware: true),
    Config(name: "hevc-main", codec: kCMVideoCodecType_HEVC, profile: kVTProfileLevel_HEVC_Main_AutoLevel, requireHardware: true),
    Config(name: "hevc-default(production --hevc)", codec: kCMVideoCodecType_HEVC, profile: nil, requireHardware: true),
    Config(name: "h264-high-software-allowed", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_High_AutoLevel, requireHardware: false),
    Config(name: "hevc-main-software-allowed", codec: kCMVideoCodecType_HEVC, profile: kVTProfileLevel_HEVC_Main_AutoLevel, requireHardware: false),
]
// Without the low-latency rate-control specification VideoToolbox selects a
// different encoder (the listed hardware family); measured for comparison only.
configs.append(Config(name: "h264-high-no-lowlatency-rc", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_High_AutoLevel, requireHardware: true, lowLatency: false))
configs.append(Config(name: "h264-baseline-no-lowlatency-rc", codec: kCMVideoCodecType_H264, profile: kVTProfileLevel_H264_Baseline_AutoLevel, requireHardware: true, lowLatency: false))
configs.append(Config(name: "hevc-main-no-lowlatency-rc", codec: kCMVideoCodecType_HEVC, profile: kVTProfileLevel_HEVC_Main_AutoLevel, requireHardware: true, lowLatency: false))
// AV1 has no SDK constant on every toolchain; use its four-character code.
let av1: CMVideoCodecType = 0x6176_3031 // 'av01'
configs.append(Config(name: "av1-hardware", codec: av1, profile: nil, requireHardware: true))
configs.append(Config(name: "av1-software-allowed", codec: av1, profile: nil, requireHardware: false))

for (width, height) in sizes {
    let pixels = canvas(width, height)
    for config in configs {
        var spec: [String: Any] = [:]
        if config.lowLatency { spec[kVTVideoEncoderSpecification_EnableLowLatencyRateControl as String] = true }
        if config.requireHardware { spec[kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String] = true }
        var session: VTCompressionSession?
        let created = VTCompressionSessionCreate(allocator: nil, width: Int32(width), height: Int32(height), codecType: config.codec,
            encoderSpecification: spec as CFDictionary, imageBufferAttributes: nil, compressedDataAllocator: nil,
            outputCallback: callback, refcon: nil, compressionSessionOut: &session)
        var row: [String: Any] = ["kind": "config", "config": config.name, "width": width, "height": height, "create_status": Int(created)]
        guard created == noErr, let session else { emit(row); continue }
        func set(_ key: CFString, _ value: CFTypeRef) -> Int { Int(VTSessionSetProperty(session, key: key, value: value)) }
        var statuses: [String: Int] = [:]
        statuses["RealTime"] = set(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        statuses["AllowFrameReordering"] = set(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
        statuses["MaxKeyFrameInterval"] = set(kVTCompressionPropertyKey_MaxKeyFrameInterval, NSNumber(value: Int32.max))
        statuses["ExpectedFrameRate"] = set(kVTCompressionPropertyKey_ExpectedFrameRate, NSNumber(value: 60))
        statuses["AverageBitRate"] = set(kVTCompressionPropertyKey_AverageBitRate, NSNumber(value: max(500_000, width * height * 3)))
        if let profile = config.profile { statuses["ProfileLevel"] = set(kVTCompressionPropertyKey_ProfileLevel, profile) }
        row["property_status"] = statuses
        row["prepare_status"] = Int(VTCompressionSessionPrepareToEncodeFrames(session))
        var value: CFTypeRef?
        let hardwareStatus = withUnsafeMutablePointer(to: &value) { VTSessionCopyProperty(session, key: kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder, allocator: nil, valueOut: $0) }
        row["using_hardware"] = hardwareStatus == noErr ? (value as? Bool ?? false) as Any : "unreported(\(hardwareStatus))"
        var encoderID: CFTypeRef?
        if withUnsafeMutablePointer(to: &encoderID, { VTSessionCopyProperty(session, key: kVTCompressionPropertyKey_EncoderID, allocator: nil, valueOut: $0) }) == noErr {
            row["encoder_id"] = encoderID as? String ?? ""
        }
        var profileValue: CFTypeRef?
        if withUnsafeMutablePointer(to: &profileValue, { VTSessionCopyProperty(session, key: kVTCompressionPropertyKey_ProfileLevel, allocator: nil, valueOut: $0) }) == noErr {
            row["profile_reported"] = profileValue as? String ?? ""
        }
        var buffer: CVPixelBuffer?
        CVPixelBufferCreate(nil, width, height, kCVPixelFormatType_32BGRA, [kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary, &buffer)
        let pixel = buffer!
        // Workloads: first IDR, static repeats, typing-size damage, full-content scroll.
        var results: [String: Any] = [:]
        var firstFrameMs = 0.0
        for (workload, count) in [("first", 1), ("static", 60), ("typing", 120), ("scroll", 120)] {
            var latencies: [Double] = [], sizesOut: [Int] = [], keys = 0, drops = 0, failures = 0
            let cpu0 = cpuSeconds(), service0 = serviceSeconds(), wall0 = nowNs()
            for index in 0..<count {
                CVPixelBufferLockBaseAddress(pixel, [])
                let base = CVPixelBufferGetBaseAddress(pixel)!, stride = CVPixelBufferGetBytesPerRow(pixel)
                let offset = workload == "scroll" ? (index * 8) % height : 0
                pixels.withUnsafeBytes { raw in
                    for row in 0..<height { base.advanced(by: row * stride).copyMemory(from: raw.baseAddress!.advanced(by: (row + offset) * width * 4), byteCount: width * 4) }
                }
                if workload == "typing" {
                    // One glyph-sized cell changes per frame, advancing like a caret.
                    let cellX = 12 + (index % 60) * 9, cellY = 40 + (index / 60) * 16
                    for row in cellY..<min(height, cellY + 14) {
                        let line = base.advanced(by: row * stride + min(cellX, width - 8) * 4).assumingMemoryBound(to: UInt8.self)
                        for column in 0..<(8 * 4) where column % 4 != 3 { line[column] = UInt8((index * 37 + column) & 0x7f) }
                    }
                }
                CVPixelBufferUnlockBaseAddress(pixel, [])
                let box = Box(); let ref = Unmanaged.passRetained(box).toOpaque()
                let submitted = nowNs()
                let options = workload == "first" ? [kVTEncodeFrameOptionKey_ForceKeyFrame as String: true] as CFDictionary : nil
                let status = VTCompressionSessionEncodeFrame(session, imageBuffer: pixel, presentationTimeStamp: CMTime(value: Int64(submitted), timescale: 1_000_000_000),
                                                             duration: CMTime(value: 1, timescale: 60), frameProperties: options, sourceFrameRefcon: ref, infoFlagsOut: nil)
                if status != noErr || box.done.wait(timeout: .now() + 2) != .success || box.status != noErr { failures += 1 }
                else if box.dropped { drops += 1 }
                else { latencies.append(Double(box.at - submitted) / 1e6); sizesOut.append(box.bytes); if box.key { keys += 1 } }
                Unmanaged<Box>.fromOpaque(ref).release()
                // Pace like a 60 Hz source; one frame in flight.
                let next = submitted + 16_666_667
                while nowNs() < next { usleep(500) }
            }
            let wall = Double(nowNs() - wall0) / 1e9
            if workload == "first" { firstFrameMs = latencies.first ?? -1; continue }
            results[workload] = ["frames": count, "encoded": latencies.count, "dropped": drops, "failed": failures, "keyframes": keys,
                                 "latency_ms_p50": pct(latencies, 0.5), "latency_ms_p95": pct(latencies, 0.95), "latency_ms_p99": pct(latencies, 0.99),
                                 "bytes_mean": sizesOut.isEmpty ? 0 : sizesOut.reduce(0, +) / sizesOut.count, "kbit_per_s_at_60fps": Double(sizesOut.reduce(0, +)) * 8 / 1000 / (Double(count) / 60),
                                 "cpu_percent_self": (cpuSeconds() - cpu0) / wall * 100, "cpu_percent_encoder_service": (serviceSeconds() - service0) / wall * 100]
        }
        row["first_idr_ms"] = firstFrameMs
        row["workloads"] = results
        VTCompressionSessionInvalidate(session)
        emit(row)
    }
}
