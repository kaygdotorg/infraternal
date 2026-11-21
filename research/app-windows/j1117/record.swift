/// Role: flicker-proof recorder for the App Windows tile lane: drive the product's own capture pipeline with known pictures and keep every packet [#146 proposal C].
///
/// Compile together with the product's native sources (see README.md), then run
/// `record <out-dir> <width> <height>`. It needs no capture permission: it renders deterministic editor-like pictures with
/// CoreText into IOSurface-backed buffers and hands them to `SurfaceCapture.receiveFrame`, the same handoff ScreenCaptureKit
/// uses, so the product's real mailbox, exact-pixel history, tile lane and hardware encoder decide every packet.
///
/// Scenarios, in this order: `typing` (160 characters, 60 ms apart), `blink` (an idle caret for 3 s), `scroll` (90 frames
/// at 60 Hz, 6 px each), `mixed` (typing every 50 ms with a 60 Hz spinner, a 10 Hz clock and a one-line scroll every 7th
/// key) and `burst` (30 times: a scroll, then a key 3 ms later, so a tile arrives right behind a video frame).
///
/// Output in `<out-dir>`:
/// - `packets.bin`: every kind-70 body as sent, `t_ns u64be | length u32be | body`, where `t_ns` is when it was sent;
/// - `source.bin`: `"J1117SRC" | width u32be | height u32be | count u32be`, then per frame `capture_ns u64be | length u32be |
///   raw-DEFLATE BGRA rows`, written in a second pass that re-renders each recorded state and checks it against a hash taken
///   live, so the file holds exactly the pictures the pipeline saw;
/// - `manifest.json`: scenario names with their first and last capture stamps.
/// The product's METRIC lines (with `INFRATERNAL_DESKTOP_MEASURE=1`) go to standard error.
import AppKit
import Compression
import CoreMedia
import CoreText
import CoreVideo
import Foundation

/// The product's native sources throw this; the companion's main.swift normally defines it.
enum HelperFailure: Error { case invalid, permission, unavailable }

/// Everything one picture shows. Rendering a state twice gives the same pixels.
struct Scene {
    /// Document lines, top to bottom.
    var lines: [String] = [""]
    /// Pixels the document is scrolled up by.
    var scroll = 0
    /// True while the caret is drawn.
    var caret = true
    /// Spinner position, 0..<12, or -1 for no spinner.
    var spinner = -1
    /// Clock text in the status bar, empty for none.
    var clock = ""
}

/// Draws `Scene`s into BGRA buffers.
final class Renderer {
    let width: Int, height: Int
    let font = CTFontCreateWithName("Menlo" as CFString, 13, nil)
    let lineHeight = 17
    let margin = 12
    let statusHeight = 22
    private let color = CGColorSpace(name: CGColorSpace.sRGB)!
    init(width: Int, height: Int) { self.width = width; self.height = height }

    /// One text line as a CoreText line in `rgb` colour.
    private func line(_ text: String, _ rgb: CGColor) -> CTLine {
        let attributes: [NSAttributedString.Key: Any] = [.init(kCTFontAttributeName as String): font, .init(kCTForegroundColorAttributeName as String): rgb]
        return CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attributes))
    }

    /// Renders `scene` into `pixel` (locked here). Top-left origin in scene terms; CoreGraphics is bottom-left.
    func render(_ scene: Scene, into pixel: CVPixelBuffer) {
        CVPixelBufferLockBaseAddress(pixel, [])
        defer { CVPixelBufferUnlockBaseAddress(pixel, []) }
        let context = CGContext(data: CVPixelBufferGetBaseAddress(pixel), width: width, height: height, bitsPerComponent: 8,
                                bytesPerRow: CVPixelBufferGetBytesPerRow(pixel), space: color,
                                bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)!
        context.setFillColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let ink = CGColor(srgbRed: 0.1, green: 0.1, blue: 0.12, alpha: 1)
        let textTop = margin
        let visibleBottom = height - statusHeight
        for (index, text) in scene.lines.enumerated() {
            let top = textTop + index * lineHeight - scene.scroll
            if top + lineHeight < 0 || top > visibleBottom { continue }
            context.saveGState()
            context.clip(to: CGRect(x: 0, y: statusHeight, width: width, height: height - statusHeight))
            context.textPosition = CGPoint(x: margin, y: height - top - 13)
            CTLineDraw(line(text, ink), context)
            context.restoreGState()
        }
        if scene.caret, let last = scene.lines.last {
            let advance = CTLineGetTypographicBounds(line(last, ink), nil, nil, nil)
            let top = textTop + (scene.lines.count - 1) * lineHeight - scene.scroll
            if top >= 0 && top + lineHeight <= visibleBottom {
                context.setFillColor(ink)
                context.fill(CGRect(x: Double(margin) + advance, y: Double(height - top - lineHeight + 1), width: 2, height: 15))
            }
        }
        // Status bar: a grey strip with the clock and the spinner.
        context.setFillColor(CGColor(srgbRed: 0.93, green: 0.93, blue: 0.95, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: statusHeight))
        if !scene.clock.isEmpty {
            context.textPosition = CGPoint(x: margin, y: 6)
            CTLineDraw(line(scene.clock, ink), context)
        }
        if scene.spinner >= 0 {
            let center = CGPoint(x: Double(width - 16), y: 11)
            for spoke in 0..<12 {
                let angle = Double(spoke) * .pi / 6
                let shade = Double((spoke - scene.spinner + 12) % 12) / 12
                context.setStrokeColor(CGColor(srgbRed: shade, green: shade, blue: shade, alpha: 1))
                context.setLineWidth(2)
                context.move(to: CGPoint(x: center.x + 3 * cos(angle), y: center.y + 3 * sin(angle)))
                context.addLine(to: CGPoint(x: center.x + 8 * cos(angle), y: center.y + 8 * sin(angle)))
                context.strokePath()
            }
        }
    }

    /// FNV-1a over the visible bytes, to prove the second pass re-renders the same pictures.
    func hash(_ pixel: CVPixelBuffer) -> UInt64 {
        CVPixelBufferLockBaseAddress(pixel, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixel, .readOnly) }
        let base = CVPixelBufferGetBaseAddress(pixel)!, stride = CVPixelBufferGetBytesPerRow(pixel)
        var value: UInt64 = 0xcbf29ce484222325
        for row in 0..<height {
            let words = base.advanced(by: row * stride).assumingMemoryBound(to: UInt64.self)
            for index in 0..<(width / 2) { value = (value ^ words[index]) &* 0x100000001b3 }
        }
        return value
    }

    /// The picture's visible rows, packed.
    func packed(_ pixel: CVPixelBuffer) -> [UInt8] {
        CVPixelBufferLockBaseAddress(pixel, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixel, .readOnly) }
        let base = CVPixelBufferGetBaseAddress(pixel)!, stride = CVPixelBufferGetBytesPerRow(pixel)
        var out = [UInt8](repeating: 0, count: width * height * 4)
        out.withUnsafeMutableBytes { destination in
            for row in 0..<height { destination.baseAddress!.advanced(by: row * width * 4).copyMemory(from: base.advanced(by: row * stride), byteCount: width * 4) }
        }
        return out
    }
}

/// Appends a big-endian integer of `bytes` bytes.
func append(_ data: inout Data, _ value: UInt64, _ bytes: Int) {
    for shift in stride(from: (bytes - 1) * 8, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) }
}

@main struct Record {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 4, let width = Int(arguments[2]), let height = Int(arguments[3]) else {
            fputs("usage: record <out-dir> <width> <height>\n", stderr); exit(2)
        }
        let out = URL(fileURLWithPath: arguments[1])
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let renderer = Renderer(width: width, height: height)
        let lock = NSLock()
        var packets = Data()
        var errors = 0
        let source = SurfaceCapture(target: [:], rect: CGRect(x: 0, y: 0, width: width, height: height),
                                    size: CGSize(width: width, height: height), hevc: false, fps: 60) { kind, body in
            lock.withLock {
                guard kind == 70 else { errors += 1; return }
                append(&packets, nanos(mach_absolute_time()), 8); append(&packets, UInt64(body.count), 4); packets.append(body)
            }
        }
        var pool: CVPixelBufferPool?
        let attributes = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA, kCVPixelBufferWidthKey as String: width,
                          kCVPixelBufferHeightKey as String: height, kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary
        guard CVPixelBufferPoolCreate(kCFAllocatorDefault, nil, attributes, &pool) == kCVReturnSuccess, let pool else { fputs("pool\n", stderr); exit(1) }
        var frames: [(UInt64, Scene, UInt64)] = []
        var scenarios: [(String, UInt64, UInt64)] = []
        var scene = Scene()
        let damage = [CGRect(x: 0, y: 0, width: width, height: height).dictionaryRepresentation]
        let start = ProcessInfo.processInfo.systemUptime
        var clock = 0.0
        /// Shows `scene` after waiting until `at` seconds into the run (an absolute schedule, so render time does not drift it).
        func show(at time: Double) {
            let wait = start + time - ProcessInfo.processInfo.systemUptime
            if wait > 0 { Thread.sleep(forTimeInterval: wait) }
            var pixel: CVPixelBuffer?
            guard CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &pixel) == kCVReturnSuccess, let pixel else { fputs("buffer\n", stderr); exit(1) }
            renderer.render(scene, into: pixel)
            let ticks = mach_absolute_time()
            frames.append((nanos(ticks), scene, renderer.hash(pixel)))
            source.receiveFrame(pixel, ticks: ticks, damage: damage)
        }
        /// Runs one named scenario and records its first and last capture stamps.
        func scenario(_ name: String, _ body: () -> Void) {
            let first = frames.count
            body()
            scenarios.append((name, frames[first].0, frames.last!.0))
            clock += 0.6
        }
        let text = Array("The quick brown fox jumps over the lazy dog; pack my box with five dozen liquor jugs. 0123456789 ")
        /// Types one character, wrapping lines at 70 characters.
        func type(_ index: Int) {
            if scene.lines[scene.lines.count - 1].count >= 70 { scene.lines.append("") }
            scene.lines[scene.lines.count - 1].append(text[index % text.count])
        }
        // Startup picture, then let the first keyframe and its sharp refresh settle.
        show(at: clock); clock += 0.6
        scenario("typing") { for i in 0..<160 { type(i); scene.caret = true; clock += 0.06; show(at: clock) } }
        scenario("blink") { for _ in 0..<6 { scene.caret.toggle(); clock += 0.53; show(at: clock) } }
        scene.caret = true
        for i in 0..<160 { type(i + 7) }
        show(at: clock); clock += 0.6
        scenario("scroll") { for _ in 0..<90 { scene.scroll += 6; clock += 1.0 / 60; show(at: clock) } }
        scene.scroll = 0
        scenario("mixed") {
            var key = 0, tick = 0
            let begin = clock
            while clock - begin < 6 {
                clock += 1.0 / 60; tick += 1
                scene.spinner = tick % 12
                if tick % 6 == 0 { scene.clock = String(format: "00:%02d.%d", tick / 60, (tick / 6) % 10) }
                if tick % 3 == 0 {
                    type(key); key += 1
                    if key % 7 == 0 { scene.scroll = scene.scroll == 0 ? 17 : 0 }
                }
                show(at: clock)
            }
        }
        scene.spinner = -1; scene.clock = ""
        scenario("burst") {
            for i in 0..<30 {
                clock += 0.12; scene.scroll = scene.scroll == 0 ? 17 : 0; show(at: clock)
                clock += 0.003; type(i + 300); show(at: clock)
            }
        }
        clock += 0.8; Thread.sleep(forTimeInterval: max(0, start + clock - ProcessInfo.processInfo.systemUptime))
        source.stop()
        Thread.sleep(forTimeInterval: 0.2)
        let sent = lock.withLock { packets }
        guard lock.withLock({ errors }) == 0 else { fputs("native error packets\n", stderr); exit(1) }
        try sent.write(to: out.appendingPathComponent("packets.bin"))
        // Second pass: re-render every recorded state, check it is the same picture, and store it.
        var file = Data("J1117SRC".utf8)
        append(&file, UInt64(width), 4); append(&file, UInt64(height), 4); append(&file, UInt64(frames.count), 4)
        var compressed = [UInt8](repeating: 0, count: width * height * 4)
        for (capture, state, hash) in frames {
            var pixel: CVPixelBuffer?
            _ = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &pixel)
            renderer.render(state, into: pixel!)
            guard renderer.hash(pixel!) == hash else { fputs("re-render differs at \(capture)\n", stderr); exit(1) }
            let raw = renderer.packed(pixel!)
            let length = compression_encode_buffer(&compressed, compressed.count, raw, raw.count, nil, COMPRESSION_ZLIB)
            guard length > 0 else { fputs("source compression\n", stderr); exit(1) }
            append(&file, capture, 8); append(&file, UInt64(length), 4); file.append(contentsOf: compressed[0..<length])
        }
        try file.write(to: out.appendingPathComponent("source.bin"))
        let manifest = ["width": width, "height": height, "frames": frames.count, "packet_bytes": sent.count,
                        "scenarios": scenarios.map { ["name": $0.0, "first_ns": String($0.1), "last_ns": String($0.2)] }] as [String: Any]
        try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys]).write(to: out.appendingPathComponent("manifest.json"))
        print("RECORDED frames=\(frames.count) packet_bytes=\(sent.count) source_bytes=\(file.count)")
    }
}
