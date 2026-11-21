/// J1118 measurement harness (not product code): several App Window encoder processes sharing one hardware
/// encoder, and whether the controlled window can be served first (#146). Build with the product encoder:
///   swiftc -O -swift-version 5 -o share main.swift ../../../../crates/plugins/desktop/native/{CaptureState,LowDelaySPS,Encoder,EncoderPriority}.swift
///   ./share N MECH SECONDS     MECH: none | nice | bg | qos | coop:<hold_ms>:<wait_ms> | product
/// `product` uses the product's own EncoderPriority (claim by the "control companion", lease, bounded wait).
/// Process 0 is the controlled window; the others are windows that move at the same time. Every process encodes a
/// 1520x1026 scrolling picture at 120 Hz with the product's own `Encoder`, one frame in flight, like the product.
import AppKit
import CoreVideo
import Foundation

/// The product's `main.swift` defines this; the harness needs only the name.
enum HelperFailure: Error { case invalid, permission, gone, unavailable }

/// Converts mach ticks to nanoseconds.
var timebase = mach_timebase_info_data_t(); mach_timebase_info(&timebase)
/// Milliseconds in `t` mach ticks.
func ms(_ t: UInt64) -> Double { Double(t) * Double(timebase.numer) / Double(timebase.denom) / 1e6 }
/// Mach ticks in `ms` milliseconds.
func ticks(ms: Double) -> UInt64 { UInt64(ms * 1e6 * Double(timebase.denom) / Double(timebase.numer)) }
/// The `p` quantile (0 to 1) of `v`, or NaN for an empty list.
func pct(_ v: [Double], _ p: Double) -> Double { let s = v.sorted(); return s.isEmpty ? .nan : s[min(s.count - 1, Int(Double(s.count) * p))] }
/// Two-decimal text for a number.
func f(_ v: Double) -> String { String(format: "%.2f", v) }

/// The command line: `child ...` for a worker, otherwise `N MECH SECONDS` for the parent.
let args = CommandLine.arguments
if args.count >= 2 && args[1] == "child" {
    // child IDX N MECH SECONDS SHM
    let index = Int(args[2])!, count = Int(args[3])!, mech = args[4], seconds = Double(args[5])!, shmPath = args[6]
    let controlled = index == 0
    let fd = open(shmPath, O_RDWR); let map = mmap(nil, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)!
    let lease = map.bindMemory(to: UInt64.self, capacity: 8)   // [0] = mach time until which the controlled window holds the encoder
    var wait = 0.0, hold = 0.0
    if !controlled {
        if mech == "nice" { setpriority(PRIO_PROCESS, 0, 10) }
        if mech == "bg" { setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) }
    }
    if mech == "qos" { pthread_set_qos_class_self_np(controlled ? QOS_CLASS_USER_INTERACTIVE : QOS_CLASS_UTILITY, 0) }
    if mech.hasPrefix("coop:") { let p = mech.split(separator: ":"); hold = Double(p[1])!; wait = Double(p[2])! }
    let product = mech == "product" ? EncoderPriority(key: UInt64(index + 1), path: shmPath + ".product") : nil
    let w = 1520, h = 1026, source = 3000
    var pixel: CVPixelBuffer?
    CVPixelBufferCreate(nil, w, h, kCVPixelFormatType_32BGRA, [kCVPixelBufferIOSurfacePropertiesKey: [:]] as CFDictionary, &pixel)
    guard let pixel else { fatalError("pixel buffer") }
    // A tall picture of text-like stripes, scrolled by a few rows per frame.
    var tall = [UInt8](repeating: 255, count: w * (h + source) * 4)
    var seed = UInt64(0x9e3779b97f4a7c15) &+ UInt64(index)
    func rnd() -> UInt64 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed }
    for row in 0..<(h + source) where row % 18 < 12 {
        var x = 20
        while x < w - 20 { let run = Int(rnd() % 60) + 4, gap = Int(rnd() % 14) + 4, shade = UInt8(rnd() % 120)
            for i in x..<min(x + run, w - 20) { let o = (row * w + i) * 4; tall[o] = shade; tall[o + 1] = shade; tall[o + 2] = shade }
            x += run + gap }
    }
    let encoder = Encoder()
    do { try encoder.configure(width: w, height: h, hevc: false, fps: 120) } catch { fatalError("encoder \(error)") }
    var duration: [Double] = [], age: [Double] = []; var delivered = 0, drops = 0, late = 0
    let interval = 1000.0 / 120.0
    // Everyone starts together: wait for the shared start time written by the parent.
    while lease[1] == 0 { usleep(500) }
    let origin = lease[1]; let end = origin + ticks(ms: seconds * 1000)
    var tick = 0
    while true {
        let due = origin + ticks(ms: Double(tick) * interval)
        if due > end { break }
        while mach_absolute_time() + ticks(ms: 0.4) < due { usleep(200) }
        while mach_absolute_time() < due {}
        let now = mach_absolute_time()
        if now > due + ticks(ms: interval) { late += Int((ms(now - due)) / interval); tick += Int(ms(now - due) / interval) + 1; continue }
        CVPixelBufferLockBaseAddress(pixel, [])
        let base = CVPixelBufferGetBaseAddress(pixel)!; let stride = CVPixelBufferGetBytesPerRow(pixel)
        let offset = (tick * 7) % source
        tall.withUnsafeBytes { src in for row in 0..<h { memcpy(base + row * stride, src.baseAddress! + ((row + offset) * w) * 4, w * 4) } }
        CVPixelBufferUnlockBaseAddress(pixel, [])
        if let product {
            if controlled { product.claim(target: 1) }   // the control companion accepted input for window 1
            product.beforeEncode()
        } else if controlled { lease[0] = mach_absolute_time() + ticks(ms: 1000) }   // wants the encoder, now and until it is done
        else if wait > 0 {
            let limit = mach_absolute_time() + ticks(ms: wait)
            while lease[0] > mach_absolute_time() && mach_absolute_time() < limit { usleep(150) }
        }
        let begin = mach_absolute_time()
        let result = try? encoder.encodeSurface(pixel, ticks: begin, force: tick == 0, bitrate: 6_000_000)
        let done = mach_absolute_time()
        if let product { product.afterEncode() } else if controlled { lease[0] = done + ticks(ms: hold) }
        if result != nil && result! != nil { delivered += 1; duration.append(ms(done - begin)); age.append(ms(done - due)) } else { drops += 1 }
        tick += 1
    }
    let elapsed = seconds
    print("CHILD index=\(index) controlled=\(controlled) delivered=\(delivered) fps=\(f(Double(delivered) / elapsed)) drops=\(drops) skipped=\(late) encode_p50=\(f(pct(duration, 0.5))) encode_p95=\(f(pct(duration, 0.95))) age_p50=\(f(pct(age, 0.5))) age_p95=\(f(pct(age, 0.95)))")
    exit(0)
}

// parent: share N MECH SECONDS
/// How many windows (processes) take part.
let n = Int(args[1])!, mech = args[2], seconds = Double(args[3])!
/// The shared file the processes use as their start signal and, for the harness mechanisms, their lease.
let shm = NSTemporaryDirectory() + "j1118-share-\(getpid())"
/// Descriptor of the shared file.
let fd = open(shm, O_RDWR | O_CREAT, 0o600); ftruncate(fd, 4096)
/// The shared words: [0] lease end, [1] common start time.
let map = mmap(nil, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)!.bindMemory(to: UInt64.self, capacity: 8)
for i in 0..<8 { map[i] = 0 }
/// The child processes and the pipes their results come back on.
var processes: [(Process, Pipe)] = []
for i in 0..<n {
    let p = Process(); p.executableURL = URL(fileURLWithPath: args[0]); p.arguments = ["child", "\(i)", "\(n)", mech, "\(seconds)", shm]
    let pipe = Pipe(); p.standardOutput = pipe; try p.run(); processes.append((p, pipe))
}
sleep(3)   // sessions come up
map[1] = mach_absolute_time() + ticks(ms: 200)
for (p, pipe) in processes { p.waitUntilExit(); let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    for line in out.split(separator: "\n") where line.hasPrefix("CHILD") { print("RESULT n=\(n) mech=\(mech) \(line.dropFirst(6))") } }
unlink(shm)
