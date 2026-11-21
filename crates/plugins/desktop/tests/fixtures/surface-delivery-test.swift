/// Role: drive the production mailbox and hardware encoder with real buffers, without starting a screen stream [D254,D266].
import AppKit
import CoreMedia
import CoreVideo
import Foundation

enum HelperFailure: Error { case invalid, permission, unavailable }

/// The fixture's entry point: the production mailbox and hardware encoder driven with real buffers,
/// including one tile; it counts startup, the sharp refresh in the configured rate mode, changes and repair.
@main struct SurfaceDeliveryTest {
    static func expect(_ value: Bool, _ label: String) {
        if !value { fputs("FAIL \(label)\n", stderr); exit(1) }
    }
    /// Runs the delivery sequence and prints one PASS line; the first failure exits with status 1.
    static func main() {
        let lock = NSLock()
        var keys: [Bool] = []
        var tiles: [Bool] = []
        var failed = false
        let source = SurfaceCapture(target: [:], rect: CGRect(x: 0, y: 0, width: 64, height: 48), size: CGSize(width: 64, height: 48), hevc: false, fps: 120) { kind, body in
            lock.withLock {
                if kind == 70 && body.count > 9 { keys.append(body[8] == 1); tiles.append(body[9] == 0xF7) }
                else { failed = true }
            }
        }
        func count() -> Int { lock.withLock { keys.count } }
        func awaitCount(_ target: Int) {
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while count() < target && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.005) }
            expect(count() >= target && !lock.withLock({ failed }), "hardware output \(target)")
        }
        var storage: CVPixelBuffer?
        let attrs = [kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary
        expect(CVPixelBufferCreate(kCFAllocatorDefault, 64, 48, kCVPixelFormatType_32BGRA, attrs, &storage) == kCVReturnSuccess, "real frame allocation")
        let pixel = storage!
        func fill(_ value: UInt8) {
            expect(CVPixelBufferLockBaseAddress(pixel, []) == kCVReturnSuccess, "frame write lock")
            CVPixelBufferGetBaseAddress(pixel)!.initializeMemory(as: UInt8.self, repeating: value, count: CVPixelBufferGetDataSize(pixel))
            CVPixelBufferUnlockBaseAddress(pixel, [])
        }
        let damage = [CGRect(x: 0, y: 0, width: 64, height: 48).dictionaryRepresentation]
        fill(127)
        source.receiveFrame(pixel, ticks: mach_absolute_time(), damage: damage)
        awaitCount(1)
        expect(lock.withLock { keys.first == true }, "first packet is a keyframe")
        for _ in 0..<7 {
            Thread.sleep(forTimeInterval: 0.035)
            source.receiveFrame(pixel, ticks: mach_absolute_time(), damage: damage)
        }
        Thread.sleep(forTimeInterval: 0.4)
        let idleCount = count()
        // The startup picture is a keyframe at the motion budget, so every row counts as touched:
        // the sharp refresh is one keyframe or the heavy-motion refinement passes (deltas).
        let plan = SharpRefreshPlan(mode: Encoder().mode), passes = plan.passes(touched: 1)
        expect(idleCount == 1 + max(1, passes), "eight identical callbacks need startup plus one sharp refresh, got \(idleCount)")
        expect(lock.withLock { keys.dropFirst().allSatisfy { $0 == (passes == 0) } }, "the sharp refresh is a keyframe or only deltas")
        for value in 1...8 {
            fill(UInt8(value))
            let next = count() + 1
            source.receiveFrame(pixel, ticks: mach_absolute_time(), damage: damage)
            awaitCount(next)
        }
        // sleep: the sharp refresh owed after the last whole-picture change fires 0.25 s later; let it go out first.
        Thread.sleep(forTimeInterval: 0.4)
        expect(!lock.withLock { tiles.contains(true) }, "whole-picture changes stay video")
        // A 3x3 change in a 64x48 picture is within the tile lane's 4% area limit [#146 C].
        expect(CVPixelBufferLockBaseAddress(pixel, []) == kCVReturnSuccess, "tile write lock")
        let stride = CVPixelBufferGetBytesPerRow(pixel)
        for row in 10..<13 { CVPixelBufferGetBaseAddress(pixel)!.advanced(by: row * stride + 40).initializeMemory(as: UInt8.self, repeating: 250, count: 12) }
        CVPixelBufferUnlockBaseAddress(pixel, [])
        let beforeTile = count()
        source.receiveFrame(pixel, ticks: mach_absolute_time(), damage: damage)
        awaitCount(beforeTile + 1)
        expect(lock.withLock { tiles.last == true && keys.last == false }, "small change is a tile update, not a keyframe")
        // sleep: a refresh would be due 0.25 s after the tile; wait past it to prove none comes.
        Thread.sleep(forTimeInterval: 0.4)
        expect(count() == beforeTile + 1, "a tile owes no sharp refresh")
        let beforeRepair = count()
        source.repair(); awaitCount(beforeRepair + 1)
        expect(lock.withLock { keys.last == true }, "static repair emits IDR")
        source.stop()
        Thread.sleep(forTimeInterval: 0.1)
        expect(!lock.withLock { failed }, "no native error")
        print("PASS production surface delivery: identical_callbacks=8 idle_pictures=\(idleCount) rate_mode=\(Encoder().mode.rawValue) distinct_changes=8 tile=1 static_repair=IDR")
    }
}
