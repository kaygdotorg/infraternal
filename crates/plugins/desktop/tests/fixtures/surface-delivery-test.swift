/// Role: drive the production mailbox and hardware encoder with real buffers, without starting a screen stream [D254,D266].
import AppKit
import CoreMedia
import CoreVideo
import Foundation

enum HelperFailure: Error { case invalid, permission, unavailable }

@main struct SurfaceDeliveryTest {
    static func expect(_ value: Bool, _ label: String) {
        if !value { fputs("FAIL \(label)\n", stderr); exit(1) }
    }
    static func main() {
        let lock = NSLock()
        var keys: [Bool] = []
        var failed = false
        let source = SurfaceCapture(target: [:], rect: CGRect(x: 0, y: 0, width: 64, height: 48), size: CGSize(width: 64, height: 48), hevc: false, fps: 120) { kind, body in
            lock.withLock {
                if kind == 70 && body.count > 9 { keys.append(body[8] == 1) }
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
        expect(idleCount == 2, "eight identical callbacks need startup plus one sharp refresh, got \(idleCount)")
        for value in 1...8 {
            fill(UInt8(value))
            let next = count() + 1
            source.receiveFrame(pixel, ticks: mach_absolute_time(), damage: damage)
            awaitCount(next)
        }
        let beforeRepair = count()
        source.repair(); awaitCount(beforeRepair + 1)
        expect(lock.withLock { keys.last == true }, "static repair emits IDR")
        source.stop()
        Thread.sleep(forTimeInterval: 0.1)
        expect(!lock.withLock { failed }, "no native error")
        print("PASS production surface delivery: identical_callbacks=8 idle_pictures=2 distinct_changes=8 static_repair=IDR")
    }
}
