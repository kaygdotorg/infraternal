/// Role: verify owned picture history, padding, mutation and unsuccessful delivery with real CoreVideo storage [D254,D266].
import CoreVideo
import Foundation

@main struct FramePixelsTest {
    static func expect(_ value: Bool, _ label: String) {
        if !value { fputs("FAIL \(label)\n", stderr); exit(1) }
    }
    static func pixel(_ width: Int, _ height: Int, format: OSType = kCVPixelFormatType_32BGRA) -> CVPixelBuffer {
        var result: CVPixelBuffer?
        let attrs = [kCVPixelBufferBytesPerRowAlignmentKey as String: 128] as CFDictionary
        expect(CVPixelBufferCreate(kCFAllocatorDefault, width, height, format, attrs, &result) == kCVReturnSuccess, "real buffer allocation")
        return result!
    }
    static func fill(_ pixel: CVPixelBuffer, _ byte: UInt8, padding: UInt8 = 0) {
        expect(CVPixelBufferLockBaseAddress(pixel, []) == kCVReturnSuccess, "write lock")
        defer { CVPixelBufferUnlockBaseAddress(pixel, []) }
        let base = CVPixelBufferGetBaseAddress(pixel)!
        let stride = CVPixelBufferGetBytesPerRow(pixel), rowBytes = CVPixelBufferGetWidth(pixel) * 4
        for y in 0..<CVPixelBufferGetHeight(pixel) {
            base.advanced(by: y * stride).initializeMemory(as: UInt8.self, repeating: padding, count: stride)
            base.advanced(by: y * stride).initializeMemory(as: UInt8.self, repeating: byte, count: rowBytes)
        }
    }
    static func main() {
        let history = FramePixels(), a = pixel(17, 9), b = pixel(17, 9)
        fill(a, 31); fill(b, 31, padding: 199)
        expect(history.prepare(a), "first picture")
        history.dropped()
        expect(history.prepare(a), "unconfirmed picture must retry")
        history.delivered()
        expect(!history.prepare(b), "padding is not content")
        history.dropped()
        expect(!history.prepare(a), "dropped refresh retains delivered history")
        fill(a, 47)
        expect(history.prepare(a), "reused object changed")
        // The original input may be reused after submission. History owns bytes.
        fill(a, 31)
        history.delivered()
        expect(history.prepare(a), "history is independent of reused buffer")
        history.delivered()
        expect(CVPixelBufferLockBaseAddress(a, []) == kCVReturnSuccess, "last-pixel write lock")
        let last = CVPixelBufferGetBaseAddress(a)!.advanced(by: (CVPixelBufferGetHeight(a) - 1) * CVPixelBufferGetBytesPerRow(a) + (CVPixelBufferGetWidth(a) - 1) * 4 + 3)
        last.storeBytes(of: UInt8(7), as: UInt8.self)
        CVPixelBufferUnlockBaseAddress(a, [])
        expect(history.prepare(a), "last-row alpha is picture content")
        history.delivered()
        let resized = pixel(9, 17); fill(resized, 31)
        expect(history.prepare(resized), "equal byte count with different dimensions")
        history.delivered()
        let planar = pixel(16, 16, format: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)
        expect(history.prepare(planar), "unknown format is conservative")
        history.delivered()
        expect(history.prepare(resized), "unknown format invalidates history")
        history.delivered()
        let oversized = pixel(4096, 1025)
        expect(history.prepare(oversized), "oversized input is conservative")
        history.delivered()
        expect(history.prepare(resized), "oversized input invalidates history")
        history.delivered(); history.reset()
        expect(history.prepare(resized), "reset retires history")
        print("PASS exact BGRA history: padding, reused storage, last-row alpha, dimensions, raw drop, refresh drop, unknown format and reset")
    }
}
