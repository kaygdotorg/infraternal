/// Role: bounded exact BGRA history for delivered pictures; encoder-queue-only state preserves repair and refresh [D254,D266].
import CoreVideo
import Darwin
import Foundation

final class FramePixels {
    private var bytes = Data()
    private var width = 0
    private var height = 0
    private var valid = false
    private var prepared = false
    private var alreadyDelivered = false

    /// Prepare one encoder input. Only visible row bytes count; row padding is
    /// neither a picture nor safe history. Unknown storage stays conservative.
    /// The single owned buffer is bounded to 16 MiB and reused across inputs.
    func prepare(_ pixel: CVPixelBuffer) -> Bool {
        prepared = false; alreadyDelivered = false
        let w = CVPixelBufferGetWidth(pixel), h = CVPixelBufferGetHeight(pixel)
        let stride = CVPixelBufferGetBytesPerRow(pixel)
        guard CVPixelBufferGetPixelFormatType(pixel) == kCVPixelFormatType_32BGRA,
              w > 0, h > 0, w <= 4096, h <= 4096, w * h <= 4 * 1024 * 1024,
              stride >= w * 4, CVPixelBufferGetDataSize(pixel) / h >= stride,
              CVPixelBufferLockBaseAddress(pixel, .readOnly) == kCVReturnSuccess else {
            reset(); return true
        }
        defer { CVPixelBufferUnlockBaseAddress(pixel, .readOnly) }
        guard let base = CVPixelBufferGetBaseAddress(pixel) else { reset(); return true }
        let rowBytes = w * 4
        let same = valid && width == w && height == h && bytes.withUnsafeBytes { old in
            for row in 0..<h {
                if memcmp(base.advanced(by: row * stride), old.baseAddress!.advanced(by: row * rowBytes), rowBytes) != 0 { return false }
            }
            return true
        }
        prepared = true; alreadyDelivered = same
        if same { return false }
        // Overwriting history invalidates it until this exact prepared input is
        // delivered. A raw drop must never suppress an unconfirmed new picture.
        valid = false; width = w; height = h
        if bytes.count != rowBytes * h { bytes = Data(count: rowBytes * h) }
        bytes.withUnsafeMutableBytes { destination in
            for row in 0..<h {
                destination.baseAddress!.advanced(by: row * rowBytes).copyMemory(from: base.advanced(by: row * stride), byteCount: rowBytes)
            }
        }
        return true
    }

    func delivered() { valid = prepared }
    func dropped() {
        // A failed repair/sharp refresh still has the same delivered picture.
        // Preserve that knowledge so duplicates cannot demote its pending retry.
        valid = prepared && alreadyDelivered
    }
    func reset() {
        bytes = Data(); width = 0; height = 0
        valid = false; prepared = false; alreadyDelivered = false
    }
}
