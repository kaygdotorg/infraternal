/// Role: reads the pointer shape the Mac is showing, so the viewer can draw its own pointer in that shape [#146].
/// The picture no longer carries the pointer (`SurfaceCapture` captures without it), because a pointer
/// drawn into video trails the real one by the whole capture and network pipeline. The viewer draws
/// the pointer itself, at once, and only the shape comes from here: an image, its hotspot and its
/// pixel density, named by a short id so the viewer decodes each shape once.
import AppKit
import CryptoKit
import Darwin

/// The window server's counter for the visible pointer image. It changes whenever the shape does,
/// so reading it costs next to nothing. This is a private CoreGraphics symbol (private calls are
/// allowed here); when it is missing, `MachineCursor` falls back to rate-limited re-reads.
private let cursorSeed: (@convention(c) () -> Int32)? = {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGSCurrentCursorSeed") else { return nil }
    return unsafeBitCast(symbol, to: (@convention(c) () -> Int32).self)
}()

/// Largest pointer image the viewer will use, in pixels per side. Browsers ignore larger cursor
/// images, so a larger shape is reported as absent and the viewer keeps its ordinary pointer.
private let maxCursorPixels = 128

/// Largest PNG the viewer accepts, before base64 (24 000 characters after it). Real system pointers
/// are a few kilobytes; this only bounds a pathological image so a status reply stays small.
private let maxCursorPNGBytes = 18_000

/// Reads and remembers the current pointer shape. Use from the main thread only (AppKit).
final class MachineCursor {
    /// Seed value when `cached` was made; `nil` before the first read.
    private var seen: Int32?
    /// Monotonic seconds of the last read, used only when the seed is unavailable.
    private var readAt = -Double.infinity
    /// The reply fields for the shape at `seen`, or `nil` when it has no usable image.
    private var cached: [String: Any]?
    /// Reported shapes by id, so a shape that comes back is not encoded again.
    private var byID: [String: [String: Any]] = [:]

    /// The current shape as JSON-ready fields: `id` (16 hex characters), `png` (base64), `hot_x` and
    /// `hot_y` (the hotspot, in points from the image's top left), `scale` (pixels per point),
    /// `width` and `height` (pixels). `nil` when the system reports no pointer image or it is too large.
    func current() -> [String: Any]? {
        let now = ProcessInfo.processInfo.systemUptime
        if let cursorSeed {
            let value = cursorSeed()
            if value == seen { return cached }
            seen = value
        } else {
            // Without the seed, one read a quarter second is plenty for a shape that changes by hand.
            if now - readAt < 0.25 { return cached }
            readAt = now
        }
        cached = read()
        return cached
    }

    /// Renders the system cursor at its sharpest representation.
    private func read() -> [String: Any]? {
        guard let cursor = NSCursor.currentSystem else { return nil }
        let image = cursor.image
        guard image.size.width > 0, image.size.height > 0,
              let best = image.representations.max(by: { $0.pixelsWide < $1.pixelsWide }),
              best.pixelsWide > 0, best.pixelsHigh > 0,
              best.pixelsWide <= maxCursorPixels, best.pixelsHigh <= maxCursorPixels,
              let picture = best.cgImage(forProposedRect: nil, context: nil, hints: nil),
              let png = NSBitmapImageRep(cgImage: picture).representation(using: .png, properties: [:]),
              png.count <= maxCursorPNGBytes else { return nil }
        let scale = Double(best.pixelsWide) / Double(image.size.width)
        let hot = cursor.hotSpot
        var digest = SHA256()
        digest.update(data: png)
        digest.update(data: Data("\(hot.x),\(hot.y),\(scale)".utf8))
        let id = digest.finalize().prefix(8).map { String(format: "%02x", $0) }.joined()
        if let known = byID[id] { return known }
        let shape: [String: Any] = ["id": id, "png": png.base64EncodedString(), "hot_x": Double(hot.x), "hot_y": Double(hot.y),
                                    "scale": scale, "width": best.pixelsWide, "height": best.pixelsHigh]
        if byID.count >= 64 { byID.removeAll() }
        byID[id] = shape
        return shape
    }
}
