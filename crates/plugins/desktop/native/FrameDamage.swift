/// Role: classify native frame damage, decide what goes to the tile lane, and report geometry-only diagnostics in opt-in measurements [D254,D266,#146].
/// ScreenCaptureKit attaches a list of changed rectangles (the damage) to every captured frame.
/// These functions decide from that list whether the picture really changed, and avoid sending
/// duplicate frames to the encoder.
import Foundation
import CoreGraphics

/// Objective-C type encoding of a boxed `CGRect`, used to recognize rectangles inside `NSValue`.
private let damageRectangleEncoding = String(cString: NSValue(rect: .zero).objCType)

/// How much a captured frame changed.
enum CaptureFrameDamage: String, Equatable {
    /// The damage list is present but holds only empty rectangles: nothing to encode.
    case unchanged
    /// Only a small text-cursor-sized area changed.
    case caret
    /// Anything else, including damage in a form we do not understand.
    case content
}

/// Classifies a frame's damage metadata.
///
/// When unsure the answer is `.content`, so a changed picture is never suppressed. The first
/// usable frame (`initial`) is always `.content`. A single rectangle at most 3 wide and 8 to 32
/// high counts as a caret.
/// - Parameters:
///   - metadata: The damage rectangles as delivered by the framework, or `nil` if absent.
///   - initial: True for the first frame of a capture.
func captureFrameDamage(_ metadata: Any?, initial: Bool) -> CaptureFrameDamage {
    // The first usable buffer establishes the picture even without damage.
    // Unknown metadata must never suppress a potentially changed picture.
    guard !initial, let rectangles = metadata as? [Any] else { return .content }
    var changedCount = 0
    var onlyChange: CGRect?
    for value in rectangles {
        let rectangle: CGRect?
        if let dictionary = value as? [String: Any] {
            rectangle = CGRect(dictionaryRepresentation: dictionary as CFDictionary)
        } else if let boxed = value as? NSValue,
                  String(cString: boxed.objCType) == damageRectangleEncoding {
            rectangle = boxed.rectValue
        } else if let unboxed = value as? CGRect {
            rectangle = unboxed
        } else { return .content }
        guard let rectangle else { return .content }
        // A nonempty framework list may contain only empty sentinels. Encoding
        // those duplicates consumes the decoder's bounded reference queue.
        if !rectangle.isEmpty {
            changedCount += 1
            if changedCount == 1 { onlyChange = rectangle } else { onlyChange = nil }
        }
    }
    guard changedCount > 0 else { return .unchanged }
    // NSText-style insertion cursors occupy one narrow vertical damage region.
    // Keep the bound conservative so glyphs, cursor-plus-glyph updates and
    // scrolling continue to reset the settled sharp refresh deadline.
    if changedCount == 1,
       let rectangle = onlyChange,
       rectangle.width.isFinite, rectangle.height.isFinite,
       rectangle.width > 0, rectangle.width <= 3,
       rectangle.height >= 8, rectangle.height <= 32 {
        return .caret
    }
    return .content
}

/// True unless the frame is `.unchanged`; a shortcut for callers that don't care about carets.
func captureFrameHasDamage(_ metadata: Any?, initial: Bool) -> Bool {
    captureFrameDamage(metadata, initial: initial) != .unchanged
}

/// Compact geometry for opt-in capture measurements; rectangle contents do not
/// include pixels, titles or other app data, and unknown values remain labeled.
func captureFrameDamageDiagnostics(_ metadata: Any?) -> String {
    guard let rectangles = metadata as? [Any] else { return "unknown" }
    return rectangles.map { value in
        let kind: String
        let rectangle: CGRect?
        if let dictionary = value as? [String: Any] {
            kind = "dictionary"
            rectangle = CGRect(dictionaryRepresentation: dictionary as CFDictionary)
        } else if let boxed = value as? NSValue,
                  String(cString: boxed.objCType) == damageRectangleEncoding {
            kind = "nsvalue"
            rectangle = boxed.rectValue
        } else if let unboxed = value as? CGRect {
            kind = "cgrect"
            rectangle = unboxed
        } else {
            return "unknown-\(String(reflecting: type(of: value)))"
        }
        guard let rectangle else { return "invalid-\(kind)" }
        return "\(kind):\(rectangle.minX),\(rectangle.minY),\(rectangle.width),\(rectangle.height)"
    }.joined(separator: ";")
}

/// When a small change goes to the tile lane instead of the video encoder [#146 proposal C].
///
/// Encoding a typed letter costs the hardware encoder a fixed ~4.6 ms plus ~2.9 ms per megapixel
/// on an M1 (J1078), while cutting and compressing a letter-sized tile costs ~0.04 ms. Tiles are
/// therefore used for small changes only: at most 4% of the picture and at most 65,536 pixels in
/// total, where raw DEFLATE still takes about 2 ms. Larger changes (scrolling, video, resizing)
/// stay video, which also keeps tile bytes near what a video delta would cost.
///
/// Tile bytes come out of the same bit rate the video uses. A token bucket refills at the
/// adaptive bit rate and holds at most a quarter second of it (at least 64 KiB); a tile that does
/// not fit goes to video instead, so a burst of tiles can never outrun the link the encoder is
/// already being throttled to. Times are monotonic seconds, passed in for deterministic tests.
struct TileLane {
    /// Largest total tile area in pixels, whatever the picture size.
    static let maximumArea = 65_536
    /// Smallest burst the bucket allows, in bytes: a few full tile updates.
    static let minimumBurst = 64 * 1024
    /// Bytes available right now.
    private var tokens = Double(TileLane.minimumBurst)
    /// When `tokens` was last refilled, or `nil` before the first use.
    private var refilled: Double?

    /// The largest changed area, in pixels, that may go as tiles for a picture of this size.
    static func areaLimit(width: Int, height: Int) -> Int {
        guard width > 0, height > 0 else { return 0 }
        return min(maximumArea, width * height / 25)
    }

    /// Refills the bucket for the time since the last call. The burst is a quarter second at
    /// `bitsPerSecond`, never below `minimumBurst`.
    private mutating func refill(bitsPerSecond: Int, at now: Double) {
        let rate = Double(max(0, bitsPerSecond)) / 8
        let burst = max(Double(Self.minimumBurst), rate / 4)
        if let refilled, now.isFinite, now > refilled { tokens = min(burst, tokens + (now - refilled) * rate) }
        tokens = min(tokens, burst)
        if now.isFinite { refilled = max(refilled ?? now, now) }
    }

    /// True when a tile update of `bytes` fits the budget now. Spends nothing; call `spend` when
    /// the update is actually sent.
    mutating func admits(_ bytes: Int, bitsPerSecond: Int, at now: Double) -> Bool {
        refill(bitsPerSecond: bitsPerSecond, at: now)
        return bytes > 0 && Double(bytes) <= tokens
    }

    /// Takes `bytes` out of the budget for an update that was sent.
    mutating func spend(_ bytes: Int) { tokens = max(0, tokens - Double(bytes)) }
}
