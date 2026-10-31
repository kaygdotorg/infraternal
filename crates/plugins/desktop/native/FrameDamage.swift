/// Role: classify native frame damage and report geometry-only diagnostics in opt-in measurements [D254,D266,#146].
import Foundation
import CoreGraphics

private let damageRectangleEncoding = String(cString: NSValue(rect: .zero).objCType)

enum CaptureFrameDamage: String, Equatable {
    case unchanged
    case caret
    case content
}

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
