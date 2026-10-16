/// Role: classify native frame damage without reading pixels or queuing unchanged pictures [D254,D266].
import Foundation
import CoreGraphics

private let damageRectangleEncoding = String(cString: NSValue(rect: .zero).objCType)

func captureFrameHasDamage(_ metadata: Any?, initial: Bool) -> Bool {
    // The first usable buffer establishes the picture even without damage.
    // Unknown metadata must never suppress a potentially changed picture.
    guard !initial, let rectangles = metadata as? [Any] else { return true }
    for value in rectangles {
        let rectangle: CGRect?
        if let dictionary = value as? [String: Any] {
            rectangle = CGRect(dictionaryRepresentation: dictionary as CFDictionary)
        } else if let boxed = value as? NSValue,
                  String(cString: boxed.objCType) == damageRectangleEncoding {
            rectangle = boxed.rectValue
        } else if let unboxed = value as? CGRect {
            rectangle = unboxed
        } else { return true }
        guard let rectangle else { return true }
        // A nonempty framework list may contain only empty sentinels. Encoding
        // those duplicates consumes the decoder's bounded reference queue.
        if !rectangle.isEmpty { return true }
    }
    return false
}
