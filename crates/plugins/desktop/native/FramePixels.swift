/// Role: bounded exact BGRA history classifies caret cadence so idle blink deltas do not restart sharp refresh [D254,D266,#146].
import CoreVideo
import Darwin
import Foundation

enum PixelDamageKind: Equatable {
    case unchanged
    case caret
    case content
}

struct PixelDamageBounds: Equatable {
    let x: Int
    let y: Int
    let width: Int
    let height: Int
}

final class FramePixels {
    private static let maximumScannedDamageWidth = 10
    private static let maximumScannedDamageHeight = 40
    private static let maximumScannedDamagePixels = 160
    private static let maximumCaretWidth = 9
    // A focused 1x insertion caret changed only four to six rows in production capture.
    private static let minimumCaretHeight = 4
    private static let measuredNinePixelCaretAnchorHeight = 17
    // Focused capture measured an 8-pixel-wide caret at one origin, with fade extents from 16 to 19 pixels.
    private static let maximumCaretHeightDelta = 3
    // Successive helper-managed blink anchors shift by up to three pixels in either axis.
    private static let maximumCaretAnchorPositionDelta = 3
    // Helper-managed sizing alternates the same caret between seven and eight changed columns.
    private static let maximumCaretAnchorWidthDelta = 1
    private static let maximumCaretAnchorVariants = 8
    // Newly seen fade pixels stay content until the same transition recurs at blink cadence.
    private static let maximumCaretFadeVariants = 8
    // Measured 7/8-pixel anchors produce a 10-pixel intermediate fade at the same insertion point.
    private static let maximumFadePositionDelta = 3
    private static let maximumFadeWidthDelta = 2
    private static let maximumFadeHeightDelta = 9
    // The measured 9x17 helper-managed anchor only fades to 9x15 or 9x16.
    private static let maximumNinePixelFadeHeightDelta = 2
    private static let minimumBlinkInterval = 0.25
    private static let maximumBlinkInterval = 1.5

    /// Exact pixels make a repeated transition distinguishable from new text with the same bounds.
    private struct PixelTransition {
        let before: Data
        let after: Data

        func matches(_ other: PixelTransition) -> Bool {
            (before == other.before && after == other.after)
                || (before == other.after && after == other.before)
        }
    }

    private struct DamageVariant {
        let bounds: PixelDamageBounds
        let transition: PixelTransition
        var at: Double

        func matches(_ bounds: PixelDamageBounds, transition: PixelTransition) -> Bool {
            self.bounds == bounds && self.transition.matches(transition)
        }
    }

    /// Bounded pixel-identical anchor variants and their last-seen time establish caret cadence.
    private struct CaretCandidate {
        var bounds: PixelDamageBounds
        var at: Double
        var anchorVariants: [DamageVariant]
        var fadeVariants: [DamageVariant]

        init(bounds: PixelDamageBounds, transition: PixelTransition, at: Double) {
            self.bounds = bounds
            self.at = at
            anchorVariants = [DamageVariant(bounds: bounds, transition: transition, at: at)]
            anchorVariants.reserveCapacity(FramePixels.maximumCaretAnchorVariants)
            fadeVariants = []
            fadeVariants.reserveCapacity(FramePixels.maximumCaretFadeVariants)
        }

        func hasAnchor(_ bounds: PixelDamageBounds, transition: PixelTransition) -> Bool {
            anchorVariants.contains { $0.matches(bounds, transition: transition) }
        }

        mutating func observeAnchor(
            _ bounds: PixelDamageBounds,
            transition: PixelTransition,
            at now: Double
        ) -> Bool {
            guard let index = anchorVariants.firstIndex(where: { $0.matches(bounds, transition: transition) }) else {
                guard anchorVariants.count < FramePixels.maximumCaretAnchorVariants else { return false }
                anchorVariants.append(DamageVariant(bounds: bounds, transition: transition, at: now))
                return false
            }
            let previous = anchorVariants[index].at
            anchorVariants[index].at = now
            return now > previous && FramePixels.blinkInterval(now - previous)
        }

        mutating func observeFade(
            _ bounds: PixelDamageBounds,
            transition: PixelTransition,
            at now: Double
        ) -> PixelDamageKind {
            guard let index = fadeVariants.firstIndex(where: { $0.matches(bounds, transition: transition) }) else {
                guard fadeVariants.count < FramePixels.maximumCaretFadeVariants else { return .content }
                fadeVariants.append(DamageVariant(bounds: bounds, transition: transition, at: now))
                return .content
            }
            let previous = fadeVariants[index].at
            fadeVariants[index].at = now
            guard now > previous, FramePixels.blinkInterval(now - previous) else { return .content }
            return .caret
        }
    }

    private struct CaretRecognition {
        var candidate: CaretCandidate?
        var active: Bool

        static let empty = CaretRecognition(candidate: nil, active: false)
    }

    private var bytes = Data()
    private var width = 0
    private var height = 0
    private var valid = false
    private var prepared = false
    private var alreadyDelivered = false
    private(set) var damageKind: PixelDamageKind = .content
    private(set) var damageBounds: PixelDamageBounds?
    private(set) var changedPixels = 0
    private(set) var damageBoundsComplete = true
    private var caretRecognition = CaretRecognition.empty
    private var recognitionBeforePrepare: CaretRecognition?

    /// Prepare one encoder input. Only visible row bytes count; row padding is
    /// neither a picture nor safe history. Unknown storage stays conservative.
    /// The single owned buffer is bounded to 16 MiB and reused across inputs.
    func prepare(_ pixel: CVPixelBuffer, at now: Double = ProcessInfo.processInfo.systemUptime) -> Bool {
        prepared = false; alreadyDelivered = false
        recognitionBeforePrepare = nil
        damageKind = .content; damageBounds = nil; changedPixels = 0; damageBoundsComplete = true
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
        let comparable = valid && width == w && height == h
        var same = comparable
        var minX = w, minY = h, maxX = -1, maxY = -1
        var transition: PixelTransition?
        if comparable {
            bytes.withUnsafeBytes { old in
                let previous = old.baseAddress!
                for row in 0..<h {
                    let currentRow = base.advanced(by: row * stride)
                    let previousRow = previous.advanced(by: row * rowBytes)
                    if memcmp(currentRow, previousRow, rowBytes) == 0 { continue }
                    same = false
                    for column in 0..<w {
                        let currentPixel = currentRow.advanced(by: column * 4)
                        let previousPixel = previousRow.advanced(by: column * 4)
                        guard memcmp(currentPixel, previousPixel, 4) != 0 else { continue }
                        changedPixels += 1
                        minX = min(minX, column); maxX = max(maxX, column)
                        minY = min(minY, row); maxY = max(maxY, row)
                        if maxX - minX + 1 > Self.maximumScannedDamageWidth
                            || maxY - minY + 1 > Self.maximumScannedDamageHeight
                            || changedPixels > Self.maximumScannedDamagePixels {
                            damageBoundsComplete = false
                            break
                        }
                    }
                    if !damageBoundsComplete { break }
                }
                if changedPixels > 0, damageBoundsComplete {
                    let bounds = PixelDamageBounds(
                        x: minX,
                        y: minY,
                        width: maxX - minX + 1,
                        height: maxY - minY + 1
                    )
                    transition = pixelTransition(
                        bounds,
                        previous: previous,
                        previousStride: rowBytes,
                        current: base,
                        currentStride: stride
                    )
                }
            }
        }
        prepared = true; alreadyDelivered = same
        if same { damageKind = .unchanged; return false }
        if comparable, changedPixels > 0 {
            let bounds = PixelDamageBounds(x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1)
            damageBounds = bounds
            recognitionBeforePrepare = caretRecognition
            if let transition {
                damageKind = classifyCaretDamage(bounds, transition: transition, at: now)
            } else {
                caretRecognition = .empty
            }
        } else {
            recognitionBeforePrepare = caretRecognition
            caretRecognition = .empty
        }
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

    func delivered() {
        valid = prepared
        recognitionBeforePrepare = nil
    }
    func dropped() {
        // A failed repair/sharp refresh still has the same delivered picture.
        // Preserve that knowledge so duplicates cannot demote its pending retry.
        valid = prepared && alreadyDelivered
        if let previous = recognitionBeforePrepare { caretRecognition = previous }
        recognitionBeforePrepare = nil
    }
    func reset() {
        bytes = Data(); width = 0; height = 0
        valid = false; prepared = false; alreadyDelivered = false
        damageKind = .content; damageBounds = nil; changedPixels = 0; damageBoundsComplete = true
        caretRecognition = .empty; recognitionBeforePrepare = nil
    }

    private func pixelTransition(
        _ bounds: PixelDamageBounds,
        previous: UnsafeRawPointer,
        previousStride: Int,
        current: UnsafeRawPointer,
        currentStride: Int
    ) -> PixelTransition {
        let bytesPerRow = bounds.width * 4
        var before = Data()
        var after = Data()
        before.reserveCapacity(bytesPerRow * bounds.height)
        after.reserveCapacity(bytesPerRow * bounds.height)
        for row in bounds.y..<(bounds.y + bounds.height) {
            let previousRow = previous.advanced(by: row * previousStride + bounds.x * 4)
                .assumingMemoryBound(to: UInt8.self)
            let currentRow = current.advanced(by: row * currentStride + bounds.x * 4)
                .assumingMemoryBound(to: UInt8.self)
            before.append(contentsOf: UnsafeBufferPointer(start: previousRow, count: bytesPerRow))
            after.append(contentsOf: UnsafeBufferPointer(start: currentRow, count: bytesPerRow))
        }
        return PixelTransition(before: before, after: after)
    }

    private func classifyCaretDamage(
        _ bounds: PixelDamageBounds,
        transition: PixelTransition,
        at now: Double
    ) -> PixelDamageKind {
        guard damageBoundsComplete, now.isFinite,
              bounds.width <= Self.maximumScannedDamageWidth,
              bounds.height >= Self.minimumCaretHeight, bounds.height <= Self.maximumScannedDamageHeight,
              changedPixels <= Self.maximumScannedDamagePixels else {
            caretRecognition = .empty
            return .content
        }
        let current = CaretCandidate(bounds: bounds, transition: transition, at: now)
        guard let previous = caretRecognition.candidate else {
            caretRecognition = isCaretAnchor(bounds)
                ? CaretRecognition(candidate: current, active: false)
                : .empty
            return .content
        }
        let interval = now - previous.at
        guard interval.isFinite, interval >= 0 else {
            caretRecognition = .empty
            return .content
        }
        // A nine-pixel fade can also match the measured nine-by-seventeen anchor shape.
        // When a narrower anchor is already being tracked, keep its cadence instead.
        if bounds.width == Self.maximumCaretWidth,
           previous.bounds.width < Self.maximumCaretWidth,
           isAssociatedCaretFade(bounds, with: previous.bounds) {
            guard interval <= Self.maximumBlinkInterval else {
                caretRecognition = .empty
                return .content
            }
            var candidate = previous
            let kind = candidate.observeFade(bounds, transition: transition, at: now)
            caretRecognition.candidate = candidate
            return caretRecognition.active ? kind : .content
        }
        if isCaretAnchor(bounds), isCaretAnchor(previous.bounds), isSameCaretAnchor(bounds, previous.bounds) {
            if caretRecognition.active {
                guard interval <= Self.maximumBlinkInterval else {
                    caretRecognition = CaretRecognition(candidate: current, active: false)
                    return .content
                }
                // A looser positional match alone would suppress a nearby edit. Require the
                // exact pixels in this transition to have recurred as well as its shape.
                guard previous.hasAnchor(bounds, transition: transition) else {
                    var candidate = previous
                    _ = candidate.observeAnchor(bounds, transition: transition, at: now)
                    candidate.bounds = bounds
                    candidate.at = now
                    caretRecognition = CaretRecognition(candidate: candidate, active: false)
                    return .content
                }
                var candidate = previous
                _ = candidate.observeAnchor(bounds, transition: transition, at: now)
                if isBlinkInterval(interval) {
                    candidate.bounds = bounds
                    candidate.at = now
                }
                caretRecognition.candidate = candidate
                return .caret
            }
            var candidate = previous
            let recurringTransition = candidate.observeAnchor(bounds, transition: transition, at: now)
            candidate.bounds = bounds
            candidate.at = now
            caretRecognition.candidate = candidate
            guard recurringTransition, isBlinkInterval(interval) else { return .content }
            caretRecognition.active = true
            return .caret
        }
        if isAssociatedCaretFade(bounds, with: previous.bounds) {
            guard interval <= Self.maximumBlinkInterval else {
                caretRecognition = .empty
                return .content
            }
            var candidate = previous
            let kind = candidate.observeFade(bounds, transition: transition, at: now)
            caretRecognition.candidate = candidate
            return caretRecognition.active ? kind : .content
        }
        if isCaretAnchor(bounds) {
            caretRecognition = CaretRecognition(candidate: current, active: false)
        } else {
            caretRecognition = .empty
        }
        return .content
    }

    private func isCaretAnchor(_ bounds: PixelDamageBounds) -> Bool {
        guard bounds.width <= Self.maximumCaretWidth,
              bounds.height >= Self.minimumCaretHeight,
              bounds.height <= Self.maximumScannedDamageHeight else { return false }
        // Nine-pixel changes are anchors only at the measured 17-pixel shape.
        // Other nine-pixel heights remain fades and must match an established anchor.
        return bounds.width < Self.maximumCaretWidth
            || bounds.height == Self.measuredNinePixelCaretAnchorHeight
    }

    private func isSameCaretAnchor(_ left: PixelDamageBounds, _ right: PixelDamageBounds) -> Bool {
        abs(left.x - right.x) <= Self.maximumCaretAnchorPositionDelta
            && abs(left.y - right.y) <= Self.maximumCaretAnchorPositionDelta
            && abs(left.width - right.width) <= Self.maximumCaretAnchorWidthDelta
            && abs(left.height - right.height) <= Self.maximumCaretHeightDelta
    }

    private func isAssociatedCaretFade(_ bounds: PixelDamageBounds, with anchor: PixelDamageBounds) -> Bool {
        let maximumHeightDelta = anchor.width == Self.maximumCaretWidth
            ? Self.maximumNinePixelFadeHeightDelta
            : Self.maximumFadeHeightDelta
        return abs(bounds.x - anchor.x) <= Self.maximumFadePositionDelta
            && abs(bounds.y - anchor.y) <= Self.maximumFadePositionDelta
            && bounds.width >= anchor.width
            && bounds.width <= anchor.width + Self.maximumCaretAnchorWidthDelta + Self.maximumFadeWidthDelta
            && abs(bounds.height - anchor.height) <= maximumHeightDelta
    }

    private func isBlinkInterval(_ interval: Double) -> Bool {
        interval >= Self.minimumBlinkInterval && interval <= Self.maximumBlinkInterval
    }

    private static func blinkInterval(_ interval: Double) -> Bool {
        interval.isFinite && interval >= minimumBlinkInterval && interval <= maximumBlinkInterval
    }
}
