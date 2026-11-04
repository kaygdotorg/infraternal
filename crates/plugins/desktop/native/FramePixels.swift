/// Role: bounded exact BGRA history classifies caret cadence so idle blink deltas do not restart sharp refresh [D254,D266,#146].
/// The capture framework reports damage regions, but a blinking text cursor can still look like
/// real content. This file compares the exact pixels of consecutive frames and recognizes a cursor
/// that blinks at a steady rate, so an idle editor does not keep restarting the sharp refresh.
/// Anything it cannot positively identify as a cursor is `content`: a wrong guess in that
/// direction only costs bandwidth, never a stale picture. Pixels are 32-bit BGRA.
import CoreVideo
import Darwin
import Foundation

/// How the latest frame differs from the previous delivered one.
enum PixelDamageKind: Equatable {
    /// Every visible pixel is identical.
    case unchanged
    /// A small region changed in the way a steadily blinking text cursor does.
    case caret
    /// Anything else, and the answer whenever there is not enough history to tell.
    case content
}

/// The smallest rectangle containing every changed pixel, in pixels from the frame's top left.
struct PixelDamageBounds: Equatable {
    /// Left edge.
    let x: Int
    /// Top edge.
    let y: Int
    /// Width, at least 1.
    let width: Int
    /// Height, at least 1.
    let height: Int
}

/// Keeps a copy of the last delivered picture and classifies how each new one differs from it.
///
/// Use one instance per video stream, from one thread. For each captured buffer call `prepare`,
/// then read `damageKind` and friends, then call `delivered` if the picture reached the viewer or
/// `dropped` if it did not. Call `reset` when the stream restarts or changes size.
///
/// The numeric limits below come from measuring real cursors in production captures; the `//`
/// comments beside them give the measurement.
final class FramePixels {
    /// Scanning gives up once the changed area is wider than this many pixels; the damage is then content.
    private static let maximumScannedDamageWidth = 10
    /// Scanning gives up once the changed area is taller than this many pixels.
    private static let maximumScannedDamageHeight = 40
    /// Scanning gives up after this many changed pixels.
    private static let maximumScannedDamagePixels = 160
    /// Widest changed area that can still be a cursor (anchor or fade).
    private static let maximumCaretWidth = 9
    // A focused 1x insertion caret changed only four to six rows in production capture.
    /// Shortest changed area that can be a cursor, in pixels.
    private static let minimumCaretHeight = 4
    /// The only height at which a nine-pixel-wide change counts as a cursor anchor rather than a fade.
    private static let measuredNinePixelCaretAnchorHeight = 17
    // Focused capture measured an 8-pixel-wide caret at one origin, with fade extents from 16 to 19 pixels.
    /// How much the height of two anchors of the same cursor may differ.
    private static let maximumCaretHeightDelta = 3
    // Successive helper-managed blink anchors shift by up to three pixels in either axis.
    /// How far, in pixels per axis, successive anchors of the same cursor may move.
    private static let maximumCaretAnchorPositionDelta = 3
    // Helper-managed sizing alternates the same caret between seven and eight changed columns.
    /// How much the width of two anchors of the same cursor may differ.
    private static let maximumCaretAnchorWidthDelta = 1
    /// How many distinct exact-pixel anchors are remembered per cursor candidate.
    private static let maximumCaretAnchorVariants = 8
    // Newly seen fade pixels stay content until the same transition recurs at blink cadence.
    /// How many distinct exact-pixel fades are remembered per cursor candidate.
    private static let maximumCaretFadeVariants = 8
    // Measured 7/8-pixel anchors produce a 10-pixel intermediate fade at the same insertion point.
    /// How far, per axis, a fade may sit from its anchor.
    private static let maximumFadePositionDelta = 3
    /// How much wider than its anchor (beyond the anchor width tolerance) a fade may be.
    private static let maximumFadeWidthDelta = 2
    /// How much taller or shorter than its anchor a fade may be.
    private static let maximumFadeHeightDelta = 9
    // The measured 9x17 helper-managed anchor only fades to 9x15 or 9x16.
    /// The tighter height tolerance used when the anchor is nine pixels wide.
    private static let maximumNinePixelFadeHeightDelta = 2
    /// Shortest time in seconds between two sightings that still counts as one blink cycle.
    private static let minimumBlinkInterval = 0.25
    /// Longest time in seconds between two sightings that still counts as one blink cycle.
    private static let maximumBlinkInterval = 1.5

    /// Exact pixels make a repeated transition distinguishable from new text with the same bounds.
    private struct PixelTransition {
        /// The changed rectangle's pixels in the previous frame (rows packed, 4 bytes per pixel).
        let before: Data
        /// The same rectangle's pixels in the newer frame.
        let after: Data

        /// True when `other` is the same change, in either direction (a blink on and the matching blink off).
        func matches(_ other: PixelTransition) -> Bool {
            (before == other.before && after == other.after)
                || (before == other.after && after == other.before)
        }
    }

    /// One exact-pixel change that has been seen: where it was, what it looked like, and when.
    private struct DamageVariant {
        /// Where the change was.
        let bounds: PixelDamageBounds
        /// The exact before and after pixels.
        let transition: PixelTransition
        /// Monotonic seconds when this variant was last seen.
        var at: Double

        /// True when the same rectangle shows the same change.
        func matches(_ bounds: PixelDamageBounds, transition: PixelTransition) -> Bool {
            self.bounds == bounds && self.transition.matches(transition)
        }
    }

    /// Bounded pixel-identical anchor variants and their last-seen time establish caret cadence.
    private struct CaretCandidate {
        /// Rectangle of the latest anchor sighting.
        var bounds: PixelDamageBounds
        /// Monotonic seconds of the latest anchor sighting.
        var at: Double
        /// Distinct exact anchor changes seen so far, at most `maximumCaretAnchorVariants`.
        var anchorVariants: [DamageVariant]
        /// Distinct exact fade changes seen so far, at most `maximumCaretFadeVariants`.
        var fadeVariants: [DamageVariant]

        /// Starts a candidate from its first anchor sighting.
        init(bounds: PixelDamageBounds, transition: PixelTransition, at: Double) {
            self.bounds = bounds
            self.at = at
            anchorVariants = [DamageVariant(bounds: bounds, transition: transition, at: at)]
            anchorVariants.reserveCapacity(FramePixels.maximumCaretAnchorVariants)
            fadeVariants = []
            fadeVariants.reserveCapacity(FramePixels.maximumCaretFadeVariants)
        }

        /// True when this exact change has been seen as an anchor before.
        func hasAnchor(_ bounds: PixelDamageBounds, transition: PixelTransition) -> Bool {
            anchorVariants.contains { $0.matches(bounds, transition: transition) }
        }

        /// Records an anchor sighting. Returns `true` when this exact change recurred at a blink-cycle
        /// interval; `false` for a new variant or when the variant list is full.
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

        /// Records a fade sighting. Returns `.caret` only when this exact fade recurred at a blink-cycle
        /// interval, otherwise `.content` (first sighting or list full).
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

    /// Whether a cursor is being tracked, and whether it has been confirmed as blinking.
    private struct CaretRecognition {
        /// The cursor being tracked, if any.
        var candidate: CaretCandidate?
        /// True once a blink cycle has been confirmed; only then are changes reported as `.caret`.
        var active: Bool

        /// Nothing tracked.
        static let empty = CaretRecognition(candidate: nil, active: false)
    }

    /// Copy of the last picture's visible bytes, rows packed without padding.
    private var bytes = Data()
    /// Width of the stored picture in pixels.
    private var width = 0
    /// Height of the stored picture in pixels.
    private var height = 0
    /// True when `bytes` is a picture the viewer has actually received.
    private var valid = false
    /// True when `prepare` has stored a picture that is not yet confirmed.
    private var prepared = false
    /// True when the prepared picture was identical to the delivered one.
    private var alreadyDelivered = false
    /// Classification of the latest prepared picture against the delivered one.
    private(set) var damageKind: PixelDamageKind = .content
    /// Rectangle that changed in the latest picture, or `nil` if unknown, unchanged or too large.
    private(set) var damageBounds: PixelDamageBounds?
    /// Number of changed pixels counted before scanning stopped.
    private(set) var changedPixels = 0
    /// False when scanning stopped early because the change was too large to be a cursor.
    private(set) var damageBoundsComplete = true
    /// Cursor-tracking state.
    private var caretRecognition = CaretRecognition.empty
    /// Tracking state from before the latest `prepare`, restored if that picture is dropped.
    private var recognitionBeforePrepare: CaretRecognition?

    /// True only after a picture has been successfully delivered to the stream.
    var hasDeliveredHistory: Bool { valid }

    /// Prepare one encoder input. Only visible row bytes count; row padding is
    /// neither a picture nor safe history. Unknown storage stays conservative.
    /// The single owned buffer is bounded to 16 MiB and reused across inputs.
    /// Compares a new picture with the delivered one and stores it as the candidate for the next one.
    ///
    /// Only visible row bytes count; row padding is neither picture nor history. Buffers that are not
    /// BGRA, are larger than 4096 per side or 4 Mi pixels, or cannot be read clear the history.
    ///
    /// Returns `false` only when the picture is pixel-identical to the delivered one and need not be
    /// encoded; `true` otherwise (including when there is no history yet). It also fills in
    /// `damageKind`, `damageBounds`, `changedPixels` and `damageBoundsComplete`. History is not
    /// updated until `delivered` is called.
    /// - Parameters:
    ///   - pixel: The frame, read-only; it is locked only during the call.
    ///   - now: Monotonic seconds, for blink timing.
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

    /// Seed exact-pixel history only after the first picture has reached the stream.
    /// Stores a picture as delivered history. Call after the first picture has reached the stream.
    func seedAfterFirstPaint(_ pixel: CVPixelBuffer) {
        _ = prepare(pixel)
        delivered()
    }

    /// Confirms the prepared picture reached the viewer, so it becomes the comparison baseline.
    func delivered() {
        valid = prepared
        recognitionBeforePrepare = nil
    }
    /// The prepared picture was not delivered. History stays valid only if that picture was identical
    /// to the delivered one, and cursor tracking returns to its earlier state.
    func dropped() {
        // A failed repair/sharp refresh still has the same delivered picture.
        // Preserve that knowledge so duplicates cannot demote its pending retry.
        valid = prepared && alreadyDelivered
        if let previous = recognitionBeforePrepare { caretRecognition = previous }
        recognitionBeforePrepare = nil
    }
    /// Forgets all history and tracking, for a new stream or a size change.
    func reset() {
        bytes = Data(); width = 0; height = 0
        valid = false; prepared = false; alreadyDelivered = false
        damageKind = .content; damageBounds = nil; changedPixels = 0; damageBoundsComplete = true
        caretRecognition = .empty; recognitionBeforePrepare = nil
    }

    /// Copies the before and after pixels of `bounds` out of the two buffers, each with its own row
    /// stride in bytes.
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

    /// Decides whether a change inside `bounds` is a blinking cursor, updating the tracking state.
    ///
    /// A cursor must first be seen as an anchor shape, then again with the same exact pixels at a
    /// blink-cycle interval, before changes are reported as `.caret`; intermediate fades are `.caret`
    /// only after the same fade has also recurred. Everything else is `.content` and usually resets
    /// the tracking.
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

    /// True when the shape could be the full-strength cursor.
    private func isCaretAnchor(_ bounds: PixelDamageBounds) -> Bool {
        guard bounds.width <= Self.maximumCaretWidth,
              bounds.height >= Self.minimumCaretHeight,
              bounds.height <= Self.maximumScannedDamageHeight else { return false }
        // Nine-pixel changes are anchors only at the measured 17-pixel shape.
        // Other nine-pixel heights remain fades and must match an established anchor.
        return bounds.width < Self.maximumCaretWidth
            || bounds.height == Self.measuredNinePixelCaretAnchorHeight
    }

    /// True when two anchor shapes are close enough in position and size to be one cursor.
    private func isSameCaretAnchor(_ left: PixelDamageBounds, _ right: PixelDamageBounds) -> Bool {
        abs(left.x - right.x) <= Self.maximumCaretAnchorPositionDelta
            && abs(left.y - right.y) <= Self.maximumCaretAnchorPositionDelta
            && abs(left.width - right.width) <= Self.maximumCaretAnchorWidthDelta
            && abs(left.height - right.height) <= Self.maximumCaretHeightDelta
    }

    /// True when `bounds` is close enough to `anchor` to be that cursor's intermediate fade.
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

    /// True when `interval` seconds fits a blink cycle.
    private func isBlinkInterval(_ interval: Double) -> Bool {
        interval >= Self.minimumBlinkInterval && interval <= Self.maximumBlinkInterval
    }

    /// Same as `isBlinkInterval`, for use from nested types; also rejects non-finite values.
    private static func blinkInterval(_ interval: Double) -> Bool {
        interval.isFinite && interval >= minimumBlinkInterval && interval <= maximumBlinkInterval
    }
}
