/// Role: bounded exact BGRA history classifies caret cadence and cuts small changes into exact tiles [D254,D266,#146].
/// The capture framework reports damage regions, but a blinking text cursor can still look like
/// real content. This file compares the exact pixels of consecutive frames and recognizes a cursor
/// that blinks at a steady rate, so an idle editor does not keep restarting the sharp refresh.
/// Anything it cannot positively identify as a cursor is `content`: a wrong guess in that
/// direction only costs bandwidth, never a stale picture. Pixels are 32-bit BGRA.
///
/// The same comparison also finds the changed rows. When they fit a few small rectangles, the
/// tile lane (#146 proposal C) sends those exact pixels as a tile update instead of encoding a
/// whole video frame; `tileUpdate` builds that message from the stored history.
import CoreVideo
import Darwin
import Compression
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
    /// Largest changed area, in pixels, that `prepare` still describes as tile rectangles, counted
    /// after splitting them at unchanged columns. Zero (the default) turns the tile pass off, so
    /// only the caret scan runs.
    var tileAreaLimit = 0
    /// The changed rectangles of the latest prepared picture, at most `TileBands.maximumRectangles`
    /// of them with a total area within `tileAreaLimit`, top to bottom. `nil` when the picture is
    /// unchanged, has no comparable history, or changed too much to be sent as tiles.
    private(set) var tileRects: [PixelDamageBounds]?
    /// Rows found changed by the latest comparison, reused between calls to avoid allocation.
    private var changedRows: [Int] = []
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
        tileRects = nil
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
        // Row bands are tracked up to four times the limit: two changes on nearby rows (the caret left
        // at the end of a line and the letter typed at the start of the next) form one wide band that
        // the column split below cuts back to two small rectangles. The limit applies after the split.
        var bands = TileBands(limit: tileAreaLimit * 4)
        var splitRectangles: [PixelDamageBounds]?
        changedRows.removeAll(keepingCapacity: true)
        if comparable {
            bytes.withUnsafeBytes { old in
                let previous = old.baseAddress!
                for row in 0..<h {
                    let currentRow = base.advanced(by: row * stride)
                    let previousRow = previous.advanced(by: row * rowBytes)
                    if memcmp(currentRow, previousRow, rowBytes) == 0 { continue }
                    same = false
                    changedRows.append(row)
                    // Every changed row is recorded so only those rows are copied into the history
                    // below; once neither the caret scan nor the tile bands need detail, the rest of
                    // the frame is still compared, never copied.
                    if !damageBoundsComplete && !bands.tracking { continue }
                    // Pixels outside [first, last] are equal, so skipping them keeps the caret
                    // scan's raster-order counts and limits exactly as a full-row walk.
                    let first = Self.firstDifferentPixel(currentRow, previousRow, width: w)
                    let last = Self.lastDifferentPixel(currentRow, previousRow, width: w)
                    bands.add(row: row, first: first, last: last)
                    guard damageBoundsComplete else { continue }
                    for column in first...last {
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
                }
                if let rectangles = bands.rectangles {
                    splitRectangles = Self.splitAtUnchangedColumns(rectangles, current: base, currentStride: stride, previous: previous, previousStride: rowBytes)
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
        tileRects = comparable && !same ? splitRectangles.flatMap { rects in
            rects.reduce(0) { $0 + $1.width * $1.height } <= tileAreaLimit ? rects : nil
        } : nil
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
        valid = false
        // Comparable history already holds every unchanged row, so only changed rows are copied;
        // a small change then costs one read of the frame instead of a read plus a full copy.
        let rows: [Int] = comparable ? changedRows : Array(0..<h)
        width = w; height = h
        if bytes.count != rowBytes * h { bytes = Data(count: rowBytes * h) }
        bytes.withUnsafeMutableBytes { destination in
            for row in rows {
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
        tileRects = nil
        caretRecognition = .empty; recognitionBeforePrepare = nil
    }

    /// Index of the leftmost pixel that differs between two rows of `width` BGRA pixels. The rows
    /// must differ somewhere; whole pixels are compared as 32-bit words.
    private static func firstDifferentPixel(_ current: UnsafeRawPointer, _ previous: UnsafeRawPointer, width: Int) -> Int {
        var column = 0
        while column < width - 1,
              current.loadUnaligned(fromByteOffset: column * 4, as: UInt32.self)
                == previous.loadUnaligned(fromByteOffset: column * 4, as: UInt32.self) { column += 1 }
        return column
    }

    /// Index of the rightmost pixel that differs between two rows of `width` BGRA pixels. The rows
    /// must differ somewhere.
    private static func lastDifferentPixel(_ current: UnsafeRawPointer, _ previous: UnsafeRawPointer, width: Int) -> Int {
        var column = width - 1
        while column > 0,
              current.loadUnaligned(fromByteOffset: column * 4, as: UInt32.self)
                == previous.loadUnaligned(fromByteOffset: column * 4, as: UInt32.self) { column -= 1 }
        return column
    }

    /// Unchanged columns that split one tile rectangle in two. Narrower gaps cost less to send
    /// than the extra rectangle header and the lost DEFLATE context.
    private static let tileColumnGap = 32

    /// Splits each rectangle where at least `tileColumnGap` columns are unchanged in all its rows,
    /// and trims each part to the rows that changed inside it. A row band holding two separate
    /// changes (a clock at the left of a status bar and a spinner at its right) becomes two small
    /// rectangles instead of one as wide as the window. If splitting would need more than
    /// `TileBands.maximumRectangles`, the rectangles are returned unsplit. The rectangles are
    /// within the tile area limit, so this compares at most that many pixels.
    private static func splitAtUnchangedColumns(
        _ rectangles: [PixelDamageBounds],
        current: UnsafeRawPointer, currentStride: Int,
        previous: UnsafeRawPointer, previousStride: Int
    ) -> [PixelDamageBounds] {
        func differs(_ x: Int, _ y: Int) -> Bool {
            current.loadUnaligned(fromByteOffset: y * currentStride + x * 4, as: UInt32.self)
                != previous.loadUnaligned(fromByteOffset: y * previousStride + x * 4, as: UInt32.self)
        }
        var result: [PixelDamageBounds] = []
        for rect in rectangles {
            var changed = [Bool](repeating: false, count: rect.width)
            for y in rect.y..<(rect.y + rect.height) {
                for column in 0..<rect.width where !changed[column] && differs(rect.x + column, y) { changed[column] = true }
            }
            var column = 0
            while column < rect.width {
                guard changed[column] else { column += 1; continue }
                var end = column, gap = 0, probe = column + 1
                while probe < rect.width, gap < tileColumnGap {
                    if changed[probe] { end = probe; gap = 0 } else { gap += 1 }
                    probe += 1
                }
                let left = rect.x + column, width = end - column + 1
                var top = rect.y + rect.height, bottom = rect.y - 1
                for y in rect.y..<(rect.y + rect.height) where (left..<(left + width)).contains(where: { differs($0, y) }) {
                    top = min(top, y); bottom = max(bottom, y)
                }
                result.append(PixelDamageBounds(x: left, y: top, width: width, height: bottom - top + 1))
                column = end + 1
            }
        }
        return result.count <= TileBands.maximumRectangles ? result : rectangles
    }

    /// Builds a tile update (see `tileUpdate(width:height:rects:pixels:)`) for `rects` from the
    /// picture the latest `prepare` stored. Call it after `prepare` and before the next one, with
    /// rectangles inside that picture (normally `tileRects`). Returns `nil` when there is no stored
    /// picture or a rectangle falls outside it.
    func tileUpdate(_ rects: [PixelDamageBounds]) -> Data? {
        guard prepared, width > 0, height > 0 else { return nil }
        return bytes.withUnsafeBytes { stored in
            InfraternalDesktop.tileUpdate(width: width, height: height, rects: rects, pixels: stored)
        }
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

/// Collects the changed rows of one picture into at most `maximumRectangles` rectangles for the
/// tile lane [#146 proposal C].
///
/// Feed it each changed row top to bottom with its first and last changed column. Rows closer than
/// `rowGap` unchanged rows join the current rectangle, which widens to cover both. Tracking stops
/// for good (`tracking` becomes false) once the total area passes `limit` or more rectangles would
/// be needed; the picture then goes to video. A `limit` of zero never tracks.
struct TileBands {
    /// The most rectangles one tile update carries; more scattered changes go to video.
    static let maximumRectangles = 8
    /// Unchanged rows that may sit inside one rectangle. Text lines changing together (a letter
    /// and its caret, a wrapped word) stay one rectangle instead of several thin ones.
    static let rowGap = 4
    /// Largest total area in pixels.
    let limit: Int
    /// Finished rectangles, top to bottom.
    private var closed: [PixelDamageBounds] = []
    /// Total area of `closed`.
    private var closedArea = 0
    /// The rectangle still growing: top row, bottom row, left and right columns (inclusive).
    private var open: (top: Int, bottom: Int, left: Int, right: Int)?
    /// False once the change is too large or scattered for tiles, or when `limit` is zero.
    private(set) var tracking: Bool

    /// Starts empty. `limit` is the largest total area, in pixels, still worth tracking.
    init(limit: Int) { self.limit = limit; tracking = limit > 0 }

    /// Adds one changed row. `first` and `last` are its outermost changed columns, inclusive.
    mutating func add(row: Int, first: Int, last: Int) {
        guard tracking else { return }
        if var current = open, row - current.bottom - 1 <= Self.rowGap {
            current.bottom = row; current.left = min(current.left, first); current.right = max(current.right, last)
            open = current
        } else {
            if let current = open {
                closed.append(PixelDamageBounds(x: current.left, y: current.top, width: current.right - current.left + 1, height: current.bottom - current.top + 1))
                closedArea += closed.last!.width * closed.last!.height
            }
            open = (row, row, first, last)
        }
        let current = open!
        let area = closedArea + (current.right - current.left + 1) * (current.bottom - current.top + 1)
        if closed.count + 1 > Self.maximumRectangles || area > limit { tracking = false; closed = []; open = nil }
    }

    /// The rectangles, or `nil` when tracking stopped. Empty when no row was added.
    var rectangles: [PixelDamageBounds]? {
        guard tracking else { return nil }
        guard let current = open else { return closed }
        return closed + [PixelDamageBounds(x: current.left, y: current.top, width: current.right - current.left + 1, height: current.bottom - current.top + 1)]
    }
}

/// Namespace so the free tile builder can be named from inside `FramePixels`, whose method has the
/// same base name.
enum InfraternalDesktop {
    /// First byte of a tile update. An H.264 or HEVC Annex B access unit always starts with a zero
    /// byte (its start code), so one byte tells the two kinds apart.
    static let tileMagic: UInt8 = 0xF7
    /// Second byte of a tile update ("T").
    static let tileMagic2: UInt8 = 0x54
    /// Format version of the tile update.
    static let tileVersion: UInt8 = 1
    /// Tile pixels are stored as they are.
    static let tileRaw: UInt8 = 0
    /// Tile pixels are compressed as raw DEFLATE (RFC 1951, no zlib or gzip wrapper).
    static let tileDeflate: UInt8 = 1

    /// Builds one tile update: exact pixels for a few changed rectangles of a picture, sent in the
    /// video stream instead of an encoded frame when the change is small [#146 proposal C].
    ///
    /// Layout, big-endian:
    /// `0xF7 'T' | version u8 = 1 | encoding u8 (0 raw, 1 raw DEFLATE) | width u16 | height u16 |
    ///  count u8 (1...8) | count × (x u16, y u16, w u16, h u16) | pixel bytes u32 | data`.
    /// `width`/`height` is the picture the rectangles belong to; a viewer showing another size
    /// ignores the update. The pixel bytes are every rectangle's RGBA rows (alpha 255), rectangle
    /// after rectangle, and `pixel bytes` is their length before compression. DEFLATE is used only
    /// when it is smaller. Returns `nil` for no rectangles, too many, or one outside the picture.
    /// - Parameters:
    ///   - width: Picture width in pixels.
    ///   - height: Picture height in pixels.
    ///   - rects: Changed rectangles in picture pixels.
    ///   - pixels: The picture as packed BGRA rows (`width * 4` bytes per row).
    static func tileUpdate(width: Int, height: Int, rects: [PixelDamageBounds], pixels: UnsafeRawBufferPointer) -> Data? {
        guard !rects.isEmpty, rects.count <= TileBands.maximumRectangles,
              width > 0, height > 0, width <= 4096, height <= 4096,
              pixels.count >= width * height * 4,
              rects.allSatisfy({ $0.x >= 0 && $0.y >= 0 && $0.width > 0 && $0.height > 0 && $0.x + $0.width <= width && $0.y + $0.height <= height })
        else { return nil }
        let rawLength = rects.reduce(0) { $0 + $1.width * $1.height * 4 }
        var raw = [UInt8](repeating: 0, count: rawLength)
        var offset = 0
        let source = pixels.bindMemory(to: UInt8.self)
        for rect in rects {
            for row in rect.y..<(rect.y + rect.height) {
                var index = (row * width + rect.x) * 4
                for _ in 0..<rect.width {
                    // Capture delivers BGRA; canvas image data is RGBA. Alpha is forced opaque
                    // because the picture is opaque and the canvas has no alpha.
                    raw[offset] = source[index + 2]; raw[offset + 1] = source[index + 1]
                    raw[offset + 2] = source[index]; raw[offset + 3] = 255
                    offset += 4; index += 4
                }
            }
        }
        var compressed = [UInt8](repeating: 0, count: rawLength)
        // COMPRESSION_ZLIB is raw DEFLATE; 0 means "did not fit", so DEFLATE is never larger.
        let deflated = compression_encode_buffer(&compressed, rawLength, raw, rawLength, nil, COMPRESSION_ZLIB)
        var unit = Data([tileMagic, tileMagic2, tileVersion, deflated > 0 ? tileDeflate : tileRaw])
        func u16(_ value: Int) { unit.append(UInt8(value >> 8)); unit.append(UInt8(value & 0xFF)) }
        u16(width); u16(height)
        unit.append(UInt8(rects.count))
        for rect in rects { u16(rect.x); u16(rect.y); u16(rect.width); u16(rect.height) }
        for shift in [24, 16, 8, 0] { unit.append(UInt8((rawLength >> shift) & 0xFF)) }
        if deflated > 0 { unit.append(contentsOf: compressed[0..<deflated]) } else { unit.append(contentsOf: raw) }
        return unit
    }
}
