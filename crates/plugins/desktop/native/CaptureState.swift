/// Role: framework-free geometry and event-driven encoding/control decisions shared with deterministic tests [D200,D208,D266].
/// Everything here is plain value logic with no capture or window-server calls, so it is
/// compiled and unit-tested on any platform. All times are seconds on a monotonic clock
/// (`ProcessInfo.systemUptime`) and are passed in, never read, which keeps the code deterministic.
import Foundation
#if canImport(CoreGraphics)
// Foundation supplies geometry on Linux; Apple SDK geometry operations live here.
import CoreGraphics
#endif

/// Executable basenames used only for factual process detection [D290].
/// Names of the tiling window managers that are known to fight over window sizes.
/// Only the names of running executables are compared; nothing else about them is read.
let tilingManagerExecutables: Set<String> = [
    "OmniWM", "yabai", "AeroSpace", "Amethyst", "paneru", "glide"
]

/// A single externally undone resize permanently yields ownership to the desktop.
/// The monotonic two-second observation window includes asynchronous AX notifications.
/// Decides whether the infraternal agent may resize a shared window or must leave it to the desktop.
///
/// When the infraternal agent resizes a window to match a viewer and something else (a tiling
/// manager) immediately undoes it, resizing again would start a fight. This struct notices that
/// once, sets `managed`, and never lets go of it. Feed it the window size actually observed
/// after each `attempt`.
struct WindowResizeOwnership {
    /// True once the desktop is known to own this window's size. Never goes back to false.
    private(set) var managed = false
    /// Size requested by the last accepted `attempt`, which `observe` checks against.
    private var expected: CGSize?
    /// Time of the last accepted `attempt`, bounding the observation window.
    private var attemptedAt: Double?
    /// Last size requested, so the same size is not requested a second time.
    private var attempted: CGSize?

    /// Records that a tiling manager is running. Passing `false` never clears `managed`.
    mutating func detectManager(_ present: Bool) { managed = managed || present }

    /// Reports the window size seen after an `attempt`.
    ///
    /// If it differs from the requested size (within 1 point) and the report arrives no more than
    /// two seconds after the attempt, the desktop undid the resize and `managed` latches. Reports
    /// with a non-finite time, a time before the attempt, or a late time are ignored; late ones
    /// are more likely the user resizing than a manager.
    /// - Parameters:
    ///   - actual: Current window size in points.
    ///   - now: Monotonic seconds.
    mutating func observe(_ actual: CGSize, at now: Double) {
        guard !managed, let expected, let attemptedAt, now.isFinite,
              now >= attemptedAt, now - attemptedAt <= 2 else { return }
        if !matches(actual, expected) { managed = true }
    }

    /// Asks whether a resize to `desired` should be sent now.
    ///
    /// Returns `true` (and remembers the request) only when the window is not managed, `desired`
    /// is a finite positive size, the window is not already that size, and this exact size was not
    /// already requested. Returns `false` otherwise, in which case the caller must not resize.
    /// - Parameters:
    ///   - desired: Wanted window size in points.
    ///   - actual: Current window size in points.
    ///   - now: Monotonic seconds.
    mutating func attempt(_ desired: CGSize, actual: CGSize, at now: Double) -> Bool {
        guard !managed, now.isFinite, desired.width.isFinite, desired.height.isFinite,
              desired.width > 0, desired.height > 0,
              !matches(actual, desired), attempted.map({ !matches($0, desired) }) ?? true else { return false }
        // A refused or constrained AX request is never retried by a timer. A new
        // canvas size may request once again, unless managed ownership latched.
        attempted = desired; expected = desired; attemptedAt = now
        return true
    }

    /// Two sizes are the same when both sides differ by less than one point (rounding noise).
    private func matches(_ a: CGSize, _ b: CGSize) -> Bool {
        abs(a.width - b.width) < 1 && abs(a.height - b.height) < 1
    }
}

/// Where picture content lands inside an output frame when it is scaled to fit and centered
/// (letterboxed or pillarboxed), keeping its aspect ratio.
///
/// Returns a rectangle in output pixels, or `.zero` if any size is empty or negative.
/// - Parameters:
///   - rect: The source area (any units; only its size matters).
///   - output: The size of the encoded frame in pixels.
func fittedContent(_ rect: CGRect, _ output: CGSize) -> CGRect {
    guard rect.width > 0, rect.height > 0, output.width > 0, output.height > 0 else { return .zero }
    let scale = min(output.width / rect.width, output.height / rect.height)
    let size = CGSize(width: rect.width * scale, height: rect.height * scale)
    return CGRect(x: (output.width - size.width) / 2, y: (output.height - size.height) / 2, width: size.width, height: size.height)
}

/// Converts a point in the encoded frame back to a point in the source area, for input.
///
/// `x` and `y` are in output pixels. Returns the point in `source` coordinates, or `nil` when
/// any value is not finite or the point falls in the letterbox bars outside the picture.
/// - Parameters:
///   - source: The captured area in screen points.
///   - output: The size of the encoded frame in pixels.
func mappedPoint(x: Double, y: Double, source: CGRect, output: CGSize) -> CGPoint? {
    guard [x, y, source.minX, source.minY, source.width, source.height, output.width, output.height].allSatisfy({ $0.isFinite }) else { return nil }
    let content = fittedContent(source, output)
    // Half-open output bounds prevent the last pixel mapping into an adjacent display.
    guard content.width > 0, content.height > 0, x >= content.minX, y >= content.minY, x < content.maxX, y < content.maxY else { return nil }
    return CGPoint(x: source.minX + (x - content.minX) * source.width / content.width,
                   y: source.minY + (y - content.minY) * source.height / content.height)
}

/// Tracks the last time the person at the Mac used the keyboard or mouse, so remote input can
/// step aside. Remote (tagged) events never count as local activity.
struct LocalInputPause {
    /// Monotonic seconds of the latest local event.
    private(set) var lastLocal: Double
    /// Notes an input event. Returns `true` when it was local and was counted, `false` for remote
    /// events and non-finite times.
    mutating func observe(at now: Double, remote: Bool) -> Bool {
        guard !remote, now.isFinite else { return false }
        lastLocal = max(lastLocal, now)
        return true
    }
    /// Seconds since the last local input, never negative; 0 for a non-finite `now`.
    func idle(at now: Double) -> Double { now.isFinite ? max(0, now - lastLocal) : 0 }
    /// True when the local user has been idle for at least two seconds, so remote input may act.
    func permits(at now: Double) -> Bool { idle(at: now) >= 2 }
}

/// What the video encoder should do for the next captured picture.
enum EncodeDecision: Equatable {
    /// Encode a changed picture. `keyframe` forces a full (IDR) frame instead of a delta.
    case motion(keyframe: Bool)
    /// Encode a delta for a text-cursor blink only. It does not restart the settle timer.
    case caret
    /// Encode a sharp full keyframe of the settled, unchanged picture.
    case refresh
    /// Whether this decision must produce a keyframe.
    var keyframe: Bool {
        switch self {
        case .motion(let force): return force
        case .caret: return false
        case .refresh: return true
        }
    }
}

/// Event-driven scheduler for the encoder. It turns capture events (`changed`) and encoder
/// results (`completed`, `encoderDropped`) into the next `EncodeDecision`, with no timer: an idle
/// desktop encodes nothing. After motion stops for 0.25 s it owes one sharp `refresh`.
struct DamageEncodingState {
    /// A picture has been captured at least once.
    private var hasFrame = false
    /// A change arrived that has not been encoded yet.
    private var damaged = false
    /// The pending change was only a cursor blink.
    private var damagedCaret = false
    /// The next picture must be a keyframe (start, repair after loss, resize).
    private var keyframe = true
    /// Time after which the sharp refresh is due; `nil` when none is owed.
    private var settle: Double?
    /// A refresh was dropped by the encoder and must be tried again.
    private var retryRefresh = false
    /// Records that the captured picture changed.
    /// - Parameters:
    ///   - now: Monotonic seconds.
    ///   - caret: `true` if the change was only a cursor blink.
    mutating func changed(at now: Double, caret: Bool = false) {
        hasFrame = true
        damaged = true
        damagedCaret = caret
        // A blink is a real delta, but it does not postpone the one sharp
        // refresh owed after content motion or cancel a dropped refresh retry.
        if !caret {
            settle = now + 0.25
            retryRefresh = false
        }
    }
    /// Forces the next encoded picture to be a keyframe, after the viewer lost one.
    mutating func repair() { keyframe = true }
    /// Returns what to encode now, or `nil` if nothing is due. Call it after a capture event or when
    /// `refreshDeadline` is reached.
    mutating func next(at now: Double) -> EncodeDecision? {
        guard hasFrame else { return nil }
        if damaged {
            damaged = false
            let caret = damagedCaret && !keyframe
            damagedCaret = false
            return caret ? .caret : .motion(keyframe: keyframe)
        }
        if retryRefresh { retryRefresh = false; return .refresh }
        if keyframe { return .motion(keyframe: true) }
        if let settle, now >= settle { self.settle = nil; return .refresh }
        return nil
    }
    // A dropped encoder input never became a decoder reference. Only a lost
    // encoded picture needs repair; raw motion drops preserve the next delta.
    // Requested IDRs and sharp refreshes must still be fulfilled, even if the
    // window becomes static before another capture arrives.
    /// Reports that the encoder dropped a picture that `next` returned. Returns `true` when a
    /// keyframe is still owed to the viewer (the dropped picture was a keyframe or a refresh, which
    /// is also queued to be retried); a dropped plain delta returns `false` because the next delta
    /// still builds on the last picture the decoder received.
    mutating func encoderDropped(_ decision: EncodeDecision) -> Bool {
        if decision == .refresh { retryRefresh = true; return true }
        return decision.keyframe
    }
    /// Reports that an encoded picture was handled. When it was not `delivered`, the next picture
    /// becomes a keyframe because the viewer's decoder never saw it.
    mutating func completed(delivered: Bool) { keyframe = !delivered }
    /// When the sharp refresh is due, in monotonic seconds, or `nil`. A caller sleeps until then.
    var refreshDeadline: Double? { settle }
}

/// Raises and lowers the video bit rate (bits per second) based on delivery feedback.
///
/// Congestion cuts the rate to 70 percent (at most every 0.5 s, never below 500 kbit/s). Eight
/// healthy frames in a row raise it by 5 percent or 50 kbit/s, whichever is more (at most every
/// second, never above `maximum`).
struct AdaptiveBitrate {
    /// Highest allowed bit rate; at least 500 000.
    let maximum: Int
    /// The bit rate to use right now.
    private(set) var current: Int
    /// Time of the last change, to rate-limit changes.
    private var lastAdjustment = -Double.infinity
    /// Consecutive uncongested frames, capped at 8.
    private var healthy = 0
    /// Starts at `maximum`, which is raised to the 500 kbit/s floor if lower.
    init(maximum: Int) { self.maximum = max(500_000, maximum); current = self.maximum }
    // Feedback is per delivered/dropped frame; there is no timer on an idle desktop.
    // Reduce quality under pressure, never the source's capture rate.
    /// Reports one frame's outcome and returns the bit rate to use next.
    /// - Parameters:
    ///   - now: Monotonic seconds; non-finite values change nothing.
    ///   - congested: `true` if the frame was delayed or dropped.
    mutating func feedback(at now: Double, congested: Bool) -> Int {
        guard now.isFinite else { return current }
        if congested {
            healthy = 0
            if now - lastAdjustment >= 0.5 {
                current = max(500_000, current * 7 / 10); lastAdjustment = now
            }
        } else {
            healthy = min(healthy + 1, 8)
            if healthy == 8 && now - lastAdjustment >= 1 {
                current = min(maximum, current + max(50_000, current / 20)); lastAdjustment = now; healthy = 0
            }
        }
        return current
    }
}
