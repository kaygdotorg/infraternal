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
    /// Applied size, or requested size until acknowledged, which `observe` checks against.
    private var expected: CGSize?
    /// Size before the request, so an unchanged AX read cannot hide an immediate external undo.
    private var before: CGSize?
    /// Time of the last accepted `attempt`, bounding the observation window.
    private var attemptedAt: Double?
    /// Last size requested, so the same size is not requested a second time.
    private var attempted: CGSize?

    /// Records that a tiling manager is running. Passing `false` never clears `managed`.
    mutating func detectManager(_ present: Bool) { managed = managed || present }

    /// Records the size Accessibility actually applied, including an app's size constraints.
    /// Call immediately after a successful size request, before processing later notifications.
    mutating func applied(_ actual: CGSize) {
        guard !managed, let before, actual.width.isFinite, actual.height.isFinite,
              actual.width > 0, actual.height > 0, !matches(actual, before) else { return }
        expected = actual
    }

    /// Reports the window size seen after an `attempt`.
    ///
    /// If it differs from the applied size (or requested size before acknowledgment, within 1 point)
    /// and the report arrives no more than
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
        attempted = desired; expected = desired; before = actual; attemptedAt = now
        return true
    }

    /// Two sizes are the same when both sides differ by less than one point (rounding noise).
    private func matches(_ a: CGSize, _ b: CGSize) -> Bool {
        abs(a.width - b.width) < 1 && abs(a.height - b.height) < 1
    }
}

/// Compares native point frames while allowing for sub-point rounding.
func sameWindowFrame(_ a: CGRect, _ b: CGRect) -> Bool {
    abs(a.minX - b.minX) < 1 && abs(a.minY - b.minY) < 1
        && abs(a.width - b.width) < 1 && abs(a.height - b.height) < 1
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
    /// Encode the settled, unchanged picture once more as a delta, at the sharp budget. A few of
    /// these sharpen a picture where only small areas changed, at a fraction of a keyframe's bytes.
    case refine
    /// Whether this decision must produce a keyframe.
    var keyframe: Bool {
        switch self {
        case .motion(let force): return force
        case .caret, .refine: return false
        case .refresh: return true
        }
    }
    /// Whether this decision re-encodes the settled picture at the larger sharp budget.
    var sharp: Bool { self == .refresh || self == .refine }
}

/// How the settled sharp refresh is sent, from how much of the picture changed since the last
/// sharp one and from the encoder's rate control [D200 V2, #146].
///
/// After small changes (typing) most of the picture is still the sharp one the viewer has, so a
/// few delta frames at the sharp budget beat a forced keyframe at a fraction of its bytes. On the
/// M1 at 1.56 MP (J1115): three passes reached 46.0 dB in 224 KB against the keyframe's 40.3 dB
/// in 610 KB (real-time mode), and 40.8 dB in 128 KB against 36.9 dB in 414 KB (low-latency
/// mode). After heavy motion (a scroll, a new page) the modes differ. In the low-latency mode
/// deltas plateau (31.2 dB after 8 passes against the keyframe's 36.1 dB, J1078 and J1115), so
/// the keyframe stays. In the ordinary real-time mode the keyframe itself is poor (31.2 dB in
/// 385 KB) while 8 delta passes reach 37.8 dB in 336 KB, so heavy motion is refined too.
struct SharpRefreshPlan: Equatable {
    /// Above this fraction of picture rows touched since the last sharp picture, the motion was heavy.
    static let heavyMotionFraction = 0.25
    /// Delta passes after small changes.
    static let smallChangePasses = 3
    /// Delta passes after heavy motion; 0 sends one forced keyframe instead.
    let heavyMotionPasses: Int
    /// The plan for an encoder's rate control: refine heavy motion in 8 passes in the ordinary
    /// real-time mode, keep the keyframe in the low-latency mode.
    init(mode: EncoderRateMode) { heavyMotionPasses = mode == .realtime ? 8 : 0 }
    /// How many refinement passes a refresh that is due now gets, where `touched` is the fraction
    /// (0...1) of rows changed since the last sharp picture; 0 means one forced keyframe. A
    /// non-finite `touched` counts as heavy motion.
    func passes(touched: Double) -> Int {
        touched.isFinite && touched <= Self.heavyMotionFraction ? Self.smallChangePasses : heavyMotionPasses
    }
}

/// Event-driven scheduler for the encoder. It turns capture events (`changed`) and encoder
/// results (`completed`, `encoderDropped`) into the next `EncodeDecision`, with no timer: an idle
/// desktop encodes nothing. After motion stops for 0.25 s it owes one sharp refresh: a few
/// `refine` deltas, or one keyframe `refresh`, as `plan` says.
struct DamageEncodingState {
    /// How the settled sharp refresh is sent. The default keeps a keyframe after heavy motion.
    var plan = SharpRefreshPlan(mode: .lowLatency)
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
    /// Delta refinement passes still owed for the settled picture; 0 when none.
    private var refinementsLeft = 0
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
            // Refinement sharpens a picture that is no longer the newest one;
            // the new settle deadline owes a fresh plan for the new picture.
            refinementsLeft = 0
        }
    }
    /// Records a change that went out exactly as a tile update [#146 proposal C]. A tile owes no sharp
    /// refresh, but a refresh already owed (after earlier video motion) waits until changes stop, as it
    /// does for motion: refreshing while someone types would only send a large keyframe that the next
    /// tiles and deltas make stale at once.
    /// Refinement passes already under way stop the same way: they sharpen a picture that typing is
    /// changing again, so the rest becomes an owed refresh 0.25 s after this tile.
    mutating func postponeRefresh(at now: Double) {
        if refinementsLeft > 0 { refinementsLeft = 0; settle = now }
        if settle != nil { settle = now + 0.25 }
    }
    /// Forces the next encoded picture to be a keyframe, after the viewer lost one.
    mutating func repair() { keyframe = true }
    /// Returns what to encode now, or `nil` if nothing is due. Call it after a capture event or when
    /// `refreshDeadline` is reached.
    /// - Parameters:
    ///   - now: Monotonic seconds.
    ///   - touched: Fraction of picture rows changed since the last sharp picture, read only when
    ///     a refresh starts. The default (everything) keeps the keyframe refresh.
    mutating func next(at now: Double, touched: Double = 1) -> EncodeDecision? {
        guard hasFrame else { return nil }
        if damaged {
            damaged = false
            let caret = damagedCaret && !keyframe
            damagedCaret = false
            return caret ? .caret : .motion(keyframe: keyframe)
        }
        if retryRefresh { retryRefresh = false; return .refresh }
        if keyframe {
            // A keyframe at the motion budget replaces the picture being refined;
            // deltas cannot make it sharp everywhere, so the rest becomes a refresh.
            if refinementsLeft > 0 { refinementsLeft = 0; retryRefresh = true }
            return .motion(keyframe: true)
        }
        if refinementsLeft > 0 { refinementsLeft -= 1; return .refine }
        if let settle, now >= settle {
            self.settle = nil
            let passes = plan.passes(touched: touched)
            guard passes > 0 else { return .refresh }
            refinementsLeft = passes - 1
            return .refine
        }
        return nil
    }
    // A dropped encoder input never became a decoder reference, so no drop needs
    // reference repair; only a lost encoded picture does. But a dropped picture
    // is still owed: the viewer would otherwise keep the older one until the
    // settled refresh, 250 ms later. Every drop is retried at the next source
    // tick (the caller's timer), and a newer capture replaces the retry.
    /// Reports that the encoder dropped a picture that `next` returned. Returns `true` when that
    /// picture is still owed, so the caller retries at the next source tick: always, because a
    /// dropped motion or caret delta leaves the viewer on an older picture, a dropped keyframe or
    /// refresh still owes its keyframe, and a dropped refinement pass still owes its pass. No drop
    /// forces a keyframe: the next delta still builds on the last picture the decoder received.
    mutating func encoderDropped(_ decision: EncodeDecision) -> Bool {
        switch decision {
        case .refresh: retryRefresh = true
        case .refine: refinementsLeft += 1
        case .motion, .caret: damaged = true; damagedCaret = decision == .caret
        }
        return true
    }
    /// Reports that an encoded picture was handled. When it was not `delivered`, the next picture
    /// becomes a keyframe because the viewer's decoder never saw it.
    mutating func completed(delivered: Bool) { keyframe = !delivered }
    /// True while refinement passes for the settled picture are still owed. When a delivered
    /// `refine` leaves this false, the picture is sharp.
    var refining: Bool { refinementsLeft > 0 }
    /// When the sharp refresh is due, in monotonic seconds, or `nil`. A caller sleeps until then.
    var refreshDeadline: Double? { settle }
}

/// Which VideoToolbox rate control the hardware encoder uses [D204, #146].
///
/// `realtime` is the ordinary real-time session with a data-rate cap; `lowLatency` is the
/// session with low-latency rate control that shipped before J1115. On the M1 at 1.56 MP and
/// 120 Hz the low-latency mode took 9.5 ms p50 and 14.3 ms p95 per frame against 6.8 and 6.9,
/// and a 0.28 MP window scrolling at 120 Hz dropped 139 of 160 frames against none (J1115 on
/// #146; J1078 found the same direction), so `realtime` is the default. The other mode stays one
/// setting away until the owner's M2 Max numbers are in: the companion reads the user default
/// `EncoderRateMode` (`realtime` or `low-latency`), for example
/// `defaults write com.infraternal.desktop.helper EncoderRateMode low-latency`, or the same
/// pair as launch arguments (`-EncoderRateMode low-latency`).
enum EncoderRateMode: String {
    /// Ordinary real-time rate control with `dataRateLimits`.
    case realtime
    /// Low-latency rate control, as before J1115.
    case lowLatency = "low-latency"
    /// The user-default key that selects the mode.
    static let settingKey = "EncoderRateMode"
    /// The mode named by a setting value; anything missing or unknown is `realtime`.
    init(setting value: String?) { self = value.flatMap(EncoderRateMode.init(rawValue:)) ?? .realtime }
    /// The data-rate cap for the ordinary real-time mode, as VideoToolbox `DataRateLimits` pairs of
    /// (bytes, window seconds) for an average of `bitsPerSecond`; empty for `lowLatency`, whose
    /// own rate control already holds the budget. Without a cap the ordinary mode treats a pause
    /// as saved budget and spends it on the next typed letter: 30.6 KB per letter after a 150 ms
    /// pause at 1.56 MP on the M1, against 250 bytes with this cap (J1115). The cap allows 1.5x
    /// the average over any second. Measured and rejected: 1x (scrolling fell from 30.2 to 24.6
    /// dB), and an extra 3x-over-100 ms window (no gain; it starved the first refinement pass).
    /// The encoder treats the cap as a target, not a wall: a 0.28 MP window scrolling at 120 Hz
    /// still sent 2.9 Mbit/s against a 1.25 Mbit/s cap.
    func dataRateLimits(bitsPerSecond: Int) -> [(bytes: Int, seconds: Double)] {
        guard self == .realtime, bitsPerSecond > 0 else { return [] }
        return [(Int(Double(bitsPerSecond) / 8 * 1.5), 1)]
    }
}

/// Raises and lowers the video bit rate (bits per second) based on delivery feedback.
///
/// Congestion cuts the rate to 70 percent (at most every 0.5 s, never below 500 kbit/s). Eight
/// healthy frames in a row raise it by 5 percent or 50 kbit/s, whichever is more (at most every
/// second, never above `maximum`).
///
/// When the server has measured the viewer's link (`linkRate`), a congestion report cuts straight
/// to 85 percent of that rate instead, which a 70 percent step may overshoot several times over,
/// each overshoot costing a keyframe repair on a slow link. The rate then stays at or under
/// that figure for 60 s, so the controller does not climb back into the same queue every few
/// seconds; after that it probes upward again and the next report corrects it.
struct AdaptiveBitrate {
    /// Highest allowed bit rate; at least 500 000.
    let maximum: Int
    /// The bit rate to use right now.
    private(set) var current: Int
    /// Time of the last change, to rate-limit changes.
    private var lastAdjustment = -Double.infinity
    /// Consecutive uncongested frames, capped at 8.
    private var healthy = 0
    /// The highest rate the last measured link allows, and the time that limit ends.
    private var linkLimit: (rate: Int, until: Double)?
    /// Share of a measured link rate the encoder aims for, in percent.
    static let linkShare = 85
    /// How long a measured link rate limits probing upward, in seconds.
    static let linkHold = 60.0
    /// Starts at `maximum`, which is raised to the 500 kbit/s floor if lower.
    init(maximum: Int) { self.maximum = max(500_000, maximum); current = self.maximum }
    // Feedback is per delivered/dropped frame; there is no timer on an idle desktop.
    // Reduce quality under pressure, never the source's capture rate.
    /// Reports one frame's outcome and returns the bit rate to use next.
    /// - Parameters:
    ///   - now: Monotonic seconds; non-finite values change nothing.
    ///   - congested: `true` if the frame was delayed or dropped.
    ///   - linkRate: With `congested`, the viewer's measured link rate in bits per second, if known.
    mutating func feedback(at now: Double, congested: Bool, linkRate: Int? = nil) -> Int {
        guard now.isFinite else { return current }
        if congested {
            healthy = 0
            var target = max(500_000, current * 7 / 10)
            if let linkRate, linkRate > 0 {
                let aim = max(500_000, Int(clamping: Int64(linkRate) * Int64(Self.linkShare) / 100))
                linkLimit = (aim, now + Self.linkHold)
                // A measured rate above the current one means the link is not the limit: take the usual step.
                if aim < current { target = aim }
            }
            if now - lastAdjustment >= 0.5 {
                current = min(current, target); lastAdjustment = now
            }
        } else {
            healthy = min(healthy + 1, 8)
            if healthy == 8 && now - lastAdjustment >= 1 {
                var ceiling = maximum
                if let linkLimit, now < linkLimit.until { ceiling = min(ceiling, linkLimit.rate) }
                current = min(ceiling, current + max(50_000, current / 20)); lastAdjustment = now; healthy = 0
            }
        }
        return current
    }
}
