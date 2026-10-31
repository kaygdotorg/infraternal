/// Role: framework-free geometry and event-driven encoding/control decisions shared with deterministic tests [D200,D208,D266].
import Foundation
#if canImport(CoreGraphics)
// Foundation supplies geometry on Linux; Apple SDK geometry operations live here.
import CoreGraphics
#endif

/// Executable basenames used only for factual process detection [D290].
let tilingManagerExecutables: Set<String> = [
    "OmniWM", "yabai", "AeroSpace", "Amethyst", "paneru", "glide"
]

/// A single externally undone resize permanently yields ownership to the desktop.
/// The monotonic two-second observation window includes asynchronous AX notifications.
struct WindowResizeOwnership {
    private(set) var managed = false
    private var expected: CGSize?
    private var attemptedAt: Double?
    private var attempted: CGSize?

    mutating func detectManager(_ present: Bool) { managed = managed || present }

    mutating func observe(_ actual: CGSize, at now: Double) {
        guard !managed, let expected, let attemptedAt, now.isFinite,
              now >= attemptedAt, now - attemptedAt <= 2 else { return }
        if !matches(actual, expected) { managed = true }
    }

    mutating func attempt(_ desired: CGSize, actual: CGSize, at now: Double) -> Bool {
        guard !managed, now.isFinite, desired.width.isFinite, desired.height.isFinite,
              desired.width > 0, desired.height > 0,
              !matches(actual, desired), attempted.map({ !matches($0, desired) }) ?? true else { return false }
        // A refused or constrained AX request is never retried by a timer. A new
        // canvas size may request once again, unless managed ownership latched.
        attempted = desired; expected = desired; attemptedAt = now
        return true
    }

    private func matches(_ a: CGSize, _ b: CGSize) -> Bool {
        abs(a.width - b.width) < 1 && abs(a.height - b.height) < 1
    }
}

func fittedContent(_ rect: CGRect, _ output: CGSize) -> CGRect {
    guard rect.width > 0, rect.height > 0, output.width > 0, output.height > 0 else { return .zero }
    let scale = min(output.width / rect.width, output.height / rect.height)
    let size = CGSize(width: rect.width * scale, height: rect.height * scale)
    return CGRect(x: (output.width - size.width) / 2, y: (output.height - size.height) / 2, width: size.width, height: size.height)
}

func mappedPoint(x: Double, y: Double, source: CGRect, output: CGSize) -> CGPoint? {
    guard [x, y, source.minX, source.minY, source.width, source.height, output.width, output.height].allSatisfy({ $0.isFinite }) else { return nil }
    let content = fittedContent(source, output)
    // Half-open output bounds prevent the last pixel mapping into an adjacent display.
    guard content.width > 0, content.height > 0, x >= content.minX, y >= content.minY, x < content.maxX, y < content.maxY else { return nil }
    return CGPoint(x: source.minX + (x - content.minX) * source.width / content.width,
                   y: source.minY + (y - content.minY) * source.height / content.height)
}

struct LocalInputPause {
    private(set) var lastLocal: Double
    mutating func observe(at now: Double, remote: Bool) -> Bool {
        guard !remote, now.isFinite else { return false }
        lastLocal = max(lastLocal, now)
        return true
    }
    func idle(at now: Double) -> Double { now.isFinite ? max(0, now - lastLocal) : 0 }
    func permits(at now: Double) -> Bool { idle(at: now) >= 2 }
}

enum EncodeDecision: Equatable {
    case motion(keyframe: Bool)
    case caret
    case refresh
    var keyframe: Bool {
        switch self {
        case .motion(let force): return force
        case .caret: return false
        case .refresh: return true
        }
    }
}

struct DamageEncodingState {
    private var hasFrame = false
    private var damaged = false
    private var damagedCaret = false
    private var keyframe = true
    private var settle: Double?
    private var retryRefresh = false
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
    mutating func repair() { keyframe = true }
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
    mutating func encoderDropped(_ decision: EncodeDecision) -> Bool {
        if decision == .refresh { retryRefresh = true; return true }
        return decision.keyframe
    }
    mutating func completed(delivered: Bool) { keyframe = !delivered }
    var refreshDeadline: Double? { settle }
}

struct AdaptiveBitrate {
    let maximum: Int
    private(set) var current: Int
    private var lastAdjustment = -Double.infinity
    private var healthy = 0
    init(maximum: Int) { self.maximum = max(500_000, maximum); current = self.maximum }
    // Feedback is per delivered/dropped frame; there is no timer on an idle desktop.
    // Reduce quality under pressure, never the source's capture rate.
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
