/// Role: framework-free geometry and event-driven encoding/control decisions shared with deterministic tests [D200,D208,D266].
import Foundation
#if canImport(CoreGraphics)
// Foundation supplies geometry on Linux; Apple SDK geometry operations live here.
import CoreGraphics
#endif

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
    case refresh
    var keyframe: Bool { switch self { case .motion(let force): return force; case .refresh: return true } }
}

struct DamageEncodingState {
    private var hasFrame = false
    private var damaged = false
    private var keyframe = true
    private var settle: Double?
    private var retryRefresh = false
    mutating func changed(at now: Double) {
        hasFrame = true; damaged = true; settle = now + 0.25
    }
    mutating func repair() { keyframe = true }
    mutating func next(at now: Double) -> EncodeDecision? {
        guard hasFrame else { return nil }
        if damaged { damaged = false; retryRefresh = false; return .motion(keyframe: keyframe) }
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
