/// Role: deterministic coordinate, local-priority and encoding simulations without Mac frameworks [D208,D266].
import Foundation
#if canImport(CoreGraphics)
import CoreGraphics
#endif

@main struct PolicyTests {
    static func main() {
        let source = CGRect(x: -1512, y: 90, width: 1512, height: 982)
        let output = CGSize(width: 1920, height: 1080)
        let content = fittedContent(source, output)
        assert(mappedPoint(x: content.midX, y: content.midY, source: source, output: output) == CGPoint(x: source.midX, y: source.midY))
        assert(mappedPoint(x: content.minX, y: content.minY, source: source, output: output) == source.origin)
        assert(mappedPoint(x: content.maxX, y: content.midY, source: source, output: output) == nil)
        assert(mappedPoint(x: content.midX, y: content.maxY, source: source, output: output) == nil)
        assert(mappedPoint(x: 0, y: 0, source: source, output: output) == nil)
        assert(mappedPoint(x: .nan, y: 0, source: source, output: output) == nil)
        assert(mappedPoint(x: 0, y: 0, source: .zero, output: output) == nil)
        // No extra Retina factor: source coordinates are points, input is output pixels.
        assert(mappedPoint(x: 100, y: 100, source: CGRect(x: 20, y: 40, width: 500, height: 300), output: CGSize(width: 1000, height: 600)) == CGPoint(x: 70, y: 90))
        var pause = LocalInputPause(lastLocal: 10)
        assert(!pause.permits(at: 11.999) && pause.permits(at: 12))
        assert(!pause.observe(at: 12.5, remote: true))
        assert(pause.permits(at: 12.5))
        assert(pause.observe(at: 13, remote: false))
        assert(!pause.permits(at: 14.999) && pause.permits(at: 15))
        assert(pause.observe(at: 14, remote: false))
        assert(!pause.permits(at: 15.999) && pause.permits(at: 16))
        assert(!pause.permits(at: .nan))
        var damage = DamageEncodingState()
        assert(damage.next(at: 0) == nil)
        damage.changed(at: 0)
        assert(damage.next(at: 0) == .motion(keyframe: true))
        damage.completed(delivered: true)
        for frame in 1...120 {
            let now = Double(frame) / 120
            damage.changed(at: now)
            assert(damage.next(at: now) == .motion(keyframe: false))
            damage.completed(delivered: true)
        }
        assert(damage.next(at: 1.249) == nil)
        assert(damage.next(at: 1.25) == .refresh)
        damage.completed(delivered: true)
        assert(damage.next(at: 600) == nil)

        var caretDamage = DamageEncodingState()
        caretDamage.changed(at: 0)
        assert(caretDamage.next(at: 0) == .motion(keyframe: true))
        caretDamage.completed(delivered: true)
        assert(caretDamage.refreshDeadline == 0.25)
        caretDamage.changed(at: 0.1, caret: true)
        assert(caretDamage.next(at: 0.1) == .caret, "a blink remains a delta")
        caretDamage.completed(delivered: true)
        assert(caretDamage.refreshDeadline == 0.25, "a blink must not restart the sharp refresh deadline")
        assert(caretDamage.next(at: 0.249) == nil)
        assert(caretDamage.next(at: 0.25) == .refresh, "startup still receives one sharp refresh")
        caretDamage.completed(delivered: true)
        caretDamage.changed(at: 0.4, caret: true)
        assert(caretDamage.next(at: 0.4) == .caret)
        caretDamage.completed(delivered: true)
        assert(caretDamage.next(at: 2) == nil, "caret blinking alone must not schedule another refresh")
        caretDamage.changed(at: 2, caret: false)
        assert(caretDamage.next(at: 2) == .motion(keyframe: false))
        caretDamage.completed(delivered: true)
        assert(caretDamage.refreshDeadline == 2.25, "real motion starts the sharp refresh deadline")
        caretDamage.changed(at: 2.1, caret: true)
        assert(caretDamage.next(at: 2.1) == .caret)
        caretDamage.completed(delivered: true)
        assert(caretDamage.refreshDeadline == 2.25, "a blink after motion must preserve the sharp refresh")
        assert(caretDamage.next(at: 2.25) == .refresh, "real motion remains sharp after settling")

        var caretRepair = DamageEncodingState()
        caretRepair.changed(at: 0)
        assert(caretRepair.next(at: 0) == .motion(keyframe: true))
        caretRepair.completed(delivered: true)
        caretRepair.repair()
        caretRepair.changed(at: 0.1, caret: true)
        assert(caretRepair.next(at: 0.1) == .motion(keyframe: true), "a caret cannot hide required decoder repair")

        var droppedRefresh = DamageEncodingState()
        droppedRefresh.changed(at: 0)
        assert(droppedRefresh.next(at: 0) == .motion(keyframe: true))
        droppedRefresh.completed(delivered: true)
        assert(droppedRefresh.next(at: 0.25) == .refresh)
        assert(droppedRefresh.encoderDropped(.refresh))
        droppedRefresh.changed(at: 0.3, caret: true)
        assert(droppedRefresh.next(at: 0.3) == .caret)
        droppedRefresh.completed(delivered: true)
        assert(droppedRefresh.next(at: 0.4) == .refresh, "caret damage cannot cancel a dropped sharp refresh")

        damage.repair()
        assert(damage.next(at: 601) == .motion(keyframe: true))
        damage.completed(delivered: false)
        assert(damage.next(at: 602) == .motion(keyframe: true))
        damage.completed(delivered: true)
        assert(damage.next(at: 603) == nil)
        var rawDrop = DamageEncodingState()
        rawDrop.changed(at: 0)
        guard rawDrop.next(at: 0) == .motion(keyframe: true) else { fatalError("initial IDR missing") }
        rawDrop.completed(delivered: true)
        rawDrop.changed(at: 0.1)
        guard rawDrop.next(at: 0.1) == .motion(keyframe: false),
              rawDrop.encoderDropped(.motion(keyframe: false)), rawDrop.next(at: 0.11) == .motion(keyframe: false) else {
            fatalError("a dropped motion delta is retried at the next tick as a delta, without reference repair")
        }
        rawDrop.completed(delivered: true)
        guard rawDrop.next(at: 0.12) == nil else { fatalError("a delivered retry goes idle until the refresh") }
        guard rawDrop.next(at: 0.35) == .refresh, rawDrop.encoderDropped(.refresh),
              rawDrop.next(at: 0.36) == .refresh else { fatalError("a dropped sharp refresh must retain its quality budget") }
        rawDrop.completed(delivered: true)
        rawDrop.changed(at: 0.5)
        guard rawDrop.next(at: 0.5) == .motion(keyframe: false) else { fatalError("motion after a raw drop must remain a delta") }
        rawDrop.completed(delivered: false)
        guard rawDrop.next(at: 0.6) == .motion(keyframe: true),
              rawDrop.encoderDropped(.motion(keyframe: true)),
              rawDrop.next(at: 0.61) == .motion(keyframe: true) else { fatalError("lost encoded pictures and requested IDRs still require repair") }
        rawDrop.completed(delivered: true)
        guard rawDrop.next(at: 600) == .refresh else { fatalError("settled refresh must survive repair") }
        rawDrop.completed(delivered: true)
        guard rawDrop.next(at: 601) == nil else { fatalError("successful refresh must go idle") }
        // Sharp refresh after small changes: delta refinement passes, not a keyframe.
        var refine = DamageEncodingState()
        assert(refine.plan == SharpRefreshPlan(mode: .lowLatency), "the default keeps the keyframe after heavy motion")
        refine.changed(at: 0)
        assert(refine.next(at: 0, touched: 1) == .motion(keyframe: true))
        refine.completed(delivered: true)
        refine.changed(at: 0.1)
        assert(refine.next(at: 0.1, touched: 0.02) == .motion(keyframe: false))
        refine.completed(delivered: true)
        assert(refine.next(at: 0.349, touched: 0.02) == nil)
        for pass in 1...SharpRefreshPlan.smallChangePasses {
            assert(refine.next(at: 0.35, touched: 0.02) == .refine, "refinement pass \(pass)")
            refine.completed(delivered: true)
            assert(refine.refining == (pass < SharpRefreshPlan.smallChangePasses))
        }
        assert(refine.next(at: 0.36, touched: 0) == nil, "refinement ends after its passes")
        assert(!EncodeDecision.refine.keyframe && EncodeDecision.refine.sharp && EncodeDecision.refresh.sharp && !EncodeDecision.caret.sharp)
        // A dropped pass is owed again; new motion cancels the rest and owes a new plan.
        refine.changed(at: 1)
        assert(refine.next(at: 1, touched: 0.02) == .motion(keyframe: false))
        refine.completed(delivered: true)
        assert(refine.next(at: 1.25, touched: 0.02) == .refine)
        assert(refine.encoderDropped(.refine))
        assert(refine.next(at: 1.26, touched: 0.02) == .refine, "a dropped refinement pass is retried")
        refine.completed(delivered: true)
        refine.changed(at: 1.27)
        assert(refine.next(at: 1.27, touched: 0.02) == .motion(keyframe: false))
        refine.completed(delivered: true)
        assert(!refine.refining && refine.next(at: 1.28, touched: 0.02) == nil, "new motion cancels the old picture's refinement")
        assert(refine.next(at: 1.52, touched: 0.9) == .refresh, "heavy motion keeps the keyframe refresh")
        refine.completed(delivered: true)
        assert(refine.next(at: 1.53, touched: 0) == nil)
        // A caret blink during refinement does not cancel it, and a repair comes first.
        refine.changed(at: 2)
        assert(refine.next(at: 2, touched: 0.01) == .motion(keyframe: false)); refine.completed(delivered: true)
        assert(refine.next(at: 2.25, touched: 0.01) == .refine); refine.completed(delivered: true)
        refine.changed(at: 2.26, caret: true)
        assert(refine.next(at: 2.26, touched: 0.01) == .caret); refine.completed(delivered: true)
        assert(refine.next(at: 2.27, touched: 0.01) == .refine, "a blink keeps the owed refinement")
        refine.completed(delivered: true)
        refine.repair()
        assert(refine.next(at: 2.28, touched: 0.01) == .motion(keyframe: true), "repair wins over refinement")
        refine.completed(delivered: true)
        assert(refine.next(at: 2.29, touched: 1) == .refresh && !refine.refining, "a repair during refinement owes a full refresh")
        refine.completed(delivered: true)
        assert(refine.next(at: 2.3, touched: 0) == nil)
        let keep = SharpRefreshPlan(mode: .lowLatency), refineAll = SharpRefreshPlan(mode: .realtime)
        assert(keep.passes(touched: .nan) == 0 && keep.passes(touched: SharpRefreshPlan.heavyMotionFraction) == SharpRefreshPlan.smallChangePasses)
        assert(refineAll.passes(touched: 1) == 8 && refineAll.passes(touched: 0.01) == SharpRefreshPlan.smallChangePasses)
        // The real-time plan refines heavy motion too, in more passes.
        var heavy = DamageEncodingState(); heavy.plan = refineAll
        heavy.changed(at: 0); _ = heavy.next(at: 0); heavy.completed(delivered: true)
        heavy.changed(at: 0.1); _ = heavy.next(at: 0.1); heavy.completed(delivered: true)
        for pass in 1...8 { assert(heavy.next(at: 0.35, touched: 1) == .refine, "heavy pass \(pass)"); heavy.completed(delivered: true) }
        assert(heavy.next(at: 0.4, touched: 1) == nil)

        // Encoder rate mode setting and its cap.
        assert(EncoderRateMode(setting: nil) == .realtime && EncoderRateMode(setting: "bogus") == .realtime)
        assert(EncoderRateMode(setting: "low-latency") == .lowLatency && EncoderRateMode(setting: "realtime") == .realtime)
        assert(EncoderRateMode.lowLatency.dataRateLimits(bitsPerSecond: 8_000_000).isEmpty)
        let cap = EncoderRateMode.realtime.dataRateLimits(bitsPerSecond: 8_000_000)
        assert(cap.count == 1 && cap[0].bytes == 1_500_000 && cap[0].seconds == 1)

        var rate = AdaptiveBitrate(maximum: 12_000_000)
        assert(rate.feedback(at: 0, congested: true) == 8_400_000)
        assert(rate.feedback(at: 0.1, congested: true) == 8_400_000)
        for step in 1...100 { _ = rate.feedback(at: Double(step), congested: true) }
        assert(rate.current == 500_000)
        for step in 101...300 { _ = rate.feedback(at: Double(step), congested: false) }
        // Recovery needs eight healthy feedbacks for each bounded increase; 200
        // feedbacks demonstrate gradual recovery, not a jump from floor to maximum.
        assert(rate.current > 500_000 && rate.current < 12_000_000)
        for step in 301...1100 { _ = rate.feedback(at: Double(step), congested: false) }
        assert(rate.current == 12_000_000)
        print("PASS geometry/local-priority/repair; motion_frames=120 caret=delta refresh_drop=retry motion_drop=retry refine_passes=\(SharpRefreshPlan.smallChangePasses)/8 encoded_gap=IDR bitrate_feedbacks=1102")
    }
}
