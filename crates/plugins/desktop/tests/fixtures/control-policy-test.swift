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
        damage.repair()
        assert(damage.next(at: 601) == .motion(keyframe: true))
        damage.completed(delivered: false)
        assert(damage.next(at: 602) == .motion(keyframe: true))
        damage.completed(delivered: true)
        assert(damage.next(at: 603) == nil)
        var rate = AdaptiveBitrate(maximum: 12_000_000)
        assert(rate.feedback(at: 0, congested: true) == 8_400_000)
        assert(rate.feedback(at: 0.1, congested: true) == 8_400_000)
        for step in 1...100 { _ = rate.feedback(at: Double(step), congested: true) }
        assert(rate.current == 500_000)
        for step in 101...300 { _ = rate.feedback(at: Double(step), congested: false) }
        assert(rate.current == 12_000_000)
        print("PASS coordinate cases=8 local-priority cases=8 damage frames=120 idle/repair/drop cases=7 bitrate simulations=302")
    }
}
