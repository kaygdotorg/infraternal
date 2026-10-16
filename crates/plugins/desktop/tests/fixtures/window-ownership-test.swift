/// Role: deterministic managed-desktop backoff, unmanaged resizing and aspect-fit regressions [D290].
import Foundation

@main struct WindowOwnershipTests {
    static func main() {
        let tiled = CGSize(width: 1920, height: 1080)
        let canvas = CGSize(width: 800, height: 600)
        var known = WindowResizeOwnership()
        known.detectManager(true)
        known.detectManager(false)
        for step in 0..<300 {
            precondition(!known.attempt(CGSize(width: 800 + step, height: 600), actual: tiled, at: Double(step)), "managed windows never resize, even after the manager exits")
        }
        var undone = WindowResizeOwnership()
        precondition(undone.attempt(canvas, actual: tiled, at: 10))
        undone.observe(canvas, at: 10.01) // Our own AX notification is harmless.
        precondition(!undone.managed)
        undone.observe(tiled, at: 10.1)
        precondition(undone.managed, "one externally undone size must latch managed mode")
        for step in 0..<300 {
            precondition(!undone.attempt(CGSize(width: 900 + step, height: 650), actual: tiled, at: 11 + Double(step)), "timer, notification and new canvas sizes cannot retry")
        }
        var coalesced = WindowResizeOwnership()
        precondition(coalesced.attempt(canvas, actual: tiled, at: 0))
        coalesced.observe(tiled, at: 0.2) // AX can coalesce away our applied size.
        precondition(coalesced.managed)
        var delayed = WindowResizeOwnership()
        precondition(delayed.attempt(canvas, actual: tiled, at: 0))
        delayed.observe(canvas, at: 0.1)
        delayed.observe(tiled, at: 2)
        precondition(delayed.managed, "the boundary belongs to the observation window")
        var ordinary = WindowResizeOwnership()
        precondition(!ordinary.attempt(canvas, actual: canvas, at: 0))
        precondition(ordinary.attempt(canvas, actual: tiled, at: 1))
        ordinary.observe(CGSize(width: 800.5, height: 599.5), at: 1.01)
        precondition(!ordinary.managed, "subpoint AX rounding is not an external resize")
        ordinary.observe(tiled, at: 4)
        precondition(!ordinary.managed, "later unrelated size changes do not attribute an undone resize")
        precondition(!ordinary.attempt(canvas, actual: tiled, at: 4), "timers cannot retry even an old refusal")
        precondition(ordinary.attempt(CGSize(width: 1000, height: 700), actual: tiled, at: 5), "unmanaged canvas changes still resize")
        var invalid = WindowResizeOwnership()
        precondition(!invalid.attempt(.zero, actual: tiled, at: 0))
        precondition(!invalid.attempt(canvas, actual: tiled, at: .nan))
        precondition(invalid.attempt(canvas, actual: tiled, at: 10))
        invalid.observe(tiled, at: .nan)
        invalid.observe(tiled, at: 9)
        precondition(!invalid.managed)
        let source = CGRect(origin: .zero, size: tiled)
        let fitted = fittedContent(source, canvas)
        precondition(fitted == CGRect(x: 0, y: 75, width: 800, height: 450))
        precondition(mappedPoint(x: 400, y: 300, source: source, output: canvas) == CGPoint(x: 960, y: 540))
        precondition(mappedPoint(x: 400, y: 74, source: source, output: canvas) == nil)
        precondition(tilingManagerExecutables.isSuperset(of: ["OmniWM", "yabai", "AeroSpace", "Amethyst", "paneru", "glide"]))
        precondition(!tilingManagerExecutables.contains("TextEdit"))
        print("PASS managed=300 undone=300 coalesced=1 boundary=1 unmanaged=2 invalid=4 aspect_fit=3")
    }
}
