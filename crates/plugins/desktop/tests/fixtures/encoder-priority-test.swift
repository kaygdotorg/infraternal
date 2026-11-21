/// Role: verify that the controlled window is encoded first and every other window is only delayed, never stopped [#146].
import Darwin
import Foundation

/// Runs the checks below and exits non-zero at the first that fails.
@main struct EncoderPriorityTest {
    /// Stops the test with the label of the failed check.
    static func expect(_ value: Bool, _ label: String) {
        if !value { fputs("FAIL \(label)\n", stderr); exit(1) }
    }
    /// Milliseconds one call takes.
    static func timed(_ body: () -> Void) -> Double {
        var base = mach_timebase_info_data_t(); mach_timebase_info(&base)
        let begin = mach_absolute_time(); body()
        return Double(mach_absolute_time() - begin) * Double(base.numer) / Double(base.denom) / 1e6
    }
    /// Checks claim, lease, bounded wait and fail-open behaviour over a private shared file.
    static func main() {
        let segment = (EncoderPriority.sharedDirectory() ?? "/tmp/") + "infraternal-ep-test-\(getpid())"
        defer { unlink(segment) }
        let control = EncoderPriority(key: 0, path: segment)
        let controlled = EncoderPriority(key: 7, path: segment)
        let other = EncoderPriority(key: 8, path: segment)

        // With no claim, nobody waits, whatever the lease says.
        expect(timed { other.beforeEncode() } < 2, "no claim: an unclaimed window does not wait")
        expect(timed { controlled.beforeEncode() } < 2, "no claim: the window itself does not wait")

        // Input accepted for window 7 claims it. It never waits; it takes the lease.
        control.claim(target: EncoderPriority.targetKey(windowID: 7, displayID: nil))
        expect(timed { controlled.beforeEncode() } < 2, "the controlled window goes straight on")
        // While it encodes, another window waits, but only up to the bound.
        let held = timed { other.beforeEncode() }
        expect(held >= EncoderPriority.waitMilliseconds - 2 && held < EncoderPriority.waitMilliseconds + 15,
               "another window waits at most the bound while the lease is held (waited \(held) ms)")
        // Once the controlled window is done it keeps the lease for the hold time only.
        controlled.afterEncode()
        let gap = timed { other.beforeEncode() }
        expect(gap >= EncoderPriority.holdMilliseconds - 3 && gap < EncoderPriority.holdMilliseconds + 10,
               "after the encode the others wait for the hold time (waited \(gap) ms)")
        expect(timed { other.beforeEncode() } < 2, "when the lease has run out nobody waits")

        // The controlled window itself is never delayed by another's lease.
        other.afterEncode()
        expect(timed { controlled.beforeEncode() } < 2, "another window cannot take the lease")

        // A screen and a window never share a key.
        expect(EncoderPriority.targetKey(windowID: nil, displayID: 7) != EncoderPriority.targetKey(windowID: 7, displayID: nil), "display and window keys differ")
        expect(EncoderPriority.targetKey(windowID: nil, displayID: nil) == 0, "no target has no key")

        // Without a usable segment everything fails open.
        let broken = EncoderPriority(key: 9, path: "/nonexistent-directory/priority")
        broken.claim(target: 9)
        expect(timed { broken.beforeEncode(); broken.afterEncode() } < 2, "no segment: no waiting")
        print("PASS")
    }
}
