/// Role: exercise actual framework rectangle representations and unchanged-frame sentinels [D254,D266].
import Foundation
import CoreGraphics

@main struct FrameDamageTest {
    static func expect(_ condition: Bool, _ name: String) {
        if !condition { fputs("FAIL \(name)\n", stderr); exit(1) }
    }
    static func main() {
        let empty = CGRect.zero.dictionaryRepresentation
        expect(!captureFrameHasDamage([empty], initial: false), "nonempty list of empty dictionaries is unchanged")
        expect(!captureFrameHasDamage([NSValue(rect: .zero)], initial: false), "empty boxed rectangle is unchanged")
        expect(!captureFrameHasDamage([], initial: false), "empty list is unchanged")
        expect(captureFrameHasDamage([empty], initial: true), "first picture is always delivered")
        expect(captureFrameHasDamage(nil, initial: false), "absent metadata is conservative")
        expect(captureFrameHasDamage(["unknown"], initial: false), "unknown entry is conservative")
        expect(captureFrameHasDamage([["X": 1]], initial: false), "incomplete dictionary is conservative")
        for n in 1...32 {
            let zero = CGRect(x: n, y: n * 2, width: 0, height: n).dictionaryRepresentation
            let changed = CGRect(x: n, y: n * 2, width: n, height: n).dictionaryRepresentation
            expect(!captureFrameHasDamage([empty, zero], initial: false), "empty corpus \(n)")
            expect(captureFrameHasDamage([empty, changed], initial: false), "changed corpus \(n)")
            expect(captureFrameHasDamage([zero, "unknown"], initial: false), "unknown corpus \(n)")
        }
        print("PASS native damage metadata: empty sentinels, first picture, changed and unknown corpus")
    }
}
