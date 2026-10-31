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
        let caret = CGRect(x: 120, y: 60, width: 2, height: 17).dictionaryRepresentation
        expect(captureFrameDamage([caret], initial: false) == .caret, "a narrow vertical cursor change is transient")
        let shortLine = CGRect(x: 120, y: 60, width: 2, height: 7).dictionaryRepresentation
        expect(captureFrameDamage([shortLine], initial: false) == .content, "short narrow changes remain content")
        let wideCaret = CGRect(x: 120, y: 60, width: 4, height: 17).dictionaryRepresentation
        expect(captureFrameDamage([wideCaret], initial: false) == .content, "wide changes remain content")
        let glyph = CGRect(x: 120, y: 60, width: 7, height: 13).dictionaryRepresentation
        expect(captureFrameDamage([glyph], initial: false) == .content, "a typed glyph remains real content motion")
        expect(captureFrameDamage([caret, glyph], initial: false) == .content, "caret plus glyph stays real content motion")
        expect(captureFrameDamage([caret, caret], initial: false) == .content, "multiple narrow changes remain conservative")
        let scroll = CGRect(x: 0, y: 0, width: 640, height: 200).dictionaryRepresentation
        expect(captureFrameDamage([scroll], initial: false) == .content, "scroll damage remains real content motion")
        expect(captureFrameHasDamage(nil, initial: false), "absent metadata is conservative")
        expect(captureFrameDamage(nil, initial: false) == .content, "unknown changes remain real content motion")
        expect(captureFrameHasDamage(["unknown"], initial: false), "unknown entry is conservative")
        expect(captureFrameHasDamage([["X": 1]], initial: false), "incomplete dictionary is conservative")
        for n in 1...32 {
            let zero = CGRect(x: n, y: n * 2, width: 0, height: n).dictionaryRepresentation
            let changed = CGRect(x: n, y: n * 2, width: n, height: n).dictionaryRepresentation
            expect(!captureFrameHasDamage([empty, zero], initial: false), "empty corpus \(n)")
            expect(captureFrameHasDamage([empty, changed], initial: false), "changed corpus \(n)")
            expect(captureFrameHasDamage([zero, "unknown"], initial: false), "unknown corpus \(n)")
        }
        print("PASS native damage metadata: empty sentinels, caret, content motion and unknown corpus")
    }
}
