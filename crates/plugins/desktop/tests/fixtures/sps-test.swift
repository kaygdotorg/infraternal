/// Role: bounded encoder SPS corpus plus full 840-AU fixture byte equivalence (#146).
import Foundation

private func sps(_ hex: String) -> Data {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else { fatalError("odd SPS hex length") }
    var bytes: [UInt8] = []
    for offset in stride(from: 0, to: digits.count, by: 2) {
        let pair = String(decoding: digits[offset..<offset + 2], as: UTF8.self)
        guard let byte = UInt8(pair, radix: 16) else { fatalError("invalid SPS hex") }
        bytes.append(byte)
    }
    return Data(bytes)
}

@main struct Test {
    static func main() throws {
        let original = Data([0x27,0x64,0x00,0x2a,0xac,0x56,0x80,0xf0,0x13,0x7e,0x54])
        let expected = Data([0x27,0x64,0x00,0x2a,0xac,0x56,0x80,0xf0,0x13,0x7e,0x58,0x06,0xd0,0x44,0x23,0x50])
        let m2Max = sps("2764002aac1314501e0089f966a0404040f0804258")
        guard try lowDelaySPS(m2Max) == m2Max else { fatalError("already no-reorder M2 SPS must remain byte-identical") }
        guard try lowDelaySPS(original) == expected else { fatalError("known SPS mismatch") }
        guard try lowDelaySPS(expected) == expected else { fatalError("SPS must be idempotent") }
        // Each profile has an encoder SPS with restriction syntax, plus derived valid forms without restriction and without VUI.
        let corpus: [(String, Data, Bool)] = [
            ("baseline VUI restriction", sps("6742c028d940780227e5c044000003000400000300f03c60c960"), true),
            ("baseline VUI no restriction", sps("6742c028d940780227e5c044000003000400000300f010"), false),
            ("baseline no VUI", sps("6742c028d940780227e540"), false),
            ("main VUI restriction", sps("674d4028d940780227e5c044000003000400000300f03c60c960"), true),
            ("main VUI no restriction", sps("674d4028d940780227e5c044000003000400000300f010"), false),
            ("main no VUI", sps("674d4028d940780227e540"), false),
            ("high VUI restriction", sps("67640028acb280f0044fcb8088000003000800000301e078c192c0"), true),
            ("high VUI no restriction", sps("67640028acb280f0044fcb8088000003000800000301e020"), false),
            ("high no VUI", sps("67640028acb280f0044fca80"), false),
        ]
        for (name, input, alreadyNoReorder) in corpus {
            let output = try lowDelaySPS(input)
            guard output.count <= 1024, try lowDelaySPS(output) == output else { fatalError("invalid or non-idempotent \(name) SPS") }
            guard (output == input) == alreadyNoReorder else { fatalError("unexpected byte preservation for \(name) SPS") }
        }
        var unreferenced = original; unreferenced[0] = 0x07
        var reserved = original; reserved[2] = 0x01
        for invalid in [unreferenced, reserved, Data(repeating: 0, count: 1025)] {
            do { _ = try lowDelaySPS(invalid); fatalError("invalid SPS header or bound accepted") }
            catch SPSFailure.invalid {}
        }
        for length in 0..<original.count {
            do { _ = try lowDelaySPS(original.prefix(length)); fatalError("truncation accepted \(length)") }
            catch SPSFailure.invalid {}
        }
        // A deterministic mutation corpus exercises bounded refusal without a
        // decoder or platform framework. Accepted inputs must stay idempotent.
        var state: UInt64 = 146
        for _ in 0..<24_000 {
            state = state &* 6364136223846793005 &+ 1
            var bytes = [UInt8](state & 1 == 0 ? original : expected)
            let index = Int((state >> 8) % UInt64(bytes.count))
            bytes[index] ^= UInt8(truncatingIfNeeded: state >> 32)
            do {
                let result = try lowDelaySPS(Data(bytes))
                guard try lowDelaySPS(result) == result else { fatalError("accepted SPS was not idempotent") }
            } catch SPSFailure.invalid {}
        }
        let cache = LowDelayParameterSets()
        let bundled = try cache.packet(original)
        guard bundled.starts(with: Data([0,0,0,1]) + expected),
              bundled.suffix(original.count + 1) == original + Data([0x80]) else { fatalError("SPS variant envelope mismatch") }
        for _ in 0..<7 { guard try cache.packet(original) == bundled else { fatalError("cache changed bytes") } }
        guard cache.rewrites == 1 else { fatalError("unchanged parameter sets were rewritten") }
        guard try cache.packet(Data([0x68,0xff])) == Data([0,0,0,1,0x68,0xff]) else { fatalError("PPS changed") }
        cache.reset(); _ = try cache.packet(original)
        guard cache.rewrites == 2 else { fatalError("session reset retained old cache") }
        let root = URL(fileURLWithPath:CommandLine.arguments[1])
        let fixture = try Data(contentsOf:root.appendingPathComponent("mac-vt-annexb.h264"))
        let candidate = try Data(contentsOf:root.appendingPathComponent("mac-vt-vui.h264"))
        var output = Data(); var remaining = fixture[...]; var count = 0
        while let range = remaining.range(of:original) {
            output.append(contentsOf:remaining[..<range.lowerBound]);output.append(try lowDelaySPS(original))
            remaining = remaining[range.upperBound...];count += 1
        }
        output.append(contentsOf:remaining)
        guard count == 7, output == candidate else { fatalError("840-AU fixture differs beyond known SPS changes") }
        print("PASS: exact no-reorder M2 SPS unchanged; 9-vector High/Main/Baseline VUI/restriction corpus idempotent; 24,000 bounded mutations; all 11 truncations; 840-AU fixture equivalence; cache envelope and reset")
    }
}
