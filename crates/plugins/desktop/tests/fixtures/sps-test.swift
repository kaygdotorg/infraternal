/// Role: hand-checked SPS vectors plus full 840-AU fixture byte equivalence (#146).
import Foundation
@main struct Test {
    static func main() throws {
        let original = Data([0x27,0x64,0x00,0x2a,0xac,0x56,0x80,0xf0,0x13,0x7e,0x54])
        let expected = Data([0x27,0x64,0x00,0x2a,0xac,0x56,0x80,0xf0,0x13,0x7e,0x58,0x06,0xd0,0x44,0x23,0x50])
        guard try lowDelaySPS(original) == expected else { fatalError("known SPS mismatch") }
        guard try lowDelaySPS(expected) == expected else { fatalError("SPS must be idempotent") }
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
        print("PASS: exact SPS, idempotence, all11truncations, 7parameter-set changes; whole840-AU fixture bytes match retained candidate; cached original/restricted envelope and reset match")
    }
}
