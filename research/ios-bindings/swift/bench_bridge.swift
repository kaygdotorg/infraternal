/// The benchmark calls through the swift-bridge-generated Swift API (J1158).
import Foundation

/// The executable: times every row, then the async row.
@main
struct BenchBridge {
    /// Builds the rows for this binding and prints their timings.
    static func main() async {
        var ops: [Op] = [
            Op(name: "noop", iterations: 10_000_000) { noop() },
            Op(name: "add", iterations: 10_000_000) { blackhole &+= add(blackhole, 1) },
        ]
        for size in frameSizes {
            let bytes = [UInt8](repeating: 0x5A, count: size)
            ops.append(Op(name: "frame_in_\(size)", iterations: iterations(for: size)) {
                bytes.withUnsafeBufferPointer { blackhole &+= frame_in($0) }
            })
            ops.append(Op(name: "frame_out_\(size)", iterations: iterations(for: size)) {
                let v = frame_out(UInt32(size)); blackhole &+= UInt64(v.len()) &+ UInt64(v.get(index: 0) ?? 0)
            })
        }
        ops.append(Op(name: "parse_ok", iterations: 1_000_000) { blackhole &+= UInt64((try? parse("12345")) ?? 0) })
        ops.append(Op(name: "parse_err", iterations: 1_000_000) {
            do { blackhole &+= UInt64(try parse("x")) } catch let e as RustString { blackhole &+= UInt64(e.len()) } catch {}
        })
        runAll(binding: "swift-bridge", ops: ops)
        await timeAsync(binding: "swift-bridge", count: 10_000) { await delayed_echo(0, 7) }
    }
}
