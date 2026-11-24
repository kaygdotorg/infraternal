/// The benchmark calls through the UniFFI-generated Swift API (J1158).
import Foundation

/// The executable: times every row, then the async row.
@main
struct BenchUniffi {
    /// Builds the rows for this binding and prints their timings.
    static func main() async {
        var ops: [Op] = [
            Op(name: "noop", iterations: 10_000_000) { noop() },
            Op(name: "add", iterations: 10_000_000) { blackhole &+= add(a: blackhole, b: 1) },
        ]
        for size in frameSizes {
            let data = Data(repeating: 0x5A, count: size)
            ops.append(Op(name: "frame_in_\(size)", iterations: iterations(for: size)) { blackhole &+= frameIn(buf: data) })
            ops.append(Op(name: "frame_out_\(size)", iterations: iterations(for: size)) {
                let d = frameOut(len: UInt32(size)); blackhole &+= UInt64(d.count) &+ UInt64(d[d.startIndex])
            })
        }
        ops.append(Op(name: "parse_ok", iterations: 1_000_000) { blackhole &+= (try? parse(input: "12345")) ?? 0 })
        ops.append(Op(name: "parse_err", iterations: 1_000_000) {
            do { blackhole &+= try parse(input: "x") } catch CoreError.NotANumber(let input) { blackhole &+= UInt64(input.utf8.count) } catch {}
        })
        runAll(binding: "uniffi", ops: ops)
        await timeAsync(binding: "uniffi", count: 10_000) { await delayedEcho(ms: 0, value: 7) }
    }
}
