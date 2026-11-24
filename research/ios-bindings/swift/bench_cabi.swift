/// The benchmark calls the hand-written C ABI through its cbindgen header,
/// with the thin Swift wrappers a hand ABI needs (J1158).
import Foundation

/// The Swift error a failed `cabi_parse` becomes.
enum CabiError: Error { case notANumber, panic }

/// Wraps `cabi_parse`: Swift string in, number out, status code to `throws`.
func cabiParse(_ s: String) throws -> UInt64 {
    var s = s
    var value: UInt64 = 0
    let status = s.withUTF8 { cabi_parse($0.baseAddress, UInt($0.count), &value) }
    switch status {
    case Ok: return value
    case NotANumber: throw CabiError.notANumber
    default: throw CabiError.panic
    }
}

/// Wraps `cabi_delayed_echo` in a checked continuation. The continuation box
/// is retained across the C call and released in the callback.
func cabiDelayedEcho(ms: UInt64, value: UInt64) async -> UInt64 {
    await withCheckedContinuation { (cont: CheckedContinuation<UInt64, Never>) in
        let box = Unmanaged.passRetained(Box(cont)).toOpaque()
        cabi_delayed_echo(ms, value, box) { ctx, v in
            let b = Unmanaged<Box>.fromOpaque(ctx!).takeRetainedValue()
            b.cont.resume(returning: v)
        }
    }
}

/// Holds a continuation while Rust owns the callback.
final class Box: @unchecked Sendable {
    /// The suspended Swift caller.
    let cont: CheckedContinuation<UInt64, Never>
    /// Wraps `c` for the trip through Rust.
    init(_ c: CheckedContinuation<UInt64, Never>) { cont = c }
}

/// The executable: times every row, then the async row.
@main
struct BenchCabi {
    /// Builds the rows for this binding and prints their timings.
    static func main() async {
        var ops: [Op] = [
            Op(name: "noop", iterations: 10_000_000) { cabi_noop() },
            Op(name: "add", iterations: 10_000_000) { blackhole &+= cabi_add(blackhole, 1) },
        ]
        for size in frameSizes {
            let bytes = [UInt8](repeating: 0x5A, count: size)
            ops.append(Op(name: "frame_in_\(size)", iterations: iterations(for: size)) {
                bytes.withUnsafeBufferPointer { blackhole &+= cabi_frame_in($0.baseAddress, UInt($0.count)) }
            })
            // The caller owns one reusable output buffer for all frames.
            let out = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: size)
            ops.append(Op(name: "frame_out_\(size)", iterations: iterations(for: size)) {
                let n = cabi_frame_out(out.baseAddress, UInt(out.count), UInt32(size)); blackhole &+= UInt64(n) &+ UInt64(out[0])
            })
        }
        ops.append(Op(name: "parse_ok", iterations: 1_000_000) { blackhole &+= (try? cabiParse("12345")) ?? 0 })
        ops.append(Op(name: "parse_err", iterations: 1_000_000) {
            do { blackhole &+= try cabiParse("x") } catch { blackhole &+= 1 }
        })
        runAll(binding: "cabi", ops: ops)
        await timeAsync(binding: "cabi", count: 10_000) { await cabiDelayedEcho(ms: 0, value: 7) }
    }
}
