/// Timing helpers shared by the three binding benchmarks (J1158, #580).
///
/// Each benchmark executable links one Rust prototype and builds a list of
/// `Op` rows, the same named operations for every binding. `runAll` times each one and
/// prints one JSON line per operation, so results can be compared row by row.
import Foundation

/// Values the timed closures fold their results into, so the optimiser
/// cannot drop the calls.
nonisolated(unsafe) var blackhole: UInt64 = 0

/// One timed operation: a name, how many calls one round makes, and the body
/// that makes one call.
struct Op {
    /// The row name in the output.
    let name: String
    /// Calls per timed round.
    let iterations: Int
    /// Makes one call.
    let body: () -> Void
}

/// Times `op` over `rounds` rounds and returns nanoseconds per call for each
/// round, after one warm-up round.
func time(_ op: Op, rounds: Int = 7) -> [Double] {
    for _ in 0..<min(op.iterations, 10_000) { op.body() }
    var samples: [Double] = []
    let clock = ContinuousClock()
    for _ in 0..<rounds {
        let start = clock.now
        for _ in 0..<op.iterations { op.body() }
        let elapsed = clock.now - start
        let ns = Double(elapsed.components.seconds) * 1e9 + Double(elapsed.components.attoseconds) / 1e9
        samples.append(ns / Double(op.iterations))
    }
    return samples.sorted()
}

/// Times every operation and prints `{"binding":…,"op":…,"median_ns":…,"min_ns":…}` lines.
func runAll(binding: String, ops: [Op]) {
    for op in ops {
        let s = time(op)
        let median = s[s.count / 2]
        print(String(format: "{\"binding\":\"%@\",\"op\":\"%@\",\"median_ns\":%.1f,\"min_ns\":%.1f}", binding, op.name, median, s[0]))
    }
}

/// Times `count` sequential awaits of `call` and prints microseconds per await.
func timeAsync(binding: String, count: Int, _ call: () async -> UInt64) async {
    for _ in 0..<100 { blackhole &+= await call() }
    let clock = ContinuousClock()
    var samples: [Double] = []
    for _ in 0..<5 {
        let start = clock.now
        for _ in 0..<count { blackhole &+= await call() }
        let e = clock.now - start
        let ns = Double(e.components.seconds) * 1e9 + Double(e.components.attoseconds) / 1e9
        samples.append(ns / Double(count) / 1000)
    }
    samples.sort()
    print(String(format: "{\"binding\":\"%@\",\"op\":\"async_spawned_echo\",\"median_us\":%.2f,\"min_us\":%.2f}", binding, samples[2], samples[0]))
}

/// Frame sizes the byte-buffer rows use: a small input event, a terminal
/// frame, a large frame.
let frameSizes = [64, 4096, 65536]

/// Calls per round for a frame of `size` bytes.
func iterations(for size: Int) -> Int { size >= 65536 ? 50_000 : 1_000_000 }
