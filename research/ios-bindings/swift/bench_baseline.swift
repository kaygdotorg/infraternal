/// A Swift-only executable with the same timing code and no Rust, so the
/// size table can subtract what Swift itself costs (J1158).
/// The executable: one Swift-only row.
@main
struct BenchBaseline {
    /// Prints the one row.
    static func main() async {
        runAll(binding: "baseline", ops: [Op(name: "swift_noop", iterations: 10_000_000) { blackhole &+= 1 }])
    }
}
