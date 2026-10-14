/// Role: bounded stdin fuzz entry point for the exact SPS parser; accepted syntax must remain idempotent [D204,D266], #146.
import Foundation

@main struct SPSFuzz {
    static func main() throws {
        // One extra byte exercises the parser's size refusal without allowing
        // the harness itself to copy an arbitrarily large incoming corpus item.
        let input = FileHandle.standardInput.readData(ofLength: 1025)
        do {
            let output = try lowDelaySPS(input)
            guard output.count <= 1024, try lowDelaySPS(output) == output else {
                fatalError("accepted SPS violated its bounded idempotence invariant")
            }
        } catch SPSFailure.invalid {}
    }
}
