/// Role: verify the real scoped window lookup preserves identity and excludes unrelated windows without input or resizing.
import AppKit
import Foundation

enum HelperFailure: Error { case invalid, permission, unavailable }

@main struct KeyboardTargetTests {
    static func main() {
        let environment = ProcessInfo.processInfo.environment
        guard let rawID = environment["INFRATERNAL_OWNED_WINDOW_ID"], let id = UInt32(rawID),
              let rawPID = environment["INFRATERNAL_OWNED_WINDOW_PID"], let pid = Int32(rawPID) else {
            fatalError("supply the fixture-owned window identity")
        }
        let selected = windowSnapshot(applicationMetadata: false, windowID: id)
        guard selected.count == 1, selected[0]["window_id"] as? UInt32 == id,
              selected[0]["owner_pid"] as? Int32 == pid else { fatalError("scoped query changed window identity") }
        guard windowSnapshot(applicationMetadata: false, windowID: UInt32.max).isEmpty else {
            fatalError("missing identity enumerated unrelated windows")
        }
        print("PASS scoped keyboard inventory selected=1 missing=0")
    }
}
