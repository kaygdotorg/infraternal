/// Role: bracket host-clock samples for an external browser measurement without capture, input or permission APIs [D208,#146].
import Darwin
import Foundation

func emit(_ value: [String: Any]) throws {
    try FileHandle.standardOutput.write(contentsOf: JSONSerialization.data(withJSONObject: value) + Data([10]))
}

do {
    var timebase = mach_timebase_info_data_t()
    guard mach_timebase_info(&timebase) == KERN_SUCCESS else { exit(1) }
    try emit(["numer": timebase.numer, "denom": timebase.denom, "pid": getpid()])
    // One byte requests one sample. The caller timestamps both sides of this
    // exchange, retaining an interval rather than assuming symmetric pipe delay.
    while !FileHandle.standardInput.readData(ofLength: 1).isEmpty {
        let before = mach_absolute_time()
        let wall = Date().timeIntervalSince1970
        let after = mach_absolute_time()
        try emit(["before_ticks": before, "after_ticks": after, "wall_seconds": wall])
    }
} catch { exit(1) }
