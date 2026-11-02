/// Role: prove native launch changes privacy responsibility without changing the caller-owned PID or stdio [D203,D208].
import Darwin
import Foundation

@main
struct ResponsibilityTest {
    static func main() throws {
        let originalPID = getpid()
        // Parent passes the expected PID through stdin, which must survive SETEXEC.
        try establishResponsibility()
        let expected = readLine().flatMap(Int32.init)
        precondition(expected == originalPID, "responsible launch must preserve the owned PID and stdin")
        typealias ResponsiblePID = @convention(c) (pid_t) -> pid_t
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_get_pid_responsible_for_pid") else {
            fatalError("responsibility inspection unavailable on this test host")
        }
        let responsiblePID = unsafeBitCast(symbol, to: ResponsiblePID.self)
        precondition(responsiblePID(getpid()) == getpid(), "companion must be responsible for itself")
        print("PASS: own responsibility, preserved PID/stdin/stdout")
    }
}
