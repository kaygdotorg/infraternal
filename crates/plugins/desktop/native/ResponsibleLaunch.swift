/// Role: retain the signed bundle's privacy attribution and launch PID for its private channel [D203,D208,#146].
import Darwin
import Foundation

/// Resolve the system responsibility hook at runtime: it is shipped by macOS,
/// but is not a public SDK contract. Missing support is an error, never a launch
/// that silently charges permissions to the infraternal agent's launcher.
func establishResponsibility() throws {
    let marker = "--responsible-child"
    if CommandLine.arguments.contains(marker) { return }
    typealias Disclaim = @convention(c) (UnsafeMutablePointer<posix_spawnattr_t?>, Int32) -> Int32
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_spawnattrs_setdisclaim") else {
        throw POSIXError(.ENOTSUP)
    }
    let disclaim = unsafeBitCast(symbol, to: Disclaim.self)
    var attributes: posix_spawnattr_t?
    func check(_ result: Int32) throws {
        if result != 0 { throw POSIXError(POSIXErrorCode(rawValue:result) ?? .EINVAL) }
    }
    try check(posix_spawnattr_init(&attributes))
    defer { posix_spawnattr_destroy(&attributes) }
    try check(disclaim(&attributes, 1))
    // SETEXEC replaces this process rather than leaving a supervising child.
    // LaunchServices retains the app bundle identity and PID while its private
    // socket carries the bounded protocol and closes to request cleanup.
    try check(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETEXEC)))
    let executable = Bundle.main.executablePath ?? CommandLine.arguments[0]
    let arguments = ([executable] + Array(CommandLine.arguments.dropFirst()) + [marker]).map { strdup($0) }
    defer { arguments.forEach { free($0) } }
    var argv = arguments + [nil]
    let environment = ProcessInfo.processInfo.environment.map { strdup("\($0.key)=\($0.value)") }
    defer { environment.forEach { free($0) } }
    var envp = environment + [nil]
    var pid: pid_t = 0
    try check(executable.withCString { path in
        posix_spawn(&pid, path, nil, &attributes, &argv, &envp)
    })
    // Successful SETEXEC never returns, even if the replacement later fails.
    throw POSIXError(.EIO)
}

/// Publish this bundle's PID to the per-launch bridge record before it serves requests.
func recordLaunchPIDIfRequested() throws {
    let marker = "--launch-pid-file"
    guard let index = CommandLine.arguments.firstIndex(of: marker) else { return }
    guard CommandLine.arguments.count > index + 1 else { throw POSIXError(.EINVAL) }
    let path = CommandLine.arguments[index + 1]
    guard path.hasPrefix("/") else { throw POSIXError(.EINVAL) }
    let descriptor = Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL, mode_t(S_IRUSR | S_IWUSR))
    guard descriptor >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { _ = Darwin.close(descriptor) }

    let bytes = Array("\(getpid())\n".utf8)
    var offset = 0
    while offset < bytes.count {
        let written = bytes.withUnsafeBufferPointer { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
        }
        if written < 0 {
            if errno == EINTR { continue }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard written > 0 else { throw POSIXError(.EIO) }
        offset += written
    }
}
