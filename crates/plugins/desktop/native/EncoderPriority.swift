/// Role: when several windows stream at once, the window being controlled is encoded first [#146, D254, D266].
/// The Mac's hardware encoder is one shared unit, and every streamed window has its own encoding
/// process. Left alone, windows that change in the same instant take turns in whatever order they
/// arrive, so the one the person is driving waits behind pictures nobody is acting on (J1118 on an M1:
/// with three windows scrolling, the controlled one's encode took 11.3 ms median and 20.6 ms at the
/// 95th percentile, against 9.5 ms alone). Process priority does not help: the hardware queue ignores
/// it (nice and QoS changed nothing in the measurement).
///
/// So the processes cooperate through one small shared file per user (memory-mapped, in the user's
/// private temporary directory):
/// - The control companion writes a *claim* each time it accepts remote input: which target (window
///   or display) is controlled, valid for `claimMilliseconds` after the last input.
/// - The encoding process of the claimed target holds a *lease* while it encodes and for
///   `holdMilliseconds` after, because a moving window submits again within a frame.
/// - Every other encoding process, before it submits, waits while a lease is held, but never longer
///   than `waitMilliseconds`: they are slowed, never stopped, and a lost or crashed lease expires by
///   itself.
/// Everything fails open: without the segment, or without a claim, no one waits.
import Darwin
import Foundation

/// Shared encoder priority. One instance per encoding process; the control companion only calls
/// `claim(target:)`. All timing uses `mach_absolute_time`, which is the same clock in every process.
final class EncoderPriority {
    /// How long a claim stays valid after the last accepted remote input, in milliseconds.
    static let claimMilliseconds = 1500.0
    /// How long the controlled window keeps its lease after an encode finishes, in milliseconds.
    /// It covers the gap to the window's next frame, so others do not slip in between two frames.
    static let holdMilliseconds = 8.0
    /// The longest another window waits for the lease, in milliseconds. About two frames at 120 Hz:
    /// a window that is not controlled is delayed by this much at most, so it still keeps moving.
    static let waitMilliseconds = 16.0
    /// While the controlled window is encoding, its lease runs this long unless it ends sooner, in
    /// milliseconds. Bounds the damage of a process that dies mid-encode.
    private static let inFlightMilliseconds = 50.0

    /// Words of the segment: [0] lease end, [1] claimed target, [2] claim end (all in mach ticks).
    private let words: UnsafeMutablePointer<UInt64>?
    /// The target this process encodes (see `targetKey`), or 0 for the control companion.
    private let key: UInt64
    /// Mach ticks per millisecond.
    private static let ticksPerMillisecond: Double = {
        var base = mach_timebase_info_data_t(); mach_timebase_info(&base)
        return 1e6 * Double(base.denom) / Double(base.numer)
    }()

    /// A single number naming a capture target, so two processes agree on it: the window ID of a
    /// window, or the display ID of a screen with a high bit that no window ID has.
    static func targetKey(windowID: UInt32?, displayID: UInt32?) -> UInt64 {
        if let windowID { return UInt64(windowID) }
        if let displayID { return (1 << 32) | UInt64(displayID) }
        return 0
    }

    /// The user's private temporary directory, the same for every process of the user whatever its
    /// environment (unlike `TMPDIR`, which a launcher may change). `nil` if the system has none.
    static func sharedDirectory() -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard confstr(_CS_DARWIN_USER_TEMP_DIR, &buffer, buffer.count) > 0 else { return nil }
        return String(cString: buffer)
    }

    /// Opens (creating it if needed) the user's shared file.
    /// - Parameters:
    ///   - key: The target this process encodes; 0 when the process only claims.
    ///   - path: The file. The default is `infraternal-encoder-priority` in the user's private
    ///     temporary directory; tests pass a private one. A path that cannot be opened leaves
    ///     priority off.
    init(key: UInt64 = 0, path: String? = nil) {
        self.key = key
        guard let path = path ?? Self.sharedDirectory().map({ $0 + "infraternal-encoder-priority" }) else { words = nil; return }
        let descriptor = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { words = nil; return }
        defer { close(descriptor) }
        // A new file is empty; sizing it again later is harmless.
        _ = ftruncate(descriptor, 4096)
        let mapped = mmap(nil, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0)
        words = mapped == MAP_FAILED ? nil : mapped?.bindMemory(to: UInt64.self, capacity: 3)
    }

    /// Ticks for `milliseconds`.
    private static func ticks(_ milliseconds: Double) -> UInt64 { UInt64(milliseconds * ticksPerMillisecond) }

    /// Records that remote input was just accepted for `target`, which makes it the controlled one
    /// for the next `claimMilliseconds`. Called by the control companion.
    func claim(target: UInt64) {
        guard let words, target != 0 else { return }
        words[1] = target
        words[2] = mach_absolute_time() + Self.ticks(Self.claimMilliseconds)
    }

    /// Whether a recorded end time still lies ahead, within `limit` milliseconds. A time further
    /// ahead than any writer could have set it is stale (the file outlived a reboot, which restarts
    /// the clock) and counts as over, so an old file can never make windows wait.
    private static func isAhead(_ end: UInt64, of now: UInt64, within limit: Double) -> Bool {
        end > now && end - now <= ticks(limit + 100)
    }

    /// True while this process's target holds an unexpired claim.
    private func isControlled(at now: UInt64) -> Bool {
        guard let words, key != 0 else { return false }
        return words[1] == key && Self.isAhead(words[2], of: now, within: Self.claimMilliseconds)
    }

    /// Call right before submitting a picture. The controlled window takes the lease and goes on at
    /// once; any other window waits while the lease is held, at most `waitMilliseconds`.
    func beforeEncode() {
        guard let words, key != 0 else { return }
        let now = mach_absolute_time()
        if isControlled(at: now) {
            words[0] = now + Self.ticks(Self.inFlightMilliseconds)
            return
        }
        // Someone else is controlled, or nobody is: only the first case can ask this window to wait.
        guard words[1] != 0, Self.isAhead(words[2], of: now, within: Self.claimMilliseconds) else { return }
        let limit = now + Self.ticks(Self.waitMilliseconds)
        while true {
            let current = mach_absolute_time()
            guard current < limit, Self.isAhead(words[0], of: current, within: Self.inFlightMilliseconds),
                  Self.isAhead(words[2], of: current, within: Self.claimMilliseconds) else { return }
            usleep(150)
        }
    }

    /// Call right after a picture was encoded (or dropped). The controlled window keeps the lease for
    /// `holdMilliseconds` more, for its next frame; any other window does nothing.
    func afterEncode() {
        guard let words else { return }
        let now = mach_absolute_time()
        if isControlled(at: now) { words[0] = now + Self.ticks(Self.holdMilliseconds) }
    }
}
