/// Role: signed AppKit-session companion; one private socket request/response, cleanup on EOF [D203,#146].
/// This is the macOS helper process that the infraternal agent starts inside the logged-in desktop
/// session, because only a process there can capture the screen and post input. It talks to the
/// infraternal agent over one private Unix socket (`--socket PATH`; standard input and output when
/// absent) using length-prefixed packets, and exits when that connection ends.
///
/// Packet layout: 4 bytes big-endian length (counting the two bytes after it), 1 byte version
/// (always 1), 1 byte kind, then the body. Request bodies are JSON, except kind 101, which is a
/// 4-byte JSON length, the JSON, then raw BGRA pixels. Requests: 1 inventory, 2 start, 3 resize,
/// 4 input, 5 stop, 6 geometry check, 7 request keyframe, 8 release control, 9 congestion,
/// 10 set control on or off, 101 encode these pixels. Replies: 65 inventory, 66 state after start or
/// resize, 67 input result, 68 state, 69 error, 70 encoded video. Incoming packets are limited to
/// 64 KiB (16 MiB for kind 101); outgoing ones to 64 KiB (4 MiB for video).
///
/// At launch the file also runs three command-line modes before anything else is set up:
/// `--check-permissions` prints the privacy state and exits, `--capture-still ID PID PATH.png`
/// saves a screenshot of one window under this app's own permissions, and `--launch-pid-file`
/// (see `recordLaunchPIDIfRequested`). Other flags: `--surface-capture`, `--encoder`, `--hevc`.
import AppKit
import Foundation
import Darwin

// Privacy preflights and every framework object must be created only after
// responsibility changes. The same entry path serves production and diagnostics.
do { try establishResponsibility() }
catch {
    FileHandle.standardError.write(Data("Desktop responsibility launch unavailable.\n".utf8))
    exit(1)
}
do { try recordLaunchPIDIfRequested() }
catch {
    FileHandle.standardError.write(Data("Desktop launch identity unavailable.\n".utf8))
    exit(1)
}

// Diagnostic mode shares production attribution and exits before AppKit state,
// capture, input monitors or any permission-request API can be created.
if CommandLine.arguments.contains("--check-permissions") {
    do { FileHandle.standardOutput.write(try permissionJSON() + Data([10])) }
    catch { exit(1) }
    exit(0)
}

// A local diagnostic uses the same granted identity as streaming. A separate
// shell-launched capture tool would be attributed to that shell instead.
if let index = CommandLine.arguments.firstIndex(of: "--capture-still") {
    let arguments = CommandLine.arguments
    guard arguments.count > index + 3, let id = UInt32(arguments[index + 1]), id > 0,
          let pid = Int32(arguments[index + 2]), pid > 0, CGPreflightScreenCaptureAccess(),
          windowSnapshot().contains(where: { $0["window_id"] as? UInt32 == id && $0["owner_pid"] as? Int32 == pid }),
          arguments[index + 3].hasPrefix("/"), arguments[index + 3].hasSuffix(".png") else { exit(2) }
    let capture = Process()
    capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    capture.arguments = ["-x", "-l", String(id), "-t", "png", arguments[index + 3]]
    do {
        try capture.run()
        fputs("DESKTOP_STILL child_pid=\(capture.processIdentifier)\n",stderr)
        capture.waitUntilExit(); exit(capture.terminationStatus)
    }
    catch { exit(1) }
}

/// Opt-in timing output, enabled by the `INFRATERNAL_DESKTOP_MEASURE` environment variable.
private let measureInputCommands = ProcessInfo.processInfo.environment["INFRATERNAL_DESKTOP_MEASURE"] != nil
/// True with `--surface-capture`: the window or screen is captured and encoded inside this process
/// (see `SurfaceCapture`) rather than being sent as raw pixels.
let surfaceMode = CommandLine.arguments.contains("--surface-capture")
/// True with `--encoder`: this process only encodes pixels sent by the caller and does no capture.
private let encoderMode = CommandLine.arguments.contains("--encoder")
/// Where requests are read from: the private socket, or standard input without `--socket`.
private var companionInput = FileHandle.standardInput
/// Where replies are written: the private socket, or standard output without `--socket`.
private var companionOutput = FileHandle.standardOutput

/// Why an operation failed: `invalid` (malformed or out-of-range request), `permission` (Screen
/// Recording or Accessibility missing) or `unavailable` (window closed, encoder or capture
/// failed). The text sent to the caller is generic; details go to standard error.
enum HelperFailure: Error { case invalid, permission, unavailable }

/// Connects to the Unix socket named by `--socket PATH` and uses it for all packets.
///
/// Does nothing when the option is absent. Throws `HelperFailure.invalid` for a repeated option,
/// a missing, relative or too long path, and a `POSIXError` when the connection fails.
private func connectCompanionChannel() throws {
    let matches = CommandLine.arguments.indices.filter { CommandLine.arguments[$0] == "--socket" }
    guard !matches.isEmpty else { return }
    guard matches.count == 1, let index = matches.first,
          CommandLine.arguments.count > index + 1 else { throw HelperFailure.invalid }
    let path = CommandLine.arguments[index + 1]
    let encoded = Array(path.utf8) + [0]
    var address = sockaddr_un()
    guard path.hasPrefix("/"), encoded.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw HelperFailure.invalid }
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    address.sun_family = sa_family_t(AF_UNIX)
    let copied = withUnsafeMutableBytes(of: &address.sun_path) { (destination: UnsafeMutableRawBufferPointer) -> Bool in
        guard encoded.count <= destination.count else { return false }
        destination.copyBytes(from: encoded)
        return true
    }
    guard copied else { throw HelperFailure.invalid }
    let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else {
        let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        _ = Darwin.close(descriptor)
        throw error
    }
    let outputDescriptor = Darwin.dup(descriptor)
    guard outputDescriptor >= 0 else {
        let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        _ = Darwin.close(descriptor)
        throw error
    }
    companionInput = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    companionOutput = FileHandle(fileDescriptor: outputDescriptor, closeOnDealloc: true)
}

do { try connectCompanionChannel() }
catch {
    FileHandle.standardError.write(Data("Desktop companion channel unavailable.\n".utf8))
    exit(1)
}

/// Reads exactly `count` bytes, blocking. Throws `HelperFailure.unavailable` at end of input.
private func readExactly(_ count: Int) throws -> Data {
    var result = Data()
    while result.count < count {
        let part = companionInput.readData(ofLength:count-result.count)
        guard !part.isEmpty else { throw HelperFailure.unavailable }
        result.append(part)
    }
    return result
}

/// Reads one request. Returns its kind and body. Throws `HelperFailure.invalid` for a wrong version
/// or a length over the limit for that kind.
private func readPacket() throws -> (UInt8, Data) {
    let header = try readExactly(6)
    let length = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard length >= 2, length <= (header[5] == 101 ? 16*1024*1024+1024 : 64*1024), header[4] == 1 else { throw HelperFailure.invalid }
    return (header[5],try readExactly(Int(length)-2))
}

/// Serializes writes, because replies and video are sent from different threads.
private let outputLock = NSLock()
/// Writes one packet. Safe to call from any thread. Throws `HelperFailure.invalid` when the body
/// exceeds the limit for its kind (4 MiB for video kind 70, 64 KiB otherwise).
func sendPacket(_ kind: UInt8, _ body: Data) throws {
    guard body.count+2 <= (kind == 70 ? 4*1024*1024 : 64*1024) else { throw HelperFailure.invalid }
    var length = UInt32(body.count+2).bigEndian
    let header = withUnsafeBytes(of:&length) { Data($0) } + Data([1,kind])
    outputLock.lock(); defer { outputLock.unlock() }
    companionOutput.write(header + body)
}

/// Encodes a dictionary as JSON with sorted keys, so replies are deterministic.
private func json(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) }

/// Everything the helper holds for the one active capture and control session.
///
/// It is only touched on the main thread: requests arrive on a background thread and are run with
/// `DispatchQueue.main.sync`, because Accessibility and AppKit need the main run loop.
private final class Session {
    /// Set while a single window is shared.
    var geometry: WindowGeometry?
    /// The shared area in screen points for a whole display or a surface capture.
    var screen: CGRect?
    /// The display being shared, when sharing a whole screen.
    var displayID: UInt32?
    /// Size in pixels of the encoded picture.
    var output: CGSize = .zero
    /// Remote keyboard and mouse input.
    let control = RemoteControl()
    /// The video encoder used in `--encoder` mode and for pixels sent by the caller.
    let encoder = Encoder()
    /// Once a second, re-reads the window's frame and state so it is followed while idle.
    var timer: Timer?
    /// The in-process capture and encode pipeline in `--surface-capture` mode.
    var surface: SurfaceCapture?
    /// True between starting a surface capture and sending its first reply; the stream begins only after
    /// that reply so video can never be mistaken for the answer to the start request.
    var surfacePending = false

    /// Ends sharing: restores the window's size, stops input, capture and encoding, and clears the target.
    /// Returns a state dictionary with `restored` telling whether the window was put back.
    func stop() -> [String: Any] {
        timer?.invalidate(); timer = nil
        let restored = geometry?.restore() ?? true
        control.stop(); surface?.stop(); surface = nil; surfacePending = false; encoder.stop(); geometry = nil; screen = nil; displayID = nil
        return ["state":"off","restored":restored]
    }

    /// Runs one request and returns the reply kind and body. Throws `HelperFailure`.
    ///
    /// Kinds: 1 lists windows and displays; 2 starts sharing a `target` (`window` or `screen`) at
    /// `size` and needs both permissions; 3 changes the output size; 4 posts input (see
    /// `RemoteControl.inject`); 5 stops; 6 refreshes geometry and stamps the time; 7 asks the surface
    /// capture for a keyframe; 8 lets go of held input; 9 reports congestion; 10 turns control on or
    /// off.
    func command(_ kind: UInt8, _ body: [String: Any]) throws -> (UInt8, [String: Any]) {
        switch kind {
        case 1: return (65,try inventory())
        case 2:
            guard geometry == nil && screen == nil, CGPreflightScreenCaptureAccess(), AXIsProcessTrusted(),
                  let target = body["target"] as? [String: Any], let type = target["type"] as? String,
                  let size = body["size"] as? [String: Any], let w = size["width"] as? Int, let h = size["height"] as? Int else { throw HelperFailure.permission }
            do {
                if surfaceMode {
                    guard let raw = body["capture_rect"] as? [String:Any] else { throw HelperFailure.invalid }
                    screen = try rect(raw)
                    let fps = sourceFrameRate(screen!)
                    surface = SurfaceCapture(target:target, rect:screen!, size:CGSize(width:w,height:h), hevc:CommandLine.arguments.contains("--hevc"), fps:fps, output:sendPacket)
                    surfacePending = true
                } else if type == "window" {
                    guard let id = target["window_id"] as? UInt32, let pid = target["owner_pid"] as? Int32 else { throw HelperFailure.invalid }
                    geometry = try WindowGeometry(id:id,pid:pid,size:size)
                } else if type == "screen" {
                    guard let id = target["display_id"] as? UInt32, CGDisplayIsActive(id) != 0 else { throw HelperFailure.invalid }
                    displayID = id; screen = CGDisplayBounds(id)
                } else { throw HelperFailure.invalid }
                output = CGSize(width:w,height:h)
                if encoderMode { try encoder.configure(width:w,height:h) }
                // Reconcile only while streaming. Local activity defers following;
                // managed windows never retry a native resize, including at idle.
                if !surfaceMode { timer = Timer.scheduledTimer(withTimeInterval:1,repeats:true) { [weak self] _ in self?.geometry?.follow() } }
                return (66,state())
            } catch { _ = stop(); throw error }
        case 3:
            guard geometry?.exists != false, geometry != nil || screen != nil, let w = body["width"] as? Int, let h = body["height"] as? Int else { throw HelperFailure.invalid }
            try geometry?.resize(body); output = CGSize(width:w,height:h)
            if encoderMode { try encoder.configure(width:w,height:h) }
            return (66,state())
        case 4:
            if let displayID {
                guard CGDisplayIsActive(displayID) != 0 else { throw HelperFailure.unavailable }
                screen = CGDisplayBounds(displayID)
            }
            guard geometry?.exists != false, geometry != nil || screen != nil else { throw HelperFailure.invalid }
            return (67,try control.inject(body,geometry:geometry,screen:screen,output:output))
        case 5: return (68,stop())
        case 6:
            if let displayID {
                guard CGDisplayIsActive(displayID) != 0 else { throw HelperFailure.unavailable }
                screen = CGDisplayBounds(displayID)
            }
            guard geometry?.exists != false else { throw HelperFailure.unavailable }
            let ticks = mach_absolute_time()
            var result = state(); result["capture_ticks"] = ticks; result["capture_ns"] = nanos(ticks)
            return (68,result)
        case 7:
            guard let surface else { throw HelperFailure.unavailable }
            surface.repair(); return (68,["state":"on","keyframe_requested":true])
        case 10:
            guard geometry != nil || screen != nil, let active = body["active"] as? Bool else { throw HelperFailure.invalid }
            try control.setActive(active)
            return (68,["state":"on","control":active,"control_visible":control.controlVisible])
        case 9:
            if let surface { surface.congestion() } else { encoder.congestion() }
            return (68,["state":"on"])
        case 8:
            control.release()
            var result = state(); result["released"] = true
            return (68,result)
        default: throw HelperFailure.invalid
        }
    }

    /// The current sharing state as a JSON-ready dictionary: geometry, output size and input status,
    /// or just `off`.
    func state() -> [String: Any] {
        if let geometry { return geometry.json().merging(["state":"on","input":control.status()]) { _,new in new } }
        if let screen { return ["state":"on","input":control.status(),"actual":rectJSON(screen),"capture_rect":rectJSON(screen),"content_rect":rectJSON(fittedContent(screen,output)),"reason":"screen","width":output.width,"height":output.height,"source_backing_scale":backingScale(screen),"source_fps":sourceFrameRate(screen)] }
        return ["state":"off","input":control.status()]
    }
}

/// The AppKit application, in `accessory` mode: no Dock icon and no menu bar.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
/// The one session. The reader loop below runs on a background thread and exits the app when the
/// connection closes.
private let session = Session()
// Framework UI and AX lifecycle run on the logged-in session's main run loop.
DispatchQueue.global(qos:.userInteractive).async {
    do {
        while true {
            let (kind,payload) = try readPacket()
            let received = kind == 4 && measureInputCommands ? nanos(mach_absolute_time()) : 0
            do {
                let metadata: Data
                let pixels: Data
                if kind == 101 {
                    guard payload.count >= 4 else { throw HelperFailure.invalid }
                    let length = payload.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                    guard length <= 1024, Int(length)+4 <= payload.count else { throw HelperFailure.invalid }
                    metadata = payload.subdata(in:4..<4+Int(length)); pixels = payload.subdata(in:4+Int(length)..<payload.count)
                } else { metadata = payload; pixels = Data() }
                guard let body = try JSONSerialization.jsonObject(with:metadata) as? [String: Any] else { throw HelperFailure.invalid }
                if kind == 101 {
                    if encoderMode {
                        guard let width = body["width"] as? Int, let height = body["height"] as? Int else { throw HelperFailure.invalid }
                        try session.encoder.configure(width:width,height:height)
                    }
                    try sendPacket(70,session.encoder.encode(body,pixels:pixels))
                } else {
                    var reply: (UInt8,[String: Any])?
                    var failure: Error?
                    var dispatched: UInt64 = 0
                    DispatchQueue.main.sync {
                        if received != 0 { dispatched = nanos(mach_absolute_time()) }
                        do { reply = try session.command(kind,body) } catch { failure = error }
                    }
                    if received != 0 {
                        // One content-free write keeps concurrent capture receipts intact.
                        let finished = nanos(mach_absolute_time())
                        FileHandle.standardError.write(Data("METRIC native_input receive_ns=\(received) dispatch_ns=\(dispatched) finished_ns=\(finished) accepted=\(reply?.1["accepted"] as? Bool == true) local_pause=\(reply?.1["reason"] as? String == "local_input") failed=\(failure != nil)\n".utf8))
                    }
                    if let failure { throw failure }
                    guard let reply else { throw HelperFailure.unavailable }
                    try sendPacket(reply.0,try json(reply.1))
                    // Start the asynchronous stream only after its solicited geometry
                    // reply. Unsolicited video must never satisfy a Start exchange.
                    DispatchQueue.main.sync {
                        if session.surfacePending, let surface = session.surface {
                            session.surfacePending = false
                            Task {
                                do { try await surface.start() }
                                catch { if surface.stop() { try? sendPacket(69,Data("{\"error\":\"Desktop capture is unavailable.\"}".utf8)) } }
                            }
                        }
                    }
                }
            } catch {
                let message = error as? HelperFailure == .permission ? "Screen Recording and Accessibility are required." : "The desktop operation is unavailable."
                try sendPacket(69,try json(["error":message]))
            }
        }
    } catch {
        DispatchQueue.main.async { _ = session.stop(); app.terminate(nil) }
    }
}
app.run()
