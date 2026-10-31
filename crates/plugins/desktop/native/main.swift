/// Role: signed AppKit-session companion; one private socket request/response, cleanup on EOF [D203,#146].
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

private let measureInputCommands = ProcessInfo.processInfo.environment["INFRATERNAL_DESKTOP_MEASURE"] != nil
let surfaceMode = CommandLine.arguments.contains("--surface-capture")
private let encoderMode = CommandLine.arguments.contains("--encoder")
private var companionInput = FileHandle.standardInput
private var companionOutput = FileHandle.standardOutput

enum HelperFailure: Error { case invalid, permission, unavailable }

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

private func readExactly(_ count: Int) throws -> Data {
    var result = Data()
    while result.count < count {
        let part = companionInput.readData(ofLength:count-result.count)
        guard !part.isEmpty else { throw HelperFailure.unavailable }
        result.append(part)
    }
    return result
}

private func readPacket() throws -> (UInt8, Data) {
    let header = try readExactly(6)
    let length = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard length >= 2, length <= (header[5] == 101 ? 16*1024*1024+1024 : 64*1024), header[4] == 1 else { throw HelperFailure.invalid }
    return (header[5],try readExactly(Int(length)-2))
}

private let outputLock = NSLock()
func sendPacket(_ kind: UInt8, _ body: Data) throws {
    guard body.count+2 <= (kind == 70 ? 4*1024*1024 : 64*1024) else { throw HelperFailure.invalid }
    var length = UInt32(body.count+2).bigEndian
    let header = withUnsafeBytes(of:&length) { Data($0) } + Data([1,kind])
    outputLock.lock(); defer { outputLock.unlock() }
    companionOutput.write(header + body)
}

private func json(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) }

private final class Session {
    var geometry: WindowGeometry?
    var screen: CGRect?
    var displayID: UInt32?
    var output: CGSize = .zero
    let control = RemoteControl()
    let encoder = Encoder()
    var timer: Timer?
    var surface: SurfaceCapture?
    var surfacePending = false

    func stop() -> [String: Any] {
        timer?.invalidate(); timer = nil
        let restored = geometry?.restore() ?? true
        control.stop(); surface?.stop(); surface = nil; surfacePending = false; encoder.stop(); geometry = nil; screen = nil; displayID = nil
        return ["state":"off","restored":restored]
    }

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

    func state() -> [String: Any] {
        if let geometry { return geometry.json().merging(["state":"on","input":control.status()]) { _,new in new } }
        if let screen { return ["state":"on","input":control.status(),"actual":rectJSON(screen),"capture_rect":rectJSON(screen),"content_rect":rectJSON(fittedContent(screen,output)),"reason":"screen","width":output.width,"height":output.height,"source_backing_scale":backingScale(screen),"source_fps":sourceFrameRate(screen)] }
        return ["state":"off","input":control.status()]
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
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
