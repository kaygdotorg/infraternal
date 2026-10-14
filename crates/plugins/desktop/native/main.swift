/// Role: private AppKit-session companion; one bounded stdio request/response, cleanup on EOF [D203].
import AppKit
import Foundation
import Darwin

let surfaceMode = CommandLine.arguments.contains("--surface-capture")
private let encoderMode = CommandLine.arguments.contains("--encoder")

enum HelperFailure: Error { case invalid, permission, unavailable }

private func readExactly(_ count: Int) throws -> Data {
    var result = Data()
    while result.count < count {
        let part = FileHandle.standardInput.readData(ofLength:count-result.count)
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
    FileHandle.standardOutput.write(header + body)
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
                // Timer exists only during a stream; refusal and local activity are retried when idle.
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
        if let geometry { return geometry.json().merging(["state":"on"]) { _,new in new } }
        if let screen { return ["state":"on","actual":rectJSON(screen),"capture_rect":rectJSON(screen),"content_rect":rectJSON(fittedContent(screen,output)),"reason":"screen","width":output.width,"height":output.height,"source_backing_scale":backingScale(screen),"source_fps":sourceFrameRate(screen)] }
        return ["state":"off"]
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
                    DispatchQueue.main.sync {
                        do { reply = try session.command(kind,body) } catch { failure = error }
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
