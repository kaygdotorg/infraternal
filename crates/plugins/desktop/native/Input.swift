/// Role: hardware-local input wins; tagged private-state remote input and visible control indicator [D208 A3].
import AppKit
import ApplicationServices

private let measureInput = ProcessInfo.processInfo.environment["INFRATERNAL_DESKTOP_MEASURE"] != nil
private let remoteTag: Int64 = 0x696e667261746572
// Releases restart the local pause even when the preceding press was long ago.
private let inputTypes: [CGEventType] = [.mouseMoved, .leftMouseDown, .leftMouseUp, .rightMouseDown, .rightMouseUp, .otherMouseDown, .otherMouseUp,
    .leftMouseDragged, .rightMouseDragged, .otherMouseDragged, .scrollWheel, .keyDown, .keyUp, .flagsChanged]

private final class LocalInputClock {
    private var pause = LocalInputPause(lastLocal: ProcessInfo.processInfo.systemUptime - (inputTypes.map { CGEventSource.secondsSinceLastEventType(.hidSystemState,eventType:$0) }.min() ?? 0))
    var onLocal: (() -> Void)?
    private var global: Any?
    private var local: Any?
    init() {
        let mask: NSEvent.EventTypeMask = [.mouseMoved,.leftMouseDown,.leftMouseUp,.rightMouseDown,.rightMouseUp,.otherMouseDown,.otherMouseUp,.leftMouseDragged,.rightMouseDragged,.otherMouseDragged,.scrollWheel,.keyDown,.keyUp,.flagsChanged]
        global = NSEvent.addGlobalMonitorForEvents(matching:mask) { [weak self] event in self?.observe(event) }
        local = NSEvent.addLocalMonitorForEvents(matching:mask) { [weak self] event in self?.observe(event); return event }
    }
    private func observe(_ event: NSEvent) {
        // Posting private-source events still changes the HID idle clock. Filter the
        // explicit tag instead, and retain this clock across control connections.
        if pause.observe(at: ProcessInfo.processInfo.systemUptime, remote: event.cgEvent?.getIntegerValueField(.eventSourceUserData) == remoteTag) { onLocal?() }
    }
    var idle: Double { pause.idle(at: ProcessInfo.processInfo.systemUptime) }
    deinit { if let global { NSEvent.removeMonitor(global) }; if let local { NSEvent.removeMonitor(local) } }
}
private var clock: LocalInputClock?
func localIdleSeconds() -> Double {
    if let clock { return clock.idle }
    return inputTypes.map { CGEventSource.secondsSinceLastEventType(.hidSystemState,eventType:$0) }.min() ?? 0
}

final class RemoteControl {
    private var indicator: NSPanel?
    private let source = CGEventSource(stateID: .privateState)
    private var keys: Set<CGKeyCode> = []
    private var buttons: Set<UInt32> = []
    private var lastPoint = CGPoint.zero
    private var owner: NSRunningApplication?

    init() { if clock == nil && !CommandLine.arguments.contains("--encoder") { clock = LocalInputClock() } }

    var controlVisible: Bool { indicator?.isVisible == true }

    func begin() throws {
        if controlVisible { return }
        guard let screen = NSScreen.main ?? NSScreen.screens.first else { throw HelperFailure.unavailable }
        // A status item can be omitted when the menu bar is full. A nonactivating
        // panel makes control visible without stealing the target's keyboard focus.
        let frame = NSRect(x:screen.visibleFrame.maxX-260,y:screen.visibleFrame.maxY-44,width:248,height:32)
        let panel = NSPanel(contentRect:frame,styleMask:[.borderless,.nonactivatingPanel],backing:.buffered,defer:false)
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces,.fullScreenAuxiliary,.stationary]
        panel.hidesOnDeactivate = false
        panel.ignoresMouseEvents = true
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .windowBackgroundColor
        let label = NSTextField(labelWithString:"Controlled from infraternal")
        label.frame = NSRect(x:8,y:7,width:232,height:18)
        label.alignment = .center
        label.font = .systemFont(ofSize:13,weight:.medium)
        panel.contentView?.addSubview(label)
        panel.orderFrontRegardless()
        panel.displayIfNeeded()
        guard panel.isVisible else { panel.close(); throw HelperFailure.unavailable }
        indicator = panel
        clock?.onLocal = { [weak self] in self?.releaseHeld() }
    }

    // Reading priority never acquires control, posts an event or starts a timer.
    func status() -> [String: Any] {
        ["pause_remaining_ms": min(2000, max(0, 2-localIdleSeconds())*1000),
         "control_visible": indicator?.isVisible == true]
    }

    private func flags(_ bits: UInt8) -> CGEventFlags {
        var value: CGEventFlags = []
        if bits & 1 != 0 { value.insert(.maskShift) }; if bits & 2 != 0 { value.insert(.maskControl) }
        if bits & 4 != 0 { value.insert(.maskAlternate) }; if bits & 8 != 0 { value.insert(.maskCommand) }
        return value
    }

    private func post(_ event: CGEvent, modifiers: UInt8) {
        event.flags = flags(modifiers)
        event.setIntegerValueField(.eventSourceUserData, value: remoteTag)
        if measureInput {
            FileHandle.standardError.write(Data("METRIC native_input_post at_ns=\(nanos(mach_absolute_time())) type=\(event.type.rawValue)\n".utf8))
        }
        // Keyboard delivery is process-specific. Pointer delivery uses the HID tap
        // only after the topmost window owner at that point has been checked.
        if let owner, event.type == .keyDown || event.type == .keyUp || event.type == .flagsChanged {
            if !owner.isTerminated { event.postToPid(owner.processIdentifier) }
        } else { event.post(tap: .cghidEventTap) }
    }

    func inject(_ input: [String: Any], geometry: WindowGeometry?, screen: CGRect?, output: CGSize) throws -> [String: Any] {
        guard AXIsProcessTrusted(), CGPreflightPostEventAccess(), let source else { throw HelperFailure.permission }
        let idle = localIdleSeconds()
        guard idle >= 2 else { releaseHeld(); return ["accepted": false, "reason": "local_input", "pause_remaining_ms": (2-idle)*1000] }
        guard let type = input["type"] as? String else { throw HelperFailure.invalid }
        if type == "text" || type == "key" { geometry?.validateKeyboardTarget() }
        else { geometry?.follow() }
        guard geometry?.exists != false else { throw HelperFailure.unavailable }
        if let geometry, let app = NSRunningApplication(processIdentifier: geometry.pid) {
            if !app.isActive {
                guard app.activate(options: []) else { throw HelperFailure.unavailable }
                let deadline = ProcessInfo.processInfo.systemUptime+0.5
                while !app.isActive && ProcessInfo.processInfo.systemUptime < deadline {
                    _ = RunLoop.main.run(mode:.default,before:Date(timeIntervalSinceNow:0.005))
                }
                guard app.isActive else { throw HelperFailure.unavailable }
            }
            owner = app
            if let window = geometry.window {
                if axValue(window,kAXMinimizedAttribute as CFString) as? Bool == true {
                    _ = AXUIElementSetAttributeValue(window,kAXMinimizedAttribute as CFString,kCFBooleanFalse)
                }
                if axValue(window,kAXMainAttribute as CFString) as? Bool != true { _ = AXUIElementPerformAction(window,kAXRaiseAction as CFString) }
            }
        }
        guard localIdleSeconds() >= 2 else { releaseHeld(); return ["accepted":false,"reason":"local_input","pause_remaining_ms":max(0,2-localIdleSeconds())*1000] }
        let mods = input["modifiers"] as? UInt8 ?? 0
        try begin()
        if geometry == nil { owner = NSWorkspace.shared.frontmostApplication }
        if type == "text" {
            guard let scalar = input["scalar"] as? UInt32, let value = UnicodeScalar(scalar), scalar >= 32, !(127...159).contains(scalar) else { throw HelperFailure.invalid }
            let units = Array(String(value).utf16)
            // Committed Unicode text follows the viewer's layout; shortcuts use physical keys.
            // Posting both halves as one event preserves supplementary Unicode characters.
            for down in [true, false] {
                guard let event = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { throw HelperFailure.unavailable }
                units.withUnsafeBufferPointer { event.keyboardSetUnicodeString(stringLength: units.count, unicodeString: $0.baseAddress!) }
                post(event, modifiers: 0)
            }
        } else if type == "key" {
            guard let key = input["keycode"] as? UInt16, key <= 127, let down = input["down"] as? Bool,
                  let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: down) else { throw HelperFailure.invalid }
            if (54...62).contains(key) && key != 57 { event.type = .flagsChanged }
            post(event, modifiers: mods)
            if down { keys.insert(key) } else { keys.remove(key) }
        } else {
            guard let x = input["x"] as? Double, let y = input["y"] as? Double else { throw HelperFailure.invalid }
            let point: CGPoint?
            if let geometry { point = geometry.point(x:x,y:y) }
            else if let screen {
                point = mappedPoint(x:x,y:y,source:screen,output:output)
            } else { point = nil }
            guard let point else { return ["accepted": false, "reason": "letterbox"] }
            if let geometry {
                let front = windowSnapshot(applicationMetadata: false).first { entry in
                    guard entry["on_screen"] as? Bool == true, let raw = entry["frame"] as? [String:Any], let frame = try? rect(raw) else { return false }
                    return frame.contains(point)
                }
                guard front?["owner_pid"] as? Int32 == geometry.pid else { return ["accepted":false,"reason":"occluded"] }
            }
            lastPoint = point
            if type == "mouse" {
                guard let button = input["button"] as? UInt32, button <= 2, let state = input["state"] as? UInt8, state <= 2,
                      let mouseButton = CGMouseButton(rawValue:button) else { throw HelperFailure.invalid }
                let down: [CGEventType] = [.leftMouseDown,.rightMouseDown,.otherMouseDown]
                let up: [CGEventType] = [.leftMouseUp,.rightMouseUp,.otherMouseUp]
                let drag: [CGEventType] = [.leftMouseDragged,.rightMouseDragged,.otherMouseDragged]
                let eventType = state == 1 ? down[Int(button)] : state == 2 ? up[Int(button)] : buttons.contains(button) ? drag[Int(button)] : .mouseMoved
                guard let event = CGEvent(mouseEventSource: source, mouseType:eventType, mouseCursorPosition:point, mouseButton:mouseButton) else { throw HelperFailure.unavailable }
                post(event, modifiers:mods)
                if state == 1 { buttons.insert(button) } else if state == 2 { buttons.remove(button) }
            } else if type == "scroll" {
                guard let dx = input["dx"] as? Int32, let dy = input["dy"] as? Int32,
                      let event = CGEvent(scrollWheelEvent2Source:source, units:.pixel, wheelCount:2, wheel1:dy, wheel2:dx, wheel3:0) else { throw HelperFailure.invalid }
                event.location = point; post(event, modifiers:mods)
            } else { throw HelperFailure.invalid }
        }
        return ["accepted": true]
    }

    private func releaseHeld() {
        // Release held remote keys/buttons on disconnect, even during a local-input pause,
        // to prevent sticky modifiers or drags. These tagged releases are cleanup, not new control.
        for key in keys { if let e = CGEvent(keyboardEventSource:source,virtualKey:key,keyDown:false) { if (54...62).contains(key) && key != 57 { e.type = .flagsChanged }; post(e,modifiers:0) } }
        for button in buttons {
            let types: [CGEventType] = [.leftMouseUp,.rightMouseUp,.otherMouseUp]
            if let b = CGMouseButton(rawValue:button), let e = CGEvent(mouseEventSource:source,mouseType:types[Int(button)],mouseCursorPosition:lastPoint,mouseButton:b) { post(e,modifiers:0) }
        }
        keys.removeAll(); buttons.removeAll()
    }

    // Controller handover cleans held input even during a local-input pause;
    // capture and the local-activity monitor remain active for the new owner.
    func release() {
        releaseHeld(); owner = nil
    }

    func setActive(_ active: Bool) throws {
        if active { releaseHeld(); owner = nil; try begin() } else { stop() }
    }

    func stop() {
        clock?.onLocal = nil
        releaseHeld(); owner = nil
        indicator?.orderOut(nil); indicator?.close(); indicator = nil
    }
}
