/// Role: AX window identity and aspect-preserving geometry that yields permanently to managed desktops [D208 A2,D290].
/// Coordinates: window frames are in screen points with the origin at the top left of the main
/// display (the Core Graphics and Accessibility convention). `output` sizes are encoded pixels.
import AppKit
import ApplicationServices
import Darwin

/// Read executable names, never arguments or settings. Cache across viewers;
/// manager presence latches separately in each window, including on restoration.
/// Process names are compared against `tilingManagerExecutables`. Scans at most once per second.
private enum WindowManagerPresence {
    /// Monotonic seconds of the last process scan.
    static var checkedAt = -Double.infinity
    /// Result of the last scan.
    static var present = false
    /// True if a tiling manager is running. Scans the process list at most once per second;
    /// `now` is monotonic seconds.
    static func current(at now: Double) -> Bool {
        if now - checkedAt < 1 { return present }
        checkedAt = now
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return present }
        var pids = [Int32](repeating: 0, count: Int(count) + 64)
        let found = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        present = pids.prefix(max(0, min(Int(found), pids.count))).contains { pid in
            var name = [CChar](repeating: 0, count: 1024)
            let length = name.withUnsafeMutableBytes { proc_name(pid, $0.baseAddress, UInt32($0.count)) }
            guard length > 0 else { return false }
            return tilingManagerExecutables.contains(String(decoding: name.prefix(Int(length)).map { UInt8(bitPattern: $0) }, as: UTF8.self))
        }
        return present
    }
}

/// Reads one Accessibility attribute, or `nil` if the element does not have it or the call fails.
func axValue(_ element: AXUIElement, _ name: CFString) -> CFTypeRef? {
    var value: CFTypeRef?
    guard AXUIElementCopyAttributeValue(element, name, &value) == .success else { return nil }
    return value
}

/// The on-screen frame of an Accessibility window element in points, or `nil` if unreadable.
func axFrame(_ element: AXUIElement) -> CGRect? {
    guard let p = axValue(element, kAXPositionAttribute as CFString), CFGetTypeID(p) == AXValueGetTypeID(),
          let s = axValue(element, kAXSizeAttribute as CFString), CFGetTypeID(s) == AXValueGetTypeID() else { return nil }
    var point = CGPoint.zero; var size = CGSize.zero
    guard AXValueGetValue(p as! AXValue, .cgPoint, &point), AXValueGetValue(s as! AXValue, .cgSize, &size) else { return nil }
    return CGRect(origin: point, size: size)
}

/// Follows one application window and keeps the capture area, output size and resizing in step.
///
/// The infraternal agent may resize the real window so its shape matches the viewer, but it gives
/// up for good when a tiling manager owns the desktop, and pauses while the local user is active.
/// All methods must run on the main thread: the Accessibility observer is attached to its run
/// loop.
final class WindowGeometry {
    /// Process ID of the app that owns the window.
    let pid: Int32
    /// Window server ID of the window.
    let id: UInt32
    /// The matching Accessibility element, or `nil` when no single window matched; then the window can
    /// be followed but never resized.
    let window: AXUIElement?
    /// The window's frame when we first saw it; `restore` puts it back.
    let original: CGRect
    /// The window's current frame in points.
    var actual: CGRect
    /// The window size, in points, that would fill the viewer's output at the display's density.
    var desired: CGSize
    /// Size of the encoded picture in pixels, as requested by the viewer.
    var output: CGSize
    /// Where the captured area sits inside `output`, in output pixels, after fitting.
    var content: CGRect = .zero
    /// Area captured, in screen points: the window plus overlapping popups of the same app.
    var captureRect: CGRect = .zero
    /// Accessibility observer that calls `follow` on moves, resizes and menu changes.
    private var observer: AXObserver?
    /// Why the window is or is not being resized: `following`, `refused`, `managed`, `local_input` or
    /// `closed`.
    var reason = "following"
    /// True once we changed the window's size, so `restore` knows it has work to do.
    var didResize = false
    /// Tracks whether the desktop owns this window's size.
    private var ownership = WindowResizeOwnership()
    /// Number of resize requests sent, for diagnostics.
    private var resizeRequests = 0
    /// False once the window has gone.
    var exists = true
    /// Frames where clicks may go: the window and its overlapping popups. Gaps between them are excluded.
    private var interactive: [CGRect] = []

    /// Starts following a window.
    ///
    /// Throws `HelperFailure.permission` when Accessibility access is missing or the window ID and
    /// process do not match a real window, and `HelperFailure.invalid` for a bad `size`. `size` has
    /// the keys described at `resize`.
    init(id: UInt32, pid: Int32, size: [String: Any]) throws {
        guard AXIsProcessTrusted(), let entry = windowSnapshot(applicationMetadata: false).first(where: {
            ($0["window_id"] as? UInt32) == id && ($0["owner_pid"] as? Int32) == pid
        }), let frame = entry["frame"] as? [String: Any] else { throw HelperFailure.permission }
        self.pid = pid; self.id = id; original = try rect(frame); actual = original
        desired = .zero; output = .zero
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(app, 0.25)
        let candidates = axValue(app, kAXWindowsAttribute as CFString) as? [AXUIElement] ?? []
        // Public AX has no guaranteed CG window-ID attribute. Refuse ambiguous matches
        // rather than resizing another window with the same title or position.
        let originalFrame = original
        let matches = candidates.filter { candidate in
            guard let f = axFrame(candidate) else { return false }
            return abs(f.minX - originalFrame.minX) < 2 && abs(f.minY - originalFrame.minY) < 2
                && abs(f.width - originalFrame.width) < 2 && abs(f.height - originalFrame.height) < 2
        }
        window = matches.count == 1 ? matches.first : nil
        if let window { AXUIElementSetMessagingTimeout(window,0.025) }
        try resize(size)
        var created: AXObserver?
        if AXObserverCreate(pid, { _, _, _, context in
            guard let context else { return }
            let geometry = Unmanaged<WindowGeometry>.fromOpaque(context).takeUnretainedValue()
            geometry.follow()
        }, &created) == .success, let created {
            observer = created
            let context = Unmanaged.passUnretained(self).toOpaque()
            for name in [kAXMenuOpenedNotification, kAXMenuClosedNotification, kAXWindowCreatedNotification] {
                _ = AXObserverAddNotification(created, app, name as CFString, context)
            }
            if let window {
                for name in [kAXMovedNotification, kAXResizedNotification] {
                    _ = AXObserverAddNotification(created, window, name as CFString, context)
                }
            }
            CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(created), .commonModes)
        }
    }

    /// Detaches the observer from the main run loop.
    deinit {
        if let observer { CFRunLoopRemoveSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(observer), .commonModes) }
    }

    /// Applies a new output size from the viewer and refreshes the geometry.
    ///
    /// `size` holds `canvas_width`, `canvas_height`, `backing_scale`, `width` and `height`, all
    /// finite and greater than 0; `width` and `height` are output pixels. Throws
    /// `HelperFailure.invalid` otherwise.
    func resize(_ size: [String: Any]) throws {
        guard let cw = size["canvas_width"] as? Double, let ch = size["canvas_height"] as? Double,
              let scale = size["backing_scale"] as? Double,
              let w = size["width"] as? Double, let h = size["height"] as? Double,
              [cw,ch,scale,w,h].allSatisfy({ $0.isFinite && $0 > 0 }) else { throw HelperFailure.invalid }
        // The request describes output pixels (canvas × requested scale). AX takes
        // host points: divide by the actual display density, never an untrusted hint.
        let hostScale = backingScale(actual)
        desired = CGSize(width: w / hostScale, height: h / hostScale)
        output = CGSize(width: w, height: h)
        follow()
    }

    /// Keyboard input has no coordinates. Validate the same live window/PID on
    /// every event without enumerating other windows, reading AX geometry or
    /// attempting a resize. Pointer input and AX notifications still reconcile
    /// geometry, menus and the managed-window detector through follow().
    func validateKeyboardTarget() {
        exists = windowSnapshot(applicationMetadata: false, windowID: id).contains {
            ($0["window_id"] as? UInt32) == id && ($0["owner_pid"] as? Int32) == pid
        }
        if !exists { interactive = []; reason = "closed" }
    }

    /// Re-reads the window's state, decides whether to resize it and recomputes `captureRect`,
    /// `content` and the click areas. Sets `exists` to false and `reason` to `closed` when the window
    /// has gone.
    ///
    /// A resize is requested at most once per new size, never while a tiling manager is present and
    /// not within 60 seconds of local keyboard or mouse use.
    func follow() {
        let snapshot = windowSnapshot(applicationMetadata: false)
        guard let selected = snapshot.first(where: { ($0["window_id"] as? UInt32) == id && ($0["owner_pid"] as? Int32) == pid }),
              let raw = selected["frame"] as? [String: Any], let cgFrame = try? rect(raw) else {
            exists = false; interactive = []; reason = "closed"; return
        }
        exists = true
        if let window, let f = axFrame(window) { actual = f } else { actual = cgFrame }
        let density = backingScale(actual)
        desired = CGSize(width:output.width/density,height:output.height/density)
        let now = ProcessInfo.processInfo.systemUptime
        ownership.detectManager(WindowManagerPresence.current(at: now))
        ownership.observe(actual.size, at: now)
        if ownership.managed { reason = "managed" }
        else if localIdleSeconds() < 60 { reason = "local_input" }
        else if let window {
            var settable = DarwinBoolean(false)
            let canSet = AXUIElementIsAttributeSettable(window, kAXSizeAttribute as CFString, &settable) == .success && settable.boolValue
            if canSet && ownership.attempt(desired, actual: actual.size, at: now) {
                var size = desired
                if let value = AXValueCreate(.cgSize, &size),
                   requestSize(window, value) == .success {
                    didResize = true
                    if let f = axFrame(window) { actual = f }
                }
            }
            reason = canSet && abs(actual.width - desired.width) < 1 && abs(actual.height - desired.height) < 1 ? "following" : "refused"
        } else { reason = "refused" }
        // Include complete same-process auxiliary windows when they overlap the selected
        // window; the capture filter still enforces ownership independently.
        captureRect = actual; interactive = [actual]
        for entry in snapshot where (entry["owner_pid"] as? Int32) == pid && (entry["window_id"] as? UInt32) != id && (entry["on_screen"] as? Bool) == true {
            if let raw = entry["frame"] as? [String: Any], let frame = try? rect(raw), frame.intersects(actual) {
                captureRect = captureRect.union(frame); interactive.append(frame)
            }
        }
        let ratio = min(output.width / captureRect.width, output.height / captureRect.height)
        let size = CGSize(width: captureRect.width * ratio, height: captureRect.height * ratio)
        content = CGRect(x: (output.width - size.width)/2, y: (output.height - size.height)/2, width: size.width, height: size.height)
    }

    /// Puts the window back to its original size and position.
    ///
    /// Returns `true` when there was nothing to undo or the window is back within 1 point of the
    /// original; `false` if it could not be restored. Does nothing for a managed window, because
    /// restoring would start a fight with the manager.
    func restore() -> Bool {
        ownership.detectManager(WindowManagerPresence.current(at: ProcessInfo.processInfo.systemUptime))
        // Restoring an old size after ownership changed would restart the fight.
        if ownership.managed { didResize = false; return true }
        guard didResize, let window else { return true }
        var size = original.size; var point = original.origin
        guard let s = AXValueCreate(.cgSize, &size), let p = AXValueCreate(.cgPoint, &point) else { return false }
        let resized = AXUIElementSetAttributeValue(window, kAXSizeAttribute as CFString, s) == .success
        let moved = AXUIElementSetAttributeValue(window, kAXPositionAttribute as CFString, p) == .success
        guard let f = axFrame(window) else { return false }
        didResize = false
        return resized && moved && abs(f.minX-original.minX) < 1 && abs(f.minY-original.minY) < 1
            && abs(f.width-original.width) < 1 && abs(f.height-original.height) < 1
    }

    /// The window's state as a JSON-ready dictionary (rectangles, reason, output size, IDs, scale).
    func json() -> [String: Any] {
        ["original": rectJSON(original), "actual": rectJSON(actual), "capture_rect": rectJSON(captureRect), "content_rect": rectJSON(content),
         "reason": reason, "width": output.width, "height": output.height, "window_id": id, "owner_pid": pid, "source_backing_scale": backingScale(actual), "managed": ownership.managed, "resize_requests": resizeRequests]
    }

    /// Sends one size change through Accessibility and counts it.
    private func requestSize(_ window: AXUIElement, _ value: AXValue) -> AXError {
        resizeRequests += 1
        return AXUIElementSetAttributeValue(window, kAXSizeAttribute as CFString, value)
    }

    /// Converts a point in the encoded picture (output pixels) to screen points.
    ///
    /// Returns `nil` when the window is gone, the point is in the letterbox bars, or it is in a gap
    /// between the window and its popups, where a click could reach another app.
    func point(x: Double, y: Double) -> CGPoint? {
        guard exists, let point = mappedPoint(x:x,y:y,source:captureRect,output:output) else { return nil }
        // The bounding rectangle includes gaps between menus and the main window.
        // A click in such a gap could reach a different app behind the filtered image.
        return interactive.contains(where: { $0.contains(point) }) ? point : nil
    }
}
