/// Role: fast Core Graphics inventory joined to app identity without ScreenCaptureKit enumeration [D208].
import AppKit
import CoreGraphics

// Input and geometry need ownership and bounds, not application labels. Keep
// their projection on the same validated CG entries without LaunchServices work
// per window on every keystroke or AX notification. The picker retains labels.
/// Lists the windows known to the window server as JSON-ready dictionaries.
///
/// Each has `window_id`, `owner_pid`, `title` (or null), `layer`, `frame` (points, see
/// `rectJSON`) and `on_screen`. Windows with a missing field or an empty frame are skipped.
/// - Parameters:
///   - applicationMetadata: Also add `bundle_id` and `app_name` (slower: one lookup per window).
///   - windowID: Only report this one window instead of all windows.
func windowSnapshot(applicationMetadata: Bool = true, windowID: CGWindowID? = nil) -> [[String: Any]] {
    let entries = CGWindowListCopyWindowInfo(windowID == nil ? .optionAll : .optionIncludingWindow, windowID ?? kCGNullWindowID) as? [[String: Any]] ?? []
    return entries.compactMap { entry in
        guard let id = entry[kCGWindowNumber as String] as? UInt32,
              let pid = entry[kCGWindowOwnerPID as String] as? Int32,
              let raw = entry[kCGWindowBounds as String] as? [String: CGFloat],
              let x = raw["X"], let y = raw["Y"], let w = raw["Width"], let h = raw["Height"], w > 0, h > 0 else { return nil }
        // Dialogs, menu-bar apps and off-screen windows remain selectable [A5].
        var window: [String: Any] = ["window_id": id, "owner_pid": pid,
                "title": entry[kCGWindowName as String] ?? NSNull(),
                "layer": entry[kCGWindowLayer as String] ?? 0,
                "frame": rectJSON(CGRect(x:x,y:y,width:w,height:h)),
                "on_screen": entry[kCGWindowIsOnscreen as String] ?? false]
        if applicationMetadata {
            let app = NSRunningApplication(processIdentifier: pid)
            window["bundle_id"] = app?.bundleIdentifier as Any? ?? NSNull()
            window["app_name"] = app?.localizedName as Any? ?? NSNull()
        }
        return window
    }
}

/// Reads a rectangle from `x`, `y`, `width` and `height` numbers in a dictionary.
/// Throws `HelperFailure.invalid` if a key is missing, a number is not finite, or the size is not
/// positive.
func rect(_ value: [String: Any]) throws -> CGRect {
    guard let x = value["x"] as? Double, let y = value["y"] as? Double,
          let w = value["width"] as? Double, let h = value["height"] as? Double,
          [x,y,w,h].allSatisfy({ $0.isFinite }), w > 0, h > 0 else { throw HelperFailure.invalid }
    return CGRect(x: x, y: y, width: w, height: h)
}

/// The inverse of `rect(_:)`: a rectangle as `x`, `y`, `width`, `height`.
func rectJSON(_ rect: CGRect) -> [String: Double] {
    ["x": rect.minX, "y": rect.minY, "width": rect.width, "height": rect.height]
}

/// Pixels per point of the display that contains the center of `frame`; 1 if none does.
func backingScale(_ frame: CGRect) -> CGFloat {
    for screen in NSScreen.screens {
        guard let id = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? UInt32 else { continue }
        if CGDisplayBounds(id).contains(CGPoint(x:frame.midX,y:frame.midY)) { return screen.backingScaleFactor }
    }
    return 1
}

/// Everything the picker needs: `windows`, `displays` (id, name, frame, pixel size and backing
/// scale), `permission_state` (screen recording and accessibility, read without prompting) and a
/// `source` marker. Throws `HelperFailure.unavailable` if the display list cannot be read.
func inventory() throws -> [String: Any] {
    var ids = [CGDirectDisplayID](repeating: 0, count: 32)
    var count: UInt32 = 0
    guard CGGetActiveDisplayList(UInt32(ids.count), &ids, &count) == .success else { throw HelperFailure.unavailable }
    let displays: [[String: Any]] = ids.prefix(Int(count)).map { id in
        ["display_id": id, "name": "Whole screen", "frame": rectJSON(CGDisplayBounds(id)),
         "pixel_width": CGDisplayPixelsWide(id), "pixel_height": CGDisplayPixelsHigh(id), "backing_scale": backingScale(CGDisplayBounds(id))]
    }
    return ["windows": windowSnapshot(), "displays": displays,
            "permission_state": ["screen_recording": CGPreflightScreenCaptureAccess(), "accessibility": AXIsProcessTrusted()],
            "source": "core_graphics"]
}

// Zero refresh-rate modes are variable-rate displays. Use the screen's maximum,
// preserving 120 Hz sources instead of applying the former 30 fps pacing cap.
/// The frame rate to capture at for the display showing `frame`: that screen's maximum refresh
/// rate, between 1 and 240, or 120 if no screen matches.
func sourceFrameRate(_ frame: CGRect) -> Int {
    for screen in NSScreen.screens {
        guard let id = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? UInt32,
              CGDisplayBounds(id).intersects(frame) else { continue }
        return max(1, min(240, screen.maximumFramesPerSecond))
    }
    return 120
}
