/// Role: bounded window inventory plus bundle identity and cached app PNGs without ScreenCaptureKit enumeration [D208,D349].
import AppKit
import CoreGraphics

/// The maximum app icons the helper remembers or sends in one inventory.
private let maxAppIconEntries = 32
/// The largest PNG sent for one app icon; the infraternal agent refuses anything larger (#146).
private let maxAppIconPNGBytes = 16 * 1024
/// The maximum decoded image bytes the helper keeps in its process cache.
private let maxAppIconCatalogBytes = 512 * 1024

/// An app icon's identity, stable only while both bundle ID and version match.
private struct AppIconIdentity: Hashable {
    /// The app bundle identifier.
    let bundleID: String
    /// The app's short version and build version, joined with `+` when both exist.
    let appVersion: String

    /// Creates a safe cache identity from an app bundle identifier and version string.
    init?(bundleID: String?, appVersion: String?) {
        guard let bundleID, let appVersion,
              !bundleID.isEmpty, bundleID.utf8.count <= 256,
              !appVersion.isEmpty, appVersion.utf8.count <= 128,
              !bundleID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              !appVersion.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return nil }
        self.bundleID = bundleID
        self.appVersion = appVersion
    }
}

/// The base64 64 by 64 PNG cached for one bundle version, plus its decoded byte cost.
/// The browser draws the same image in picker rows and the window pill.
private struct CachedAppIcon {
    /// The 64 by 64 PNG.
    let png64: String
    /// Decoded bytes, used to keep the cache inside its budget.
    let byteCount: Int
}

/// A small helper-process cache for app icons; all access stays on the AppKit main thread.
private final class AppIconCache {
    /// Cached images by their validated bundle/version pair.
    private var icons: [AppIconIdentity: CachedAppIcon] = [:]
    /// Least-to-most-recently used cache keys.
    private var recency: [AppIconIdentity] = []
    /// The decoded bytes held by `icons`.
    private var totalBytes = 0

    /// Returns a cached icon and moves it to the recent end of the bounded eviction order.
    func value(for identity: AppIconIdentity) -> CachedAppIcon? {
        guard let icon = icons[identity] else { return nil }
        recency.removeAll { $0 == identity }
        recency.append(identity)
        return icon
    }

    /// Stores one already-bounded icon and evicts the least recently used entries as needed.
    func insert(_ icon: CachedAppIcon, for identity: AppIconIdentity) {
        if let old = icons.removeValue(forKey: identity) {
            totalBytes -= old.byteCount
            recency.removeAll { $0 == identity }
        }
        icons[identity] = icon
        recency.append(identity)
        totalBytes += icon.byteCount
        while icons.count > maxAppIconEntries || totalBytes > maxAppIconCatalogBytes {
            guard let oldest = recency.first else { break }
            recency.removeFirst()
            if let removed = icons.removeValue(forKey: oldest) { totalBytes -= removed.byteCount }
        }
    }
}

/// One cache is shared by the helper's serialized main-thread inventory requests.
private let appIconCache = AppIconCache()

/// AppKit metadata read once per process ID while building a window snapshot.
private struct RunningApplicationMetadata {
    /// The bundle identifier, when the process belongs to an app bundle.
    let bundleID: String?
    /// The display name macOS gives the running app.
    let appName: String?
    /// The bundle's version key for joining windows to icons.
    let appVersion: String?
}

/// Reads the display name, bundle ID and version for one running process.
private func runningApplicationMetadata(processID: Int32) -> RunningApplicationMetadata {
    guard let application = NSRunningApplication(processIdentifier: processID) else {
        return RunningApplicationMetadata(bundleID: nil, appName: nil, appVersion: nil)
    }
    let bundleID = application.bundleIdentifier
    let appVersion: String?
    if let bundleURL = application.bundleURL, let bundle = Bundle(url: bundleURL) {
        let short = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        let parts = [short, build].compactMap { $0 }.filter { !$0.isEmpty }
        appVersion = parts.isEmpty ? nil : parts.joined(separator: "+")
    } else {
        appVersion = nil
    }
    return RunningApplicationMetadata(bundleID: bundleID, appName: application.localizedName, appVersion: appVersion)
}

/// Renders an AppKit image as a square PNG at exactly `size` pixels per side.
private func appIconPNG(_ image: NSImage, size: Int) -> Data? {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                        isPlanar: false, colorSpaceName: .deviceRGB,
                                        bytesPerRow: 0, bitsPerPixel: 0),
          let context = NSGraphicsContext(bitmapImageRep: bitmap) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    image.draw(in: CGRect(x: 0, y: 0, width: size, height: size), from: .zero,
               operation: .copy, fraction: 1, respectFlipped: true, hints: nil)
    NSGraphicsContext.restoreGraphicsState()
    guard let data = bitmap.representation(using: .png, properties: [:]), data.count <= maxAppIconPNGBytes else { return nil }
    return data
}

/// Looks up the bundle's NSWorkspace icon, renders it at 64 px and remembers it under the bundle/version pair.
private func appIcon(for application: NSRunningApplication, identity: AppIconIdentity) -> CachedAppIcon? {
    if let cached = appIconCache.value(for: identity) { return cached }
    guard let bundleURL = application.bundleURL else { return nil }
    let image = NSWorkspace.shared.icon(forFile: bundleURL.path)
    guard let png64 = appIconPNG(image, size: 64) else { return nil }
    let icon = CachedAppIcon(png64: png64.base64EncodedString(), byteCount: png64.count)
    appIconCache.insert(icon, for: identity)
    return icon
}

/// Reads at most 32 valid bundle/version acknowledgements from the list request.
private func knownAppIconIdentities(_ value: Any?) -> Set<AppIconIdentity> {
    guard let values = value as? [[String: Any]] else { return [] }
    return Set(values.prefix(maxAppIconEntries).compactMap { value in
        AppIconIdentity(bundleID: value["bundle_id"] as? String, appVersion: value["app_version"] as? String)
    })
}

/// Builds one bounded icon catalog for apps represented by the current window snapshot.
private func appIconCatalog(windows: [[String: Any]], known: Set<AppIconIdentity>) -> [[String: String]] {
    var result: [[String: String]] = []
    var seen = Set<AppIconIdentity>()
    var totalBytes = 0
    for window in windows {
        guard let processID = window["owner_pid"] as? Int32,
              let identity = AppIconIdentity(bundleID: window["bundle_id"] as? String,
                                             appVersion: window["app_version"] as? String),
              !known.contains(identity), seen.insert(identity).inserted,
              result.count < maxAppIconEntries,
              let application = NSRunningApplication(processIdentifier: processID),
              let icon = appIcon(for: application, identity: identity),
              totalBytes + icon.byteCount <= maxAppIconCatalogBytes else { continue }
        result.append(["bundle_id": identity.bundleID, "app_version": identity.appVersion,
                       "png_64": icon.png64])
        totalBytes += icon.byteCount
    }
    return result
}

// Input and geometry need ownership and bounds, not application labels. Keep
// their projection on the same validated CG entries without LaunchServices work
// per window on every keystroke or AX notification. The picker retains labels.
/// Lists the windows known to the window server as JSON-ready dictionaries.
///
/// Each has `window_id`, `owner_pid`, `title` (or null), `layer`, `frame` (points, see
/// `rectJSON`) and `on_screen`. Windows with a missing field or an empty frame are skipped.
/// - Parameters:
///   - applicationMetadata: Also add `bundle_id`, `app_name` and `app_version`; metadata is read once per process.
///   - windowID: Only report this one window instead of all windows.
func windowSnapshot(applicationMetadata: Bool = true, windowID: CGWindowID? = nil) -> [[String: Any]] {
    let entries = CGWindowListCopyWindowInfo(windowID == nil ? .optionAll : .optionIncludingWindow, windowID ?? kCGNullWindowID) as? [[String: Any]] ?? []
    var applications: [Int32: RunningApplicationMetadata] = [:]
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
            let metadata = applications[pid] ?? runningApplicationMetadata(processID: pid)
            applications[pid] = metadata
            window["bundle_id"] = (metadata.bundleID as Any?) ?? NSNull()
            window["app_name"] = (metadata.appName as Any?) ?? NSNull()
            window["app_version"] = (metadata.appVersion as Any?) ?? NSNull()
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
func inventory(knownIcons rawKnownIcons: Any? = nil) throws -> [String: Any] {
    var ids = [CGDirectDisplayID](repeating: 0, count: 32)
    var count: UInt32 = 0
    guard CGGetActiveDisplayList(UInt32(ids.count), &ids, &count) == .success else { throw HelperFailure.unavailable }
    let displays: [[String: Any]] = ids.prefix(Int(count)).map { id in
        ["display_id": id, "name": "Whole screen", "frame": rectJSON(CGDisplayBounds(id)),
         "pixel_width": CGDisplayPixelsWide(id), "pixel_height": CGDisplayPixelsHigh(id), "backing_scale": backingScale(CGDisplayBounds(id))]
    }
    let windows = windowSnapshot()
    var response: [String: Any] = ["windows": windows, "displays": displays,
                                   "permission_state": ["screen_recording": CGPreflightScreenCaptureAccess(), "accessibility": AXIsProcessTrusted()],
                                   "source": "core_graphics"]
    var icons = appIconCatalog(windows: windows, known: knownAppIconIdentities(rawKnownIcons))
    while !icons.isEmpty {
        response["app_icons"] = icons
        if let data = try? JSONSerialization.data(withJSONObject: response), data.count + 2 <= 64 * 1024 { break }
        icons.removeLast()
    }
    if !icons.isEmpty { response["app_icons"] = icons }
    else { response.removeValue(forKey: "app_icons") }
    return response
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
