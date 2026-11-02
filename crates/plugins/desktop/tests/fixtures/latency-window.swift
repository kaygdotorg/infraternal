/// Role: a real, isolated AppKit window with numbered colour changes and input receipts for end-to-end measurements [D208,#146].
import AppKit
import Darwin

func emit(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
}
let colours: [(CGFloat, CGFloat, CGFloat)] = [
    (0.15, 0.35, 0.80), (0.15, 0.75, 0.35), (0.80, 0.25, 0.20), (0.70, 0.25, 0.75),
    (0.15, 0.70, 0.75), (0.80, 0.65, 0.15), (0.40, 0.25, 0.80), (0.75, 0.40, 0.20),
]
final class Picture: NSView {
    let fixtureIndex: Int
    var sequence = 0
    private var typed = ""
    init(frame: NSRect, fixtureIndex: Int) {
        self.fixtureIndex = fixtureIndex
        super.init(frame: frame)
    }
    required init?(coder: NSCoder) { fatalError("fixture views are created in code") }
    override var acceptsFirstResponder: Bool { true }
    override func keyDown(with event: NSEvent) {
        // Only this isolated fixture's known test text is recorded. The bounded
        // display suffix is not an input ledger and cannot prove a long burst.
        emit(["kind": "input", "ticks": mach_absolute_time(), "window_id": window?.windowNumber ?? 0, "sequence": sequence + 1,
              "characters": event.characters ?? ""])
        if let characters = event.characters, !event.modifierFlags.contains(.command) {
            typed = String((typed + characters).suffix(80))
        }
        advance()
    }
    func advance() { sequence += 1; needsDisplay = true; displayIfNeeded() }
    private func drawContentMarker() {
        // The eight fixture colours repeat; this 32-bit marker identifies the
        // native content sequence independently of transport frame freshness.
        let marker = UInt32(truncatingIfNeeded: sequence)
        let markerHeader: UInt8 = 0xa5
        let markerCellCount = 40
        // Capture includes the title bar; use that same full-window coordinate
        // space so the worker's fixed sample row intersects the marker cells.
        let picture = window?.frame.size ?? bounds.size
        let cell = picture.width * 0.2 / CGFloat(markerCellCount)
        for position in 0..<markerCellCount {
            let set: Bool
            if position < 8 {
                set = markerHeader & (UInt8(1) << position) != 0
            } else {
                set = marker & (UInt32(1) << (position - 8)) != 0
            }
            (set ? NSColor.white : NSColor.black).setFill()
            NSBezierPath(rect: NSRect(x: picture.width * 0.8 + CGFloat(position) * cell,
                                      y: picture.height * 0.3,
                                      width: cell, height: cell)).fill()
        }
    }
    override func draw(_ dirtyRect: NSRect) {
        let begin = mach_absolute_time()
        let colour = colours[sequence % colours.count]
        NSColor(srgbRed: colour.0, green: colour.1, blue: colour.2, alpha: 1).setFill()
        bounds.fill()
        drawContentMarker()
        let label = "App window measurement\nFrame \(sequence)\nType to change this native window\n\(typed)"
        label.draw(at: NSPoint(x: 24, y: bounds.height - 100), withAttributes: [
            .font: NSFont.systemFont(ofSize: 22), .foregroundColor: NSColor.white,
        ])
        emit(["kind": "draw", "window_id": window?.windowNumber ?? 0, "fixture_index": fixtureIndex,
              "sequence": sequence, "begin_ticks": begin, "end_ticks": mach_absolute_time(), "typed_count": typed.count])
    }
}
let countIndex = CommandLine.arguments.firstIndex(of: "--window-count")
let windowCount: Int
if let countIndex {
    guard CommandLine.arguments.indices.contains(countIndex + 1),
          let parsedCount = Int(CommandLine.arguments[countIndex + 1]) else { exit(2) }
    windowCount = parsedCount
} else { windowCount = 1 }
guard (1...10).contains(windowCount) else { exit(2) }
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let fixtureSize = windowCount == 1 ? NSSize(width: 640, height: 400) : NSSize(width: 280, height: 180)
let displayMaximumFPS = NSScreen.main?.maximumFramesPerSecond ?? 60
let animationInterval = 1.0 / Double(max(1, displayMaximumFPS))
let views = (0..<windowCount).map { Picture(frame: NSRect(origin: .zero, size: fixtureSize), fixtureIndex: $0) }
let windows = views.enumerated().map { index, view -> NSWindow in
    let window = NSWindow(contentRect: view.bounds, styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.title = windowCount == 1 ? "App window measurement" : "App window measurement \(index + 1)"
    window.contentView = view
    if windowCount == 1, let screen = NSScreen.main {
        window.setFrameTopLeftPoint(NSPoint(x: screen.visibleFrame.maxX - window.frame.width - 10,
                                            y: screen.visibleFrame.maxY - 10))
    } else if let screen = NSScreen.main {
        let columns = 4
        let column = index % columns, row = index / columns
        window.setFrameOrigin(NSPoint(x: screen.visibleFrame.minX + CGFloat(column) * (fixtureSize.width + 8),
                                      y: screen.visibleFrame.minY + CGFloat(row) * (fixtureSize.height + 32)))
    }
    if index == 0 { window.makeKeyAndOrderFront(nil) } else { window.orderFront(nil) }
    return window
}
let view = views[0]
let window = windows[0]
if CommandLine.arguments.contains("--check-content-marker") {
    // Read our own rendered view in memory, without screen capture or input.
    // The observer samples the entire window, so account for its title bar
    // when projecting that row into the content-only bitmap.
    view.sequence = 257
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(1) }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    let scale = CGFloat(bitmap.pixelsWide) / view.bounds.width
    let width = window.frame.width * scale
    let height = window.frame.height * scale
    let cell = width * 0.2 / 40
    let y = Int(floor(height * 0.7 - cell / 2 - (window.frame.height - view.bounds.height) * scale))
    var header: UInt32 = 0
    var sequence: UInt32 = 0
    for position in 0..<40 {
        let x = Int(floor(width * 0.8 + (CGFloat(position) + 0.5) * cell))
        guard let colour = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { exit(1) }
        if (colour.redComponent + colour.greenComponent + colour.blueComponent) / 3 > 0.5 {
            if position < 8 { header |= UInt32(1) << position }
            else { sequence |= UInt32(1) << (position - 8) }
        }
    }
    emit(["kind": "marker_check", "header": header, "sequence": sequence,
          "expected_sequence": view.sequence, "title_height": window.frame.height - view.bounds.height])
    exit(header == 0xa5 && sequence == UInt32(view.sequence) ? 0 : 1)
}
if CommandLine.arguments.contains("--check-window-count") {
    let ids = windows.map(\.windowNumber)
    emit(["kind": "window_count_check", "count": ids.count, "unique_ids": Set(ids).count,
          "titles": windows.map(\.title)])
    exit(ids.count == windowCount && Set(ids).count == windowCount ? 0 : 1)
}
window.makeFirstResponder(view)
app.activate(ignoringOtherApps: true)
var timers: [Int: Timer] = [:]
DispatchQueue.global().async {
    while let line = readLine() {
        DispatchQueue.main.async {
            let parts = line.split(separator: " ")
            let command = parts.first.map(String.init) ?? ""
            let index = parts.count > 1 ? Int(parts[1]) ?? 0 : 0
            guard views.indices.contains(index) else { return }
            switch command {
            case "next": views[index].advance()
            case "motion":
                timers[index]?.invalidate()
                timers[index] = Timer.scheduledTimer(withTimeInterval: animationInterval, repeats: true) { _ in views[index].advance() }
            case "idle":
                timers.values.forEach { $0.invalidate() }
                timers.removeAll()
            case "shape", "wide":
                windows[index].setContentSize(command == "shape" ? NSSize(width: 480, height: 600) : fixtureSize)
            case "quit": app.terminate(nil)
            default: break
            }
        }
    }
    DispatchQueue.main.async { app.terminate(nil) }
}
for (index, window) in windows.enumerated() {
    emit(["kind": "ready", "pid": getpid(), "window_id": window.windowNumber, "fixture_index": index,
          "title": window.title, "frame_x": window.frame.minX, "screen_width": NSScreen.main?.frame.width ?? 0,
          "display_maximum_fps": displayMaximumFPS, "animation_interval_seconds": animationInterval])
}
app.run()
