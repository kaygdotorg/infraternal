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
    var sequence = 0
    private var typed = ""
    override var acceptsFirstResponder: Bool { true }
    override func keyDown(with event: NSEvent) {
        // Only this isolated fixture's known test text is recorded. The bounded
        // display suffix is not an input ledger and cannot prove a long burst.
        emit(["kind": "input", "ticks": mach_absolute_time(), "sequence": sequence + 1,
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
        emit(["kind": "draw", "sequence": sequence, "begin_ticks": begin, "end_ticks": mach_absolute_time(), "typed_count": typed.count])
    }
}
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let view = Picture(frame: NSRect(x: 0, y: 0, width: 640, height: 400))
// Native sizing belongs to this fixture. The viewer observes its shape without
// negotiating a resize or changing the surrounding desktop layout.
let window = NSWindow(contentRect: view.bounds, styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = "App window measurement"
window.contentView = view
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
if let screen = NSScreen.main {
    window.setFrameTopLeftPoint(NSPoint(x: screen.visibleFrame.maxX - window.frame.width - 10, y: screen.visibleFrame.maxY - 10))
}
window.makeKeyAndOrderFront(nil)
window.makeFirstResponder(view)
app.activate(ignoringOtherApps: true)
var timer: Timer?
DispatchQueue.global().async {
    while let line = readLine() {
        DispatchQueue.main.async {
            switch line {
            case "next": view.advance()
            case "motion":
                timer?.invalidate()
                timer = Timer.scheduledTimer(withTimeInterval: 1.0 / 120.0, repeats: true) { _ in view.advance() }
            case "idle": timer?.invalidate(); timer = nil
            case "shape", "wide":
                window.setContentSize(line == "shape" ? NSSize(width: 480, height: 600) : NSSize(width: 640, height: 400))
                if let screen = NSScreen.main {
                    window.setFrameTopLeftPoint(NSPoint(x: screen.visibleFrame.maxX - window.frame.width - 10, y: screen.visibleFrame.maxY - 10))
                }
            case "quit": app.terminate(nil)
            default: break
            }
        }
    }
    DispatchQueue.main.async { app.terminate(nil) }
}
emit(["kind": "ready", "pid": getpid(), "window_id": window.windowNumber, "frame_x": window.frame.minX, "screen_width": NSScreen.main?.frame.width ?? 0])
app.run()
