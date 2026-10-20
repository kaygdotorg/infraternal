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
    override func draw(_ dirtyRect: NSRect) {
        let begin = mach_absolute_time()
        let colour = colours[sequence % colours.count]
        NSColor(srgbRed: colour.0, green: colour.1, blue: colour.2, alpha: 1).setFill()
        bounds.fill()
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
