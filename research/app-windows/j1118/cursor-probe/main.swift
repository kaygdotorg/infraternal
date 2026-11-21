// J1118 check (not product code): the pointer shape the product reports (Cursor.swift), read from a second process
// while a test window shows different shapes under the pointer. Run as the logged-in GUI user:
//   swiftc -O -swift-version 5 -o cursor-probe main.swift ../../../../crates/plugins/desktop/native/Cursor.swift
//   ./cursor-probe window &          # shows a strip window and moves the pointer over each strip in turn
//   ./cursor-probe read OUTDIR 12    # prints each reported shape and saves it as OUTDIR/shape-<id>.png
import AppKit
import Foundation

enum HelperFailure: Error { case invalid, permission, gone, unavailable }

let strips: [(String, NSCursor)] = [("arrow", .arrow), ("iBeam", .iBeam), ("pointingHand", .pointingHand), ("resizeLeftRight", .resizeLeftRight),
                                    ("crosshair", .crosshair), ("openHand", .openHand), ("notAllowed", .operationNotAllowed)]

final class Strips: NSView {
    override func resetCursorRects() {
        let w = bounds.width / CGFloat(strips.count)
        for (i, strip) in strips.enumerated() { addCursorRect(NSRect(x: CGFloat(i) * w, y: 0, width: w, height: bounds.height), cursor: strip.1) }
    }
    override func draw(_ dirtyRect: NSRect) {
        let w = bounds.width / CGFloat(strips.count)
        for (i, strip) in strips.enumerated() {
            NSColor(calibratedHue: CGFloat(i) / 8, saturation: 0.25, brightness: 0.95, alpha: 1).setFill()
            NSRect(x: CGFloat(i) * w, y: 0, width: w, height: bounds.height).fill()
            (strip.0 as NSString).draw(at: NSPoint(x: CGFloat(i) * w + 4, y: bounds.height / 2), withAttributes: [.font: NSFont.systemFont(ofSize: 10)])
        }
    }
}

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
if mode == "window" {
    let app = NSApplication.shared; app.setActivationPolicy(.regular)
    let frame = NSRect(x: 300, y: 300, width: 840, height: 140)
    let window = NSWindow(contentRect: frame, styleMask: [.titled], backing: .buffered, defer: false)
    window.contentView = Strips(frame: NSRect(origin: .zero, size: frame.size)); window.level = .floating
    window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true)
    var index = 0
    Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { _ in
        // Screen points with the origin at the top left: the window's content is 840 wide.
        let top = NSScreen.screens[0].frame.height - window.frame.maxY
        let x = window.frame.minX + (CGFloat(index % strips.count) + 0.5) * 840 / CGFloat(strips.count), y = top + 70
        CGWarpMouseCursorPosition(CGPoint(x: x, y: y)); CGAssociateMouseAndMouseCursorPosition(1)
        // A warp raises no mouse-moved event, so the window's cursor rects would not apply; set the shape directly.
        strips[index % strips.count].1.set()
        print("MOVE strip=\(strips[index % strips.count].0)"); fflush(stdout)
        index += 1
    }
    app.run()
} else if mode == "read" {
    _ = NSApplication.shared
    let out = CommandLine.arguments[2], seconds = Double(CommandLine.arguments[3])!
    try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)
    let cursor = MachineCursor(); var last = ""; let end = Date().addingTimeInterval(seconds)
    while Date() < end {
        RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        let began = Date()
        guard let shape = cursor.current(), let id = shape["id"] as? String, id != last else { continue }
        last = id
        print("SHAPE read_ms=\(String(format: "%.2f", Date().timeIntervalSince(began) * 1000)) id=\(id) px=\(shape["width"]!)x\(shape["height"]!) scale=\(shape["scale"]!) hot=\(shape["hot_x"]!),\(shape["hot_y"]!) png_base64=\((shape["png"] as! String).count)"); fflush(stdout)
        try? Data(base64Encoded: shape["png"] as! String)?.write(to: URL(fileURLWithPath: "\(out)/shape-\(id).png"))
    }
}
