// J1118 measurement harness (not product code): the cost of one remote pointer event's window reads, before and
// after (#146), using the product's own Inventory.swift and Cursor.swift. Needs the logged-in user's session.
//   swiftc -O -swift-version 5 -o pbench main.swift ../../../../crates/plugins/desktop/native/{Inventory,Cursor}.swift
//   ./pbench
// before: a pointer event read the whole list twice (Geometry.follow and the occlusion check).
// after:  a move asks only for the windows above the target (`topmostOwner`); the whole list is read once a second.
import AppKit
import Foundation

enum HelperFailure: Error { case invalid, permission, gone, unavailable }

var timebase = mach_timebase_info_data_t(); mach_timebase_info(&timebase)
func ms(_ t: UInt64) -> Double { Double(t) * Double(timebase.numer) / Double(timebase.denom) / 1e6 }
func pct(_ v: [Double], _ p: Double) -> Double { let s = v.sorted(); return s.isEmpty ? .nan : s[min(s.count - 1, Int(Double(s.count) * p))] }
func f(_ v: Double) -> String { String(format: "%.3f", v) }
func time(_ label: String, n: Int = 600, _ body: () -> Int) {
    var t: [Double] = []; var count = 0
    for _ in 0..<n { let a = mach_absolute_time(); count = body(); t.append(ms(mach_absolute_time() - a)) }
    print("RESULT case=\(label) entries=\(count) n=\(n) p50_ms=\(f(pct(t, 0.5))) p95_ms=\(f(pct(t, 0.95))) max_ms=\(f(t.max() ?? .nan))")
}
setvbuf(stdout, nil, _IOLBF, 0)
_ = NSApplication.shared
let all = windowSnapshot(applicationMetadata: false)
let visible = all.filter { $0["on_screen"] as? Bool == true && $0["layer"] as? Int == 0 }
print("INFO windows_all=\(all.count) on_screen_layer0=\(visible.count)")
time("before_event_two_full_reads") { windowSnapshot(applicationMetadata: false).count + windowSnapshot(applicationMetadata: false).count }
time("after_refresh_one_full_read_per_second") { windowSnapshot(applicationMetadata: false).count }
if let target = visible.last, let id = target["window_id"] as? UInt32, let raw = target["frame"] as? [String: Double] {
    let point = CGPoint(x: raw["x"]! + raw["width"]! / 2, y: raw["y"]! + raw["height"]! / 2)
    time("after_event_windows_above_target") { topmostOwner(above: id, at: point) == nil ? 0 : 1 }
}
if let top = visible.first, let id = top["window_id"] as? UInt32, let raw = top["frame"] as? [String: Double] {
    time("after_event_windows_above_frontmost") { topmostOwner(above: id, at: CGPoint(x: raw["x"]! + 4, y: raw["y"]! + 4)) == nil ? 0 : 1 }
}
let cursor = MachineCursor()
let first = mach_absolute_time(); let shape = cursor.current(); let cold = ms(mach_absolute_time() - first)
print("INFO cursor_first_read_ms=\(f(cold)) id=\(shape?["id"] ?? "none") width=\(shape?["width"] ?? 0) height=\(shape?["height"] ?? 0) png_base64_bytes=\((shape?["png"] as? String)?.count ?? 0) scale=\(shape?["scale"] ?? 0) hot=\(shape?["hot_x"] ?? 0),\(shape?["hot_y"] ?? 0)")
time("cursor_status_unchanged_shape", n: 5000) { cursor.current() == nil ? 0 : 1 }
if let png = shape?["png"] as? String, let data = Data(base64Encoded: png) { try? data.write(to: URL(fileURLWithPath: "/tmp/j1118-cursor-\(shape!["id"]!).png")) }
print("DONE")
