/// J1078 measurement probe (not product code): cost of the window-list reads that
/// crates/plugins/desktop/native/{Geometry,Inventory,Input}.swift make for every remote pointer event.
import CoreGraphics
import Foundation

/// The machine's tick-to-nanosecond ratio, read once.
var timebase = mach_timebase_info_data_t(); mach_timebase_info(&timebase)
/// Milliseconds for a `mach_absolute_time` span.
func ms(_ t: UInt64) -> Double { Double(t) * Double(timebase.numer) / Double(timebase.denom) / 1e6 }
/// Nearest-rank percentile of `v`; NaN when empty.
func pct(_ v: [Double], _ p: Double) -> Double { let s = v.sorted(); return s.isEmpty ? .nan : s[min(s.count - 1, Int(Double(s.count) * p))] }
/// Three decimals.
func f(_ v: Double) -> String { String(format: "%.3f", v) }

/// Same reads and conversions as `windowSnapshot(applicationMetadata: false, windowID:)` in Inventory.swift.
func snapshot(_ option: CGWindowListOption, _ relative: CGWindowID) -> [[String: Any]] {
    let entries = CGWindowListCopyWindowInfo(option, relative) as? [[String: Any]] ?? []
    return entries.compactMap { entry in
        guard let id = entry[kCGWindowNumber as String] as? UInt32, let pid = entry[kCGWindowOwnerPID as String] as? Int32,
              let raw = entry[kCGWindowBounds as String] as? [String: CGFloat],
              let x = raw["X"], let y = raw["Y"], let w = raw["Width"], let h = raw["Height"], w > 0, h > 0 else { return nil }
        return ["window_id": id, "owner_pid": pid, "title": entry[kCGWindowName as String] ?? NSNull(), "layer": entry[kCGWindowLayer as String] ?? 0,
                "frame": ["x": x, "y": y, "width": w, "height": h], "on_screen": entry[kCGWindowIsOnscreen as String] ?? false]
    }
}
/// Runs `body` `n` times and prints its p50/p95 in one RESULT line.
func time(_ label: String, n: Int = 300, _ body: () -> Int) {
    var t: [Double] = []; var count = 0
    for _ in 0..<n { let a = mach_absolute_time(); count = body(); t.append(ms(mach_absolute_time() - a)) }
    print("RESULT kind=window_list case=\(label) entries=\(count) n=\(n) p50_ms=\(f(pct(t, 0.5))) p95_ms=\(f(pct(t, 0.95))) max_ms=\(f(t.max() ?? .nan))")
}
/// Every window the window server lists.
let all = snapshot(.optionAll, kCGNullWindowID)
/// The on-screen windows of the normal layer, as a pointer event would consider them.
let onScreen = all.filter { $0["on_screen"] as? Bool == true && $0["layer"] as? Int == 0 }
setvbuf(stdout, nil, _IOLBF, 0)
print("INFO windows_all=\(all.count) on_screen_layer0=\(onScreen.count)")
time("all_as_product") { snapshot(.optionAll, kCGNullWindowID).count }
time("pointer_event_two_reads") { snapshot(.optionAll, kCGNullWindowID).count + snapshot(.optionAll, kCGNullWindowID).count }
time("all_raw_no_bridging") { CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID).map { CFArrayGetCount($0) } ?? -1 }
time("on_screen_only") { snapshot([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID).count }
if let target = onScreen.last?["window_id"] as? UInt32 {
    time("one_window_key_event") { snapshot(.optionIncludingWindow, target).count }
    time("above_one_window") { snapshot([.optionOnScreenAboveWindow, .excludeDesktopElements], target).count }
} else { print("NOTE no on-screen window visible to this session") }
print("DONE")
