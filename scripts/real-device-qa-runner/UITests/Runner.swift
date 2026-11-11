// SPDX-License-Identifier: AGPL-3.0-only
//
// Real-device QA runner: one XCUITest that drives iOS Safari in the iPhone Simulator from an action script.
//
// Why a script instead of one test per step: every `xcodebuild test` costs about ten seconds of start-up, and the
// checklist is dozens of taps and screenshots. `scripts/real-device-qa` hands this test an ACTIONS string such as
// `open~https://host/|wait~3|tap~Continue|shot~after-continue` and gets screenshots and `QA_RESULT` lines back.
//
// Safari is the system app, so everything goes through accessibility labels and screen coordinates. The page's own DOM
// is not readable here; layout checks use the frames of accessibility elements (`frame~`), and the rest is judged from
// the screenshots the script saves.
import XCTest
import notify

final class DeviceQA: XCTestCase {
    let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    var failures = 0

    /// Reads a parameter that `ui.sh` forwarded as `TEST_RUNNER_<NAME>`.
    func parameter(_ name: String, default fallback: String = "") -> String {
        ProcessInfo.processInfo.environment[name] ?? ProcessInfo.processInfo.environment["TEST_RUNNER_" + name] ?? fallback
    }

    override func setUp() { continueAfterFailure = true }

    /// Saves a full-screen screenshot as a kept XCTest attachment; the wrapper exports and renames it by `name`.
    func capture(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = "qa-" + name
        attachment.lifetime = .keepAlways
        add(attachment)
        print("QA_SHOT \(name)")
    }

    /// Prints one machine-readable result line. A FAIL never stops the run: later steps still give evidence.
    func result(_ name: String, _ ok: Bool, _ detail: String = "") {
        if !ok { failures += 1 }
        print("QA_RESULT \(ok ? "PASS" : "FAIL") \(name) \(detail)")
    }

    /// Finds the first element of Safari (web content included) whose label or identifier matches.
    func element(_ text: String, contains: Bool = false) -> XCUIElement {
        let format = contains ? "label CONTAINS[c] %@ OR identifier CONTAINS[c] %@" : "label == %@ OR identifier == %@"
        return safari.descendants(matching: .any).matching(NSPredicate(format: format, text, text)).firstMatch
    }

    /// One element of the page as the hierarchy dump describes it.
    struct Row { let kind: String; let frame: CGRect; let label: String; let line: String }

    /// Reads Safari's whole accessibility tree ONCE as text and turns it into rows. Asking XCUITest to match a label
    /// against the live tree is minutes slow here (the canvas keeps every window in the tree), while one dump is seconds.
    func rows() -> [Row] {
        let pattern = try! NSRegularExpression(pattern: #"^\s*(\w+), 0x[0-9a-f]+, \{\{(-?[\d.]+), (-?[\d.]+)\}, \{([\d.]+), ([\d.]+)\}\}(.*)$"#)
        var out: [Row] = []
        for line in safari.debugDescription.split(separator: "\n") {
            let text = String(line)
            guard let m = pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { continue }
            func part(_ i: Int) -> String { String(text[Range(m.range(at: i), in: text)!]) }
            let rest = part(6)
            var label = ""
            if let r = rest.range(of: "label: '") {
                let tail = rest[r.upperBound...]
                if let end = tail.range(of: "', value:") ?? tail.range(of: "',") ?? (tail.hasSuffix("'") ? tail.index(before: tail.endIndex)..<tail.endIndex : nil) { label = String(tail[..<end.lowerBound]) }
            }
            out.append(Row(kind: part(1), frame: CGRect(x: Double(part(2))!, y: Double(part(3))!, width: Double(part(4))!, height: Double(part(5))!), label: label, line: text))
        }
        return out
    }

    /// The first row whose label equals (or contains) `text` and whose middle is on screen, waiting up to `timeout`.
    /// The page keeps its whole canvas in the tree, so an off-screen window can share a label with the control you see.
    func findRow(_ text: String, contains: Bool = false, timeout: TimeInterval = 15, onScreen: Bool = true) -> Row? {
        let screen = safari.frame
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            let found = rows().first { row in
                (contains ? row.label.localizedCaseInsensitiveContains(text) : row.label == text)
                    && row.frame.width > 0 && row.frame.height > 0
                    && (!onScreen || screen.contains(CGPoint(x: row.frame.midX, y: row.frame.midY)))
            }
            if let found = found { return found }
            usleep(700_000)
        } while Date() < deadline
        return nil
    }

    /// Taps the middle of a row through screen coordinates; web elements ignore `tap()` when partly covered.
    @discardableResult
    func tapRow(_ row: Row?) -> Bool {
        guard let row = row else { return false }
        springboard.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: row.frame.midX, dy: row.frame.midY)).tap()
        sleep(1)
        return true
    }

    /// Taps an XCUIElement found the ordinary way (used for the few Safari-chrome controls with stable queries).
    @discardableResult
    func tapElement(_ element: XCUIElement?) -> Bool {
        guard let element = element else { return false }
        let frame = element.frame
        springboard.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: frame.midX, dy: frame.midY)).tap()
        sleep(1)
        return true
    }

    /// Runs the ACTIONS script. Steps are separated by `|`, arguments by `~`. See the runbook for the full list.
    func testSafari() throws {
        for action in parameter("ACTIONS", default: "dump").components(separatedBy: "|") {
            let a = action.components(separatedBy: "~")
            switch a[0] {
            case "open":
                // A fresh load of an https URL in Safari, past the first-run sheets.
                XCUIDevice.shared.system.open(URL(string: a[1])!)
                result("open \(a[1])", safari.wait(for: .runningForeground, timeout: 15))
                for label in ["Continue", "Not Now", "Start Browsing"] {
                    let button = safari.buttons[label]
                    if button.exists && button.isHittable && a.count < 3 { tapElement(button) }
                }
            case "tap":
                result("tap \(a[1])", tapRow(findRow(a[1])))
            case "tapif":
                // tapif~LABEL~SECONDS: taps the control if it shows up within SECONDS, otherwise moves on (for steps a
                // flow may or may not show, such as a host key that was already trusted).
                let found = findRow(a[1], timeout: Double(a.count > 2 ? a[2] : "5")!)
                if found != nil { tapRow(found) }
                print("QA_NOTE tapif \(a[1]) \(found != nil ? "tapped" : "absent")")
            case "tapx":
                result("tap~contains \(a[1])", tapRow(findRow(a[1], contains: true)))
            case "field":
                // field~LABEL: focuses a text field (a field and its caption can share a label; this picks the field).
                let match = NSPredicate(format: "label CONTAINS[c] %@ OR placeholderValue CONTAINS[c] %@", a[1], a[1])
                var field = safari.textFields.matching(match).firstMatch
                if !field.waitForExistence(timeout: 5) { field = safari.secureTextFields.matching(match).firstMatch }
                // A tap during page load is lost, so retry until the keyboard is really up (typing without it goes nowhere).
                var focused = false
                for _ in 0..<4 where !focused {
                    tapElement(field.waitForExistence(timeout: 10) ? field : nil)
                    focused = safari.keyboards.firstMatch.waitForExistence(timeout: 3)
                }
                result("field \(a[1])", focused)
            case "tapsb":
                // tapsb~LABEL: taps a button in a system sheet (the passkey prompt belongs to the system, not to Safari).
                let sheet = springboard.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", a[1])).firstMatch
                var hit = sheet.waitForExistence(timeout: 10)
                if hit { let f = sheet.frame; springboard.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: f.midX, dy: f.midY)).tap() }
                else { hit = false }
                result("tapsb \(a[1])", hit)
                sleep(1)
            case "tapsbif":
                // tapsbif~LABEL~SECONDS: like tapsb, but a missing sheet is fine (sign-in sheets only show without a session).
                let sheet = springboard.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", a[1])).firstMatch
                if sheet.waitForExistence(timeout: Double(a.count > 2 ? a[2] : "5")!) {
                    let f = sheet.frame
                    springboard.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: f.midX, dy: f.midY)).tap()
                    print("QA_NOTE tapsbif \(a[1]) tapped")
                } else { print("QA_NOTE tapsbif \(a[1]) absent") }
                sleep(1)
            case "dumpsb":
                print("QA_DUMP_BEGIN\n\(springboard.debugDescription)\nQA_DUMP_END")
            case "xy":
                springboard.coordinate(withNormalizedOffset: CGVector(dx: Double(a[1])!, dy: Double(a[2])!)).tap()
                sleep(1)
            case "type":
                safari.typeText(a[1])
            case "typefile":
                // Types the last word of a 0600 file, so a secret never travels through argv or the log.
                let text = (try? String(contentsOfFile: a[1], encoding: .utf8)) ?? ""
                let word = text.split(whereSeparator: { $0.isWhitespace }).last.map(String.init) ?? ""
                result("typefile", !word.isEmpty, "chars=\(word.count) fileBytes=\(text.utf8.count)")
                safari.typeText(word)
            case "return":
                safari.typeText("\n")
            case "face":
                // Approves the pending Face ID prompt; the simulator listens for this Darwin notification.
                notify_post("com.apple.BiometricKit_Sim.pearl.match")
                sleep(2)
            case "wait":
                sleep(UInt32(a[1])!)
            case "shot":
                capture(a[1])
            case "exists":
                // exists~LABEL~NAME[~contains]: passes when a row with that label is in the tree (on screen or not).
                result(a[2], findRow(a[1], contains: a.count > 3, timeout: 10, onScreen: false) != nil, a[1])
            case "absent":
                result(a[2], findRow(a[1], contains: true, timeout: 1) == nil, a[1])
            case "frame", "frames":
                // frame~LABEL~NAME prints the first matching row's frame; frames~LABEL~NAME prints every match.
                // The screen size is in points, the same unit as the frames, so a row wider than screenW overflows.
                let all = rows().filter { $0.label.localizedCaseInsensitiveContains(a[1]) && $0.frame.width > 0 }
                let picked = a[0] == "frame" ? Array(all.prefix(1)) : all
                if picked.isEmpty { result("frame \(a[2])", false, "missing \(a[1])") }
                for row in picked {
                    let f = row.frame, s = safari.frame
                    print("QA_FRAME \(a[2]) kind=\(row.kind) label=\(row.label.prefix(40).replacingOccurrences(of: " ", with: "_")) x=\(f.minX) y=\(f.minY) w=\(f.width) h=\(f.height) screenW=\(s.width) screenH=\(s.height)")
                }
            case "labels":
                // labels: prints every labelled row that is on screen, to see what a screen offers without a full dump.
                let screen = safari.frame
                for row in rows() where !row.label.isEmpty && screen.contains(CGPoint(x: row.frame.midX, y: row.frame.midY)) {
                    print("QA_LABEL \(row.kind) x=\(Int(row.frame.minX)) y=\(Int(row.frame.minY)) w=\(Int(row.frame.width)) h=\(Int(row.frame.height)) \(row.label.prefix(70).replacingOccurrences(of: "\n", with: " "))")
                }
            case "swipe":
                // swipe~x1~y1~x2~y2~seconds, normalized to the screen.
                let start = springboard.coordinate(withNormalizedOffset: CGVector(dx: Double(a[1])!, dy: Double(a[2])!))
                let end = springboard.coordinate(withNormalizedOffset: CGVector(dx: Double(a[3])!, dy: Double(a[4])!))
                let width = springboard.frame.width, height = springboard.frame.height
                let distance = hypot((Double(a[3])! - Double(a[1])!) * width, (Double(a[4])! - Double(a[2])!) * height)
                start.press(forDuration: 0.05, thenDragTo: end, withVelocity: XCUIGestureVelocity(rawValue: max(1, distance / max(Double(a[5]) ?? 0.3, 0.05))), thenHoldForDuration: 0)
                sleep(1)
            case "hold":
                // hold~x~y~seconds: a long press at a normalized point.
                springboard.coordinate(withNormalizedOffset: CGVector(dx: Double(a[1])!, dy: Double(a[2])!)).press(forDuration: Double(a[3])!)
            case "dump":
                let text = safari.debugDescription
                if a.count > 1 { try? text.write(toFile: a[1], atomically: true, encoding: .utf8) } else { print("QA_DUMP_BEGIN\n\(text)\nQA_DUMP_END") }
            default:
                result("unknown action \(a[0])", false)
            }
        }
        capture("final")
        XCTAssertEqual(failures, 0, "\(failures) QA step(s) failed; see QA_RESULT lines")
    }
}
