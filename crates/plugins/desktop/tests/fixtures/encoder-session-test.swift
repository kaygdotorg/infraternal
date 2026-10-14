/// Role: real Apple SDK hardware-session admission regression; no capture, input or timing measurements [D204].
import Foundation

enum HelperFailure: Error { case invalid, permission, unavailable }

@main struct EncoderSessionTests {
    static func main() throws {
        let encoder = Encoder()
        for hevc in [false, true] {
            try encoder.configure(width: 1280, height: 800, hevc: hevc, fps: 120)
            encoder.stop()
        }
        print("PASS hardware-required encoder sessions=2")
    }
}
