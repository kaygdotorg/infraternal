/// Role: real hardware callback/access-unit regression across successive frames, refresh and reconfiguration (#146).
import Foundation
import VideoToolbox

enum HelperFailure: Error { case invalid, permission, unavailable }

@main struct EncoderSessionTests {
    static func main() throws {
        let dropped = EncodeResult(parameters: LowDelayParameterSets())
        encodedCallback(nil, Unmanaged.passUnretained(dropped).toOpaque(), noErr, .frameDropped, nil)
        guard try dropped.completedPayload(timeout: .now()) == nil else { fatalError("a dropped frame must complete without retiring capture") }
        for (status,flags) in [(OSStatus(-12902), VTEncodeInfoFlags.frameDropped), (noErr, VTEncodeInfoFlags())] {
            let failed = EncodeResult(parameters: LowDelayParameterSets())
            encodedCallback(nil, Unmanaged.passUnretained(failed).toOpaque(), status, flags, nil)
            do { _ = try failed.completedPayload(timeout: .now()); fatalError("an encoder failure must not masquerade as a drop") }
            catch HelperFailure.unavailable {}
        }
        let missing = EncodeResult(parameters: LowDelayParameterSets())
        do { _ = try missing.completedPayload(timeout: .now()); fatalError("a missing callback must remain a timeout") }
        catch HelperFailure.unavailable {}
        let encoder = Encoder()
        var count = 0
        for hevc in [false, true] {
            for (width,height) in [(1280,800),(1920,1080),(640,480)] {
                try encoder.configure(width: width, height: height, hevc: hevc, fps: 120)
                var pixels = Data(repeating: 255, count: width * height * 4)
                for frame in 0..<12 {
                    pixels[frame * 400] = UInt8(frame)
                    let packet = try encoder.encode([
                        "capture_ticks": mach_absolute_time(), "sharp": frame == 0 || frame == 6,
                        "width": width, "height": height,
                    ], pixels: pixels)
                    guard packet.count > 13, packet.subdata(in: 9..<13) == Data([0,0,0,1]),
                          frame != 0 || packet[8] == 1 else { fatalError("missing Annex-B frame or startup keyframe") }
                    count += 1
                    // Functional cadence only: there is deliberately no timing assertion.
                    Thread.sleep(forTimeInterval: 0.03)
                }
            }
            encoder.stop()
        }
        print("PASS hardware-required encoder sessions=6 frames=\(count)")
    }
}
