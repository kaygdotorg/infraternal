/// Role: read privacy authorization for this responsible companion without requesting access or creating UI [D203,D208].
import ApplicationServices
import CoreGraphics
import Foundation

func permissionJSON() throws -> Data {
    try JSONSerialization.data(withJSONObject:[
        "screen_recording":CGPreflightScreenCaptureAccess(),
        "device_control":AXIsProcessTrusted()
    ],options:[.sortedKeys])
}
