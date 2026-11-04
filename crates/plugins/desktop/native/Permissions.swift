/// Role: read privacy authorization for this responsible companion without requesting access or creating UI [D203,D208].
import ApplicationServices
import CoreGraphics
import Foundation

/// Current privacy permissions as JSON with sorted keys: `screen_recording` and `device_control`
/// (Accessibility). Both are booleans. Reading never shows a system prompt.
func permissionJSON() throws -> Data {
    try JSONSerialization.data(withJSONObject:[
        "screen_recording":CGPreflightScreenCaptureAccess(),
        "device_control":AXIsProcessTrusted()
    ],options:[.sortedKeys])
}
