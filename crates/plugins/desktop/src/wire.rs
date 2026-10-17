//! Shared immutable desktop native wire declaration and complete-packet identity decoders [D198,D232].
use infraternal_plugin_api::streams::WireStreamDef;
use infraternal_protocol::{Frame, decode_frame, desktop::Message};

/// The same declaration is used by node admission and server lane opening.
pub static WIRE: WireStreamDef = WireStreamDef {
    capability: infraternal_protocol::desktop::NATIVE_CAPABILITY,
    browser_capability: Some(infraternal_protocol::desktop::CAPABILITY),
    opening_tag: 0x40,
    opening_identity: Some(opening_identity),
    requests: &[0x40, 0x42, 0x43, 0x44],
    replies: &[0x41],
    max_streams: 128,
    datagram_tag: Some(0x45),
    datagram_identity: Some(datagram_identity),
};
fn opening_identity(packet: &[u8]) -> Option<[u8; 16]> {
    wire_identity(packet, true)
}
fn datagram_identity(packet: &[u8]) -> Option<[u8; 16]> {
    wire_identity(packet, false)
}
fn wire_identity(packet: &[u8], opening: bool) -> Option<[u8; 16]> {
    let decoded = decode_frame(packet).ok()?;
    if decoded.wire_len != packet.len() {
        return None;
    }
    match (decoded.frame, opening) {
        (Frame::Desktop(Message::Attach { session_id, .. }), true)
        | (Frame::Desktop(Message::Fragment { session_id, .. }), false) => Some(*session_id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! The desktop lane bit must stay clear of every core leg-B transport bit.
    use super::WIRE;

    #[test]
    fn desktop_lane_is_a_valid_native_lane_above_core_bits() {
        assert!(WIRE.validate().is_ok());
        assert!(WIRE.capability >= infraternal_plugin_api::channel::MIN_NATIVE_STREAM_CAPABILITY);
        assert_eq!(
            WIRE.capability
                & (infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                    | infraternal_plugin_api::channel::REMOTE_PATH_PROOF),
            0
        );
    }
}
