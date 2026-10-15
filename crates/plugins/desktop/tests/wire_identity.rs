//! Keeps opening admission separate from fragment routing and refuses incomplete or concatenated packets [D198,D232].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_desktop::server::WIRE;
use infraternal_protocol::{
    Frame,
    desktop::{Delivery, Message},
    encode_frame_into,
};

#[test]
fn only_complete_attach_packets_create_a_native_identity() {
    let mut packet = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: &[7; 16],
            delivery: Delivery::Reliable,
        }),
        &mut packet,
    )
    .unwrap();
    let opening = WIRE.opening_identity.unwrap();
    let datagram = WIRE.datagram_identity.unwrap();
    assert_eq!(opening(&packet), Some([7; 16]));
    assert_eq!(datagram(&packet), None);
    for length in 0..packet.len() {
        assert_eq!(opening(&packet[..length]), None);
    }
    packet.push(0);
    assert_eq!(opening(&packet), None);
}
