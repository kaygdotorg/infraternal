//! Checks admitted datagram ownership, bounded queues and generation retirement.
use super::*;
fn identity(bytes: &[u8]) -> Option<Identity> {
    (bytes.len() == 17 && bytes[0] == 0x45).then(|| bytes[1..].try_into().unwrap())
}
static DEFINITION: WireStreamDef = WireStreamDef {
    browser_capability: None,
    capability: 256,
    opening_tag: 0x40,
    opening_identity: None,
    requests: &[0x40, 0x42, 0x43, 0x44],
    replies: &[0x41],
    max_streams: 2,
    datagram_tag: Some(0x45),
    datagram_identity: Some(identity),
};
fn packet(id: Identity) -> Bytes {
    let mut bytes = vec![0x45];
    bytes.extend(id);
    bytes.into()
}
#[tokio::test]
async fn unbound_and_foreign_packets_cannot_allocate_or_displace_an_admitted_lane() {
    let hub = DatagramHub::default();
    let active = hub.active();
    hub.push(packet([1; 16]));
    assert_eq!(*active.borrow(), 0);
    let mut a = hub.register(&DEFINITION, [1; 16]).unwrap();
    let mut b = hub.register(&DEFINITION, [2; 16]).unwrap();
    assert_eq!(*active.borrow(), 2);
    assert!(matches!(
        hub.register(&DEFINITION, [1; 16]),
        Err(AdmissionError::Duplicate)
    ));
    assert!(matches!(
        hub.register(&DEFINITION, [3; 16]),
        Err(AdmissionError::Limit)
    ));
    hub.push(packet([9; 16]));
    hub.push(Bytes::from_static(b"malformed"));
    for _ in 0..100 {
        hub.push(packet([1; 16]));
    }
    hub.push(packet([2; 16]));
    assert_eq!(b.receive().await, Some(packet([2; 16])));
    for _ in 0..4 {
        assert_eq!(a.receive().await, Some(packet([1; 16])));
    }
    assert!(a.receive.try_recv().is_err());
    assert!(b.receive.try_recv().is_err());
    drop(a);
    assert_eq!(*active.borrow(), 1);
    drop(b);
    assert_eq!(*active.borrow(), 0);
    let mut a = hub.register(&DEFINITION, [1; 16]).unwrap();
    assert!(a.receive.try_recv().is_err());
    hub.push(packet([1; 16]));
    assert_eq!(a.receive().await, Some(packet([1; 16])));
}
#[test]
fn ambiguous_definition_cannot_replace_a_live_decoder() {
    static ALIAS: WireStreamDef = WireStreamDef {
        max_streams: 3,
        ..DEFINITION
    };
    static INVALID: WireStreamDef = WireStreamDef {
        browser_capability: None,
        capability: 3,
        ..DEFINITION
    };
    let hub = DatagramHub::default();
    let _a = hub.register(&DEFINITION, [1; 16]).unwrap();
    assert!(matches!(
        hub.register(&ALIAS, [2; 16]),
        Err(AdmissionError::Invalid)
    ));
    assert!(matches!(
        hub.register(&INVALID, [2; 16]),
        Err(AdmissionError::Invalid)
    ));
}

#[test]
fn distinct_capabilities_cannot_claim_the_same_packet_tag() {
    static OTHER: WireStreamDef = WireStreamDef {
        browser_capability: None,
        capability: 512,
        ..DEFINITION
    };
    let hub = DatagramHub::default();
    let _a = hub.register(&DEFINITION, [1; 16]).unwrap();
    assert!(matches!(
        hub.register(&OTHER, [2; 16]),
        Err(AdmissionError::Invalid)
    ));
}
