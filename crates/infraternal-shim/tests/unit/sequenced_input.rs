//! Restart-safe input cursor and bounded acknowledgment regression checks [41].
use super::*;

#[test]
fn trim_duplicates_gaps_overflow_and_capacity_are_transactional() {
    let mut cursors = InputCursors::default();
    let mut queue = VecDeque::new();
    cursors.accept(0, b"abc", &mut queue).unwrap();
    cursors.accept(1, b"bcde", &mut queue).unwrap();
    assert_eq!(queue.iter().copied().collect::<Vec<_>>(), b"abcde");
    cursors.accept(0, b"abc", &mut queue).unwrap();
    assert_eq!(queue.len(), 5);
    assert!(cursors.accept(6, b"x", &mut queue).is_err());
    assert!(cursors.accept(u64::MAX, b"xx", &mut queue).is_err());
    assert!(cursors.accept(5, &vec![0; MAX_FRAME], &mut queue).is_err());
    assert_eq!(cursors.accepted, 5);
    assert_eq!(cursors.written, 0);
}

#[test]
fn new_frames_roundtrip_and_refuse_noncanonical_payloads() {
    for frame in [
        Frame::SequencedInput(7, b"abc".to_vec()),
        Frame::InputAck(10),
        Frame::InputStateRequest,
        Frame::InputState(10, 12),
    ] {
        let wire = frame.encode().unwrap();
        for split in 0..wire.len() {
            let mut decoder = Decoder::default();
            let mut frames = decoder.feed(&wire[..split]).unwrap();
            frames.extend(decoder.feed(&wire[split..]).unwrap());
            assert_eq!(frames, vec![frame.clone()]);
        }
    }
    for bytes in [&[0x17][..], &[0x18][..], &[0x19, 0][..], &[0x1a, 0][..]] {
        assert!(Frame::decode(bytes).is_err());
    }
}

#[test]
fn coalesced_ack_never_overwrites_a_partial_output_and_cursors_survive_peer_loss() {
    let (stream, _remote) = UnixStream::pair().unwrap();
    let mut peer = Peer {
        stream,
        decoder: Decoder::default(),
        attached: true,
        caps: SEQUENCED_INPUT,
        input_reply: None,
        writer: Some(0),
        ack_queued: 0,
        size: (200, 60, 0, 0),
        cursor: None,
        pending: Vec::new(),
        written: 0,
        exited_sent: false,
        request: None,
    };
    let mut cursors = InputCursors::default();
    let mut queue = VecDeque::new();
    cursors.accept(0, b"abc", &mut queue).unwrap();
    peer.queue(&Frame::Output(0, b"output".to_vec())).unwrap();
    let output = peer.pending.clone();
    for _ in 0..3 {
        queue.pop_front();
        cursors.written += 1;
        peer.input_reply = Some(InputReply::Ack);
    }
    assert_eq!(peer.pending, output);
    assert!(matches!(peer.input_reply, Some(InputReply::Ack)));
    drop(peer);
    cursors.accept(0, b"abc", &mut queue).unwrap();
    assert!(queue.is_empty());
    assert_eq!((cursors.written, cursors.accepted), (3, 3));
}

#[test]
fn reusable_encoder_retains_capacity_and_refuses_growth_before_mutation() {
    let mut bytes = Vec::with_capacity(256);
    let capacity = bytes.capacity();
    let frame = Frame::SequencedInput(7, b"reuse".to_vec());
    frame.encode_into(&mut bytes).unwrap();
    assert_eq!(bytes, frame.encode().unwrap());
    assert_eq!(bytes.capacity(), capacity);
    let saved = bytes.clone();
    assert!(
        Frame::SequencedInput(0, vec![0; MAX_FRAME])
            .encode_into(&mut bytes)
            .is_err()
    );
    assert_eq!(bytes, saved);
    assert_eq!(bytes.capacity(), capacity);
}
