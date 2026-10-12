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
fn negotiated_queue_deferral_validates_ranges_before_waiting() {
    let mut pty = Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap();
    let (socket, _remote) = UnixStream::pair().unwrap();
    let mut peer = Peer {
        stream: socket,
        decoder: Decoder::default(),
        trailing: Vec::new(),
        deferred: None,
        attached: true,
        caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER,
        input_reply: None,
        writer: Some(7),
        shared_writer: true,
        ack_queued: 0,
        size: (80, 24, 0, 0),
        cursor: None,
        pending: Vec::new(),
        written: 0,
        exited_sent: false,
        request: None,
    };
    let mut cursors = Inputs::with_geometry(peer.size);
    cursors.select(7, peer.size).unwrap();
    let mut terminal = Terminal::new(80, 24).unwrap();
    let ring = Ring::new(8192);
    let mut config = Config::new([0; 16], Uid::effective().as_raw());
    let mut input = VecDeque::from(vec![0; MAX_FRAME - 3]);
    for (sequence, bytes, expected) in [
        (0, b"abcde".as_slice(), io::ErrorKind::WouldBlock),
        (1, b"x".as_slice(), io::ErrorKind::InvalidData),
        (u64::MAX, b"xx".as_slice(), io::ErrorKind::InvalidData),
    ] {
        assert_eq!(
            handle(
                FrameRef::SequencedInput(sequence, bytes),
                &mut peer,
                &mut pty,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                false,
                false
            )
            .unwrap_err()
            .kind(),
            expected
        );
        assert_eq!(input.len(), MAX_FRAME - 3);
        assert_eq!(cursors.get(Some(7)).unwrap().accepted, 0);
        assert_eq!(cursors.active_writer, None);
    }
    peer.caps &= !SHARED_WRITER;
    assert_eq!(
        handle(
            FrameRef::SequencedInput(0, b"abcde"),
            &mut peer,
            &mut pty,
            &mut terminal,
            &ring,
            &mut config,
            &mut input,
            &mut cursors,
            false,
            false
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData,
        "unnegotiated input retains capacity refusal"
    );
    assert_eq!(
        peer.input_waits(0, 1, 0, 100, true).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "reserved space retains legacy capacity refusal even before the queue fills"
    );
    assert!(
        !peer.input_waits(0, 1, 1, 100, true).unwrap(),
        "an already accepted legacy suffix needs no reserved space"
    );
    let _ = pty.child.kill();
    let _ = pty.child.wait();
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_completed_deferred_frame_gives_its_trailing_input_a_fresh_ticket() {
    struct Child(Pty);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.child.kill();
            let _ = self.0.child.wait();
        }
    }
    let mut pty = Child(Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap());
    let peer = |writer| {
        let (socket, _remote) = UnixStream::pair().unwrap();
        Peer {
            stream: socket,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER,
            input_reply: None,
            writer: Some(writer),
            shared_writer: true,
            ack_queued: 0,
            size: (80, 24, 0, 0),
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            request: None,
        }
    };
    let mut first = peer(7);
    let mut second = peer(8);
    first.deferred = Some(0);
    second.deferred = Some(1);
    let mut cursors = Inputs::with_geometry(first.size);
    cursors.select(7, first.size).unwrap();
    cursors.select(8, second.size).unwrap();
    let mut input = VecDeque::new();
    // A sibling already delivered the first deferred request while these two
    // peers waited. The first peer must not extend its reservation to new input.
    cursors.accept(7, 0, b"once", &mut input).unwrap();
    input.clear();
    cursors.advance(4).unwrap();
    first
        .decoder
        .feed_until(
            &Frame::SequencedInput(0, b"once".to_vec()).encode().unwrap(),
            |_| Ok(false),
        )
        .unwrap();
    second
        .decoder
        .feed_until(
            &Frame::SequencedInput(0, b"wait".to_vec()).encode().unwrap(),
            |_| Ok(false),
        )
        .unwrap();
    let trailing = Frame::SequencedInput(4, b"next".to_vec()).encode().unwrap();
    let mut terminal = Terminal::new(80, 24).unwrap();
    let ring = Ring::new(8192);
    let mut config = Config::new([0; 16], Uid::effective().as_raw());
    let mut ticket = 2;
    consume_peer(
        &trailing,
        &mut first,
        &mut pty.0,
        &mut terminal,
        &ring,
        &mut config,
        &mut input,
        &mut cursors,
        false,
        false,
        &mut ticket,
    )
    .unwrap();
    assert_eq!(
        first.deferred,
        Some(2),
        "later input inherited an earlier reservation"
    );
    assert_eq!(cursors.get(Some(7)).unwrap().accepted, 4);
    assert_eq!(
        [first.deferred, second.deferred]
            .into_iter()
            .flatten()
            .min(),
        Some(1)
    );
    consume_peer(
        &[],
        &mut second,
        &mut pty.0,
        &mut terminal,
        &ring,
        &mut config,
        &mut input,
        &mut cursors,
        false,
        false,
        &mut ticket,
    )
    .unwrap();
    assert!(second.deferred.is_none());
    consume_peer(
        &[],
        &mut first,
        &mut pty.0,
        &mut terminal,
        &ring,
        &mut config,
        &mut input,
        &mut cursors,
        false,
        false,
        &mut ticket,
    )
    .unwrap();
    assert!(first.deferred.is_none());
    assert_eq!(cursors.get(Some(7)).unwrap().accepted, 8);
    assert_eq!(cursors.get(Some(8)).unwrap().accepted, 4);
}

#[test]
fn new_frames_roundtrip_and_refuse_noncanonical_payloads() {
    for frame in [
        Frame::SequencedInput(7, b"abc".to_vec()),
        Frame::InputAck(10),
        Frame::InputStateRequest,
        Frame::InputState(10, 12),
        Frame::SelectWriter(0x0102_0304),
    ] {
        let wire = frame.encode().unwrap();
        for split in 0..wire.len() {
            let mut decoder = Decoder::default();
            let mut frames = decoder.feed(&wire[..split]).unwrap();
            frames.extend(decoder.feed(&wire[split..]).unwrap());
            assert_eq!(frames, vec![frame.clone()]);
        }
    }
    for bytes in [
        &[0x17][..],
        &[0x18][..],
        &[0x19, 0][..],
        &[0x1a, 0][..],
        &[0x1b][..],
        &[0x1b, 1, 2, 3, 4, 5][..],
    ] {
        assert!(Frame::decode(bytes).is_err());
    }
}

#[test]
fn coalesced_ack_never_overwrites_a_partial_output_and_cursors_survive_peer_loss() {
    let (stream, _remote) = UnixStream::pair().unwrap();
    let mut peer = Peer {
        stream,
        decoder: Decoder::default(),
        trailing: Vec::new(),
        deferred: None,
        attached: true,
        caps: SEQUENCED_INPUT,
        input_reply: None,
        writer: Some(0),
        shared_writer: false,
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

#[test]
fn writer_selection_has_a_frozen_little_endian_layout() {
    assert_eq!(
        Frame::SelectWriter(0x0102_0304).encode().unwrap(),
        [5, 0, 0, 0, 0x1b, 4, 3, 2, 1]
    );
}
