//! Restart-safe input cursor and bounded acknowledgment regression checks [41].
use super::*;

#[test]
fn merge_review_replies_cannot_consume_space_reserved_for_deferred_typing() {
    const REPLY: &[u8] = b"\x1b[1;1R";
    struct Child(Pty);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.child.kill();
            let _ = self.0.child.wait();
        }
    }
    let mut pty = Child(Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap());
    let make_peer = |writer| {
        let (socket, remote) = UnixStream::pair().unwrap();
        let peer = Peer {
            stream: socket,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER | QUERY_REPLIES,
            input_reply: None,
            writer: Some(writer),
            shared_writer: false,
            ack_queued: 0,
            size: (80, 24, 0, 0),
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            stopping: false,
            request: None,
        };
        (peer, remote)
    };
    let (mut peer, _remote) = make_peer(9);
    let (mut waiting_peer, _waiting_remote) = make_peer(7);
    let mut cursors = Inputs::with_geometry(peer.size);
    cursors.select(7, peer.size).unwrap();
    cursors.select(9, peer.size).unwrap();
    let mut input = VecDeque::new();
    for seq in 0..512 {
        cursors.accept(9, seq, b"t", &mut input).unwrap();
        assert!(cursors.reply(false, REPLY, &mut input));
    }
    // Start at the shared-host segment cap with a reply tail. Coalescing
    // replies can then fill the byte budget without adding another segment.
    // Two seven-byte position reports make the remaining space divisible
    // by six, so every queued reply is also valid terminal reply syntax.
    assert!(cursors.reply(false, b"\x1b[10;1R", &mut input));
    assert!(cursors.reply(false, b"\x1b[10;1R", &mut input));
    while input.len() < MAX_FRAME {
        assert!(cursors.reply(false, REPLY, &mut input));
    }
    let mut terminal = Terminal::new(80, 24).unwrap();
    let ring = Ring::new(8192);
    let mut config = Config::new([0; 16], Uid::effective().as_raw());
    // A full queue drops best-effort replies without closing the peer or
    // changing typing ownership. The decoder already validates reply size.
    assert!(
        handle(
            Frame::QueryReply(REPLY.to_vec()),
            &mut peer,
            &mut pty.0,
            &mut terminal,
            &ring,
            &mut config,
            &mut input,
            &mut cursors,
            false,
            false,
        )
        .is_ok(),
        "a full queue must drop a reply without closing its peer"
    );
    assert_eq!(input.len(), MAX_FRAME);
    assert_eq!(cursors.get(Some(9)).unwrap().accepted, 512);
    assert_eq!(cursors.get(Some(9)).unwrap().written, 0);
    // An older shared writer waits for eight bytes of room. Each bounded PTY
    // write frees six bytes; a fresh reply must leave that reservation alone.
    // Repeating this schedule otherwise keeps the oldest typing frame parked.
    assert!(waiting_peer.input_waits(0, 8, 0, 0, false).unwrap());
    waiting_peer.deferred = Some(0);
    for _ in 0..16 {
        input.drain(..REPLY.len());
        cursors.advance(REPLY.len()).unwrap();
        // A best-effort reply may be refused, dropped or deferred. None of
        // those choices permits it to consume another frame's reservation.
        let _ = handle(
            Frame::QueryReply(REPLY.to_vec()),
            &mut peer,
            &mut pty.0,
            &mut terminal,
            &ring,
            &mut config,
            &mut input,
            &mut cursors,
            false,
            waiting_peer.deferred.is_some(),
        );
    }
    let available = MAX_FRAME - input.len();
    assert!(
        !waiting_peer.input_waits(0, 8, 0, available, false).unwrap(),
        "oldest 8-byte typing frame is still parked after 16 partial writes: \
         queued={} available={available}; fresh replies consumed its reservation",
        input.len()
    );
}

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
        stopping: false,
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
            stopping: false,
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
#[allow(clippy::too_many_lines)]
fn coalesced_probe_and_input_preserve_the_written_ack_in_both_orders() {
    struct Child(Pty);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.child.kill();
            let _ = self.0.child.wait();
        }
    }
    for probe_first in [true, false] {
        let mut pty = Child(Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap());
        let (stream, _remote) = UnixStream::pair().unwrap();
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: SEQUENCED_INPUT | MULTI_WRITER,
            input_reply: None,
            writer: Some(7),
            shared_writer: false,
            ack_queued: 30,
            size: (80, 24, 0, 0),
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            stopping: false,
            request: None,
        };
        let mut cursors = Inputs::with_geometry(peer.size);
        cursors.select(7, peer.size).unwrap();
        cursors.active_writer = Some(7);
        let mut input = VecDeque::new();
        cursors.accept(7, 0, &[b'a'; 30], &mut input).unwrap();
        input.clear();
        cursors.advance(30).unwrap();
        let mut terminal = Terminal::new(80, 24).unwrap();
        let ring = Ring::new(8192);
        let mut config = Config::new([0; 16], Uid::effective().as_raw());
        let mut payload = vec![b'x'; 29];
        payload[..3].copy_from_slice(b"\0\xff\x1b");
        let probe = Frame::InputStateRequest.encode().unwrap();
        let typed = Frame::SequencedInput(30, payload).encode().unwrap();
        let batch = if probe_first {
            [probe, typed].concat()
        } else {
            [typed, probe].concat()
        };
        let mut ticket = 0;
        let (exited, consumed) = consume_peer(
            &batch,
            &mut peer,
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
        assert!(!exited);
        assert_eq!(consumed, batch.len());
        assert!(
            input.is_empty(),
            "the real PTY must accept the whole suffix"
        );
        let state = cursors.get(peer.writer).unwrap();
        assert_eq!((state.written, state.accepted), (59, 59));
        // The state reply subsumes the standalone Ack in either frame order.
        // Adapters must forward its written cursor as well as probe liveness.
        assert!(matches!(peer.input_reply, Some(InputReply::State)));
        assert_eq!(peer.pending, [] as [u8; 0]);
        assert_eq!(peer.ack_queued, 30);
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
        stopping: false,
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
