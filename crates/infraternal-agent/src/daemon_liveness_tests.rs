//! Probes must cross the selected shim writer before a terminal route can claim liveness [D265, #199].
use super::*;

/// Admit the same durable writer without granting output credit or assuming a replay request.
async fn greet_writer(
    data: &mut tokio::net::UnixStream,
    id: [u8; 16],
    written: u64,
    accepted: u64,
) -> Reader {
    use infraternal_shim::frame::MULTI_WRITER;
    sessions::send(
        data,
        &Shim::Hello {
            version: 1,
            caps: SEQUENCED_INPUT | MULTI_WRITER,
            session: id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head: 0,
            start: 0,
        },
    )
    .await
    .unwrap();
    let mut reader = Reader::default();
    assert!(matches!(reader.read(data).await.unwrap(), Shim::Attach(_)));
    assert_eq!(reader.read(data).await.unwrap(), Shim::SelectWriter(2));
    assert_eq!(reader.read(data).await.unwrap(), Shim::InputStateRequest);
    sessions::send(data, &Shim::InputState(written, accepted))
        .await
        .unwrap();
    reader
}

/// Collect only acknowledgments preceding this exact correlated liveness reply.
async fn probe_acks(messages: &mut mpsc::Receiver<Message>, nonce: u64, sent_us: u64) -> Vec<u64> {
    let mut observed = Vec::new();
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(3), messages.recv())
            .await
            .expect("shim state fence did not finish")
            .expect("terminal closed before the correlated probe reply");
        match message {
            Message::Shim(2, Shim::InputAck(written)) => observed.push(written),
            Message::Pong(2, reply_nonce, reply_sent) => {
                assert_eq!((reply_nonce, reply_sent), (nonce, sent_us));
                return observed;
            }
            _ => panic!("state probe changed stream or emitted an unexpected frame"),
        }
    }
}

#[tokio::test]
async fn input_state_probe_preserves_written_ack_after_input() {
    state_ack(true).await;
}

#[tokio::test]
async fn input_state_probe_preserves_written_ack_before_input() {
    state_ack(false).await;
}

async fn state_ack(input_first: bool) {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "a{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (first_seen, first_received) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        let mut reader = greet_writer(&mut data, id, 30, 30).await;
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));

        let input = Shim::SequencedInput(30, vec![b'x'; 29]);
        let first = if input_first {
            input.clone()
        } else {
            Shim::InputStateRequest
        };
        let second = if input_first {
            Shim::InputStateRequest
        } else {
            input
        };
        assert_eq!(reader.read(&mut data).await.unwrap(), first);
        first_seen.send(()).unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), second);
        // A state fence may subsume a standalone Ack. Accepted input can be
        // ahead of the PTY write cursor; only 59 is safe to acknowledge.
        sessions::send(&mut data, &Shim::InputState(59, 88))
            .await
            .unwrap();
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(59, 88))
            .await
            .unwrap();
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(58, 88))
            .await
            .unwrap();
        // A regressing fence must close this exact writer without a Pong.
        let _ = reader.read(&mut data).await;
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let task = tokio::spawn(terminal(path, id, 2, 0, 30, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(30)))
    ));
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    let input = || Command::Input(30, vec![b'x'; 29]);
    if input_first {
        commands.try_send(input()).unwrap();
    } else {
        commands.try_send(Command::Ping(41, 73)).unwrap();
    }
    first_received.await.unwrap();
    // The peer has observed the first wire frame, so task scheduling cannot
    // change either requested input/probe order into the other one.
    if input_first {
        commands.try_send(Command::Ping(41, 73)).unwrap();
    } else {
        commands.try_send(input()).unwrap();
    }
    let mut acknowledgments = Vec::new();
    for (nonce, sent_us) in [(41, 73), (42, 74)] {
        if nonce == 42 {
            commands.try_send(Command::Ping(nonce, sent_us)).unwrap();
        }
        acknowledgments.push(probe_acks(&mut messages, nonce, sent_us).await);
    }
    commands.try_send(Command::Ping(43, 75)).unwrap();
    let regressed_reply = tokio::time::timeout(std::time::Duration::from_secs(3), messages.recv())
        .await
        .expect("regressing state fence did not retire its terminal");
    // Retire the fixture before checking the red assertion, retaining no
    // listener or pending peer task after the expected baseline failure.
    drop(commands);
    let terminal_result = task.await.unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        acknowledgments,
        [vec![59], Vec::new()],
        "advanced written cursor must emit Ack59 before Pong; unchanged state must emit only Pong"
    );
    assert!(
        regressed_reply.is_none(),
        "regressing written state must not emit an Ack or correlated Pong"
    );
    assert_eq!(
        terminal_result.unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "regressing written state must refuse the terminal route"
    );
}

#[tokio::test]
async fn detached_ping_preserves_written_ack_without_output_credit() {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "d{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        let mut reader = greet_writer(&mut data, id, 30, 30).await;
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::Error(1, "repaint unavailable".into()))
            .await
            .unwrap();
        assert!(reader.read(&mut data).await.is_err());
        for _ in 0..2 {
            let (mut replacement, _) = listener.accept().await.unwrap();
            let mut frames = greet_writer(&mut replacement, id, 59, 88).await;
            // A parked Ping crosses only the state handshake. It must not
            // require Credit, ReadFrom, another input or a different writer.
            assert!(frames.read(&mut replacement).await.is_err());
        }
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let task = tokio::spawn(terminal(path, id, 2, 0, 30, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(30)))
    ));
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    commands.try_send(Command::Ping(41, 73)).unwrap();
    // This event is emitted after the old data socket has been parked.
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    let mut acknowledgments = Vec::new();
    for (nonce, sent_us) in [(42, 74), (43, 75)] {
        commands.try_send(Command::Ping(nonce, sent_us)).unwrap();
        acknowledgments.push(probe_acks(&mut messages, nonce, sent_us).await);
    }
    drop(commands);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        acknowledgments,
        [vec![59], Vec::new()],
        "detached Ping must publish new written progress before Pong, without repeated idle Acks"
    );
}

#[tokio::test]
async fn terminal_probe_waits_for_the_shim_fence_and_keeps_stream_identity() {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "p{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (fenced, seen) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        sessions::send(
            &mut data,
            &Shim::Hello {
                version: 1,
                caps: SEQUENCED_INPUT | MULTI_WRITER,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head: 0,
                start: 0,
            },
        )
        .await
        .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        fenced.send(()).unwrap();
        released.await.unwrap();
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        // A parked repaint drops this data link with a probe still in flight.
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::Error(1, "repaint unavailable".into()))
            .await
            .unwrap();
        let (mut replacement, _) = listener.accept().await.unwrap();
        sessions::send(
            &mut replacement,
            &Shim::Hello {
                version: 1,
                caps: SEQUENCED_INPUT | MULTI_WRITER,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head: 0,
                start: 0,
            },
        )
        .await
        .unwrap();
        let mut frames = Reader::default();
        assert!(matches!(
            frames.read(&mut replacement).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(
            frames.read(&mut replacement).await.unwrap(),
            Shim::SelectWriter(2)
        );
        assert_eq!(
            frames.read(&mut replacement).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut replacement, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(
            frames.read(&mut replacement).await.unwrap(),
            Shim::ReadFrom(0)
        );
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                frames.read(&mut replacement)
            )
            .await
            .unwrap()
            .unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut replacement, &Shim::InputState(0, 0))
            .await
            .unwrap();
        let _ = frames.read(&mut replacement).await;
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let task = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    commands.try_send(Command::Ping(41, 73)).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), seen)
        .await
        .unwrap()
        .unwrap();
    assert!(
        messages.try_recv().is_err(),
        "daemon answered before the shim fence"
    );
    release.send(()).unwrap();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(3), messages.recv())
        .await
        .unwrap();
    assert!(matches!(reply, Some(Message::Pong(2, 41, 73))));
    commands.try_send(Command::Ping(42, 74)).unwrap();
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    commands.try_send(Command::Credit(1024)).unwrap();
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    commands.try_send(Command::Ping(43, 75)).unwrap();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(3), messages.recv())
        .await
        .expect("a replacement data link must accept a new probe");
    assert!(matches!(reply, Some(Message::Pong(2, 43, 75))));
    drop(commands);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
}
