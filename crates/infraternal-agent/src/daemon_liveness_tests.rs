//! Probes must cross the selected shim writer before a terminal route can claim liveness [D265, #199].
use super::*;

#[tokio::test]
#[allow(clippy::too_many_lines)]
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
