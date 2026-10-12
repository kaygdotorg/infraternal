//! Preserves queued private-probe output when ownership EOF precedes credit-funded delivery (#169).
use super::*;

#[tokio::test]
async fn ownership_eof_does_not_discard_private_terminal_output() {
    use infraternal_shim::frame::{MULTI_WRITER, SESSION_OWNER};
    use std::time::Duration;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "e{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (retired, done) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        let hello = Shim::Hello {
            version: 1,
            caps: SEQUENCED_INPUT | MULTI_WRITER | SESSION_OWNER,
            session: id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head: 0,
            start: 0,
        };
        sessions::send(&mut data, &hello).await.unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        let (mut owner, _) = listener.accept().await.unwrap();
        sessions::send(&mut owner, &hello).await.unwrap();
        let mut control = Reader::default();
        assert_eq!(
            control.read(&mut owner).await.unwrap(),
            Shim::Attach(SESSION_OWNER)
        );
        assert_eq!(
            control.read(&mut owner).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut owner, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        sessions::send(&mut data, &Shim::Output(0, b"infraternal-ready".to_vec()))
            .await
            .unwrap();
        sessions::send(&mut data, &Shim::Exited(0, 16))
            .await
            .unwrap();
        // Real private shims close both sockets without writing an ended record.
        drop((data, owner));
        retired.send(()).unwrap();
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let mut relay = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    // A zero-head Hello completes replay immediately, before live output gets
    // credit. Consume and verify that ordered event before checking the drain.
    let Some(Message::Event(2, notice)) = messages.recv().await else {
        panic!("missing initial replay completion")
    };
    let notice: serde_json::Value = serde_json::from_slice(&notice).unwrap();
    assert_eq!(notice["type"], "terminal.replay_complete");
    assert_eq!(notice["out_seq"], "0");
    done.await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(50), &mut relay).await;
    // EOF cannot certify an exit until queued output has consumed its credit.
    assert!(
        early.is_err(),
        "ownership EOF discarded queued private output: {early:?}"
    );
    commands.try_send(Command::Credit(65536)).unwrap();
    assert!(
        matches!(messages.recv().await, Some(Message::Shim(2, Shim::Output(0, bytes))) if bytes == b"infraternal-ready")
    );
    let Some(Message::Exited(2, _, delivered)) = messages.recv().await else {
        panic!("missing ordered exit")
    };
    delivered.send(()).unwrap();
    relay.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
}
