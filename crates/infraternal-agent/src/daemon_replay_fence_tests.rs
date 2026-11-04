//! A shim Output frame that crosses the replay fence must be delivered whole, with no later event needed [#324].
//!
//! `Hello.head` splits the bytes already present when a link opened from the
//! bytes produced while the attach was being established. If the shell keeps
//! printing between that Hello and the shim's handling of `ReadFrom`, the shim
//! legitimately answers with ONE frame that holds both. The relay forwards the
//! prefix up to the fence, emits `ReplayComplete`, and must then forward the
//! rest of the same frame. It used to park the remainder and wait: nothing
//! re-entered the loop while credit was available, so the tail stayed invisible
//! until an unrelated command arrived.
use super::*;

/// Bytes present at Hello (a first prompt), and the frame the shim sends later.
const HEAD: usize = 104;
const FRAME: usize = 453;
/// Hang bound only: the fixed relay delivers the tail without waiting at all.
const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

#[tokio::test]
async fn output_frame_crossing_the_replay_fence_is_delivered_without_another_command() {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "f{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
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
                head: HEAD as u64,
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
        // The shell printed more after Hello: one frame, old head plus new bytes.
        sessions::send(&mut data, &Shim::Output(0, vec![b'x'; FRAME]))
            .await
            .unwrap();
        // Hold the link open until the relay is retired, like a live shim.
        assert!(reader.read(&mut data).await.is_err());
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let task = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    commands.try_send(Command::Credit(1 << 20)).unwrap();

    // Output parts in arrival order, and how many had arrived at ReplayComplete.
    let mut parts = Vec::new();
    let mut complete_after = None;
    while parts.iter().map(|&(_, len)| len).sum::<usize>() < FRAME {
        let message = tokio::time::timeout(HANG_BOUND, messages.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} of {FRAME} bytes were delivered; the rest of the frame stayed parked \
                     with credit available",
                    parts.iter().map(|&(_, len)| len).sum::<usize>()
                )
            });
        match message {
            Some(Message::Shim(2, Shim::Output(seq, bytes))) => parts.push((seq, bytes.len())),
            Some(Message::Event(2, _)) => complete_after = Some(parts.len()),
            _ => panic!("relay emitted an unexpected message"),
        }
    }
    drop(commands);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        parts,
        [(0, HEAD), (HEAD as u64, FRAME - HEAD)],
        "the frame splits exactly at the fence and the tail follows at the fence offset"
    );
    assert_eq!(
        complete_after,
        Some(1),
        "ReplayComplete follows the prefix and precedes the tail"
    );
}
