//! Rendezvous security, cancellation-safe receive storage and reader measurements [13][40][41].
use super::{discover, state};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(PathBuf::from(format!(
            "../../target/as{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refused_socket_is_removed_but_insecure_directory_is_rejected() {
    let directory = Directory::new();
    let path = state(Some(directory.0.clone())).unwrap();
    let socket = path.join("sessions/00000000000000000000000000000001.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    assert!(discover(&path).await.unwrap().is_empty());
    assert!(!socket.exists());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        state(Some(path)).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn symlink_state_cannot_redirect_private_runtime_storage() {
    let real = Directory::new();
    state(Some(real.0.clone())).unwrap();
    let link = Directory::new();
    std::os::unix::fs::symlink(&real.0, &link.0).unwrap();
    assert_eq!(
        state(Some(link.0.clone())).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    fs::remove_file(&link.0).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_fragmented_shim_read_retains_header_and_body_progress() {
    use infraternal_shim::frame::Frame;
    use tokio::io::AsyncWriteExt;
    let (mut local, mut peer) = tokio::net::UnixStream::pair().unwrap();
    let frame = Frame::Output(17, b"fragment".to_vec());
    let wire = frame.encode().unwrap();
    let mut reader = super::Reader::default();
    peer.write_all(&wire[..2]).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            reader.read(&mut local)
        )
        .await
        .is_err()
    );
    peer.write_all(&wire[2..8]).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            reader.read(&mut local)
        )
        .await
        .is_err()
    );
    peer.write_all(&wire[8..]).await.unwrap();
    assert_eq!(reader.read(&mut local).await.unwrap(), frame);
    peer.write_all(&Frame::Exited(7, 25).encode().unwrap())
        .await
        .unwrap();
    assert_eq!(reader.read(&mut local).await.unwrap(), Frame::Exited(7, 25));
}

#[tokio::test(flavor = "current_thread")]
async fn sequenced_attach_intersects_caps_and_legacy_attach_stays_zero() {
    use infraternal_shim::frame::{APPROXIMATE_SNAPSHOT, Frame, SEQUENCED_INPUT};
    for (advertised, requested) in [
        (0, SEQUENCED_INPUT),
        (SEQUENCED_INPUT, SEQUENCED_INPUT),
        (SEQUENCED_INPUT, 0),
        (
            SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT,
            SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT,
        ),
        (APPROXIMATE_SNAPSHOT, SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT),
    ] {
        let directory = Directory::new();
        let path = state(Some(directory.0.clone()))
            .unwrap()
            .join("sessions/test.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            super::send(
                &mut peer,
                &Frame::Hello {
                    version: 1,
                    caps: advertised,
                    session: [1; 16],
                    pid: 1,
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                super::Reader::default().read(&mut peer).await.unwrap(),
                Frame::Attach(advertised & requested)
            );
        });
        let session = if requested == 0 {
            super::connect(path, [1; 16]).await.unwrap()
        } else {
            super::connect_sequenced(path, [1; 16]).await.unwrap()
        };
        assert_eq!(session.caps, advertised & requested);
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn shared_writer_helper_negotiates_before_sending_its_selector() {
    use infraternal_shim::frame::Frame;
    use tokio::io::AsyncReadExt as _;
    for advertised in [0, 3, 16, 17, 18, 19, 23] {
        let directory = Directory::new();
        let path = state(Some(directory.0.clone()))
            .unwrap()
            .join("sessions/shared.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            super::send(
                &mut peer,
                &Frame::Hello {
                    version: 1,
                    caps: advertised,
                    session: [1; 16],
                    pid: 1,
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                super::Reader::default().read(&mut peer).await.unwrap(),
                Frame::Attach(advertised)
            );
            if advertised == 19 || advertised == 23 {
                assert_eq!(
                    super::Reader::default().read(&mut peer).await.unwrap(),
                    Frame::SelectSharedWriter(7)
                );
            } else {
                assert_eq!(
                    peer.read(&mut [0; 1]).await.unwrap(),
                    0,
                    "unnegotiated selector must never be sent"
                );
            }
        });
        let session = super::connect_shared_writer(path, [1; 16], 7).await;
        assert_eq!(session.is_ok(), advertised == 19 || advertised == 23);
        drop(session);
        server.await.unwrap();
    }
    assert_eq!(
        super::connect_shared_writer(PathBuf::from("missing-shim.sock"), [1; 16], 0)
            .await
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[tokio::test(flavor = "current_thread")]
async fn post_listen_chmod_wakes_a_connection_refused_at_bind() {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
    };
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let path = state.join("sessions/01010101010101010101010101010101.sock");
    // The fixture reads the raw inotify events behind the readiness wrapper.
    let watch = super::SocketReadiness::new(&state).unwrap().0;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .unwrap();
    bind(
        std::os::fd::AsRawFd::as_raw_fd(&fd),
        &UnixAddr::new(&path).unwrap(),
    )
    .unwrap();
    // Consume creation before listen, guaranteeing the startup race rather
    // than hoping scheduler timing exercises it during real shell launches.
    {
        let mut ready = watch.readable().await.unwrap();
        let events = ready
            .try_io(|fd| fd.read_events().map_err(std::io::Error::from))
            .unwrap()
            .unwrap();
        assert!(events.iter().any(|event| {
            event
                .mask
                .contains(nix::sys::inotify::AddWatchFlags::IN_CREATE)
        }));
    }
    assert_eq!(
        super::connect(path.clone(), [1; 16])
            .await
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::ConnectionRefused
    );
    listen(&fd, Backlog::new(1).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut ready = tokio::time::timeout(std::time::Duration::from_secs(2), watch.readable())
        .await
        .unwrap()
        .unwrap();
    let events = ready
        .try_io(|fd| fd.read_events().map_err(std::io::Error::from))
        .unwrap()
        .unwrap();
    assert!(events.iter().any(|event| {
        event
            .mask
            .contains(nix::sys::inotify::AddWatchFlags::IN_ATTRIB)
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn borrowed_reader_payload_uses_reusable_cancel_safe_storage() {
    use super::Reader;
    use infraternal_shim::frame::{Frame, FrameRef};
    use tokio::io::AsyncWriteExt;
    let (mut source, mut peer) = tokio::net::UnixStream::pair().unwrap();
    let wire = Frame::Output(7, vec![42; 16_384]).encode().unwrap();
    let mut reader = Reader::default();
    source.write_all(&wire[..6]).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            reader.read_ref(&mut peer)
        )
        .await
        .is_err()
    );
    source.write_all(&wire[6..]).await.unwrap();
    let pointer = match reader.read_ref(&mut peer).await.unwrap() {
        FrameRef::Output(7, bytes) => {
            assert_eq!(bytes.len(), 16_384);
            assert!(bytes.iter().all(|byte| *byte == 42));
            bytes.as_ptr()
        }
        frame => panic!("unexpected borrowed frame: {frame:?}"),
    };
    source.write_all(&wire).await.unwrap();
    match reader.read_ref(&mut peer).await.unwrap() {
        FrameRef::Output(7, bytes) => assert_eq!(bytes.as_ptr(), pointer),
        frame => panic!("unexpected borrowed frame: {frame:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "release borrowed versus owned asynchronous receive measurement"]
async fn reader_borrow_measurement() {
    use infraternal_shim::frame::Frame;
    use std::{hint::black_box, time::Instant};
    use tokio::io::AsyncWriteExt;
    let (mut source, mut peer) = tokio::net::UnixStream::pair().unwrap();
    let wire = Frame::Output(7, vec![42; 16_384]).encode().unwrap();
    let mut reader = super::Reader::default();
    let n = 10_000;
    for round in 0..5 {
        for (label, borrowed) in [("reader-owned", false), ("reader-borrowed", true)] {
            let start = Instant::now();
            for _ in 0..n {
                source.write_all(&wire).await.unwrap();
                if borrowed {
                    black_box(reader.read_ref(&mut peer).await.unwrap());
                } else {
                    black_box(reader.read(&mut peer).await.unwrap());
                }
            }
            println!(
                "{label}: round={round} n={n} ns/frame={:.1}",
                start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
            );
        }
    }
}

#[path = "session_bounds.rs"]
mod bounds;

#[tokio::test(flavor = "current_thread")]
async fn ordinary_native_writer_negotiates_queue_backpressure_without_shared_selection() {
    use infraternal_shim::frame::Frame;
    for advertised in [3, 23] {
        let directory = Directory::new();
        let path = state(Some(directory.0.clone()))
            .unwrap()
            .join("sessions/ordinary.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            super::send(
                &mut peer,
                &Frame::Hello {
                    version: 1,
                    caps: advertised,
                    session: [1; 16],
                    pid: 1,
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                super::Reader::default().read(&mut peer).await.unwrap(),
                Frame::Attach(advertised),
                "ordinary native writers need negotiated full-queue backpressure too"
            );
            assert_eq!(
                super::Reader::default().read(&mut peer).await.unwrap(),
                Frame::SelectWriter(7)
            );
        });
        let session = super::connect_writer(path, [1; 16], 7).await.unwrap();
        server.await.unwrap();
        assert_eq!(session.caps, advertised);
    }
}

/// A stand-in shim: bind the session rendezvous after `delay`, publish it like the shim (chmod after listen), and
/// answer one Hello for `id`.
fn fake_shim(
    state: &std::path::Path,
    id: uuid::Uuid,
    delay: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    use infraternal_shim::frame::Frame;
    let path = state.join(format!("sessions/{}.sock", id.simple()));
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        super::send(
            &mut peer,
            &Frame::Hello {
                version: 1,
                caps: 0,
                session: id.into_bytes(),
                pid: 1,
                cols: 80,
                rows: 24,
                created: 0,
                head: 0,
                start: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            super::Reader::default().read(&mut peer).await.unwrap(),
            Frame::Attach(0)
        );
    })
}

fn launcher(program: &str, args: &[&str]) -> tokio::process::Child {
    tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// #324: a loaded host took 3.5-5.1 s from launcher spawn to a bound shim. While the launcher lives, that is a slow
/// start, not a refusal; the per-connection HANDSHAKE must not decide it.
#[tokio::test(flavor = "current_thread")]
async fn slow_shim_start_is_not_refused_while_its_launcher_lives() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let id = uuid::Uuid::new_v4();
    let watch = super::SocketReadiness::new(&state).unwrap();
    let mut child = launcher("sleep", &["60"]);
    let shim = fake_shim(
        &state,
        id,
        super::HANDSHAKE + std::time::Duration::from_millis(500),
    );
    let path = state.join(format!("sessions/{}.sock", id.simple()));
    let session = super::await_launch(&path, id, &watch, &mut child, false)
        .await
        .expect("a live launcher's slow start must reach Hello");
    assert_eq!(session.id, id.into_bytes());
    shim.await.unwrap();
}

/// The longer bound is only for hangs: a launcher that exits before the rendezvous refuses the open at once.
#[tokio::test(flavor = "current_thread")]
async fn launcher_exit_before_rendezvous_refuses_without_waiting_for_the_bound() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let id = uuid::Uuid::new_v4();
    let path = state.join(format!("sessions/{}.sock", id.simple()));
    let watch = super::SocketReadiness::new(&state).unwrap();
    for (program, args) in [("sh", &["-c", "exit 3"][..]), ("true", &[][..])] {
        let mut child = launcher(program, args);
        let error = super::await_launch(&path, id, &watch, &mut child, false)
            .await
            .err()
            .expect("an exited shim cannot answer");
        assert_ne!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
        assert!(
            error.to_string().contains("exited before its rendezvous"),
            "{error}"
        );
    }
    // A detaching shim's failed first process is a refusal too.
    let mut child = launcher("sh", &["-c", "exit 3"]);
    let error = super::await_launch(&path, id, &watch, &mut child, true)
        .await
        .err()
        .expect("a failed detach cannot answer");
    assert_ne!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
}

/// A detaching shim's first process exits successfully once it has forked the session process; keep waiting.
#[tokio::test(flavor = "current_thread")]
async fn detached_launcher_success_keeps_waiting_for_the_session_process() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let id = uuid::Uuid::new_v4();
    let watch = super::SocketReadiness::new(&state).unwrap();
    let mut child = launcher("true", &[]);
    // Order the exit before the bind so the test covers the case, not a timing guess.
    let status = child.wait().await.unwrap();
    assert!(status.success());
    let shim = fake_shim(&state, id, std::time::Duration::from_millis(50));
    let path = state.join(format!("sessions/{}.sock", id.simple()));
    let session = super::await_launch(&path, id, &watch, &mut child, true)
        .await
        .expect("the detached session process answers after its launcher exits");
    assert_eq!(session.id, id.into_bytes());
    shim.await.unwrap();
}
