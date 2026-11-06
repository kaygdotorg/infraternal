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

/// #324: a probe with no answer stands for one launch (Detached) and is not remembered; the next launch asks again.
#[tokio::test(flavor = "current_thread")]
async fn unanswered_manager_probe_is_not_remembered() {
    use super::Manager;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let cell = tokio::sync::OnceCell::new();
    let probes = AtomicUsize::new(0);
    let first = Manager::resolve_with(&cell, || async {
        probes.fetch_add(1, Ordering::SeqCst);
        None
    })
    .await;
    assert!(matches!(first, Manager::Detached));
    assert!(cell.get().is_none(), "a stall must not be cached");
    let second = Manager::resolve_with(&cell, || async {
        probes.fetch_add(1, Ordering::SeqCst);
        Some(Manager::User)
    })
    .await;
    assert!(matches!(second, Manager::User), "{second:?}");
    // An answer is kept: no third probe.
    let third = Manager::resolve_with(&cell, || async {
        probes.fetch_add(1, Ordering::SeqCst);
        None
    })
    .await;
    assert!(matches!(third, Manager::User));
    assert_eq!(probes.load(Ordering::SeqCst), 2);
}

thread_local! {
    /// Makes every reap of an owned launcher stall for its whole bound, like a launcher stuck in
    /// uninterruptible sleep that SIGKILL cannot yet remove.
    pub(super) static REAP_STALLS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Makes the shutdown cleanup thread fail to start on this thread, so a test can prove the launcher is
    /// still stopped when the OS refuses a thread.
    pub(super) static FAIL_CLEANUP_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A per-thread shortening of the launch hang bound, so a test reaches the failure path in milliseconds.
    pub(super) static LAUNCH_BOUND: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
    /// Arms the launch bound on an event: with a path set, the next launch's bound starts only once the path
    /// exists, so a test can put "the launcher has reached this point" before the launch gives up. A Hello that
    /// arrives before then still completes the launch. Taken by that launch.
    pub(super) static LAUNCH_ARMED: std::cell::Cell<Option<std::path::PathBuf>> =
        const { std::cell::Cell::new(None) };
}

/// Whether `pid` is a live process; a zombie, which still answers `kill(0)`, counts as gone.
fn alive(pid: i32) -> bool {
    // A zombie still answers kill(0); read the state instead.
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with(['Z', 'X'])
    })
}

/// #324: a launch that fails after its process started must stop that process, found by its pid and nothing
/// else. The stand-in shim hangs without ever binding its rendezvous, so the launch fails on its bound.
#[tokio::test(flavor = "current_thread")]
async fn failed_launch_stops_the_process_it_started_and_no_other() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let pid_file = root.join("launcher.pid");
    let exe = root.join("hung-shim");
    fs::write(
        &exe,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 300\n",
            pid_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    // A bystander with the same program name: a kill by name would take it too.
    let mut bystander = launcher("sleep", &["300"]);
    let bystander_pid = i32::try_from(bystander.id().unwrap()).unwrap();

    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(500))));
    let result = super::launch_configured(
        &exe,
        &state,
        super::Manager::Detached,
        nix::unistd::Uid::effective().as_raw(),
        80,
        24,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        false,
        &[],
    )
    .await;
    LAUNCH_BOUND.with(|bound| bound.set(None));
    let error = result
        .err()
        .expect("a shim that never binds fails the launch");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");

    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // Reaping is asynchronous; give it a moment, not a clock assertion.
    for _ in 0..200 {
        if !alive(pid) {
            break;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        !alive(pid),
        "the failed launch left its process {pid} running"
    );
    assert!(alive(bystander_pid), "an unrelated process was stopped");
    bystander.kill().await.unwrap();
}

/// What a stand-in detached shim does on the rendezvous: bind after `bind_delay`, stay silent on the first
/// `silent` connections (a loaded host missing the 2 s Hello), then answer and report a received `CloseSession`.
/// With `retire` it then removes its socket as a real shim does on exit; without it, it stays live. The
/// launcher script records its session name, then runs `launcher_body`.
fn detached_fixture(
    state: &std::path::Path,
    root: &std::path::Path,
    bind_delay: std::time::Duration,
    silent: usize,
    retire: bool,
    launcher_body: &str,
) -> (
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    // sleep: the stand-in shim binds late on purpose (`bind_delay`), to exercise a late bind
    let bind = tokio::time::sleep(bind_delay);
    detached_fixture_gated(state, root, bind, silent, retire, launcher_body)
}

/// [`detached_fixture`] whose stand-in shim binds when `bind` completes, once the launcher has
/// named the session. A test passes an event here when the order of bind and launch failure matters.
fn detached_fixture_gated(
    state: &std::path::Path,
    root: &std::path::Path,
    bind: impl std::future::Future<Output = ()> + Send + 'static,
    silent: usize,
    retire: bool,
    launcher_body: &str,
) -> (
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    use infraternal_shim::frame::{CLOSE_SESSION, Frame, SEQUENCED_INPUT};
    // The detaching launcher: record the session name it was given, then exit successfully, as the real one does.
    let name_file = root.join("session.name");
    let exe = root.join("detaching-shim");
    fs::write(
        &exe,
        format!(
            "#!/bin/sh\necho \"$3\" > '{}'\n{launcher_body}\n",
            name_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let sessions = state.join("sessions");
    let shim = tokio::spawn(async move {
        let name = loop {
            if let Ok(name) = fs::read_to_string(&name_file)
                && name.ends_with('\n')
            {
                break name.trim().to_owned();
            }
            // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        bind.await;
        let id = uuid::Uuid::parse_str(&name).unwrap();
        let path = sessions.join(format!("{name}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut held = Vec::new();
        for _ in 0..silent {
            held.push(listener.accept().await.unwrap().0);
        }
        let (mut peer, _) = listener.accept().await.unwrap();
        super::send(
            &mut peer,
            &Frame::Hello {
                version: 1,
                caps: CLOSE_SESSION | SEQUENCED_INPUT,
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
        let mut reader = super::Reader::default();
        while let Ok(frame) = reader.read(&mut peer).await {
            if frame == Frame::CloseSession {
                let _ = closed_tx.send(());
                // A real shim retires its socket after closing; a live one has not yet.
                if retire {
                    let _ = fs::remove_file(&path);
                } else {
                    // sleep: a live shim has not retired; hold its connection open until the test ends
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                }
                return;
            }
        }
    });
    (exe, shim, closed_rx)
}

/// A launcher body that stands in for a detaching launcher whose shim lineage lives on: a background loop,
/// orphaned when the launcher exits, that holds the launch's lifeline until the test's directory is removed.
/// (The fixture shim itself is a task, not a process, so something else must hold the lifeline.) Once the loop
/// is forked, the launcher writes `lifeline.held`; [`live_fixture`] binds its shim only after that.
fn live_shim_body(root: &std::path::Path) -> String {
    format!(
        "while [ -e '{root}' ]; do sleep 0.2; done &\n: > '{root}/lifeline.held'\nexit 0",
        root = root.display()
    )
}

/// [`detached_fixture`] with [`live_shim_body`], whose stand-in shim binds only once the lifeline holder exists,
/// then after `bind_delay`. A real shim inherits the lifeline before it can bind, so a bound shim with nothing
/// holding the lifeline cannot happen in the product. In this fixture it could: under load cleanup killed the
/// launcher before it forked the holder, read end-of-file on the lifeline as proof that the shim had died, and
/// never sent the close (#355).
fn live_fixture(
    state: &std::path::Path,
    root: &std::path::Path,
    bind_delay: std::time::Duration,
    silent: usize,
    retire: bool,
) -> (
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let held = root.join("lifeline.held");
    let bind = async move {
        while !held.exists() {
            // sleep: poll interval for the launcher's marker; the loop ends on that condition.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // sleep: the stand-in shim binds late on purpose (`bind_delay`), to exercise a late bind
        tokio::time::sleep(bind_delay).await;
    };
    detached_fixture_gated(state, root, bind, silent, retire, &live_shim_body(root))
}

/// Launch with the fixtures' detached manager and a current server grant for
/// any attributed person. Transfer the real person fence into the reservation.
async fn launch_detached(
    exe: &std::path::Path,
    state: &std::path::Path,
    person: Option<uuid::Uuid>,
) -> std::io::Result<super::Session> {
    let person = match person {
        Some(person) => {
            crate::logins::synchronize_at(state, person)?;
            Some((
                person,
                crate::logins::rootless_launch_guard(state, person).await?,
            ))
        }
        None => None,
    };
    super::launch_configured(
        exe,
        state,
        super::Manager::Detached,
        nix::unistd::Uid::effective().as_raw(),
        80,
        24,
        None,
        None,
        None,
        None,
        None,
        false,
        person,
        false,
        &[],
    )
    .await
}

/// #324/#334: a detached shim that binds but misses the 2 s Hello fails the launch ("operation failed") while its
/// terminal lives on, unnamed. The cleanup must reach it even when the shim is still too slow for the first retry,
/// and must close it through its own authenticated session (the id in Hello), not by name.
#[tokio::test(flavor = "current_thread")]
async fn slow_hello_failure_still_closes_the_detached_session_it_started() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let (exe, shim, closed) = live_fixture(&state, &root, std::time::Duration::ZERO, 2, true);
    let error = launch_detached(&exe, &state, None)
        .await
        .err()
        .expect("a missed Hello fails the launch");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("the failed launch left its detached session running")
        .unwrap();
    shim.await.unwrap();
}

/// J200 P1: the caller's own deadline (automation gives a launch 4 s) drops the launch future. Cleanup must not
/// be cancelled with it: it owns its state and bound. The fixture answers only the cleanup's connection, so a
/// close can arrive only if cleanup survived the cancellation.
#[tokio::test(flavor = "current_thread")]
async fn cancelling_the_launch_does_not_cancel_its_cleanup() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let (exe, shim, closed) = live_fixture(&state, &root, std::time::Duration::ZERO, 1, true);
    // The caller gives up once the shim lineage exists (its lifeline holder is forked), not after a fixed
    // time: a launcher killed before it forks leaves no shim to close, which is a different case (#355).
    let held = root.join("lifeline.held");
    let launched = tokio::select! {
        result = launch_detached(&exe, &state, None) => Some(result),
        () = async {
            while !held.exists() {
                // sleep: poll interval for the launcher's marker; the loop ends on that condition.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        } => None,
    };
    assert!(
        launched.is_none(),
        "the caller's deadline must expire first"
    );
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("cancelling the launch left its detached session running")
        .unwrap();
    shim.await.unwrap();
}

/// J200 P2: a shim that binds after the launch gave up, inside the cleanup window, has no socket when cleanup
/// starts. Cleanup must wait for it on the directory watch and close it, not skip because the path is absent.
#[tokio::test(flavor = "current_thread")]
async fn a_shim_that_binds_after_the_launch_gave_up_is_still_closed() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let (exe, shim, closed) = live_fixture(
        &state,
        &root,
        std::time::Duration::from_millis(1500),
        0,
        true,
    );
    // The bound starts once the lifeline holder exists, as the shim's late bind does, so the launch gives up
    // before the bind on the same runtime's timers, however slowly the launcher starts (#355).
    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(300))));
    LAUNCH_ARMED.with(|armed| armed.set(Some(root.join("lifeline.held"))));
    let result = launch_detached(&exe, &state, None).await;
    LAUNCH_BOUND.with(|bound| bound.set(None));
    LAUNCH_ARMED.with(|armed| armed.set(None));
    let error = result
        .err()
        .expect("a shim that has not bound fails the launch");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("a late-binding shim was never closed")
        .unwrap();
    shim.await.unwrap();
}

/// J200 P2 (person records): a person-terminal launch that fails and is stopped must retire its durable
/// `.terminal` record, or revocation later refuses a person whose terminal no longer exists. The launcher here
/// never binds; stopping it (an unreaped child of this launch) is the proof of exit.
#[tokio::test(flavor = "current_thread")]
async fn a_stopped_person_launch_retires_its_terminal_record() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let locks = state.join("infraternal-login-locks");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&locks)
        .unwrap();
    let exe = root.join("hung-shim");
    fs::write(&exe, "#!/bin/sh\nexec sleep 300\n").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    let person = uuid::Uuid::new_v4();
    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(300))));
    let result = launch_detached(&exe, &state, Some(person)).await;
    LAUNCH_BOUND.with(|bound| bound.set(None));
    assert!(result.is_err(), "a shim that never binds fails the launch");
    let records = || {
        fs::read_dir(&locks)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".terminal"))
            .count()
    };
    for _ in 0..200 {
        if records() == 0 {
            break;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(
        records(),
        0,
        "a stopped launch left its person record behind"
    );
}

/// Wait, bounded, until every launch cleanup in the process has ended. The tracker is process-wide, so a
/// parallel test's cleanup is waited for too; each one is bounded.
async fn cleanups_idle() {
    for _ in 0..1200 {
        if super::CLEANUPS
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            return;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("launch cleanups did not end");
}

/// A state directory with the person-terminal record directory a person launch writes into.
fn person_locks(state: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let locks = state.join("infraternal-login-locks");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&locks)
        .unwrap();
    locks
}

/// How many person-terminal records `locks` holds.
fn person_records(locks: &std::path::Path) -> usize {
    fs::read_dir(locks)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".terminal"))
        .count()
}

/// Fail a launch whose launcher never binds, drop its runtime with the cleanup queued and never polled, and
/// report whether the owned launcher was left running. With `fail_thread` the shutdown cleanup thread cannot
/// start either.
fn launcher_left_running_after_shutdown(fail_thread: bool) -> bool {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let pid_file = root.join("launcher.pid");
    let exe = root.join("hung-shim");
    fs::write(
        &exe,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 300\n",
            pid_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(300))));
    let result = runtime.block_on(launch_detached(&exe, &state, None));
    LAUNCH_BOUND.with(|bound| bound.set(None));
    assert!(result.is_err(), "a shim that never binds fails the launch");
    // The cleanup task was spawned by the failing launch, and block_on returned without polling it.
    FAIL_CLEANUP_THREAD.with(|fail| fail.set(fail_thread));
    drop(runtime);
    FAIL_CLEANUP_THREAD.with(|fail| fail.set(false));
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..200 {
        if !alive(pid) {
            break;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let left = alive(pid);
    if left {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    left
}

/// J200 round 2, P1 (shutdown): the runtime is dropped while the failed launch's cleanup is queued and has
/// never been polled. Dropping the task must not leave the owned launcher running: the drop fallback runs
/// the cleanup to its end on its own thread.
#[test]
fn runtime_shutdown_with_a_queued_cleanup_still_stops_the_owned_launcher() {
    assert!(
        !launcher_left_running_after_shutdown(false),
        "runtime shutdown discarded the cleanup and left the launcher running"
    );
}

/// J222 (79291): the shutdown cleanup thread cannot start. The launch's parts must still be here to stop
/// the launcher, not dropped with it left running.
#[test]
fn a_cleanup_thread_that_cannot_start_still_stops_the_owned_launcher() {
    assert!(
        !launcher_left_running_after_shutdown(true),
        "a failed cleanup thread left the owned launcher running"
    );
}

/// J200 round 2, P1 (proof): the launcher has already forked the shim lineage (a child) and is still waiting
/// on it, and the shim binds after the launch gave up. Reaping the launcher would not stop the terminal, so
/// cleanup must not delete the live terminal's socket or person record unless the shim itself is seen to exit,
/// but must still stop the launcher it owns, and nothing else. This shim answers the close but stays live.
#[tokio::test(flavor = "current_thread")]
async fn a_forked_launcher_is_not_proof_the_live_terminal_is_dead() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let locks = person_locks(&state);
    let launcher_pid = root.join("launcher.pid");
    let descendant_pid = root.join("descendant.pid");
    // Each pid file is renamed into place whole, the launcher's last, so its existence means both are
    // complete and the launcher has forked its child and is waiting on it.
    let body = format!(
        "sleep 300 &\necho $! > '{d}.tmp' && mv '{d}.tmp' '{d}'\necho $$ > '{l}.tmp' && mv '{l}.tmp' '{l}'\nwait",
        d = descendant_pid.display(),
        l = launcher_pid.display()
    );
    // The shim binds only after the launch has given up, and the launch gives up only after the launcher has
    // reached that point: both orders are events, so host load cannot reorder them (#355).
    let (failed, launch_failed) = tokio::sync::oneshot::channel::<()>();
    let (exe, shim, closed) = detached_fixture_gated(
        &state,
        &root,
        async {
            let _ = launch_failed.await;
        },
        0,
        false,
        &body,
    );
    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(300))));
    LAUNCH_ARMED.with(|armed| armed.set(Some(launcher_pid.clone())));
    let result = launch_detached(&exe, &state, Some(uuid::Uuid::new_v4())).await;
    LAUNCH_BOUND.with(|bound| bound.set(None));
    LAUNCH_ARMED.with(|armed| armed.set(None));
    assert!(
        result.is_err(),
        "a shim that has not bound fails the launch"
    );
    let _ = failed.send(());
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("the late shim was never asked to close")
        .unwrap();
    cleanups_idle().await;
    let read = |file: &std::path::Path| -> i32 {
        fs::read_to_string(file).unwrap().trim().parse().unwrap()
    };
    let (launcher, descendant) = (read(&launcher_pid), read(&descendant_pid));
    let sockets = fs::read_dir(state.join("sessions"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sock"))
        .count();
    let records = person_records(&locks);
    let launcher_alive = alive(launcher);
    let descendant_alive = alive(descendant);
    // Stop the stand-in processes by their own pids before asserting.
    for pid in [launcher, descendant] {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    shim.abort();
    assert_eq!(
        sockets, 1,
        "the live terminal's rendezvous was deleted on the launcher's exit alone"
    );
    assert_eq!(
        records, 1,
        "the live terminal's person record was deleted without proof it stopped"
    );
    assert!(
        !launcher_alive,
        "an unproven cleanup left the launcher it owns running (J222 79369)"
    );
    assert!(
        descendant_alive,
        "stopping the launcher must not touch the shim lineage it forked"
    );
}

/// The other half of the proof rule: when the shim itself is seen to exit after an authenticated close, the
/// person record is retired.
#[tokio::test(flavor = "current_thread")]
async fn the_shims_own_observed_exit_retires_the_person_record() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let locks = person_locks(&state);
    let (exe, shim, closed) = live_fixture(
        &state,
        &root,
        std::time::Duration::from_millis(800),
        0,
        true,
    );
    // Armed on the lifeline holder, like the late bind (see the test above).
    LAUNCH_BOUND.with(|bound| bound.set(Some(std::time::Duration::from_millis(300))));
    LAUNCH_ARMED.with(|armed| armed.set(Some(root.join("lifeline.held"))));
    let result = launch_detached(&exe, &state, Some(uuid::Uuid::new_v4())).await;
    LAUNCH_BOUND.with(|bound| bound.set(None));
    LAUNCH_ARMED.with(|armed| armed.set(None));
    assert!(
        result.is_err(),
        "a shim that has not bound fails the launch"
    );
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("the late shim was never asked to close")
        .unwrap();
    cleanups_idle().await;
    shim.await.unwrap();
    assert_eq!(
        person_records(&locks),
        0,
        "a proven shim exit left its person record behind"
    );
}

/// Wait, bounded, for `file` to exist.
async fn file_appears(file: &std::path::Path) {
    for _ in 0..1200 {
        if file.exists() {
            return;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("{} never appeared", file.display());
}

/// What was left after a person launch was cancelled and cleaned up.
struct Outcome {
    /// Person-terminal records still on disk.
    records: usize,
    /// Rendezvous sockets still on disk.
    sockets: usize,
    /// Whether the launcher this launch owned is still running.
    launcher_alive: bool,
    /// Whether the stand-in for the detached shim's lineage is still running.
    descendant_alive: bool,
}

/// Run a person launch whose launcher script (built by `body` from the launcher pid file, the descendant
/// pid file and the `ready` marker) leaves a live process holding the launch's lifeline, cancel the launch
/// once `ready` exists, let cleanup finish, and report what survived. The fixture shim answers the close
/// but stays live. The stand-ins are stopped by their own pids before returning.
async fn cancelled_lineage_outcome(
    body: impl FnOnce(&std::path::Path, &std::path::Path, &std::path::Path) -> String,
) -> Outcome {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let locks = person_locks(&state);
    let ready = root.join("reaped.ready");
    let launcher_pid = root.join("launcher.pid");
    let descendant_pid = root.join("descendant.pid");
    let body = body(&launcher_pid, &descendant_pid, &ready);
    let (exe, shim, closed) =
        detached_fixture(&state, &root, std::time::Duration::ZERO, 1, false, &body);
    let launch = launch_detached(&exe, &state, Some(uuid::Uuid::new_v4()));
    tokio::select! {
        _ = launch => {}
        () = file_appears(&ready) => {}
    }
    assert!(
        ready.exists(),
        "the launch ended before the launcher reached its post-fork state"
    );
    tokio::time::timeout(std::time::Duration::from_secs(20), closed)
        .await
        .expect("the live shim was never asked to close")
        .unwrap();
    cleanups_idle().await;
    file_appears(&descendant_pid).await;
    let read = |file: &std::path::Path| -> i32 {
        fs::read_to_string(file).unwrap().trim().parse().unwrap()
    };
    let (launcher, descendant) = (read(&launcher_pid), read(&descendant_pid));
    let outcome = Outcome {
        records: person_records(&locks),
        sockets: fs::read_dir(state.join("sessions"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sock"))
            .count(),
        launcher_alive: alive(launcher),
        descendant_alive: alive(descendant),
    };
    for pid in [launcher, descendant] {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    shim.abort();
    outcome
}

/// The live descendant is the shim's lineage: it holds the lifeline, so cleanup must keep the socket and the
/// person record, and still stop the launcher it owns.
fn assert_live_lineage_kept(outcome: &Outcome, why: &str) {
    assert_eq!(
        outcome.records, 1,
        "{why}: the live shim's person record was deleted"
    );
    assert_eq!(
        outcome.sockets, 1,
        "{why}: the live shim's rendezvous was deleted"
    );
    assert!(
        !outcome.launcher_alive,
        "{why}: the owned launcher was left running"
    );
    assert!(
        outcome.descendant_alive,
        "{why}: the shim lineage was touched"
    );
}

/// J222 (79368), P1: the original launcher has forked the intermediate and reaped it, so its child list is
/// EMPTY, yet the detached shim, its grandchild, is alive. The subshell below runs to completion in the
/// foreground (so the launcher has reaped it), and leaves a `sleep` orphaned and alive; the launch is
/// cancelled at that point, a deterministic stand-in for the real post-reap window.
#[tokio::test(flavor = "current_thread")]
async fn a_launcher_that_has_reaped_its_child_is_not_proof_no_shim_exists() {
    let outcome = cancelled_lineage_outcome(|launcher_pid, descendant_pid, ready| {
        format!(
            "( sleep 300 & echo $! > '{}' )\necho $$ > '{}'\ntouch '{}'\nexec sleep 300",
            descendant_pid.display(),
            launcher_pid.display(),
            ready.display()
        )
    })
    .await;
    assert_live_lineage_kept(&outcome, "post-reap window");
}

/// J230 P2-A: a launcher that ignores SIGCHLD has its children reaped by the kernel, which adds nothing to its
/// wait statistics, so any proof built on them fails open. The lifeline does not care how a child went away.
/// Here the launcher forks an intermediate that forks the lineage and exits, and `waitpid` finds nothing.
#[tokio::test(flavor = "current_thread")]
async fn an_auto_reaping_launcher_is_not_proof_no_shim_exists() {
    let outcome = cancelled_lineage_outcome(|launcher_pid, descendant_pid, ready| {
        let script = [
            "import os, signal, time".to_owned(),
            "signal.signal(signal.SIGCHLD, signal.SIG_IGN)".to_owned(),
            format!(
                "open('{}', 'w').write(str(os.getpid()))",
                launcher_pid.display()
            ),
            "middle = os.fork()".to_owned(),
            "if middle == 0:".to_owned(),
            "    shim = os.fork()".to_owned(),
            "    if shim == 0:".to_owned(),
            format!(
                "        open('{}', 'w').write(str(os.getpid()))",
                descendant_pid.display()
            ),
            "        os.execvp('sleep', ['sleep', '300'])".to_owned(),
            "    os._exit(0)".to_owned(),
            "try:".to_owned(),
            "    os.waitpid(middle, 0)".to_owned(),
            "except ChildProcessError:".to_owned(),
            "    pass".to_owned(),
            format!("open('{}', 'w').write('x')", ready.display()),
            "time.sleep(300)".to_owned(),
        ]
        .join("\n");
        format!("exec python3 -c \"{script}\"")
    })
    .await;
    assert_live_lineage_kept(&outcome, "SIGCHLD ignored");
}

/// J230: when the lifeline closes, the dead shim's own leftovers go with its record: a killed shim cannot
/// unlink its socket, and a socket with no record would make person revocation refuse. Here the launcher
/// is the only holder, and the fixture shim's socket stands for what a killed shim leaves behind.
#[tokio::test(flavor = "current_thread")]
async fn a_closed_lifeline_clears_the_dead_shims_socket_and_record() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let root = fs::canonicalize(&directory.0).unwrap();
    let locks = person_locks(&state);
    let ready = root.join("ready");
    let body = format!("touch '{}'\nexec sleep 300", ready.display());
    let (exe, shim, _closed) =
        detached_fixture(&state, &root, std::time::Duration::ZERO, 1, false, &body);
    let launch = launch_detached(&exe, &state, Some(uuid::Uuid::new_v4()));
    tokio::select! {
        _ = launch => {}
        () = file_appears(&ready) => {}
    }
    // Wait for the fixture's socket, so there is a leftover to clear.
    for _ in 0..400 {
        if fs::read_dir(state.join("sessions"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".sock"))
        {
            break;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    cleanups_idle().await;
    shim.abort();
    let sockets = fs::read_dir(state.join("sessions"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sock"))
        .count();
    assert_eq!(
        sockets, 0,
        "a dead shim's socket outlived its closed lifeline"
    );
    assert_eq!(
        person_records(&locks),
        0,
        "a proven-dead launch kept its person record"
    );
}

/// J222 (79292): the whole shutdown cleanup ends within its budget, however slowly the shim behaves. This
/// shim answers its Hello after 1.5 s, takes the close and never retires, so the nested waits (the Hello,
/// then the exit observation) add up past the 2 s budget unless one outer deadline holds. Runs on the
/// runtime's paused clock, so it asserts the bound in virtual time, never wall-clock speed.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_shutdown_cleanup_ends_within_its_budget_whatever_the_shim_does() {
    use infraternal_shim::frame::{CLOSE_SESSION, Frame, SEQUENCED_INPUT};
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let id = uuid::Uuid::new_v4();
    let name = id.simple().to_string();
    let path = state.join(format!("sessions/{name}.sock"));
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let shim = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        // sleep: the stand-in shim answers its Hello 1.5 s late, on the paused clock
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        super::send(
            &mut peer,
            &Frame::Hello {
                version: 1,
                caps: CLOSE_SESSION | SEQUENCED_INPUT,
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
        let mut reader = super::Reader::default();
        while reader.read(&mut peer).await.is_ok() {}
    });
    let mut child = launcher("true", &[]);
    child.wait().await.unwrap();
    let mut parts = super::Parts {
        child,
        state: state.clone(),
        path,
        id,
        manager: super::Manager::Detached,
        name,
        detached: true,
        record: None,
        lifeline: None,
    };
    let started = tokio::time::Instant::now();
    super::cleanup(&mut parts, super::SHUTDOWN).await;
    let spent = started.elapsed();
    shim.abort();
    assert!(
        spent <= super::SHUTDOWN_CLEANUP + std::time::Duration::from_millis(250),
        "the shutdown cleanup spent {spent:?} against a {:?} budget",
        super::SHUTDOWN_CLEANUP
    );
}

/// J230 P3-1: the final kill-and-reap of the owned launcher counts against the same single deadline. A
/// launcher whose reap stalls (uninterruptible sleep) must not add a second bound after the deadline. The
/// lifeline stays held by the test, so no proof ever arrives and every wait runs to its bound; the paused
/// clock then shows the cleanup ended at its budget, not at twice it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_stalled_reap_of_the_launcher_stays_inside_the_single_deadline() {
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let id = uuid::Uuid::new_v4();
    let child = launcher("sleep", &["300"]);
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    let (read, _write_end_held_by_the_test) = nix::unistd::pipe().unwrap();
    let mut parts = super::Parts {
        child,
        state: state.clone(),
        path: state.join(format!("sessions/{}.sock", id.simple())),
        id,
        manager: super::Manager::Detached,
        name: id.simple().to_string(),
        detached: true,
        record: None,
        lifeline: Some(read),
    };
    REAP_STALLS.with(|stalls| stalls.set(true));
    let started = tokio::time::Instant::now();
    super::cleanup(&mut parts, super::SHUTDOWN).await;
    let spent = started.elapsed();
    REAP_STALLS.with(|stalls| stalls.set(false));
    for _ in 0..200 {
        if !alive(pid) {
            break;
        }
        // sleep: poll interval between checks; the loop ends on its condition and is bounded by its iteration limit
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let left = alive(pid);
    if left {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    assert!(
        spent <= super::SHUTDOWN_CLEANUP + std::time::Duration::from_millis(250),
        "the cleanup spent {spent:?} against a {:?} budget",
        super::SHUTDOWN_CLEANUP
    );
    assert!(
        !left,
        "the launcher was not sent its kill past the deadline"
    );
}
