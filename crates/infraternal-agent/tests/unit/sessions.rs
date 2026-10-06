//! Private-directory and stale-rendezvous checks for shim discovery [13][40].
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
async fn post_listen_chmod_wakes_a_connection_refused_at_bind() {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
    };
    let directory = Directory::new();
    let state = state(Some(directory.0.clone())).unwrap();
    let path = state.join("sessions/01010101010101010101010101010101.sock");
    let watch = super::socket_readiness(&state).unwrap();
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
    let mut ready = watch.readable().await.unwrap();
    let events = ready
        .try_io(|fd| fd.get_ref().0.read_events().map_err(std::io::Error::from))
        .unwrap()
        .unwrap();
    assert!(events.iter().any(|event| {
        event
            .mask
            .contains(nix::sys::inotify::AddWatchFlags::IN_CREATE)
    }));
    drop(ready);
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
        .try_io(|fd| fd.get_ref().0.read_events().map_err(std::io::Error::from))
        .unwrap()
        .unwrap();
    assert!(events.iter().any(|event| {
        event
            .mask
            .contains(nix::sys::inotify::AddWatchFlags::IN_ATTRIB)
    }));
}
