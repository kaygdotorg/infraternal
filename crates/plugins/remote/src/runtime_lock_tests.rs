//! Real lifetime-lock and admission checks for remote runtime/cleanup exclusion (#230).
#![allow(clippy::unwrap_used)]
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

#[path = "../../../infraternal-shim/tests/unit/fixture_state.rs"]
mod fixture_state;

/// The root path, plus the shared fixture state that owns it when one is used.
struct Fixture(
    PathBuf,
    #[expect(dead_code, reason = "held only so its Drop removes the shared root")]
    Option<fixture_state::FixtureState>,
);
impl Fixture {
    fn new() -> Self {
        let state = fixture_state::fixture_state();
        Self::prepare(state.to_path_buf(), Some(state))
    }

    /// Session shims bind `base/sessions/sessions/<32 hex>.sock`, which is
    /// longer than the shared fixture's `AF_UNIX` budget allows for, so these
    /// tests take a private directory directly under /tmp.
    fn short() -> Self {
        let root = nix::unistd::mkdtemp("/tmp/rl-XXXXXX").unwrap();
        Self::prepare(root, None)
    }

    fn prepare(root: PathBuf, state: Option<fixture_state::FixtureState>) -> Self {
        fs::create_dir_all(root.join("base/sessions")).unwrap();
        for path in [&root, &root.join("base"), &root.join("base/sessions")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root, state)
    }
    fn state(&self) -> PathBuf {
        self.0.join("base/sessions")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lifetime_precedes_bind_and_survives_until_last_description_closes() {
    let fixture = Fixture::new();
    let first = acquire(&fixture.state()).unwrap();
    let duplicate = first.try_clone().unwrap();
    assert!(acquire(&fixture.state()).is_err());
    drop(first);
    assert!(acquire(&fixture.state()).is_err());
    drop(duplicate);
    assert!(acquire(&fixture.state()).is_ok());
}
#[test]
fn cleanup_admission_prevents_starting_even_if_runtime_lock_was_removed() {
    let fixture = Fixture::new();
    let parent = File::open(&fixture.0).unwrap();
    parent.try_lock().unwrap();
    let state = fixture.state();
    let (ready, started) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(()).unwrap();
        acquire(&state)
    });
    started.recv().unwrap();
    assert!(!fixture.state().join(LOCK).exists());
    // Simulate final cleanup while the starter waits on directory admission.
    fs::remove_dir(fixture.state()).unwrap();
    fs::remove_dir(fixture.0.join("base")).unwrap();
    drop(parent);
    assert!(thread.join().unwrap().is_err());
}
#[test]
fn lock_links_and_replacements_are_refused() {
    let fixture = Fixture::new();
    let other = fixture.0.join("other");
    fs::write(&other, b"retained").unwrap();
    symlink(&other, fixture.state().join(LOCK)).unwrap();
    assert!(acquire(&fixture.state()).is_err());
    assert_eq!(fs::read(other).unwrap(), b"retained");
}

#[test]
fn managed_start_refuses_another_host_and_an_unfinished_receipt() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("base/.bootstrap-owner");
    let host = "11111111111111111111111111111111";
    fs::write(&marker, format!("{host}\n")).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(acquire_owned(&fixture.state(), "22222222222222222222222222222222").is_err());
    let receipt = fixture
        .0
        .join("base.bootstrap-rollback-22222222222222222222222222222222");
    fs::write(&receipt, b"retained").unwrap();
    assert!(acquire_owned(&fixture.state(), host).is_err());
    assert!(!fixture.state().join(LOCK).exists());
    fs::remove_file(receipt).unwrap();
    assert!(acquire_owned(&fixture.state(), host).is_ok());
}

#[test]
fn a_live_legacy_runtime_cannot_publish_an_unheld_lifetime_file() {
    let fixture = Fixture::new();
    let listener =
        std::os::unix::net::UnixListener::bind(fixture.state().join("plugins.sock")).unwrap();
    assert_eq!(
        acquire(&fixture.state()).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    assert!(!fixture.state().join(LOCK).exists());
    drop(listener);
    assert!(acquire(&fixture.state()).is_ok());
}

#[test]
fn unavailable_lock_support_does_not_claim_a_live_holder() {
    assert_eq!(lock_status(&std::fs::TryLockError::WouldBlock), 73);
    assert_eq!(
        lock_status(&std::fs::TryLockError::Error(
            io::ErrorKind::PermissionDenied.into()
        )),
        77
    );
}

fn record(length: usize) -> Vec<u8> {
    let mut record = vec![0_u8; length];
    let length = u32::try_from(length).unwrap();
    record[0..4].copy_from_slice(&length.to_ne_bytes());
    record[4..6].copy_from_slice(&(if length == 20 { 3_u16 } else { 20 }).to_ne_bytes());
    record[6..8].copy_from_slice(&2_u16.to_ne_bytes());
    record[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    if length == 20 {
        return record;
    }
    record[16] = 1;
    record[20..24].copy_from_slice(&1234_u32.to_ne_bytes());
    let tail = if length == 60 {
        for (offset, value) in [(32, 12_u16), (34, 1)] {
            record[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
        }
        record[36..40].copy_from_slice(&4321_u32.to_ne_bytes());
        record[40..44].copy_from_slice(&123_u32.to_ne_bytes());
        44
    } else {
        32
    };
    for (offset, value) in [(0, 5_u16), (2, 6), (8, 8), (10, 7)] {
        record[tail + offset..tail + offset + 2].copy_from_slice(&value.to_ne_bytes());
    }
    record[tail + 12..tail + 16].copy_from_slice(&1001_u32.to_ne_bytes());
    record
}

/// Only the three known kernel record shapes are accepted; anything else is unsure.
#[test]
fn dump_records_accept_only_known_shapes() {
    let owner = SocketOwner {
        uid: 1001,
        inode: 4321,
        device: 123,
    };
    for (length, expected, checked) in [
        (
            60,
            DumpRecord::Bound(owner),
            &[0, 4, 6, 8, 16, 32, 34, 44, 46, 52, 54][..],
        ),
        (
            48,
            DumpRecord::Unbound,
            &[0, 4, 6, 8, 16, 32, 34, 40, 42][..],
        ),
        (20, DumpRecord::Done, &[0, 4, 6, 8, 16][..]),
    ] {
        let record = record(length);
        assert_eq!(dump_record(&record), Some(expected));
        for length in 0..record.len() {
            assert!(dump_record(&record[..length]).is_none());
        }
        let mut extended = record.clone();
        extended.extend([0; 4]);
        assert!(dump_record(&extended).is_none());
        for &offset in checked {
            let mut changed = record.clone();
            changed[offset] ^= 0x80;
            assert!(dump_record(&changed).is_none(), "{length}:{offset}");
        }
    }
    for byte in 0..=255 {
        assert!(dump_record(&[byte; 60]).is_none());
    }
}

/// A datagram is split by declared lengths; a malformed length fails the whole read.
#[test]
fn dump_datagrams_split_exactly() {
    let mut datagram = [record(60), record(48), record(20)].concat();
    let mut seen = 0;
    assert!(dump_datagram(&datagram, |_| seen += 1).is_some());
    assert_eq!(seen, 3);
    for length in 1..datagram.len() {
        let complete = [0, 60, 108].contains(&length);
        assert_eq!(
            dump_datagram(&datagram[..length], |_| {}).is_some(),
            complete
        );
    }
    datagram[60..64].copy_from_slice(&50_u32.to_ne_bytes());
    assert!(dump_datagram(&datagram, |_| {}).is_none());
    datagram[60..64].copy_from_slice(&4096_u32.to_ne_bytes());
    assert!(dump_datagram(&datagram, |_| {}).is_none());
}

fn kernel_holds(path: &Path) -> Option<bool> {
    kernel_bound(&[(path.to_path_buf(), fs::metadata(path).unwrap())])
}

const AFTER_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Waits up to two seconds for the kernel socket dump to forget a closed endpoint.
fn after_close<T: PartialEq>(live: &T, mut inspect: impl FnMut() -> T) -> T {
    // A procfs snapshot can itself take longer than the old 100 ms budget when
    // several verification jobs run at once, leaving no poll to observe release.
    let deadline = std::time::Instant::now() + AFTER_CLOSE_TIMEOUT;
    loop {
        let result = inspect();
        if result != *live || std::time::Instant::now() >= deadline {
            return result;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn sessions_after_close(runtime: &File) -> Result<(), u8> {
    after_close(&Err(73), || sessions(runtime))
}

#[test]
fn after_close_waits_for_a_slow_socket_snapshot() {
    let mut inspections = 0;
    let result = after_close(&Some(true), || {
        inspections += 1;
        if inspections == 1 {
            std::thread::sleep(std::time::Duration::from_millis(125));
            Some(true)
        } else {
            Some(false)
        }
    });
    assert_eq!(result, Some(false));
    assert_eq!(inspections, 2);
}

/// Kernel ownership remains observable when a runtime makes descriptors private.
#[test]
fn legacy_inspection_finds_a_real_bound_socket() {
    let fixture = Fixture::new();
    let path = fixture.state().join("plugins.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let _pair = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(kernel_holds(&path), Some(true));
    let other = fixture.state().join("other.sock");
    drop(std::os::unix::net::UnixListener::bind(&other).unwrap());
    assert_eq!(
        after_close(&Some(true), || kernel_holds(&other)),
        Some(false)
    );
    drop(listener);
    assert_eq!(
        after_close(&Some(true), || kernel_holds(&path)),
        Some(false)
    );
}

/// Names are never read: newline homes and absolute aliases keep the same identity.
#[test]
fn legacy_inspection_is_independent_of_the_bound_name() {
    let fixture = Fixture::new();
    let odd = fixture.0.join("a\nb c");
    fs::create_dir(&odd).unwrap();
    let alias = fixture.0.join("alias");
    symlink(fixture.state(), &alias).unwrap();
    for (bound, probed) in [
        (odd.join("plugins.sock"), odd.join("plugins.sock")),
        (
            alias.join("plugins.sock"),
            fixture.state().join("plugins.sock"),
        ),
    ] {
        let listener = std::os::unix::net::UnixListener::bind(&bound).unwrap();
        assert_eq!(kernel_holds(&probed), Some(true));
        drop(listener);
        assert_eq!(
            after_close(&Some(true), || kernel_holds(&probed)),
            Some(false)
        );
        fs::remove_file(probed).unwrap();
    }
}

/// Session endpoints are live while any socket is bound to them, nested or
/// not and before `listen`; the control socket and leftover files are not.
#[test]
fn session_inspection_finds_bound_endpoints_by_identity() {
    let fixture = Fixture::new();
    let nested = fixture.state().join("sessions");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = directory(&fixture.state()).unwrap();
    let control =
        std::os::unix::net::UnixListener::bind(fixture.state().join("plugins.sock")).unwrap();
    drop(std::os::unix::net::UnixListener::bind(nested.join("left.sock")).unwrap());
    assert_eq!(sessions_after_close(&runtime), Ok(()));
    let bound = std::os::unix::net::UnixDatagram::bind(nested.join("live.sock")).unwrap();
    assert_eq!(sessions(&runtime), Err(73));
    drop(bound);
    assert_eq!(sessions_after_close(&runtime), Ok(()));
    drop(control);
}

/// The replacement confirmation counts sessions a shim still serves: a socket
/// file left by an exited shim and the control socket are not sessions (#305).
#[test]
fn open_session_count_includes_only_bound_endpoints() {
    let fixture = Fixture::new();
    let nested = fixture.state().join("sessions");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = directory(&fixture.state()).unwrap();
    let control =
        std::os::unix::net::UnixListener::bind(fixture.state().join("plugins.sock")).unwrap();
    drop(std::os::unix::net::UnixListener::bind(nested.join("left.sock")).unwrap());
    assert_eq!(after_close(&Ok(1), || open_sessions(&runtime)), Ok(0));
    let first = std::os::unix::net::UnixListener::bind(nested.join("one.sock")).unwrap();
    let second = std::os::unix::net::UnixListener::bind(fixture.state().join("two.sock")).unwrap();
    assert_eq!(open_sessions(&runtime), Ok(2));
    drop(first);
    assert_eq!(after_close(&Ok(2), || open_sessions(&runtime)), Ok(1));
    drop((second, control));
}

/// A non-dumpable legacy shim can be retired only through its owned session socket.
fn start_legacy_shim(
    path: &std::path::Path,
    session: &str,
    reported_pid: &str,
) -> std::process::Child {
    use std::io::{BufRead, BufReader, Read};

    let shim = r"
import ctypes, os, socket, struct, sys
path, session, reported_pid = sys.argv[1:]
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
os.chmod(path, 0o600)
listener.listen(1)
ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)
print('READY', flush=True)
peer, _ = listener.accept()
def frame(body):
    return struct.pack('<I', len(body)) + body
def read_frame():
    header = peer.recv(4)
    while len(header) < 4:
        header += peer.recv(4 - len(header))
    size = struct.unpack('<I', header)[0]
    body = b''
    while len(body) < size:
        body += peer.recv(size - len(body))
    return body
hello = b'\x01' + struct.pack('<H', 1) + struct.pack('<Q', 0)
pid = os.getpid() if reported_pid == 'self' else os.getpid() + 1
hello += bytes.fromhex(session) + struct.pack('<I', pid)
hello += struct.pack('<HHQQQ', 80, 24, 0, 0, 0)
peer.sendall(frame(hello))
assert read_frame() == b'\x02' + struct.pack('<Q', 0)
assert read_frame() == b'\x13' + struct.pack('<Q', 0)
assert read_frame() == b'\x16\x01'
peer.sendall(frame(b'\x20' + struct.pack('<iQ', 0, 0)))
assert read_frame() == b'\x21'
while True:
    peer.recv(1)
";
    let mut server = std::process::Command::new("python3")
        .args(["-c", shim])
        .arg(path)
        .arg(session)
        .arg(reported_pid)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(server.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    drop(stdout);
    if ready != "READY\n" {
        let _ = server.kill();
        let status = server.wait().unwrap();
        let mut stderr_text = String::new();
        BufReader::new(server.stderr.take().unwrap())
            .read_to_string(&mut stderr_text)
            .unwrap();
        panic!("legacy shim fixture did not start: {ready:?}, {status}: {stderr_text}");
    }
    server
}

#[test]
fn stale_session_cleanup_reaps_legacy_shell_before_stopping_its_shim() {
    use std::{
        io::{BufReader, Read},
        os::unix::process::ExitStatusExt,
    };

    let fixture = Fixture::short();
    let nested = fixture.state().join("sessions");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let id = uuid::Uuid::new_v4();
    let path = nested.join(format!("{}.sock", id.simple()));
    let mut server = start_legacy_shim(&path, &id.simple().to_string(), "self");
    let base = fixture.0.join("base");
    let root = fs::metadata(&base).unwrap();
    let args = [
        "--bootstrap-runtime".into(),
        base.as_os_str().to_owned(),
        format!("{}:{}", root.dev(), root.ino()).into(),
        "sessions-stop".into(),
    ];
    let result = command(&mut args.into_iter());
    if result != Some(0) {
        let _ = server.kill();
    }
    let status = server.wait().unwrap();
    let mut stderr_text = String::new();
    BufReader::new(server.stderr.take().unwrap())
        .read_to_string(&mut stderr_text)
        .unwrap();
    assert_eq!(
        result,
        Some(0),
        "legacy session cleanup was refused: {stderr_text}"
    );
    assert_eq!(status.signal(), Some(nix::libc::SIGTERM));
    assert!(!path.exists(), "retired session socket was left behind");
}

#[test]
fn session_cleanup_refuses_a_hello_that_names_another_peer_process() {
    use std::os::unix::process::ExitStatusExt;

    let fixture = Fixture::short();
    let nested = fixture.state().join("sessions");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let id = uuid::Uuid::new_v4();
    let path = nested.join(format!("{}.sock", id.simple()));
    let mut server = start_legacy_shim(&path, &id.simple().to_string(), "other");
    let base = fixture.0.join("base");
    let root = fs::metadata(&base).unwrap();
    let args = [
        "--bootstrap-runtime".into(),
        base.as_os_str().to_owned(),
        format!("{}:{}", root.dev(), root.ino()).into(),
        "sessions-stop".into(),
    ];
    let result = command(&mut args.into_iter());
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    let stopped_by_helper = loop {
        if server.try_wait().unwrap().is_some() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let still_bound = kernel_holds(&path) == Some(true);
    if !stopped_by_helper {
        let _ = server.kill();
    }
    let status = server.wait().unwrap();
    assert_eq!(result, Some(77), "mismatched peer pid was not refused");
    assert!(!stopped_by_helper, "cleanup signalled an unverified peer");
    assert!(still_bound, "unverified session endpoint was changed");
    assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
    assert!(path.exists(), "unverified session socket was removed");
}

/// A held lifetime description remains an explicit nonblocking refusal.
#[test]
fn lifetime_contention_preserves_would_block() {
    let fixture = Fixture::new();
    let _holder = acquire(&fixture.state()).unwrap();
    let error = acquire(&fixture.state()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn internal_dispatch_reads_only_the_normal_command_name() {
    let mut arguments = ["status", "--json"]
        .map(std::ffi::OsString::from)
        .into_iter();
    assert_eq!(command(&mut arguments), None);
    assert_eq!(arguments.next().unwrap(), "--json");
}

#[test]
fn internal_dispatch_checks_exact_argument_counts() {
    for arguments in [
        vec!["--bootstrap-runtime"],
        vec!["--bootstrap-runtime", "/unused", "1:2", "inspect", "extra"],
    ] {
        assert_eq!(
            command(&mut arguments.into_iter().map(Into::into)),
            Some(71)
        );
    }
    assert_eq!(
        command(&mut ["--bootstrap-runtime-version"].into_iter().map(Into::into)),
        Some(0)
    );
    assert_eq!(
        command(
            &mut ["--bootstrap-runtime-version", "extra"]
                .into_iter()
                .map(Into::into)
        ),
        None
    );
}

/// Review R09 (#230): `stat` and the kernel socket record can name different
/// devices for the same file. Btrfs subvolumes and overlays whose layers sit on
/// different filesystems report a per-subvolume or upper-layer `st_dev`, while
/// the diagnostic record carries the superblock device. A legacy runtime bound
/// there before `listen` must still be kept, never classified as stale.
#[test]
fn legacy_bound_endpoint_on_a_split_device_filesystem_is_kept() {
    let fixture = Fixture::new();
    for name in ["lower", "upper", "merged"] {
        fs::create_dir(fixture.0.join(name)).unwrap();
    }
    let script = "set -e; cd \"$2\"; mount -t tmpfs lower lower; mount -t tmpfs upper upper; \
        mkdir upper/u upper/w; \
        mount -t overlay split -o lowerdir=lower,upperdir=upper/u,workdir=upper/w,xino=off merged; \
        chmod 700 merged; \
        RL230_SPLIT=\"$2/merged\" exec \"$1\" --exact \
        runtime_lock::tests::split_device_inner --ignored --test-threads=1";
    let Ok(status) = std::process::Command::new("unshare")
        .args(["-Urm", "sh", "-c", script, "sh"])
        .arg(std::env::current_exe().unwrap())
        .arg(&fixture.0)
        .status()
    else {
        return;
    };
    assert!(
        status.success(),
        "a live bound endpoint was classified stale"
    );
}

#[test]
#[ignore = "runs inside the namespace prepared by the split-device test"]
fn split_device_inner() {
    use nix::sys::socket::bind;
    let Some(runtime) = std::env::var_os("RL230_SPLIT") else {
        return;
    };
    let runtime = PathBuf::from(runtime);
    let path = runtime.join("plugins.sock");
    let holder = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .unwrap();
    bind(holder.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
    let directory = directory(&runtime).unwrap();
    let inspected = control(&directory, false, true);
    let retired = control(&directory, true, true);
    eprintln!(
        "inspect={inspected:?} retire={retired:?} kept={}",
        path.exists()
    );
    assert_eq!(inspected, Err(73));
    assert_eq!(retired, Err(73));
    assert!(path.exists());
    nix::sys::socket::listen(&holder, nix::sys::socket::Backlog::new(1).unwrap()).unwrap();
}

/// Review R12 (#230): owner+inode matching ignores the filesystem, so a dead
/// session endpoint is reported live while any unrelated socket of the same
/// user on another filesystem is bound to a file with the same 32-bit inode.
/// That socket (a desktop bus, an agent socket, a system service in root mode)
/// usually lives until reboot, so every Retry answers "Setup is already
/// running" and the earlier attempt can never be finished. Two fresh tmpfs
/// mounts number their inodes from the same start, which makes the collision
/// deterministic here; on real hosts it needs the same inode on another mount.
#[test]
fn stale_session_endpoint_is_not_held_live_by_a_foreign_inode_twin() {
    let fixture = Fixture::new();
    for name in ["a", "b"] {
        fs::create_dir(fixture.0.join(name)).unwrap();
    }
    let script = "set -e; cd \"$2\"; mount -t tmpfs a a; mount -t tmpfs b b; chmod 700 a b; \
        RL230_TWIN=\"$2\" exec \"$1\" --exact \
        runtime_lock::tests::foreign_inode_twin_inner --ignored --test-threads=1";
    let Ok(status) = std::process::Command::new("unshare")
        .args(["-Urm", "sh", "-c", script, "sh"])
        .arg(std::env::current_exe().unwrap())
        .arg(&fixture.0)
        .status()
    else {
        return;
    };
    assert!(
        status.success(),
        "a dead session endpoint was held live by an unrelated socket"
    );
}

#[test]
#[ignore = "runs inside the namespace prepared by the foreign-inode test"]
fn foreign_inode_twin_inner() {
    let Some(root) = std::env::var_os("RL230_TWIN") else {
        return;
    };
    let root = PathBuf::from(root);
    let (runtime, other) = (root.join("a"), root.join("b"));
    let stale = runtime.join("33333333333333333333333333333333.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    let target = fs::metadata(&stale).unwrap().ino();
    let mut unrelated = None;
    for index in 0..64 {
        let path = other.join(format!("agent{index}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if fs::metadata(&path).unwrap().ino() == target {
            unrelated = Some(listener);
            break;
        }
    }
    let _unrelated = unrelated.expect("no inode twin on the second mount");
    let directory = directory(&runtime).unwrap();
    let result = sessions(&directory);
    eprintln!("target inode={target} sessions={result:?}");
    assert_eq!(result, Ok(()), "dead endpoint reported live (73)");
}
