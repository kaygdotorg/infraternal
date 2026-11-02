//! Real local terminal-fd and lease lifetime tests; these do not claim PAM coverage [D240,D247].
use nix::{
    pty::{Winsize, openpty},
    sys::socket::{ControlMessage, MsgFlags, sendmsg},
    unistd::{Uid, User},
};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const ENDPOINT_ENV: &str = "INFRATERNAL_LOGIN_TEST_ENDPOINT";
const CONTROLLER_ENV: &str = "INFRATERNAL_LOGIN_TEST_CONTROLLER";
const FIXTURE: &str = "login_lifecycle::worker_fixture";
const GRACE: Duration = Duration::from_secs(3);
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn worker_fixture() {
    let Some(endpoint) = std::env::var_os(ENDPOINT_ENV) else {
        return;
    };
    let controller = std::env::var(CONTROLLER_ENV).unwrap().parse().unwrap();
    crate::login::worker_as_controller(&PathBuf::from(endpoint), GRACE, controller).unwrap();
}

struct Worker {
    root: PathBuf,
    endpoint: PathBuf,
    child: Child,
}
impl Worker {
    fn new(controller: u32) -> Self {
        let scratch =
            PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/rl3");
        fs::create_dir_all(&scratch).unwrap();
        let root = scratch.join(format!(
            "l{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = root.join("l.sock");
        assert!(endpoint.as_os_str().len() < 108);
        for name in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
            fs::write(root.join(name), b"# Private login lifecycle fixture.\n").unwrap();
        }
        fs::write(
            root.join(".zlogin"),
            b"print -r -- INFRATERNAL-LIFECYCLE-READY\n",
        )
        .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("HOME", &root)
            .env("ZDOTDIR", &root)
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            .env("INFRATERNAL_LOGIN_TEST_INHERITED", "fixture-value")
            .env(ENDPOINT_ENV, &endpoint)
            .env(CONTROLLER_ENV, controller.to_string())
            .args(["--exact", FIXTURE, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // Rust's test harness creates another thread before this fixture runs.
        // Block SIGCHLD across exec so every harness thread inherits the mask;
        // otherwise the harness main thread can consume the worker's signal.
        let previous = nix::sys::signal::SigSet::thread_get_mask().unwrap();
        let mut mask = previous;
        mask.add(nix::sys::signal::Signal::SIGCHLD);
        mask.thread_set_mask().unwrap();
        let spawned = command.spawn();
        previous.thread_set_mask().unwrap();
        let child = spawned.unwrap();
        let mut worker = Self {
            root,
            endpoint,
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !worker.endpoint.exists() {
            assert!(
                worker.child.try_wait().unwrap().is_none(),
                "fixture worker exited before binding"
            );
            assert!(Instant::now() < deadline, "fixture worker socket not ready");
            thread::sleep(Duration::from_millis(2));
        }
        worker
    }
    fn peer(&self) -> UnixStream {
        let peer = UnixStream::connect(&self.endpoint).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        peer
    }
    fn probe(&self) {
        let mut peer = self.peer();
        peer.write_all(b"?").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = [0];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"R");
        assert_eq!(
            peer.read(&mut response).unwrap(),
            0,
            "readiness peer did not close"
        );
    }
    fn retired(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "fixture worker failed");
                assert!(!self.endpoint.exists(), "retired worker left its endpoint");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "worker retained a released terminal lease"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn send(peer: &UnixStream, bytes: &[u8], fds: &[i32]) {
    let buffers = [std::io::IoSlice::new(bytes)];
    assert_eq!(
        sendmsg::<()>(
            peer.as_raw_fd(),
            &buffers,
            &[ControlMessage::ScmRights(fds)],
            MsgFlags::MSG_NOSIGNAL,
            None
        )
        .unwrap(),
        bytes.len()
    );
}
fn terminal() -> (OwnedFd, OwnedFd) {
    let terminal = openpty(
        Some(&Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .unwrap();
    for fd in [&terminal.master, &terminal.slave] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .unwrap();
    }
    (terminal.master, terminal.slave)
}
fn zsh_account() -> bool {
    let user = User::from_uid(Uid::effective()).unwrap().unwrap();
    if user.shell.file_name().is_none_or(|name| name != "zsh") {
        eprintln!("SKIP login lifecycle shell case: fixture requires a zsh account");
        false
    } else {
        true
    }
}

/// All 512 leases and a stalled ordinary backlog leave lifecycle readiness available.
#[test]
#[ignore = "real worker scale512 admission gate"]
fn cleanup_bypasses_full_login_lease_table_and_connect_backlog() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let mut leases = Vec::new();
    for _ in 0..512 {
        let (mut peer, master) = open_terminal(&worker);
        nix::unistd::write(&master, b"exit 0\n").unwrap();
        let mut status = [0; 4];
        peer.read_exact(&mut status).unwrap();
        assert_eq!(i32::from_le_bytes(status), 0);
        // Ended shells still retain their worker lease until this socket closes.
        leases.push(peer);
    }
    let mut overflow = worker.peer();
    let (_master, slave) = terminal();
    send(&overflow, &[0x42; 16], &[slave.as_raw_fd()]);
    let mut refused = [0; 4];
    overflow.read_exact(&mut refused).unwrap();
    assert_eq!(i32::from_le_bytes(refused), 127);
    let pending: Vec<_> = (0..64).map(|_| worker.peer()).collect();
    let mut cleanup = UnixStream::connect(worker.endpoint.with_extension("stop")).unwrap();
    cleanup.write_all(b"!").unwrap();
    cleanup
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut proof = [0];
    cleanup.read_exact(&mut proof).unwrap();
    assert_eq!(&proof, b"S");
    worker.retired();
    assert!(!worker.endpoint.with_extension("stop").exists());
    for mut lease in leases {
        assert_eq!(lease.read(&mut proof).unwrap(), 0);
    }
    drop(pending);
    eprintln!(
        "worker_leases=512 overflow_refused=true stalled_ordinary_connections=64 cleanup_confirmed=true"
    );
}

#[test]
fn pty_handoff_does_not_require_a_proxy_executable() {
    if !zsh_account() {
        return;
    }
    let worker = Worker::new(Uid::effective().as_raw());
    let mut pty = crate::pty::Pty::spawn_with_login(
        Uid::effective().as_raw(),
        80,
        24,
        &[0x42; 16],
        Some(&worker.endpoint),
        Some(i32::try_from(worker.child.id()).unwrap()),
        None,
        None,
    )
    .expect("the shim must hand its PTY directly to the authenticated worker");
    // The test executable deliberately has no private proxy CLI arm. A fresh
    // exec therefore fails; direct descriptor transfer works against the real
    // worker without a special executable, extra process or periodic timer.
    nix::unistd::write(&pty.master, b"exit 37\n").unwrap();
    assert_eq!(pty.child.wait().unwrap().code(), Some(37));
    drop(pty);
    worker.probe();
}
fn open_terminal(worker: &Worker) -> (UnixStream, OwnedFd) {
    let (master, slave) = terminal();
    let mut peer = worker.peer();
    send(&peer, &[0x42; 16], &[slave.as_raw_fd()]);
    drop(slave);
    let mut acknowledged = [0];
    peer.read_exact(&mut acknowledged).unwrap();
    assert_eq!(
        &acknowledged, b"A",
        "worker did not acknowledge actual shell startup"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut observed = Vec::new();
    loop {
        let mut fds = [nix::poll::PollFd::new(
            master.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "fixture shell did not complete login startup"
        );
        let timeout = nix::poll::PollTimeout::try_from(remaining).unwrap();
        assert!(
            nix::poll::poll(&mut fds, timeout).unwrap() > 0,
            "fixture login startup timed out"
        );
        let mut bytes = [0; 1024];
        let length = nix::unistd::read(&master, &mut bytes).unwrap();
        assert!(length > 0, "fixture terminal closed before startup");
        observed.extend_from_slice(&bytes[..length]);
        if observed
            .windows(b"INFRATERNAL-LIFECYCLE-READY".len())
            .any(|part| part == b"INFRATERNAL-LIFECYCLE-READY")
        {
            break;
        }
        if observed.len() > 64 {
            observed.drain(..observed.len() - 64);
        }
    }
    (peer, master)
}
fn end_shell(peer: &mut UnixStream, master: &OwnedFd) {
    let command = b"if [[ $INFRATERNAL_LOGIN_TEST_INHERITED != fixture-value || $INFRATERNAL_SESSION != 42424242424242424242424242424242 ]]; then exit 99; fi; exit 7\n";
    assert_eq!(nix::unistd::write(master, command).unwrap(), command.len());
    // Keep the real terminal consumer funded while the shell echoes/editing
    // output; otherwise zsh can block writing before executing the exit line.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut fds = [
            nix::poll::PollFd::new(peer.as_fd(), nix::poll::PollFlags::POLLIN),
            nix::poll::PollFd::new(master.as_fd(), nix::poll::PollFlags::POLLIN),
        ];
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "shell exit report timed out");
        assert!(
            nix::poll::poll(
                &mut fds,
                nix::poll::PollTimeout::try_from(remaining).unwrap()
            )
            .unwrap()
                > 0
        );
        if fds[0].revents().is_some_and(|flags| {
            flags.intersects(nix::poll::PollFlags::POLLIN | nix::poll::PollFlags::POLLHUP)
        }) {
            break;
        }
        if fds[1]
            .revents()
            .is_some_and(|flags| flags.contains(nix::poll::PollFlags::POLLIN))
        {
            let mut discarded = [0; 4096];
            let _ = nix::unistd::read(master, &mut discarded);
        }
    }
    let mut status = [0; 4];
    peer.read_exact(&mut status).unwrap();
    assert_eq!(
        i32::from_le_bytes(status),
        7,
        "login shell did not inherit worker environment/session marker"
    );
}

#[test]
fn exited_shell_holds_login_until_terminal_lease_closes() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    worker.probe();
    let (mut peer, master) = open_terminal(&worker);
    end_shell(&mut peer, &master);
    let retained = peer.try_clone().unwrap();
    drop(peer);
    thread::sleep(GRACE + Duration::from_millis(150));
    assert!(
        worker.child.try_wait().unwrap().is_none(),
        "shell exit retired a still-leased terminal login"
    );
    drop(master);
    drop(retained);
    worker.retired();
}

#[test]
fn malformed_descriptor_requests_leave_an_existing_terminal_alive() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let (mut live, master) = open_terminal(&worker);
    let (_, slave) = terminal();
    let received_target = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
    // The worker opens temporary kernel process-directory and readiness fds
    // while dispatching. Count only aliases of the injected PTY: a total fd
    // count races those unrelated opens/closes and cannot establish a leak.
    let worker_pid = worker.child.id();
    let received_fds = || {
        fs::read_dir(format!("/proc/{worker_pid}/fd"))
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter(|target| *target == received_target)
            .count()
    };
    let baseline_fds = received_fds();
    for bytes in [&[0x12; 8][..], &[0x12; 16][..]] {
        let mut bad = worker.peer();
        let fds = if bytes.len() == 8 {
            vec![slave.as_raw_fd()]
        } else {
            vec![slave.as_raw_fd(), slave.as_raw_fd()]
        };
        send(&bad, bytes, &fds);
        bad.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = [0];
        assert_eq!(
            bad.read(&mut response).unwrap(),
            0,
            "malformed request was acknowledged"
        );
        worker.probe();
        assert!(worker.child.try_wait().unwrap().is_none());
        assert_eq!(
            received_fds(),
            baseline_fds,
            "malformed request leaked received PTY descriptors"
        );
    }
    end_shell(&mut live, &master);
    drop(master);
    drop(live);
    worker.retired();
}

#[test]
fn unauthorized_controller_is_refused_before_terminal_acceptance() {
    let mut worker = Worker::new(u32::MAX);
    let (_, slave) = terminal();
    let mut peer = worker.peer();
    let identity = [0x23; 16];
    let buffers = [std::io::IoSlice::new(&identity)];
    let fds = [slave.as_raw_fd()];
    match sendmsg::<()>(
        peer.as_raw_fd(),
        &buffers,
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    ) {
        Ok(16) | Err(nix::errno::Errno::EPIPE | nix::errno::Errno::ECONNRESET) => {}
        result => panic!("unexpected unauthorized request send: {result:?}"),
    }
    let mut response = [0];
    match peer.read(&mut response) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("unauthorized controller received a response: {result:?}"),
    }
    drop(peer);
    worker.retired();
}

fn detached_descendant(master: &OwnedFd) -> i32 {
    let command = b"setsid /bin/sh -c 'sleep 300 & printf \"INFRATERNAL-DESC=%s\\n\" \"$!\"'\n";
    nix::unistd::write(master, command).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    loop {
        let mut fds = [nix::poll::PollFd::new(
            master.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "fixture descendant pid was not emitted"
        );
        assert!(
            nix::poll::poll(
                &mut fds,
                nix::poll::PollTimeout::try_from(remaining).unwrap()
            )
            .unwrap()
                > 0
        );
        let mut bytes = [0; 2048];
        let count = nix::unistd::read(master, &mut bytes).unwrap();
        assert!(count > 0);
        output.extend_from_slice(&bytes[..count]);
        let marker = b"INFRATERNAL-DESC=";
        for offset in 0..output.len().saturating_sub(marker.len()) {
            if output[offset..].starts_with(marker) {
                let suffix = &output[offset + marker.len()..];
                let digits = suffix
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
                if digits > 0
                    && suffix
                        .get(digits)
                        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
                {
                    return std::str::from_utf8(&suffix[..digits])
                        .unwrap()
                        .parse()
                        .unwrap();
                }
            }
        }
        if output.len() > 4096 {
            output.drain(..output.len() - 4096);
        }
    }
}

#[test]
fn grace_reaps_detached_background_descendants_after_shell_exit() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let (mut peer, master) = open_terminal(&worker);
    let descendant = detached_descendant(&master);
    end_shell(&mut peer, &master);
    drop(master);
    drop(peer);
    worker.retired();
    let remained = PathBuf::from(format!("/proc/{descendant}")).exists();
    if remained {
        // This pid was emitted by our own fresh fixture's 300-second sleep.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(descendant),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    assert!(
        !remained,
        "retired login left its detached background descendant"
    );
}

#[test]
fn controller_stop_ends_active_shell_and_detached_descendants_with_lease_held() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let (lease, master) = open_terminal(&worker);
    let descendant = detached_descendant(&master);
    let started = Instant::now();
    let mut stop = worker.peer();
    stop.write_all(b"!").unwrap();
    stop.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = [0];
    stop.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"S");
    worker.retired();
    assert!(
        started.elapsed() < GRACE,
        "revocation waited for terminal grace"
    );
    assert!(
        !PathBuf::from(format!("/proc/{descendant}")).exists(),
        "revocation retained detached descendant"
    );
    drop(master);
    drop(lease);
}

#[test]
fn canceled_ready_and_start_replies_preserve_an_existing_login() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let (lease, master) = open_terminal(&worker);
    for terminal in [false, true] {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(worker.child.id()).unwrap());
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGSTOP).unwrap();
        let peer = worker.peer();
        let descriptor = if terminal {
            let (master, slave) = super::login_lifecycle::terminal();
            send(&peer, &[0x43; 16], &[slave.as_raw_fd()]);
            Some((master, slave))
        } else {
            (&peer).write_all(b"?").unwrap();
            None
        };
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        drop(peer);
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGCONT).unwrap();
        // Its subsequent readiness reply is a processing fence: a canceled
        // peer must be contained before the existing worker can acknowledge it.
        worker.probe();
        assert!(worker.child.try_wait().unwrap().is_none());
        drop(descriptor);
    }
    drop(master);
    drop(lease);
    worker.retired();
}

#[test]
fn fallback_proxy_refuses_a_different_kernel_parent_before_terminal_transfer() {
    let worker = Worker::new(Uid::effective().as_raw());
    let pid = i32::try_from(worker.child.id()).unwrap();
    let pinned = PathBuf::from(format!("/proc/{pid}"));
    let error = crate::login::proxy_at_parent(
        &worker.endpoint,
        Uid::effective().as_raw(),
        &[0; 16],
        false,
        Some(pid),
        Some(&pinned),
        Some(pid),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn prepared_terminal_starts_before_owner_exec_and_cancels_only_its_lease() {
    let account = User::from_uid(Uid::effective()).unwrap().unwrap();
    if account.shell.file_name().and_then(|name| name.to_str()) != Some("zsh") {
        eprintln!("skipping zsh startup marker fixture for non-zsh account shell");
        return;
    }
    let uid = Uid::effective().as_raw();
    let worker = Worker::new(uid);
    let pin = PathBuf::from(format!("/proc/{}", worker.child.id()));
    let pid = i32::try_from(worker.child.id()).unwrap();
    let peer = worker.peer();
    let prepared = crate::login_handoff::Prepared::new(uid, 80, 24).unwrap();
    prepared.request(&peer, &[37; 16], pid, &pin, None).unwrap();
    // No owner executable has started. The real shell must already produce
    // its marker on the prepared master, proving overlap without a clock gate.
    let mut reader = prepared.master().try_clone().unwrap();
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut chunk = [0; 4096];
        match reader.read(&mut chunk) {
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "prepared shell marker absent");
                thread::sleep(Duration::from_millis(2));
            }
            other => panic!("prepared shell read failed: {other:?}"),
        }
        if bytes
            .windows(b"INFRATERNAL-LIFECYCLE-READY".len())
            .any(|window| window == b"INFRATERNAL-LIFECYCLE-READY")
        {
            break;
        }
    }
    drop(peer);
    drop(prepared);
    drop(reader);
    worker.probe();
    // A second real terminal remains possible after canceled pre-exec startup.
    let second = crate::login_handoff::Prepared::new(uid, 80, 24).unwrap();
    let mut peer = worker.peer();
    second.request(&peer, &[38; 16], pid, &pin, None).unwrap();
    let mut ack = [0];
    peer.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"A");
}

#[test]
fn login_shell_uses_its_validated_account_snapshot_and_refuses_uid_changes() {
    let uid = Uid::effective();
    let worker = Worker::new(uid.as_raw());
    let mut user = User::from_uid(uid).unwrap().unwrap();
    user.dir.clone_from(&worker.root);
    user.shell = PathBuf::from("/bin/sh");
    let mut shell = crate::pty::LoginShell::new(&user).unwrap();
    let (mut master, slave) = crate::pty::open_terminal(&user, 80, 24).unwrap();
    let mut child = shell.spawn(slave, &[42; 16]).unwrap();
    master
        .write_all(b"printf 'SNAPSHOT:%s:%s\\n' \"$SHELL\" \"$HOME\"; exit\n")
        .unwrap();
    let expected = format!("SNAPSHOT:/bin/sh:{}", worker.root.display());
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut chunk = [0; 4096];
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "account snapshot marker absent");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
            Err(error) => panic!("snapshot read failed: {error}"),
        }
    }
    assert!(
        bytes
            .windows(expected.len())
            .any(|window| window == expected.as_bytes()),
        "shell reread the account instead of using its login snapshot"
    );
    assert!(child.wait().unwrap().success());
    // A second shell must get its own marker, and the reusable command must
    // release all slave copies after each spawn so master EOF remains observable.
    let (mut master, slave) = crate::pty::open_terminal(&user, 80, 24).unwrap();
    let mut child = shell.spawn(slave, &[43; 16]).unwrap();
    master
        .write_all(b"printf 'SECOND:%s\\n' \"$INFRATERNAL_SESSION\"; exit\n")
        .unwrap();
    let expected = b"SECOND:2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut chunk = [0; 4096];
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "reusable command retained terminal copies"
                );
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
            Err(error) => panic!("second shell read failed: {error}"),
        }
    }
    assert!(
        bytes
            .windows(expected.len())
            .any(|window| window == expected)
    );
    assert!(child.wait().unwrap().success());
    user.shell = PathBuf::from("/nonexistent/infraternal-shell-fixture");
    let mut missing = crate::pty::LoginShell::new(&user).unwrap();
    let (mut master, slave) = crate::pty::open_terminal(&user, 80, 24).unwrap();
    assert_eq!(
        missing.spawn(slave, &[44; 16]).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    // Failed exec releases every local cached slave copy. A concurrent fixture
    // may retain a fork-inherited CLOEXEC copy until exec; wait on readiness
    // before treating that short interval as a leak.
    {
        use std::os::fd::AsFd;
        let mut ready = [nix::poll::PollFd::new(
            master.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        assert!(nix::poll::poll(&mut ready, 5000_u16).unwrap() > 0);
    }
    let error = master.read(&mut [0; 1]).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(nix::libc::EIO));
    user.uid = nix::unistd::Uid::from_raw(uid.as_raw().wrapping_add(1));
    let error = crate::pty::LoginShell::new(&user).err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}
/// Two incomplete ordinary requests must not consume the independent stop deadline.
#[test]
fn cleanup_does_not_wait_for_two_incomplete_ordinary_handshakes() {
    if !zsh_account() {
        return;
    }
    let mut worker = Worker::new(Uid::effective().as_raw());
    let (lease, master) = open_terminal(&worker);
    let first = worker.peer();
    // Observe the worker's actual receive syscall, rather than assuming that
    // a sleep placed the cleanup request behind the first ordinary handshake.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let receiving = fs::read_dir(format!("/proc/{}/task", worker.child.id()))
            .unwrap()
            .any(|entry| {
                fs::read_to_string(entry.unwrap().path().join("syscall")).is_ok_and(|value| {
                    value.split_whitespace().next()
                        == Some(nix::libc::SYS_recvmsg.to_string().as_str())
                })
            });
        if receiving {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ordinary receive barrier not reached"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let second = worker.peer();
    let mut cleanup = UnixStream::connect(worker.endpoint.with_extension("stop")).unwrap();
    cleanup.write_all(b"!").unwrap();
    // Match the production controller's request_stop deadline. This is a
    // functional refusal reproduction, not a host performance measurement.
    cleanup
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut proof = [0];
    let result = cleanup.read_exact(&mut proof);
    let confirmed = result.is_ok() && proof == *b"S";
    eprintln!("incomplete_ordinary_requests=2 cleanup_confirmed={confirmed} result={result:?}");
    // Release both artificial handshakes even on failure and let the worker
    // retire its real terminal before the assertion, so no shell is orphaned.
    drop(first);
    drop(second);
    if !confirmed {
        cleanup
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        cleanup.read_exact(&mut proof).unwrap();
        assert_eq!(&proof, b"S");
    }
    worker.retired();
    drop(lease);
    drop(master);
    assert!(
        confirmed,
        "ordinary handshakes consumed the independent cleanup deadline"
    );
}
