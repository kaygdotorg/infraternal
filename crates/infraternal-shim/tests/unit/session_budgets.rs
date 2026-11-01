//! Session performance measurements against contract §5 [5][41].
use super::*;
#[cfg(test)]
mod budgets {
    //! Exercises session invariants against real data and frozen expectations.
    use super::*;
    #[cfg(feature = "process-per-user")]
    #[test]
    fn bounded_flush_keeps_partial_frame_and_wire_order() {
        let (stream, mut remote) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: 0,
            input_reply: None,
            writer: Some(0),
            shared_writer: false,
            ack_queued: 0,
            size: (80, 24, 0, 0),
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            request: None,
        };
        let frame = Frame::Output(13, vec![b'x'; 4096]);
        let expected = frame.encode().unwrap();
        peer.queue(&frame).unwrap();
        let mut bytes = 17;
        let mut attempts = 1;
        peer.flush_bounded(&mut bytes, &mut attempts).unwrap();
        assert_eq!((bytes, attempts, peer.written), (0, 0, 17));
        assert_eq!(peer.pending, expected);
        let mut received = vec![0; 17];
        remote.read_exact(&mut received).unwrap();
        attempts = 4;
        peer.flush_bounded(&mut bytes, &mut attempts).unwrap();
        assert_eq!((attempts, peer.written), (4, 17));
        peer.flush().unwrap();
        let mut rest = vec![0; expected.len() - received.len()];
        remote.read_exact(&mut rest).unwrap();
        received.extend(rest);
        assert_eq!(received, expected);
        assert_eq!(peer.pending, [] as [u8; 0]);
        assert_eq!(peer.written, 0);
    }
    #[test]
    fn allowlisted_signal_after_real_pty_exit_keeps_exit_ack_available() {
        let mut pty = Pty::spawn(Uid::effective().as_raw(), 20, 4).unwrap();
        pty.child.kill().unwrap();
        pty.child.wait().unwrap();
        let (stream, _other) = UnixStream::pair().unwrap();
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: 0,
            input_reply: None,
            writer: Some(0),
            shared_writer: false,
            ack_queued: 0,
            size: (20, 4, 0, 0),
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: true,
            stopping: false,
            request: None,
        };
        let mut terminal = Terminal::new(20, 4).unwrap();
        let ring = Ring::new(DEFAULT_CAPACITY);
        let mut config = Config::new([0; 16], Uid::effective().as_raw());
        let mut input = VecDeque::new();
        let mut cursors = Inputs::with_geometry(peer.size);
        assert!(
            !handle(
                Frame::Signal(9),
                &mut peer,
                &mut pty,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                true,
                false,
            )
            .unwrap()
        );
        assert!(
            handle(
                Frame::Signal(255),
                &mut peer,
                &mut pty,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                true,
                false,
            )
            .is_err()
        );
        assert!(
            handle(
                Frame::ExitAck,
                &mut peer,
                &mut pty,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                true,
                false,
            )
            .unwrap()
        );
    }
    #[test]
    #[ignore = "real-PTY performance measurement; set ZDOTDIR to tests/profile"]
    fn input_to_pty_write() {
        let mut pty = Pty::spawn(Uid::effective().as_raw(), 200, 60).unwrap();
        // Wait for the isolated profile prompt before entering a raw sink.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut output = Vec::new();
        while !output.windows(9).any(|w| w == b"shim-test") {
            let mut bytes = [0; 16384];
            if let Ok(n) = pty.master.read(&mut bytes) {
                output.extend_from_slice(&bytes[..n]);
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        pty.master
            .write_all(b"stty -echo -icanon; cat >/dev/null\n")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (stream, _other) = UnixStream::pair().unwrap();
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: 0,
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
        let mut terminal = Terminal::new(200, 60).unwrap();
        let ring = Ring::new(DEFAULT_CAPACITY);
        let mut config = Config::new([0; 16], Uid::effective().as_raw());
        let mut input = VecDeque::new();
        let mut cursors = Inputs::with_geometry(peer.size);
        let mut samples = Vec::new();
        let wire = Frame::Input(vec![b'x']).encode().unwrap();
        for _ in 0..10000 {
            let start = std::time::Instant::now();
            let requests = peer.decoder.feed(&wire).unwrap();
            for request in requests {
                handle(
                    request,
                    &mut peer,
                    &mut pty,
                    &mut terminal,
                    &ring,
                    &mut config,
                    &mut input,
                    &mut cursors,
                    false,
                    false,
                )
                .unwrap();
            }
            let elapsed = start.elapsed();
            assert!(
                input.is_empty(),
                "PTY sink must keep up so measurement ends after write"
            );
            samples.push(elapsed);
        }
        samples.sort_unstable();
        println!(
            "Input decode -> real PTY write: n=10000 p50={:.3} us p99={:.3} us",
            samples[5000].as_secs_f64() * 1e6,
            samples[9900].as_secs_f64() * 1e6
        );
        assert!(samples[9900] < std::time::Duration::from_micros(200));
        let _ = pty.signal(nix::libc::SIGKILL.try_into().unwrap());
        let _ = pty.child.kill();
        let _ = pty.child.wait();
    }
}

#[test]
#[ignore = "release poll-storage allocation measurement"]
fn poll_storage_measurement() {
    use std::{hint::black_box, time::Instant};
    let (peer, _) = UnixStream::pair().unwrap();
    let n = 1_000_000;
    for (label, heap) in [("poll-heap", true), ("poll-stack", false)] {
        let start = Instant::now();
        for _ in 0..n {
            if heap {
                black_box(vec![
                    PollFd::new(peer.as_fd(), PollFlags::POLLIN),
                    PollFd::new(peer.as_fd(), PollFlags::POLLOUT),
                    PollFd::new(peer.as_fd(), PollFlags::POLLIN),
                    PollFd::new(peer.as_fd(), PollFlags::POLLOUT),
                ]);
            } else {
                black_box([
                    PollFd::new(peer.as_fd(), PollFlags::POLLIN),
                    PollFd::new(peer.as_fd(), PollFlags::POLLOUT),
                    PollFd::new(peer.as_fd(), PollFlags::POLLIN),
                    PollFd::new(peer.as_fd(), PollFlags::POLLOUT),
                ]);
            }
        }
        println!(
            "{label}: n={n} ns/turn={:.1}",
            start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
        );
    }
}

#[cfg(feature = "host-login")]
#[test]
fn host_group_rejects_local_startup_and_readiness_before_opening_placement() {
    let local = super::Config::new([0x71; 16], nix::unistd::Uid::effective().as_raw());
    let mut readiness = local.clone();
    readiness.login_socket = Some(std::path::PathBuf::from("uncontacted-login-endpoint"));
    readiness.readiness = true;
    // An invalid path must not hide the invalid startup mode. Neither call
    // may open placement coordinates or create a local child in this API.
    let failures = [local, readiness].map(|config| {
        super::run_with_login_group(
            config,
            std::time::Duration::from_secs(1),
            std::path::Path::new("/not-a-host-login-group"),
        )
        .unwrap_err()
        .kind()
    });
    assert_eq!(failures, [std::io::ErrorKind::InvalidInput; 2]);
}
