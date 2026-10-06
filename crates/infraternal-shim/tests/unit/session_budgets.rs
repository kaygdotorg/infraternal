//! Session performance measurements against contract §5 [5][41].
use super::*;
#[cfg(test)]
mod budgets {
    //! Exercises session invariants against real data and frozen expectations.
    use super::*;
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
            attached: true,
            caps: 0,
            input_reply: None,
            cursor: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            request: None,
        };
        let mut terminal = Terminal::new(200, 60).unwrap();
        let ring = Ring::new(DEFAULT_CAPACITY);
        let mut config = Config::new([0; 16], Uid::effective().as_raw());
        let mut input = VecDeque::new();
        let mut cursors = InputCursors::default();
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
