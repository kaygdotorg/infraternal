//! Exercise the production session stop path with real pipes and a fixed-pixel capture fixture [D203,#146].
#![cfg(all(feature = "desktop", target_os = "linux"))]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
#[cfg(any(feature = "source", feature = "server"))]
use infraternal_plugin_desktop::media;
use infraternal_plugin_desktop::{capture, protocol, socket};
#[path = "../src/helper.rs"]
mod helper;
#[allow(dead_code)]
#[path = "../src/measurement.rs"]
mod measurement;
#[allow(dead_code)]
#[path = "../src/native.rs"]
mod native;

/// The platform capture boundary supplies fixed owned pixels; no Mac framework
/// behavior or performance is claimed by this Linux process-shutdown test.
mod macos {
    use super::{
        capture::{Capture, CapturedFrame, Rect},
        protocol::{Size, Target},
    };
    use std::io;
    pub struct MacCapture(Size);
    pub struct Frame;
    impl CapturedFrame for Frame {
        fn capture_ticks(&self) -> u64 {
            1
        }
    }
    impl Capture for MacCapture {
        type Frame = Frame;
        fn start(_: &Target, size: Size, _: Rect) -> io::Result<Self> {
            Ok(Self(size))
        }
        fn resize(&mut self, size: Size, _: Rect) -> io::Result<()> {
            self.0 = size;
            Ok(())
        }
        fn copy_pixels(&self) -> io::Result<Vec<u8>> {
            Ok(vec![0; self.0.width as usize * self.0.height as usize * 4])
        }
        fn take_latest(&self) -> Option<Frame> {
            Some(Frame)
        }
        fn stop(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[test]
fn signal_stop_joins_capture_without_waiting_for_a_blocked_encoder() {
    use std::{
        fs,
        net::Shutdown,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };
    // This fixed-pixel fixture deliberately exercises the owned-copy fallback.
    // Select it in a child so parallel tests never mutate process environment.
    if std::env::var_os("INFRATERNAL_DESKTOP_OWNED").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .env("INFRATERNAL_DESKTOP_OWNED", "1")
            .args([
                "--exact",
                "signal_stop_joins_capture_without_waiting_for_a_blocked_encoder",
                "--nocapture",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "owned-copy shutdown fixture failed");
        return;
    }
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    let dir = root.join(format!("desktop-helper-stop-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("native-fixture.py");
    fs::write(&executable, r"#!/usr/bin/env python3
# Role: acknowledge control cleanup but stop draining the encoder pixel packet.
import json, signal, struct, sys
source = sys.stdin.buffer
sink = sys.stdout.buffer
encoder = '--encoder' in sys.argv
while True:
    header = source.read(6)
    if len(header) != 6: break
    length, version, kind = struct.unpack('>IBB', header)
    if encoder and kind == 101:
        with open(sys.argv[0] + '.ready', 'w') as output:
            output.write('ready')
        signal.pause()
        break
    if len(source.read(length-2)) != length-2: break
    payload = {'capture_ticks': 1} if encoder else {'capture_rect': {'x': 0, 'y': 0, 'width': 512, 'height': 512}, 'restored': True}
    body = json.dumps(payload).encode()
    reply = 66 if kind == 2 else 68
    sink.write(struct.pack('>IBB', len(body)+2, 1, reply)+body)
    sink.flush()
").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut companion = native::Native::spawn(&executable).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&stopping);
    let path = executable.clone();
    let (sent, received) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = helper::session(server, &mut companion, &path, &stop);
        drop(companion);
        sent.send(result).unwrap();
    });
    let start = protocol::Start {
        target: protocol::Target::Screen { display_id: 1 },
        size: protocol::Size {
            width: 512,
            height: 512,
            canvas_width: 512.0,
            canvas_height: 512.0,
            backing_scale: 1.0,
        },
    };
    protocol::write(
        &mut client,
        protocol::Kind::Start,
        &serde_json::to_vec(&start).unwrap(),
    )
    .unwrap();
    let ready = executable.with_extension("py.ready");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // These are the same operations performed by the standalone signal handler.
    stopping.store(true, Ordering::Release);
    client.shutdown(Shutdown::Both).unwrap();
    let completed = received.recv_timeout(Duration::from_secs(1));
    worker.join().unwrap();
    let was_ready = ready.exists();
    fs::remove_dir_all(&dir).unwrap();
    assert!(
        was_ready,
        "encoder fixture did not reach its blocked pixel write"
    );
    assert!(
        completed.is_ok(),
        "signal stop waited on a blocked capture worker"
    );
}
