//! Capture cancellation must release both native pipe writes and reply waits before worker joins [D203,#146].
#![cfg(feature = "desktop")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
use infraternal_plugin_desktop::protocol;
#[allow(dead_code)]
#[path = "../src/native.rs"]
mod native;

// A sibling fork can inherit another test's still-open executable writer until
// exec closes CLOEXEC descriptors. Publish and spawn under one lock, then release
// it before exercising cancellation/deadlines so those operations stay parallel.
static FIXTURE_PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cancelled_capture_releases_native_write_and_reply_waits() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    for mode in ["write", "reply", "clock"] {
        let publication = FIXTURE_PUBLICATION.lock().unwrap();
        let dir = root.join(format!(
            "desktop-native-cancel-{mode}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let executable = dir.join("native-fixture.py");
        let read = if mode == "write" {
            "source.read(1)"
        } else {
            "length, = struct.unpack('>I', source.read(4))\nsource.read(length)"
        };
        fs::write(&executable, format!("#!/usr/bin/env python3\n# Role: block at a known native write or reply boundary.\nimport signal, struct, sys\nsource = sys.stdin.buffer\n{read}\nwith open(sys.argv[0] + '.ready', 'w') as output:\n    output.write('ready')\nsignal.pause()\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut companion = native::Native::spawn(&executable).unwrap();
        drop(publication);
        let cancellation = Arc::new(AtomicBool::new(false));
        companion.cancel_on(Arc::clone(&cancellation));
        let (sent, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let reply = if mode == "clock" {
                companion.call(protocol::Kind::Status, b"{}")
            } else {
                companion.encode(&vec![0; 512 * 512 * 4], 512, 512, 1, true)
            };
            // Include the native owner's teardown in the completion proof.
            drop(companion);
            sent.send(reply).unwrap();
        });
        let ready = executable.with_extension("py.ready");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let started = Instant::now();
        cancellation.store(true, Ordering::Release);
        let completed = received.recv_timeout(Duration::from_secs(1));
        // A failed assertion still joins after the ordinary three-second deadline
        // and native retirement, so this fixture cannot leave a worker behind.
        worker.join().unwrap();
        let was_ready = ready.exists();
        fs::remove_dir_all(&dir).unwrap();
        assert!(was_ready, "fixture did not reach {mode} boundary");
        assert!(
            completed.is_ok(),
            "{mode} cancellation did not retire the native worker: {:?}",
            started.elapsed()
        );
        assert_eq!(
            completed.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
}

#[test]
fn slow_write_and_reply_share_one_operation_deadline() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{Duration, Instant},
    };
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    let publication = FIXTURE_PUBLICATION.lock().unwrap();
    let dir = root.join(format!("desktop-native-budget-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("native-fixture.py");
    fs::write(
        &executable,
        r"#!/usr/bin/env python3
# Role: delay both drain and reply; each delay alone fits the operation budget.
import struct, sys, time
time.sleep(1.7)
source = sys.stdin.buffer
length, = struct.unpack('>I', source.read(4))
source.read(length)
time.sleep(1.7)
payload = bytes(8) + b'\x01e'
sys.stdout.buffer.write(struct.pack('>IBB', len(payload)+2, 1, 70) + payload)
sys.stdout.buffer.flush()
",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut companion = native::Native::spawn(&executable).unwrap();
    drop(publication);
    let started = Instant::now();
    let reply = companion.encode(&vec![0; 512 * 512 * 4], 512, 512, 1, true);
    let elapsed = started.elapsed();
    drop(companion);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(reply.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(
        elapsed < Duration::from_secs(4),
        "write and reply exceeded their shared deadline: {elapsed:?}"
    );
}

#[test]
fn timed_out_control_companion_gets_eof_cleanup_before_retirement() {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    let publication = FIXTURE_PUBLICATION.lock().unwrap();
    let dir = root.join(format!("desktop-native-eof-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("native-fixture.py");
    fs::write(
        &executable,
        r"#!/usr/bin/env python3
# Role: acknowledge cleanup only after the controller closes its input.
import struct, sys
source = sys.stdin.buffer
length, = struct.unpack('>I', source.read(4))
source.read(length)
if source.read(4) == b'':
    with open(sys.argv[0] + '.restored', 'w') as output:
        output.write('restored')
",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut companion = native::Native::spawn(&executable).unwrap();
    drop(publication);
    let reply = companion.call(protocol::Kind::List, b"{}");
    // Drop joins retirement, so this assertion observes completed child cleanup.
    drop(companion);
    let restored = executable.with_extension("py.restored").exists();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(reply.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(
        restored,
        "timed-out control companion was stopped before its EOF cleanup"
    );
}
