//! Real-pipe coverage for solicited control interleaved with unsolicited native-surface video [D203,D266].
#![cfg(all(feature = "desktop", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_desktop::protocol;
#[allow(dead_code)]
#[path = "../src/native.rs"]
mod native;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

#[test]
fn video_cannot_answer_a_solicited_surface_control_exchange() {
    let root =
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("use the job target directory"));
    let dir = root.join(format!("surface-pipe-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("native.py");
    fs::write(
        &path,
        r#"#!/usr/bin/env python3
# Role: interleave bounded video with source control replies over real inherited pipes.
import json, struct, sys
assert '--surface-capture' in sys.argv
def send(kind, body):
    sys.stdout.buffer.write(struct.pack('>IBB', len(body)+2, 1, kind)+body)
    sys.stdout.buffer.flush()
for phase in range(3):
    header = sys.stdin.buffer.read(6)
    length, version, kind = struct.unpack('>IBB', header)
    sys.stdin.buffer.read(length-2)
    if phase == 0:
        assert kind == 2
        send(66, b'{}')
        send(70, struct.pack('>QB', 1, 1)+b'first')
        send(70, struct.pack('>QB', 2, 0)+b'newest')
    elif phase == 1:
        assert kind == 6
        send(68, b'{"capture_ticks":3}')
    else:
        assert kind == 6
        send(70, struct.pack('>QB', 3, 0)+b'delta')
        send(70, struct.pack('>QB', 4, 1)+b'repaired')
        send(68, b'{"capture_ticks":4}')
sys.stdin.buffer.read()
"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = native::Native::spawn_surface(&path).unwrap();
    assert_eq!(
        child.call(protocol::Kind::Start, b"{}").unwrap().0,
        protocol::Kind::Geometry
    );
    let reply = child.call(protocol::Kind::Status, b"{}").unwrap();
    assert_eq!(
        reply,
        (protocol::Kind::State, br#"{"capture_ticks":3}"#.to_vec())
    );
    assert!(
        child.take_surface_gap(),
        "overwritten encoded frames must force decoder repair"
    );
    let video = child.surface_video().unwrap().unwrap();
    assert_eq!(&video[9..], b"newest");
    child.call(protocol::Kind::Status, b"{}").unwrap();
    assert!(
        !child.take_surface_gap(),
        "the newest IDR repairs discarded references"
    );
    assert_eq!(&child.surface_video().unwrap().unwrap()[9..], b"repaired");
    drop(child);
    fs::remove_dir_all(dir).unwrap();
}
