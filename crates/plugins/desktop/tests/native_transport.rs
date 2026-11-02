//! Measure responsive and nonreading native pipes at real concurrent scale; not Mac framework capacity [D203,#146].
#![cfg(all(feature = "desktop", target_os = "linux"))]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
use infraternal_plugin_desktop::protocol;
#[allow(dead_code)]
#[path = "../src/native.rs"]
mod native;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Barrier},
    time::Instant,
};
fn rss(pid: u32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .map(|value| value.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap_or(0)
}
#[test]
#[ignore = "Responsive native-pipe burst measurement at 1/10/50 companions; run alone"]
fn responsive_native_pipes_at_concurrent_scale() {
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(
            || std::path::PathBuf::from("target"),
            std::path::PathBuf::from,
        )
        .join(format!("desktop-pipe-responsive-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for count in [1, 10, 50] {
        let barrier = Arc::new(Barrier::new(count + 1));
        let finish = Arc::new(Barrier::new(count + 1));
        let mut pids = vec![];
        let mut threads = vec![];
        for index in 0..count {
            let path = root.join(format!("companion-{index}.py"));
            fs::write(
                &path,
                r"#!/usr/bin/env python3
# Role: drain complete native packets and send small framed acknowledgements.
import os, struct, sys
with open(sys.argv[0] + '.pid', 'w') as output:
    output.write(str(os.getpid()))
source=sys.stdin.buffer
sink=sys.stdout.buffer
while True:
    prefix=source.read(4)
    if len(prefix)!=4: break
    size,=struct.unpack('>I',prefix)
    body=source.read(size)
    if len(body)!=size: break
    kind=70 if body[1]==101 else 68
    payload=bytes(8)+b'\x01e' if kind==70 else b'{}'
    sink.write(struct.pack('>IBB',len(payload)+2,1,kind)+payload)
    sink.flush()
",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let mut companion = native::Native::spawn(&path).unwrap();
            companion.call(protocol::Kind::Status, b"{}").unwrap();
            let pid: u32 = fs::read_to_string(path.with_extension("py.pid"))
                .unwrap()
                .parse()
                .unwrap();
            pids.push(pid);
            let barrier = Arc::clone(&barrier);
            let finish = Arc::clone(&finish);
            threads.push(std::thread::spawn(move || {
                let pixels = vec![0; 512 * 512 * 4];
                companion.encode(&pixels, 512, 512, 1, true).unwrap();
                barrier.wait();
                let mut samples = vec![];
                for _ in 0..16 {
                    let begin = Instant::now();
                    let (kind, _) = companion.encode(&pixels, 512, 512, 1, true).unwrap();
                    assert_eq!(kind, protocol::Kind::Video);
                    samples.push(begin.elapsed().as_micros());
                }
                finish.wait();
                samples
            }));
        }
        barrier.wait();
        let holder_rss = rss(std::process::id());
        let child_rss: u64 = pids.iter().map(|pid| rss(*pid)).sum();
        finish.wait();
        let mut samples: Vec<_> = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect();
        samples.sort_unstable();
        println!(
            "METRIC sessions={count} samples={} pixel_bytes={} p50_us={} p95_us={} holder_rss_kib={holder_rss} companion_rss_kib={child_rss} load={}",
            samples.len(),
            512 * 512 * 4,
            samples[(samples.len() * 50).div_ceil(100) - 1],
            samples[(samples.len() * 95).div_ceil(100) - 1],
            fs::read_to_string("/proc/loadavg")
                .unwrap()
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "Native nonreading-pipe deadline at 1/10/50 companions; run alone"]
fn nonreading_native_pipes_at_concurrent_scale() {
    use std::time::Duration;
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(
            || std::path::PathBuf::from("target"),
            std::path::PathBuf::from,
        )
        .join(format!("desktop-pipe-nonreading-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("companion.py");
    fs::write(
        &path,
        r"#!/usr/bin/env python3
# Role: retain an open input pipe without draining it.
import signal
signal.pause()
",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    for count in [1, 10, 50] {
        let barrier = Arc::new(Barrier::new(count));
        let mut threads = vec![];
        for _ in 0..count {
            let mut child = native::Native::spawn(&path).unwrap();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let pixels = vec![0; 512 * 512 * 4];
                barrier.wait();
                let begin = Instant::now();
                let reply = child.encode(&pixels, 512, 512, 1, true);
                let elapsed = begin.elapsed();
                assert_eq!(reply.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
                drop(child);
                assert!(elapsed < Duration::from_secs(4));
                elapsed.as_micros()
            }));
        }
        let mut samples: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        samples.sort_unstable();
        println!(
            "METRIC sessions={count} completed={} pixel_bytes={} p50_us={} max_us={} load={}",
            samples.len(),
            512 * 512 * 4,
            samples[(samples.len() * 50).div_ceil(100) - 1],
            samples.last().unwrap(),
            fs::read_to_string("/proc/loadavg")
                .unwrap()
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
        );
    }
    fs::remove_dir_all(root).unwrap();
}
