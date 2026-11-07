//! Exercise reserved descriptor collisions in disposable parent processes (#414).
use super::*;
use std::net::TcpListener;

/// Run descriptor-table mutations in a dedicated test process, never the parallel runner.
fn isolated(name: &str) -> bool {
    if std::env::var_os("INFRATERNAL_PROXY_FD_FIXTURE").is_some() {
        return false;
    }
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("pty::proxy_child_tests::{name}"),
                "--nocapture"
            ])
            .env("INFRATERNAL_PROXY_FD_FIXTURE", "1")
            .status()
            .unwrap()
            .success()
    );
    true
}

/// Pin a source to a reserved number before spawn, as a busy parent can allocate it.
fn at(file: &impl AsRawFd, target: i32) -> File {
    // SAFETY: only this disposable process uses the reserved slots; dup2 gives
    // the returned File sole ownership of a fresh duplicate of the borrowed fd.
    assert_ne!(file.as_raw_fd(), target);
    assert_eq!(unsafe { nix::libc::dup2(file.as_raw_fd(), target) }, target);
    assert_ne!(
        unsafe { nix::libc::fcntl(target, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) },
        -1
    );
    unsafe { File::from_raw_fd(target) }
}

/// A listener already at its destination must survive exec despite CLOEXEC.
#[test]
fn listener_at_fd64_survives_proxy_exec() {
    if isolated("listener_at_fd64_survives_proxy_exec") {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pinned = at(&listener, 64);
    let cwd = File::open("/").unwrap();
    let mut child = Command::new("/usr/bin/python3");
    child.args([
        "-c",
        &format!(
            "import socket; assert socket.socket(fileno=64).getsockname()[1] == {}",
            listener.local_addr().unwrap().port()
        ),
    ]);
    prepare_proxy_child(&mut child, &cwd, &[(pinned.as_raw_fd(), 64)], None, None).unwrap();
    assert!(child.status().unwrap().success());
}

/// Swapping listener slots must preserve both original open file descriptions.
#[test]
fn overlapping_proxy_mappings_preserve_both_listeners() {
    if isolated("overlapping_proxy_mappings_preserve_both_listeners") {
        return;
    }
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = at(&first, 64);
    let b = at(&second, 65);
    let cwd = File::open("/").unwrap();
    let mut child = Command::new("/usr/bin/python3");
    child.args(["-c", &format!("import socket; assert socket.socket(fileno=64).getsockname()[1] == {}; assert socket.socket(fileno=65).getsockname()[1] == {}", second.local_addr().unwrap().port(), first.local_addr().unwrap().port())]);
    prepare_proxy_child(
        &mut child,
        &cwd,
        &[(b.as_raw_fd(), 64), (a.as_raw_fd(), 65)],
        None,
        None,
    )
    .unwrap();
    assert!(child.status().unwrap().success());
}

/// Enter the pinned directory before its number becomes a listener destination.
#[test]
fn proxy_mapping_cannot_overwrite_the_pinned_cwd() {
    if isolated("proxy_mapping_cannot_overwrite_the_pinned_cwd") {
        return;
    }
    let directory = File::open("/").unwrap();
    let cwd = at(&directory, 64);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pinned = at(&listener, 65);
    let mut child = Command::new("/usr/bin/python3");
    child.args([
        "-c",
        "import os,socket; assert os.getcwd() == '/'; socket.socket(fileno=64).getsockname()",
    ]);
    prepare_proxy_child(&mut child, &cwd, &[(pinned.as_raw_fd(), 64)], None, None).unwrap();
    assert!(child.status().unwrap().success());
}

/// A free destination must not swallow Command's private exec-error pipe.
#[test]
fn proxy_mapping_preserves_spawn_errors_at_reserved_slots() {
    if isolated("proxy_mapping_preserves_spawn_errors_at_reserved_slots") {
        return;
    }
    let cwd = File::open("/").unwrap();
    let source = File::open("/dev/null").unwrap();
    let mut occupied = Vec::new();
    loop {
        let file = File::open("/dev/null").unwrap();
        let number = file.as_raw_fd();
        if number == 64 {
            drop(file);
            break;
        }
        assert!(number < 64);
        occupied.push(file);
    }
    // Without a reservation, Command's error pipe takes 64 and 65 and the
    // mapping swallows ENOENT. The production allocator must own the target.
    let pinned = reserve_proxy_descriptor(&source, 65).unwrap();
    assert_eq!(pinned.as_raw_fd(), 65);
    let mut child = Command::new("/infraternal-fd-fixture-missing");
    prepare_proxy_child(&mut child, &cwd, &[(pinned.as_raw_fd(), 65)], None, None).unwrap();
    let error = child
        .status()
        .expect_err("exec failure must reach the parent");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
}
