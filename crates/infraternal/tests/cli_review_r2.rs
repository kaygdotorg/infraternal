//! Round-2 break-it review of the CLI overhaul (#239, D299, D303): the fixes for round 1.
//!
//! Each test states the contract and FAILS on the reviewed head (73661530), so the failure is
//! the finding. Nothing here changes the machine: a throw-away HOME, a fake local socket, and
//! option values that fail before any network call.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    os::fd::AsFd,
    os::unix::{fs::PermissionsExt, net::UnixListener, process::CommandExt},
    process::{Command, Output, Stdio},
    time::Duration,
};

use nix::poll::{PollFd, PollFlags, poll};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_infraternal");

fn home(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cli-review-r2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn private_state(home: &std::path::Path) -> std::path::PathBuf {
    let state = home.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    state
}

fn cli(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .output()
        .expect("run the real CLI")
}

/// Exactly one JSON line on stdout, or a panic that shows what was there.
fn one_envelope(args: &[&str], output: &Output) -> Value {
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "{args:?}: want one envelope, stdout was {text:?}"
    );
    serde_json::from_str(lines[0])
        .unwrap_or_else(|_| panic!("{args:?}: not JSON: {:.200}", lines[0]))
}

/// A local stand-in for the infraternal agent's plugin socket: one connection per reply, each
/// answered with a successful `Result` frame (stream 0, type 0x31, call 1) carrying `reply`.
fn fake_agent(state: &std::path::Path, replies: Vec<Value>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(state.join("plugins.sock")).unwrap();
    std::thread::spawn(move || {
        for reply in replies {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request);
            let json = serde_json::to_vec(&reply).unwrap();
            let mut body = vec![0x31, 1, 0, 0, 0, 1];
            body.extend_from_slice(&json);
            let mut wire = vec![0_u8]; // stream id 0
            let mut length = u32::try_from(body.len()).unwrap();
            while length >= 0x80 {
                wire.push(u8::try_from(length & 0x7f).unwrap() | 0x80);
                length >>= 7;
            }
            wire.push(u8::try_from(length).unwrap());
            wire.extend_from_slice(&body);
            let _ = socket.write_all(&wire);
        }
    })
}

fn mesh_peer(node: u64) -> Value {
    json!({
        "node": node,
        "peer": {
            "addresses": {"ipv4": format!("100.64.0.{node}")},
            "endpoint": null,
            "key": vec![1; 32],
        },
        "path": "Direct",
        "counters": {
            "received_bytes": 0,
            "sent_bytes": 0,
            "handshake_secs": 0,
        },
    })
}

// ---- one envelope (D299) ---------------------------------------------------------------

#[test]
fn help_and_version_under_json_are_one_envelope_and_exit_0() {
    // Round 1 tested `--json --help` and `status --help --json` by their first line only.
    let home = home("help-version");
    for args in [
        &["--json", "-V"][..],
        &["--json", "--version"],
        &["--json", "-h"],
        &["status", "-h", "--json"],
        &["mesh", "--help", "--json"],
    ] {
        let output = cli(&home, args);
        let envelope = one_envelope(args, &output);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert_eq!(envelope["ok"], true, "{args:?}: {envelope}");
    }
}

#[test]
fn usage_errors_under_json_are_one_envelope_and_exit_2() {
    let home = home("usage");
    for args in [
        &["--json", "--bogus"][..],
        &["--json", "no-such-command"],
        &["--json", "remove-host"],
        &["--json", "mesh", "status", "--state"],
        &["--json", "agent", "join"],
    ] {
        let output = cli(&home, args);
        let envelope = one_envelope(args, &output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {envelope}");
        assert_eq!(envelope["error"]["code"], "usage", "{args:?}: {envelope}");
    }
}

#[test]
fn a_paged_listing_is_still_one_envelope() {
    // A script must see one result after the page set is complete, with every peer in its data.
    let home = home("pages");
    let state = private_state(&home);
    let agent = fake_agent(
        &state,
        vec![
            json!({"peers": [mesh_peer(7)], "version": 1, "next_cursor": {"version": 1, "node": 7}}),
            json!({"peers": [mesh_peer(8)], "version": 1, "next_cursor": null}),
        ],
    );
    let args = [
        "--json",
        "mesh",
        "peers",
        "--state",
        state.to_str().unwrap(),
    ];
    let output = cli(&home, &args);
    let _ = agent.join();
    let envelope = one_envelope(&args, &output);
    assert_eq!(envelope["data"]["peers"].as_array().map(Vec::len), Some(2));
}

#[test]
fn a_failed_later_page_emits_only_the_failure_envelope() {
    // Discard accumulated rows when a later reply cannot be presented. The first page must
    // never report success for an incomplete listing (#239, D299).
    let home = home("failed-later-page");
    let state = private_state(&home);
    let agent = fake_agent(
        &state,
        vec![
            json!({"peers": [mesh_peer(7)], "version": 1, "next_cursor": {"version": 1, "node": 7}}),
            json!({"peers": "unexpected input", "version": 1, "next_cursor": null}),
        ],
    );
    let args = [
        "--json",
        "mesh",
        "peers",
        "--state",
        state.to_str().unwrap(),
    ];
    let output = cli(&home, &args);
    agent.join().unwrap();
    let envelope = one_envelope(&args, &output);
    assert_eq!(output.status.code(), Some(1), "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert!(envelope["data"]["peers"].is_null(), "{envelope}");
}

#[test]
fn three_pages_preserve_order_and_only_the_final_cursor() {
    let home = home("three-pages");
    let state = private_state(&home);
    let agent = fake_agent(
        &state,
        vec![
            json!({"peers": [mesh_peer(7)], "version": 1, "next_cursor": {"version": 1, "node": 7}}),
            json!({"peers": [mesh_peer(8)], "version": 1, "next_cursor": {"version": 1, "node": 8}}),
            json!({"peers": [mesh_peer(9)], "version": 1, "next_cursor": null}),
        ],
    );
    let args = [
        "--json",
        "mesh",
        "peers",
        "--state",
        state.to_str().unwrap(),
    ];
    let output = cli(&home, &args);
    agent.join().unwrap();
    let envelope = one_envelope(&args, &output);
    assert_eq!(output.status.code(), Some(0), "{envelope}");
    let nodes: Vec<_> = envelope["data"]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|peer| peer["node"].as_u64().unwrap())
        .collect();
    assert_eq!(nodes, [7, 8, 9]);
    assert!(envelope["data"]["next_cursor"].is_null(), "{envelope}");
}

// ---- Ctrl-C (D303/D305: 130 through the shell) -----------------------------------------

/// Interrupt the CLI while its JSON result is blocked, and require at most one valid line.
#[test]
fn ctrl_c_while_the_result_is_being_written_never_leaves_a_broken_line() {
    // The interrupt handler writes its envelope with no regard to what the main thread is in the
    // middle of. A reader that is slower than the CLI (a pipe that is full) shows the race
    // deterministically: half the real envelope, then the `interrupted` one glued onto it.
    let home = home("sigint-race");
    let (mut reader, writer) = std::io::pipe().unwrap();
    // The smallest pipe the kernel allows; the skill envelope for `server init` is ~5 KiB.
    let resized = nix::fcntl::fcntl(&writer, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
    assert!(resized >= 4096);
    let mut command = Command::new(BIN);
    command
        .args(["skill", "server", "init", "--json"])
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::null());
    // A package run started in the background inherits SIG_IGN. This fixture
    // represents a foreground command, so restore the normal child signal state.
    infraternal_shim::prepare_child(&mut command);
    let mut child = command.spawn().unwrap();
    drop(command);
    // Observing output proves startup completed. The four-KiB pipe cannot hold
    // the whole envelope, so the writer remains blocked while the interrupt lands.
    let mut ready = [PollFd::new(reader.as_fd(), PollFlags::POLLIN)];
    assert_eq!(poll(&mut ready, 5000_u16).unwrap(), 1, "no CLI output");
    let mut prefix = [0_u8; 1];
    reader.read_exact(&mut prefix).unwrap();
    assert!(
        child.try_wait().unwrap().is_none(),
        "the envelope fit in 4 KiB; use a bigger one"
    );
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let mut out = String::from(char::from(prefix[0]));
    reader.read_to_string(&mut out).unwrap();
    child.wait().unwrap();
    for line in out.lines() {
        assert!(
            serde_json::from_str::<Value>(line).is_ok(),
            "stdout carries a line that is not JSON ({} bytes): ...{}",
            line.len(),
            &line[line.len().saturating_sub(160)..]
        );
    }
    assert!(out.lines().count() <= 1, "two envelopes: {out:.300}");
}

/// Interrupt the CLI only after its request proves it has reached the waiting state.
#[test]
fn ctrl_c_in_a_script_loop_stops_the_loop() {
    // `_exit(130)` makes the shell believe the command handled Ctrl-C itself, so a loop in the
    // script that ran it goes on to the next machine. Dying by SIGINT (restore the default
    // action, raise it again) still reports $? = 130 and lets the script stop.
    let home = home("sigint-loop");
    let state = private_state(&home);
    // Accepts the call and never answers, so `mesh status` waits.
    let listener = UnixListener::bind(state.join("plugins.sock")).unwrap();
    let script = format!(
        "{BIN} --json mesh status --state {} >/dev/null; echo carried-on",
        state.display()
    );
    let mut command = Command::new("bash");
    command
        .args(["-c", &script])
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    // A background package runner can pass SIG_IGN to the shell. Model a
    // foreground script so its shell and CLI receive the group interrupt.
    infraternal_shim::prepare_child(&mut command);
    let mut child = command.spawn().unwrap();
    drop(command);
    let group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    // Receiving the request proves the CLI has started and installed its handler.
    let mut incoming = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    assert_eq!(poll(&mut incoming, 5000_u16).unwrap(), 1, "no CLI request");
    let (mut request, _) = listener.accept().unwrap();
    request
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    request.read_exact(&mut [0_u8; 1]).unwrap();
    // Ctrl-C at a terminal signals the whole foreground group: the shell and the CLI.
    nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGINT).unwrap();
    // The shell closes its output only after it exits; this bounds completion
    // without polling or relying on a startup delay.
    let mut completed = [PollFd::new(
        child.stdout.as_ref().unwrap().as_fd(),
        PollFlags::POLLHUP,
    )];
    assert_eq!(
        poll(&mut completed, 5000_u16).unwrap(),
        1,
        "still running after SIGINT"
    );
    let status = child.wait().unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(
        !out.contains("carried-on"),
        "the script carried on after Ctrl-C (shell status {status:?})"
    );
}

#[test]
fn a_later_runtime_handler_is_not_bypassed_by_the_interrupt_handler() {
    // pty.rs says "A later handler installed by a runtime replaces this one". The runtime's
    // signal registry chains to the handler it found and runs that one FIRST, so the process
    // `_exit`s before any graceful Ctrl-C path can run. Fixture: install the CLI handler, then
    // wait for Ctrl-C through the runtime, then raise SIGINT.
    const FIXTURE: &str = "INFRATERNAL_REVIEW_SIGINT_CHAIN";
    if std::env::var_os(FIXTURE).is_some() {
        infraternal_shim::exit_on_interrupt(b"{\"interrupted\":true}\n".to_vec());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let waiting = tokio::signal::ctrl_c();
            tokio::pin!(waiting);
            // Register the runtime handler before raising.
            let _ = tokio::time::timeout(Duration::from_millis(50), &mut waiting).await;
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT).unwrap();
            waiting.await.unwrap();
        });
        std::process::exit(42);
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_later_runtime_handler_is_not_bypassed_by_the_interrupt_handler",
            "--nocapture",
        ])
        .env(FIXTURE, "1")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(42),
        "the graceful path never ran: {:?}",
        output.status
    );
}

// ---- values are never echoed -----------------------------------------------------------

#[test]
fn an_unknown_skill_does_not_echo_what_was_typed() {
    // `skill <path>` puts the typed words, verbatim, in `details`.
    let home = home("skill-echo");
    let output = cli(
        &home,
        &[
            "skill",
            "https://user:SECRETTOKEN@example.invalid/x",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains("SECRETTOKEN"), "{all}");
}

#[test]
fn a_mistyped_word_that_looks_like_a_token_is_not_echoed() {
    // usage.rs echoes any lowercase word of up to 40 characters as "has no command <word>".
    // A hex token pasted in the wrong place is exactly such a word.
    let home = home("hex-echo");
    let token = "3f9a0c1d2b4e5f60718293a4b5c6d7e8f9012345";
    for json_flag in [true, false] {
        let mut args = vec![token];
        if json_flag {
            args.push("--json");
        }
        let output = cli(&home, &args);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains(token), "json={json_flag}: {all}");
    }
}

// ---- status: unknown is not down (D303) ------------------------------------------------

#[test]
fn status_text_does_not_call_an_unanswered_unit_not_running() {
    // The exit code was fixed to count only confirmed-down units, but the headline still uses
    // every non-active unit: one running unit plus one the manager did not answer for reads
    // "Part of this machine's setup is not running." with exit 0. Text and code disagree.
    let home = home("status-mixed");
    let units = home.join("config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    std::fs::write(
        units.join("infraternal-server.service"),
        "[Service]\nExecStart=/usr/bin/infraternal server\n",
    )
    .unwrap();
    std::fs::write(
        units.join("infraternal-agent.service"),
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    )
    .unwrap();
    // A service manager that answers for the server and fails for the infraternal agent.
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let manager = bin.join("systemctl");
    std::fs::write(
        &manager,
        "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in *server*) echo ActiveState=active ;; *) exit 1 ;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(BIN)
        .args(["status", "--json"])
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let envelope = one_envelope(&["status", "--json"], &output);
    assert_eq!(output.status.code(), Some(0), "{envelope}");
    assert!(
        !envelope["message"]
            .as_str()
            .unwrap_or("")
            .contains("not running"),
        "exit 0, yet the headline says something is not running: {envelope}"
    );
    assert!(
        envelope["message"]
            .as_str()
            .unwrap_or("")
            .contains("unknown"),
        "the headline does not name the unanswered status: {envelope}"
    );
}
