//! The short-lived root relay of a root upgrade (D376, #399): runs the server's install steps as root.
//!
//! [`crate::privilege_elevate`] starts this with the person's password, as
//! `infraternal __privilege-relay --socket <path> --uid <uid> --dir <dir>`,
//! from a digest-checked copy of the binary. It is the only thing a root
//! upgrade runs as root before the root infraternal agent itself, so it is
//! deliberately small:
//!
//! - It first reads a one-time token from its terminal, typed there by the
//!   rootless infraternal agent that started it (never in argv). It connects
//!   to that agent's socket and to nothing else, refuses unless the socket,
//!   its directory and the process listening on it all belong to `--uid`,
//!   and then refuses unless the first frame on it is that same token
//!   (J415 B5). Another process of the same account could swap the socket,
//!   but it can't read the agent's terminal where ptrace is restricted.
//! - It runs only what arrives in [`Frame::Open`]: the server's root install
//!   steps (the same scripts a root Add host runs over SSH), each under
//!   `/bin/sh -c` with an empty environment, in its own process group.
//! - It keeps the server's [`Frame::Rollback`] script and runs it itself
//!   whenever the upgrade ends without a [`Frame::Commit`]: on `Close`, end
//!   of input, a protocol error or after [`LIFETIME`] (J415 R4). It stops
//!   every step first, and the script takes the install's own setup lock.
//!   So a lost link, a server restart or a killed rootless agent puts the
//!   host back as it was (D376), instead of leaving a half-installed root
//!   service behind.
//! - It blocks `SIGHUP`: the terminal it was started on closes when the
//!   rootless agent lets go of it, and that must not skip the rollback. Its
//!   end is the socket's end (J415 B6). `--dir` (its own copy of the
//!   binary) is removed when it exits.
//!
//! It never sees the password: that was typed to sudo, doas or su before
//! this process existed.
use infraternal_plugin_remote::privilege_relay::{
    Decoder, Frame, MAX_CHANNELS, MAX_CHUNK, MAX_STDERR,
};
use std::{
    collections::HashMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use zeroize::Zeroizing;

/// The longest a relay lives. An upgrade takes seconds to a minute; this is a
/// hang guard so a lost server can't leave a root process behind.
pub const LIFETIME: Duration = Duration::from_mins(15);
/// The hidden command word.
pub const COMMAND: &str = "__privilege-relay";

/// Run the relay when this process was started as one; `None` otherwise.
///
/// The arguments must be exactly `__privilege-relay --socket <path> --uid
/// <uid> --dir <dir>`, and the process must be root.
#[must_use]
pub fn run_if_requested() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(COMMAND) {
        return None;
    }
    let parsed = match &args[1..] {
        [s, socket, u, uid, d, dir] if s == "--socket" && u == "--uid" && d == "--dir" => uid
            .parse::<u32>()
            .ok()
            .map(|uid| (PathBuf::from(socket), uid, PathBuf::from(dir))),
        _ => None,
    };
    let Some((socket, uid, dir)) = parsed else {
        return Some(ExitCode::from(2));
    };
    if !nix::unistd::Uid::effective().is_root() || uid == 0 {
        return Some(ExitCode::from(2));
    }
    // The terminal closing must not stop the rollback (see the module docs):
    // SIGHUP stays blocked (pending, never delivered) for the relay's life.
    // Blocking needs no handler code, so no unsafe; threads and the steps the
    // relay starts inherit the mask.
    let mut hangup = nix::sys::signal::SigSet::empty();
    hangup.add(nix::sys::signal::Signal::SIGHUP);
    if hangup.thread_block().is_err() {
        return Some(ExitCode::from(2));
    }
    let _cleanup = RemoveOnDrop(dir);
    let Some(token) = read_token(TOKEN_WAIT) else {
        return Some(ExitCode::from(2));
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Some(ExitCode::FAILURE);
    };
    let result = runtime.block_on(async {
        let stream = connect(&socket, uid).await?;
        let (reader, writer) = stream.into_split();
        serve(reader, writer, &token, LIFETIME).await
    });
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// How long the relay waits for its token on its terminal.
const TOKEN_WAIT: Duration = Duration::from_secs(10);
/// How long the rollback script may run.
const ROLLBACK_BOUND: Duration = Duration::from_mins(2);
/// Most stdin chunks queued per step before the relay stops that step: a
/// step that stops reading its stdin must not stall the frame loop (B4).
const STDIN_QUEUE: usize = 16;

/// Read the one-time token from stdin (the terminal the agent types it
/// to): 64 lowercase hex digits and a newline, within `wait`. Then point
/// stdin at `/dev/null`, so the terminal is no longer read.
fn read_token(wait: Duration) -> Option<Zeroizing<[u8; 32]>> {
    use std::os::fd::AsFd as _;
    let stdin = std::io::stdin();
    let deadline = std::time::Instant::now() + wait;
    let mut line = Zeroizing::new(Vec::with_capacity(65));
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") && line.len() <= 65 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let millis = u16::try_from(left.as_millis()).unwrap_or(u16::MAX);
        if millis == 0 {
            return None;
        }
        let mut fds = [nix::poll::PollFd::new(
            stdin.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        if nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(millis)).ok()? == 0 {
            continue;
        }
        match nix::unistd::read(stdin.as_fd(), &mut byte) {
            Ok(1) => line.push(byte[0]),
            _ => return None,
        }
    }
    if let Ok(null) = std::fs::File::open("/dev/null") {
        let _ = nix::unistd::dup2_stdin(null);
    }
    let mut text: &[u8] = line.strip_suffix(b"\n")?;
    if let Some(trimmed) = text.strip_suffix(b"\r") {
        text = trimmed;
    }
    if text.len() != 64 {
        return None;
    }
    let mut token = Zeroizing::new([0u8; 32]);
    for (slot, pair) in token.iter_mut().zip(text.chunks(2)) {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(token)
}

/// Removes the relay's private directory (its binary copy) when it ends.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    /// Removes the directory, but only one the snippet could have made.
    fn drop(&mut self) {
        // Only the directory the snippet made: a fresh root-owned one under /run.
        if self.0.starts_with("/run")
            && self
                .0
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("infraternal-privilege."))
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Connect to the account's socket, checking that the socket file, its
/// directory and the process behind it all belong to `uid`.
async fn connect(socket: &Path, uid: u32) -> std::io::Result<tokio::net::UnixStream> {
    let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let parent = socket.parent().ok_or_else(denied)?;
    let directory = std::fs::symlink_metadata(parent)?;
    let file = std::fs::symlink_metadata(socket)?;
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
        || file.uid() != uid
    {
        return Err(denied());
    }
    let stream = tokio::net::UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    Ok(stream)
}

/// One running install step.
struct Channel {
    /// Where its stdin bytes go; dropping it closes the script's stdin.
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    /// Its process group, to kill it.
    group: Option<nix::unistd::Pid>,
}

/// Serve the relay protocol on `reader`/`writer` until it ends.
///
/// The first frame must be [`Frame::Token`] carrying `token`, or nothing
/// runs. Then it sends [`Frame::Ready`]. The server's [`Frame::Rollback`]
/// must come before any `Open`. Each `Open` runs its script as this process
/// (root, in production) under `/bin/sh -c`, with the environment cleared
/// apart from `PATH`, `HOME` and the `C` locale, in its own process group.
/// Its stdout is forwarded whole and its stderr up to [`MAX_STDERR`] bytes,
/// the same bound the server keeps of an SSH command's stderr.
///
/// It ends on `Close`, end of input, a protocol error or `lifetime`. Every
/// step still running is killed; then, unless `Commit` came first, the
/// rollback script runs (see the module docs).
///
/// # Errors
/// The stream broke or carried something that is not relay protocol (the
/// rollback has run by then).
pub async fn serve(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin + Send + 'static,
    token: &[u8; 32],
    lifetime: Duration,
) -> std::io::Result<()> {
    let (out, mut outgoing) = mpsc::channel::<Frame>(64);
    let write = tokio::spawn(async move {
        let mut bytes = Vec::new();
        while let Some(frame) = outgoing.recv().await {
            bytes.clear();
            frame.encode(&mut bytes);
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    let mut rollback: Option<Zeroizing<String>> = None;
    let mut committed = false;
    let mut authenticated = false;
    let mut decoder = Decoder::default();
    let mut buffer = vec![0; 64 << 10];
    let deadline = tokio::time::sleep(lifetime);
    tokio::pin!(deadline);
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let result = 'serve: loop {
        let read = tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(read) => read,
                Err(error) => break 'serve Err(error),
            },
            () = &mut deadline => break 'serve Ok(()),
        };
        if read == 0 {
            break Ok(());
        }
        decoder.push(&buffer[..read]);
        loop {
            let frame = match decoder.frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => break 'serve Err(invalid()),
            };
            if !authenticated {
                // B5: the listener must prove it is the agent that typed the token.
                match frame {
                    Frame::Token { bytes } if constant_time_eq(&bytes, token) => {
                        authenticated = true;
                        let _ = out.send(Frame::Ready).await;
                        continue;
                    }
                    _ => break 'serve Err(std::io::ErrorKind::PermissionDenied.into()),
                }
            }
            match frame {
                Frame::Rollback { script } if rollback.is_none() => {
                    rollback = Some(Zeroizing::new(script));
                }
                Frame::Open { channel, script } => {
                    channels.retain(|_, open| open.group.is_some_and(alive));
                    if rollback.is_none()
                        || channels.len() >= MAX_CHANNELS
                        || channels.contains_key(&channel)
                    {
                        let _ = out
                            .send(Frame::Exit {
                                channel,
                                code: None,
                            })
                            .await;
                        continue;
                    }
                    channels.insert(channel, open(channel, &script, out.clone()));
                }
                Frame::Stdin { channel, bytes } => {
                    // Never wait on a step's stdin here: a step that stops
                    // reading would stall Kill and Close for every step (B4).
                    // A full queue stops that step instead.
                    let stuck = channels
                        .get(&channel)
                        .and_then(|open| open.stdin.as_ref())
                        .is_some_and(|stdin| stdin.try_send(bytes).is_err());
                    if stuck
                        && let Some(group) = channels.remove(&channel).and_then(|open| open.group)
                    {
                        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                    }
                }
                Frame::StdinEnd { channel } => {
                    if let Some(open) = channels.get_mut(&channel) {
                        open.stdin = None;
                    }
                }
                Frame::Kill { channel } => {
                    if let Some(group) = channels.remove(&channel).and_then(|open| open.group) {
                        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                    }
                }
                Frame::Commit => committed = true,
                Frame::Close => break 'serve Ok(()),
                // A second token or rollback, or a frame only the relay
                // sends, is a protocol error.
                Frame::Token { .. }
                | Frame::Rollback { .. }
                | Frame::Stdout { .. }
                | Frame::Stderr { .. }
                | Frame::Exit { .. }
                | Frame::Ready => break 'serve Err(invalid()),
            }
        }
    };
    for open in channels.into_values() {
        if let Some(group) = open.group {
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        }
    }
    if !committed && let Some(script) = rollback {
        run_rollback(&script).await;
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), write).await;
    result
}

/// Equal without an early exit on the first differing byte.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Run the rollback script as the steps run, with no stdin or output, in
/// its own process group, killed after [`ROLLBACK_BOUND`].
async fn run_rollback(script: &str) {
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(nix::unistd::Pid::from_raw);
    if tokio::time::timeout(ROLLBACK_BOUND, child.wait())
        .await
        .is_err()
        && let Some(group) = group
    {
        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
    }
}

/// The process group `group` still has a leader.
fn alive(group: nix::unistd::Pid) -> bool {
    nix::sys::signal::kill(group, None).is_ok()
}

/// Start one script and the tasks that carry its stdin, stdout and exit.
fn open(channel: u32, script: &str, out: mpsc::Sender<Frame>) -> Channel {
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        tokio::spawn(async move {
            out.send(Frame::Exit {
                channel,
                code: None,
            })
            .await
        });
        return Channel {
            stdin: None,
            group: None,
        };
    };
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(nix::unistd::Pid::from_raw);
    let (stdin, mut queued) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);
    if let Some(mut pipe) = child.stdin.take() {
        tokio::spawn(async move {
            while let Some(bytes) = queued.recv().await {
                if pipe.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            // Dropping the pipe closes the script's stdin.
        });
    }
    let mut stdout = child.stdout.take();
    let stderr = child.stderr.take().map(|mut pipe| {
        let out = out.clone();
        tokio::spawn(async move {
            // Forward the first MAX_STDERR bytes, then drain the rest unread
            // so the script never blocks on a full pipe.
            let mut chunk = vec![0; MAX_STDERR];
            let mut sent = 0;
            loop {
                match pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let keep = read.min(MAX_STDERR - sent);
                        if keep > 0 {
                            sent += keep;
                            let _ = out
                                .send(Frame::Stderr {
                                    channel,
                                    bytes: chunk[..keep].to_vec(),
                                })
                                .await;
                        }
                    }
                }
            }
        })
    });
    tokio::spawn(async move {
        if let Some(pipe) = stdout.as_mut() {
            let mut chunk = vec![0; MAX_CHUNK];
            loop {
                match pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if out
                            .send(Frame::Stdout {
                                channel,
                                bytes: chunk[..read].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
        if let Some(stderr) = stderr {
            // Stderr is complete before the exit is reported.
            let _ = stderr.await;
        }
        let code = child
            .wait()
            .await
            .ok()
            .and_then(|status| status.code())
            .and_then(|code| u8::try_from(code).ok());
        let _ = out.send(Frame::Exit { channel, code }).await;
    });
    Channel {
        stdin: Some(stdin),
        group,
    }
}

#[cfg(test)]
mod tests {
    //! The relay runs scripts with their stdin and reports stdout and exit codes.
    use super::*;

    /// Drive `serve` over an in-memory pipe: send `frames`, collect everything
    /// it answers until it ends.
    async fn exchange(frames: Vec<Frame>) -> Vec<Frame> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let relay =
            tokio::spawn(async move { serve(server_read, server_write, &TOKEN, LIFETIME).await });
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut bytes = Vec::new();
        Frame::Token { bytes: TOKEN }.encode(&mut bytes);
        Frame::Rollback {
            script: "true".into(),
        }
        .encode(&mut bytes);
        for frame in &frames {
            frame.encode(&mut bytes);
        }
        let mut decoder = Decoder::default();
        let mut seen = Vec::new();
        client_write.write_all(&bytes).await.unwrap();
        let mut buffer = vec![0; 1 << 16];
        let expected_exits = frames
            .iter()
            .filter(|frame| matches!(frame, Frame::Open { .. }))
            .count();
        while seen
            .iter()
            .filter(|frame| matches!(frame, Frame::Exit { .. }))
            .count()
            < expected_exits
        {
            let read = client_read.read(&mut buffer).await.unwrap();
            assert!(read > 0, "relay ended early: {seen:?}");
            decoder.push(&buffer[..read]);
            while let Some(frame) = decoder.frame().unwrap() {
                seen.push(frame);
            }
        }
        let mut close = Vec::new();
        Frame::Close.encode(&mut close);
        client_write.write_all(&close).await.unwrap();
        relay.await.unwrap().unwrap();
        seen
    }

    /// Joined stdout of `channel`.
    fn stdout(frames: &[Frame], channel: u32) -> Vec<u8> {
        frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stdout { channel: c, bytes } if *c == channel => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Ready comes first; a script reads its stdin and its exit code comes back.
    #[tokio::test]
    async fn a_script_gets_its_stdin_and_reports_output_and_exit() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 1,
                script: "read line; printf 'got %s' \"$line\"; exit 7".into(),
            },
            Frame::Stdin {
                channel: 1,
                bytes: b"hello\n".to_vec(),
            },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(seen[0], Frame::Ready);
        assert_eq!(stdout(&seen, 1), b"got hello");
        assert!(
            seen.contains(&Frame::Exit {
                channel: 1,
                code: Some(7)
            }),
            "{seen:?}"
        );
    }

    /// The environment is empty apart from PATH, HOME and the C locale, and
    /// stderr comes back on its own frames, bounded.
    #[tokio::test]
    async fn scripts_run_with_a_clean_environment_and_no_stderr() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 2,
                script: "env | sort | tr '\\n' ' '; echo refused >&2; head -c 20000 /dev/zero >&2"
                    .into(),
            },
            Frame::StdinEnd { channel: 2 },
        ])
        .await;
        let text = String::from_utf8(stdout(&seen, 2)).unwrap();
        let names: Vec<&str> = text
            .split_whitespace()
            .map(|pair| pair.split('=').next().unwrap())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| ["HOME", "LANG", "LC_ALL", "PATH", "PWD", "SHLVL", "_"].contains(name)),
            "{text}"
        );
        assert!(!text.contains("refused"));
        let errors: Vec<u8> = seen
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stderr { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(errors.starts_with(b"refused\n"));
        assert_eq!(errors.len(), MAX_STDERR);
    }

    /// Two scripts run side by side on separate channels.
    #[tokio::test]
    async fn channels_are_independent() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 1,
                script: "cat".into(),
            },
            Frame::Open {
                channel: 2,
                script: "printf two".into(),
            },
            Frame::StdinEnd { channel: 2 },
            Frame::Stdin {
                channel: 1,
                bytes: b"one".to_vec(),
            },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(stdout(&seen, 1), b"one");
        assert_eq!(stdout(&seen, 2), b"two");
    }

    /// The token the tests' "agent" typed.
    const TOKEN: [u8; 32] = [5; 32];

    /// Send `frames` to a relay with `token`, then end the input (or not,
    /// with `hold`), and return how `serve` ended. `lifetime` bounds it.
    /// The frames are written while the relay runs, so a large input can't
    /// deadlock on the pipe's buffer.
    async fn run(
        frames: Vec<Frame>,
        token: [u8; 32],
        lifetime: Duration,
        hold: bool,
    ) -> std::io::Result<()> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        // Drain the relay's answers so it never blocks on a full pipe.
        tokio::spawn(async move {
            let mut sink = vec![0; 1 << 16];
            while client_read.read(&mut sink).await.is_ok_and(|read| read > 0) {}
        });
        let writer = tokio::spawn(async move {
            let mut bytes = Vec::new();
            for frame in &frames {
                frame.encode(&mut bytes);
            }
            // The relay may stop reading early (a refused token); that's fine.
            let _ = client_write.write_all(&bytes).await;
            if hold {
                // Keep the input open: the relay must end by itself.
                std::future::pending::<()>().await;
            }
            // End of input: the link is gone.
            let _ = client_write.shutdown().await;
        });
        let result = serve(server_read, server_write, &token, lifetime).await;
        writer.abort();
        result
    }

    /// A scratch directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        /// A fresh one under the system temp directory.
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("relay-test-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        /// Its path.
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fresh scratch directory, and the rollback script that marks it.
    fn marker() -> (Scratch, String) {
        let dir = Scratch::new();
        let script = format!("touch '{}/rolled-back'", dir.path().display());
        (dir, script)
    }

    /// A frame only the relay may send ends the relay with an error.
    #[tokio::test]
    async fn a_relay_only_frame_from_the_server_is_refused() {
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Exit {
                channel: 1,
                code: Some(0),
            },
        ];
        assert!(run(frames, TOKEN, LIFETIME, false).await.is_err());
    }

    /// B5: without the typed token first, nothing runs and no rollback is
    /// even accepted.
    #[tokio::test]
    async fn a_socket_without_the_token_runs_nothing() {
        let (dir, script) = marker();
        let ran = dir.path().join("ran");
        let frames = vec![
            Frame::Token { bytes: [6; 32] },
            Frame::Rollback { script },
            Frame::Open {
                channel: 1,
                script: format!("touch '{}'", ran.display()),
            },
        ];
        assert!(run(frames, TOKEN, LIFETIME, false).await.is_err());
        assert!(!ran.exists());
        assert!(!dir.path().join("rolled-back").exists());
    }

    /// R4 / B1: losing the link (end of input) without a commit runs the
    /// rollback, after the running steps were stopped.
    #[tokio::test]
    async fn a_lost_link_rolls_the_host_back() {
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback { script },
            Frame::Open {
                channel: 1,
                script: "sleep 600".into(),
            },
        ];
        run(frames, TOKEN, LIFETIME, false).await.unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }

    /// R4: a Close without a commit rolls back too; after Commit it doesn't.
    #[tokio::test]
    async fn only_a_commit_skips_the_rollback() {
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                script: script.clone(),
            },
            Frame::Close,
        ];
        run(frames, TOKEN, LIFETIME, true).await.unwrap();
        assert!(dir.path().join("rolled-back").exists());
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback { script },
            Frame::Commit,
            Frame::Close,
        ];
        run(frames, TOKEN, LIFETIME, true).await.unwrap();
        assert!(!dir.path().join("rolled-back").exists());
    }

    /// R4: the lifetime ends a relay whose server went silent, and rolls back.
    #[tokio::test]
    async fn the_lifetime_rolls_back_a_silent_upgrade() {
        let (dir, script) = marker();
        let frames = vec![Frame::Token { bytes: TOKEN }, Frame::Rollback { script }];
        run(frames, TOKEN, Duration::from_millis(300), true)
            .await
            .unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }

    /// R4: a step is refused until the rollback script is known.
    #[tokio::test]
    async fn no_step_runs_before_the_rollback_is_known() {
        let dir = Scratch::new();
        let ran = dir.path().join("ran");
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Open {
                channel: 1,
                script: format!("touch '{}'", ran.display()),
            },
        ];
        run(frames, TOKEN, LIFETIME, false).await.unwrap();
        assert!(!ran.exists());
    }

    /// B4: a step that never reads its stdin doesn't stall the frame loop;
    /// a later Close is still served (and rolls back).
    #[tokio::test]
    async fn a_step_that_stops_reading_does_not_stall_close() {
        let (dir, script) = marker();
        let mut frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback { script },
            Frame::Open {
                channel: 1,
                script: "sleep 600".into(),
            },
        ];
        for _ in 0..64 {
            frames.push(Frame::Stdin {
                channel: 1,
                bytes: vec![0; MAX_CHUNK],
            });
        }
        frames.push(Frame::Close);
        tokio::time::timeout(Duration::from_secs(20), run(frames, TOKEN, LIFETIME, true))
            .await
            .expect("Close was served")
            .unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }
}
