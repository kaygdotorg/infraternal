//! The short-lived root relay of a root upgrade (D376, #399): runs the server's install steps as root.
//!
//! [`crate::privilege_elevate`] starts this with the person's password, as
//! `infraternal __privilege-relay --socket <path> --uid <uid> --dir <dir>`,
//! from a digest-checked copy of the binary. It is the only thing a root
//! upgrade runs as root before the root infraternal agent itself, so it is
//! deliberately small:
//!
//! - It connects to the rootless infraternal agent's socket and to nothing
//!   else, and refuses unless that socket, its directory and the process
//!   listening on it all belong to `--uid`, the account being upgraded.
//! - It runs only what arrives in [`Frame::Open`]: the server's root install
//!   steps (the same scripts a root Add host runs over SSH), each under
//!   `/bin/sh -c` with an empty environment, in its own process group.
//! - It stops on [`Frame::Close`], when the socket closes, when the terminal
//!   it was started on hangs up (the rootless infraternal agent went away),
//!   or after [`LIFETIME`], whichever comes first. Every script still running
//!   is killed, and `--dir` (its own copy of the binary) is removed.
//!
//! It never sees the password: that was typed to sudo, doas or su before
//! this process existed.
use infraternal_plugin_remote::privilege_relay::{Decoder, Frame, MAX_CHANNELS, MAX_CHUNK};
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

/// The longest a relay lives. An upgrade takes seconds to a minute; this is a
/// hang guard so a lost server can't leave a root process behind.
pub const LIFETIME: Duration = Duration::from_secs(15 * 60);
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
        [s, socket, u, uid, d, dir] if s == "--socket" && u == "--uid" && d == "--dir" => {
            uid.parse::<u32>().ok().map(|uid| (PathBuf::from(socket), uid, PathBuf::from(dir)))
        }
        _ => None,
    };
    let Some((socket, uid, dir)) = parsed else { return Some(ExitCode::from(2)) };
    if !nix::unistd::Uid::effective().is_root() || uid == 0 {
        return Some(ExitCode::from(2));
    }
    let _cleanup = RemoveOnDrop(dir);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return Some(ExitCode::FAILURE);
    };
    let result = runtime.block_on(async {
        let stream = connect(&socket, uid).await?;
        let (reader, writer) = stream.into_split();
        tokio::time::timeout(LIFETIME, serve(reader, writer)).await.unwrap_or(Ok(()))
    });
    Some(if result.is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Removes the relay's private directory (its binary copy) when it ends.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        // Only the directory the snippet made: a fresh root-owned one under /run.
        if self.0.starts_with("/run") && self.0.file_name().is_some_and(|name| name.to_string_lossy().starts_with("infraternal-privilege.")) {
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
    if !directory.is_dir() || directory.uid() != uid || directory.mode() & 0o077 != 0 || file.uid() != uid {
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
/// Sends [`Frame::Ready`] first. Each `Open` runs its script as this process
/// (root, in production) under `/bin/sh -c`, with the environment cleared
/// apart from `PATH`, `HOME` and the `C` locale, stderr discarded (install
/// steps report through stdout and their exit code, as over SSH), in its own
/// process group. Ends on `Close` or end of input, killing what still runs.
///
/// # Errors
/// The stream broke or carried something that is not relay protocol.
pub async fn serve(mut reader: impl AsyncRead + Unpin, mut writer: impl AsyncWrite + Unpin + Send + 'static) -> std::io::Result<()> {
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
    let _ = out.send(Frame::Ready).await;
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    let mut decoder = Decoder::default();
    let mut buffer = vec![0; 64 << 10];
    let result = 'serve: loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break Ok(());
        }
        decoder.push(&buffer[..read]);
        loop {
            let frame = match decoder.frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => break 'serve Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            };
            match frame {
                Frame::Open { channel, script } => {
                    channels.retain(|_, open| open.group.is_some_and(alive));
                    if channels.len() >= MAX_CHANNELS || channels.contains_key(&channel) {
                        let _ = out.send(Frame::Exit { channel, code: None }).await;
                        continue;
                    }
                    channels.insert(channel, open(channel, &script, out.clone()));
                }
                Frame::Stdin { channel, bytes } => {
                    if let Some(stdin) = channels.get(&channel).and_then(|open| open.stdin.as_ref()) {
                        let _ = stdin.send(bytes).await;
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
                Frame::Close => break 'serve Ok(()),
                // Frames only the relay sends are a protocol error from the server.
                Frame::Stdout { .. } | Frame::Exit { .. } | Frame::Ready => {
                    break 'serve Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
            }
        }
    };
    for open in channels.into_values() {
        if let Some(group) = open.group {
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        }
    }
    drop(out);
    let _ = write.await;
    result
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
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        tokio::spawn(async move { out.send(Frame::Exit { channel, code: None }).await });
        return Channel { stdin: None, group: None };
    };
    let group = child.id().and_then(|pid| i32::try_from(pid).ok()).map(nix::unistd::Pid::from_raw);
    let (stdin, mut queued) = mpsc::channel::<Vec<u8>>(16);
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
    tokio::spawn(async move {
        if let Some(pipe) = stdout.as_mut() {
            let mut chunk = vec![0; MAX_CHUNK];
            loop {
                match pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if out.send(Frame::Stdout { channel, bytes: chunk[..read].to_vec() }).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        let code = child.wait().await.ok().and_then(|status| status.code()).and_then(|code| u8::try_from(code).ok());
        let _ = out.send(Frame::Exit { channel, code }).await;
    });
    Channel { stdin: Some(stdin), group }
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
        let relay = tokio::spawn(serve(server_read, server_write));
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut bytes = Vec::new();
        for frame in &frames {
            frame.encode(&mut bytes);
        }
        let mut decoder = Decoder::default();
        let mut seen = Vec::new();
        client_write.write_all(&bytes).await.unwrap();
        let mut buffer = vec![0; 1 << 16];
        let expected_exits = frames.iter().filter(|frame| matches!(frame, Frame::Open { .. })).count();
        while seen.iter().filter(|frame| matches!(frame, Frame::Exit { .. })).count() < expected_exits {
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
            Frame::Open { channel: 1, script: "read line; printf 'got %s' \"$line\"; exit 7".into() },
            Frame::Stdin { channel: 1, bytes: b"hello\n".to_vec() },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(seen[0], Frame::Ready);
        assert_eq!(stdout(&seen, 1), b"got hello");
        assert!(seen.contains(&Frame::Exit { channel: 1, code: Some(7) }), "{seen:?}");
    }

    /// The environment is empty apart from PATH, HOME and the C locale, and
    /// stderr never reaches the server.
    #[tokio::test]
    async fn scripts_run_with_a_clean_environment_and_no_stderr() {
        let seen = exchange(vec![
            Frame::Open { channel: 2, script: "env | sort | tr '\\n' ' '; echo secret >&2".into() },
            Frame::StdinEnd { channel: 2 },
        ])
        .await;
        let text = String::from_utf8(stdout(&seen, 2)).unwrap();
        let names: Vec<&str> = text.split_whitespace().map(|pair| pair.split('=').next().unwrap()).collect();
        assert!(names.iter().all(|name| ["HOME", "LANG", "LC_ALL", "PATH", "PWD", "SHLVL", "_"].contains(name)), "{text}");
        assert!(!text.contains("secret"));
    }

    /// Two scripts run side by side on separate channels.
    #[tokio::test]
    async fn channels_are_independent() {
        let seen = exchange(vec![
            Frame::Open { channel: 1, script: "cat".into() },
            Frame::Open { channel: 2, script: "printf two".into() },
            Frame::StdinEnd { channel: 2 },
            Frame::Stdin { channel: 1, bytes: b"one".to_vec() },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(stdout(&seen, 1), b"one");
        assert_eq!(stdout(&seen, 2), b"two");
    }

    /// A frame only the relay may send ends the relay with an error.
    #[tokio::test]
    async fn a_relay_only_frame_from_the_server_is_refused() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (server_read, server_write) = tokio::io::split(server);
        let (_client_read, mut client_write) = tokio::io::split(client);
        let mut bytes = Vec::new();
        Frame::Exit { channel: 1, code: Some(0) }.encode(&mut bytes);
        client_write.write_all(&bytes).await.unwrap();
        assert!(serve(server_read, server_write).await.is_err());
    }
}
