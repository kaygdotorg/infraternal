//! Owns a full-duplex SSH command channel and its cancellation-safe child group for D255.
//!
//! A [`Duplex`] wraps an OpenSSH client process (a mux client of an already
//! authenticated connection) and exposes its stdin and stdout as raw bytes.
//! It does not parse or frame anything. The child runs in its own process
//! group; dropping the `Duplex` kills that whole group, so a cancelled task
//! cannot leave a stray SSH client behind. The child's stderr is never kept or printed.

use crate::{
    model::{Failure, FailureKind},
    process::Group,
};
use std::{os::unix::process::CommandExt, process::Stdio};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    task::JoinHandle,
};

/// A single reader and serialized writer share one authenticated SSH channel.
/// Drop retires descendants before releasing the unreaped leader identity.
pub struct Duplex {
    /// Process group of the SSH client; killed as a unit on drop.
    group: Group,
    /// Kept (unused) so the leader is not reaped before its group is retired.
    _child: Child,
    /// Child stdout, locked so only one reader runs at a time.
    read: Mutex<ChildStdout>,
    /// Child stdin, locked so whole frames are never interleaved.
    write: Mutex<ChildStdin>,
    /// Task that drains and discards the child's stderr up to a fixed bound.
    diagnostics: JoinHandle<()>,
}
impl Duplex {
    /// Start a mux client of the already authenticated connection.
    ///
    /// `command` is configured by the caller; stdin, stdout and stderr are
    /// replaced with pipes here.
    /// # Errors
    /// Refuses spawn or missing pipe descriptors without exposing diagnostics.
    pub fn spawn(command: &mut Command) -> Result<Self, Failure> {
        infraternal_shim::prepare_child(command.as_std_mut());
        command.as_std_mut().process_group(0);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Failure::install("The SSH terminal bridge could not start."))?;
        let group = Group::owned(&child)?;
        let read = child.stdout.take().ok_or_else(unavailable)?;
        let write = child.stdin.take().ok_or_else(unavailable)?;
        let mut stderr = child.stderr.take().ok_or_else(unavailable)?;
        // Remote diagnostics are private and never retained or printed. Stop
        // draining at the existing helper bound; pipe backpressure bounds abuse.
        let diagnostics = crate::tasks::spawn(async move {
            let mut bytes = [0; 1024];
            let mut remaining = 8192;
            while remaining != 0 {
                match stderr.read(&mut bytes[..remaining.min(1024)]).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => remaining -= count,
                }
            }
        });
        Ok(Self {
            group,
            _child: child,
            read: Mutex::new(read),
            write: Mutex::new(write),
            diagnostics,
        })
    }

    /// Read a bounded canonical setup receipt without consuming protocol bytes.
    ///
    /// Reads one byte at a time up to and including the first `\n`, so nothing
    /// after the line is taken. Fails if `limit` bytes arrive with no newline.
    /// # Errors
    /// Classifies a closed command channel as unreachable and refuses oversized receipts.
    pub async fn line(&self, limit: usize) -> Result<Vec<u8>, Failure> {
        let mut line = Vec::new();
        let mut reader = self.read.lock().await;
        while line.len() < limit {
            let mut byte = [0];
            if reader.read(&mut byte).await.map_err(|_| unavailable())? == 0 {
                // EOF means this command channel closed before it could return a receipt. The
                // explicit retry path may then authenticate a new transport and recheck ownership.
                return Err(Failure::new(
                    FailureKind::Unreachable,
                    "The SSH command channel closed before its receipt.",
                ));
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(line);
            }
        }
        Err(unavailable())
    }

    /// Read one ready chunk, preserving partial progress across cancellation.
    /// # Errors
    /// Returns only local pipe errors; zero bytes denotes SSH channel closure.
    pub async fn read(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.read.lock().await.read(bytes).await
    }

    /// Write a complete frame; cancellation requires dropping this channel.
    /// # Errors
    /// Returns a local pipe error if the bridge or SSH connection has closed.
    pub async fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.write.lock().await.write_all(bytes).await
    }
}
/// Kills the child's process group and stops the stderr drain.
impl Drop for Duplex {
    fn drop(&mut self) {
        self.group.retire();
        self.diagnostics.abort();
    }
}
/// Generic failure for missing pipes or oversized receipts; carries no child output.
fn unavailable() -> Failure {
    Failure::install("The SSH terminal bridge pipes are unavailable.")
}

#[cfg(test)]
mod tests {
    //! Verifies real child byte transport without parsing or inventing terminal frames.
    use super::*;

    #[tokio::test]
    async fn duplex_preserves_binary_bytes_in_both_directions() {
        let mut command = Command::new("/bin/cat");
        let channel = Duplex::spawn(&mut command).unwrap();
        let expected = b"\0\xff\r\nterminal\x1b[31m";
        channel.write(expected).await.unwrap();
        let mut actual = vec![0; expected.len()];
        let mut received = 0;
        while received != actual.len() {
            received += channel.read(&mut actual[received..]).await.unwrap();
        }
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn closed_receipt_channel_is_reported_as_unreachable() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 255"]);
        let channel = Duplex::spawn(&mut command).unwrap();
        let Err(failure) = channel.line(64).await else {
            panic!("a child that exits without a receipt must close its command channel");
        };
        assert_eq!(failure.kind, FailureKind::Unreachable);
    }
}
