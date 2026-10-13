//! Owns a full-duplex SSH command channel and its cancellation-safe child group for D255.

use crate::{model::Failure, process::Group};
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
    group: Group,
    _child: Child,
    read: Mutex<ChildStdout>,
    write: Mutex<ChildStdin>,
    diagnostics: JoinHandle<()>,
}
impl Duplex {
    /// Start a mux client of the already authenticated connection.
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
        let diagnostics = tokio::spawn(async move {
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
    /// # Errors
    /// Refuses EOF or an oversized receipt without exposing remote output.
    pub async fn line(&self, limit: usize) -> Result<Vec<u8>, Failure> {
        let mut line = Vec::new();
        let mut reader = self.read.lock().await;
        while line.len() < limit {
            let mut byte = [0];
            if reader.read(&mut byte).await.map_err(|_| unavailable())? != 1 {
                return Err(unavailable());
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
impl Drop for Duplex {
    fn drop(&mut self) {
        self.group.retire();
        self.diagnostics.abort();
    }
}
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
}
