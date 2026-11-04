//! Dedicated authenticated lifecycle readiness, independent of terminal admission [D18,D240,D247].
//! Sealed inherited-account retirement also releases its durable person attribution.
#![forbid(unsafe_code)]

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};

/// A fixed `!` byte requests cleanup. No decoder, input byte quota, writer
/// identity or owner slot admits it. A later authenticated
/// retry replaces only the proof recipient, never cancels requested cleanup.
pub(crate) struct Cleanup {
    listener: UnixListener,
    path: PathBuf,
    controller: u32,
    peer: Option<UnixStream>,
    proof: Vec<u8>,
    written: usize,
    requested: bool,
    confirmed: bool,
    accepted: bool,
}

impl Cleanup {
    /// Creates the private cleanup socket next to the session socket (same name with
    /// the `stop` extension), mode `0600`, non-blocking. `proof` is the byte string
    /// written back to whoever asked for cleanup once it is confirmed; `controller`
    /// is the one non-root uid allowed to connect.
    ///
    /// Fails if something already exists at that path: another live endpoint is
    /// never unlinked. The socket file is removed again when the `Cleanup` drops.
    #[cold]
    pub(crate) fn bind(endpoint: &Path, controller: u32, proof: Vec<u8>) -> io::Result<Self> {
        let path = endpoint.with_extension("stop");
        // Never unlink another live endpoint; startup retains the same private
        // directory/identity fence as its ordinary rendezvous.
        let listener = UnixListener::bind(&path)?;
        let cleanup = Self {
            listener,
            path,
            controller,
            peer: None,
            proof,
            written: 0,
            requested: false,
            confirmed: false,
            accepted: false,
        };
        fs::set_permissions(&cleanup.path, fs::Permissions::from_mode(0o600))?;
        cleanup.listener.set_nonblocking(true)?;
        Ok(cleanup)
    }

    /// The listening socket, for the shim's poll loop to wait on.
    pub(crate) fn listener(&self) -> &impl AsFd {
        &self.listener
    }
    /// The currently connected recipient, if any, for the poll loop to wait on.
    pub(crate) fn peer(&self) -> Option<&UnixStream> {
        self.peer.as_ref()
    }
    /// True once a valid stop request has been read. It stays true: a later
    /// reconnect or a lost recipient never cancels a requested cleanup.
    pub(crate) fn requested(&self) -> bool {
        self.requested
    }
    /// Marks cleanup as confirmed, which lets `flush` start sending the proof.
    /// Called once the session's child processes have been finished.
    pub(crate) fn confirm(&mut self) {
        self.confirmed = true;
    }
    /// True when the proof can be sent: cleanup is confirmed, a request was read
    /// and a recipient is connected. The poll loop waits for writability only then.
    pub(crate) fn writable(&self) -> bool {
        self.confirmed && self.accepted && self.peer.is_some()
    }
    /// True while a recipient is connected but its request has not been read yet,
    /// so the poll loop should wait for it to become readable.
    pub(crate) fn reading(&self) -> bool {
        !self.accepted && self.peer.is_some()
    }

    /// Deletes the on-disk records that tie this finished terminal to the people
    /// who had access to it (files named `<32 hex digits>-<session>.terminal` in the
    /// `infraternal-login-locks` directory under the state directory).
    ///
    /// Requires that the session's exit record already exists; without it this
    /// fails, so a live terminal's records are never removed. A missing directory
    /// means there is nothing to do. The directory must be private (`0700`, owned by
    /// this user) and every record an empty `0600` file of ours; anything else is
    /// refused with `PermissionDenied` rather than deleted. The directory is synced
    /// afterwards. Session ids are never reused, so only this terminal's records can
    /// match.
    #[cold]
    pub(crate) fn retire_attribution(&self) -> io::Result<()> {
        let socket = self.path.with_extension("sock");
        if crate::ended::read(&socket)?.is_none() {
            return Err(io::Error::other(
                "terminal retirement has no sealed cleanup proof",
            ));
        }
        let state = socket
            .parent()
            .and_then(Path::parent)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let directory = state.join("infraternal-login-locks");
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let session = socket
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or(io::ErrorKind::InvalidInput)?;
        let suffix = format!("-{session}.terminal");
        // Session identities are never reused. Only this sealed terminal's
        // records may be removed; live terminals keep restart-safe ownership.
        // This runs at shim retirement, even if its daemon has gone away.
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(person) = name.to_str().and_then(|name| name.strip_suffix(&suffix)) else {
                continue;
            };
            if person.len() != 32 || !person.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.len() != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        fs::File::open(directory)?.sync_all()
    }

    /// Forgets the current recipient, for example after a hang-up. A complete
    /// request that is already queued is read first, so losing the connection never
    /// cancels a cleanup that was asked for.
    pub(crate) fn disconnect(&mut self) {
        // HUP can arrive with a complete queued request. Consume it before
        // retiring the recipient: losing the proof link never cancels cleanup.
        self.read_request();
        self.peer = None;
    }

    /// Accepts at most one connection (so other events keep their turn) and makes it
    /// the recipient. Connections from users other than root or the controller are
    /// dropped silently. A new recipient replaces the old one, whose queued request
    /// is read first; the proof restarts from its first byte.
    #[cold]
    pub(crate) fn accept(&mut self) -> io::Result<()> {
        // One accept per lifecycle turn preserves SIGCHLD and PTY fairness.
        let (peer, _) = match self.listener.accept() {
            Ok(peer) => peer,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        };
        let uid = getsockopt(&peer, PeerCredentials)
            .map_err(io::Error::from)?
            .uid();
        if uid != 0 && uid != self.controller {
            return Ok(());
        }
        peer.set_nonblocking(true)?;
        // A retry replaces the recipient, never an unread admitted request.
        // Read the old authenticated socket before its descriptor is dropped.
        self.read_request();
        self.peer = Some(peer);
        self.written = 0;
        self.accepted = false;
        // The request may already be queued. Own it in this lifecycle turn,
        // before a worker can spend another bounded ordinary receive timeout.
        self.read_request();
        Ok(())
    }

    /// Reads one byte from the recipient. The fixed stop byte marks the cleanup as
    /// requested and accepted. No data yet is fine; end of input, any other byte
    /// or an error drops the recipient. Does nothing after a request was accepted.
    #[cold]
    pub(crate) fn read_request(&mut self) {
        let Some(peer) = &mut self.peer else { return };
        if self.accepted {
            return;
        }
        let mut request = [0];
        match peer.read(&mut request) {
            Ok(1)
                if matches!(
                    crate::login::decode_header(&request, 0),
                    Ok(crate::login::RequestHeader::Stop)
                ) =>
            {
                self.accepted = true;
                self.requested = true;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            _ => self.peer = None,
        }
    }

    /// Writes as much of the proof as the socket takes. Does nothing unless
    /// `writable`. When all of it is written, or the recipient fails, the recipient
    /// is dropped; a partial write is resumed on the next call.
    #[cold]
    pub(crate) fn flush(&mut self) {
        if !self.writable() {
            return;
        }
        let Some(peer) = &mut self.peer else { return };
        match peer.write(&self.proof[self.written..]) {
            Ok(0) => self.peer = None,
            Ok(length) => {
                self.written += length;
                if self.written == self.proof.len() {
                    self.peer = None;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => self.peer = None,
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    //! Stalled recipients cannot hold cleanup admission or manufacture proof.
    use super::*;
    use std::{io::Read, os::unix::fs::OpenOptionsExt};

    #[test]
    fn recipient_replacement_keeps_a_complete_queued_request_owned() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("x{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let endpoint = root.join("test.sock");
        let mut cleanup = Cleanup::bind(
            &endpoint,
            nix::unistd::Uid::effective().as_raw(),
            b"proof".to_vec(),
        )
        .unwrap();
        let mut first = UnixStream::connect(endpoint.with_extension("stop")).unwrap();
        cleanup.accept().unwrap();
        first.write_all(b"!").unwrap();
        drop(first);
        let second = UnixStream::connect(endpoint.with_extension("stop")).unwrap();
        cleanup.accept().unwrap();
        assert!(
            cleanup.requested(),
            "replacement discarded admitted cleanup"
        );
        assert!(cleanup.reading()); // A stalled retry is only a proof recipient.
        cleanup.confirm();
        assert!(!cleanup.writable());
        drop(second);
        drop(cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attribution_requires_sealed_retirement_and_preserves_other_terminals() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("t{}", std::process::id()));
        let directory = root.join("infraternal-login-locks");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("sessions")).unwrap();
        let session = "42".repeat(16);
        let socket = root.join("sessions").join(format!("{session}.sock"));
        let cleanup =
            Cleanup::bind(&socket, nix::unistd::Uid::effective().as_raw(), Vec::new()).unwrap();
        let record = directory.join(format!("{}-{session}.terminal", "44".repeat(16)));
        let other = directory.join(format!("{}-{}.terminal", "44".repeat(16), "43".repeat(16)));
        for path in [&record, &other] {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
        }
        assert!(cleanup.retire_attribution().is_err());
        assert!(record.exists() && other.exists());
        crate::ended::record(&socket, 0, 0).unwrap();
        cleanup.retire_attribution().unwrap();
        assert!(!record.exists() && other.exists());
        cleanup.retire_attribution().unwrap(); // Concurrent revocation is idempotent.
        std::os::unix::fs::symlink(&other, &record).unwrap();
        assert_eq!(
            cleanup.retire_attribution().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(fs::symlink_metadata(&record).unwrap().is_symlink());
        assert!(other.exists());
        fs::remove_file(&record).unwrap();
        fs::write(&record, b"unexpected").unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            cleanup.retire_attribution().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(record.exists());
        drop(cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn admission_consumes_an_already_queued_authenticated_stop() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("a{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let endpoint = root.join("test.sock");
        let mut cleanup = Cleanup::bind(
            &endpoint,
            nix::unistd::Uid::effective().as_raw(),
            b"proof".to_vec(),
        )
        .unwrap();
        let mut peer = UnixStream::connect(endpoint.with_extension("stop")).unwrap();
        peer.write_all(b"!").unwrap();
        cleanup.accept().unwrap();
        assert!(cleanup.requested());
        assert!(!cleanup.reading());
        assert!(!cleanup.writable());
        cleanup.confirm();
        cleanup.flush();
        let mut proof = [0; 5];
        peer.read_exact(&mut proof).unwrap();
        assert_eq!(&proof, b"proof");
        drop(cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disconnect_consumes_a_queued_request_without_retaining_the_recipient() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("e{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let endpoint = root.join("test.sock");
        let mut cleanup = Cleanup::bind(
            &endpoint,
            nix::unistd::Uid::effective().as_raw(),
            b"proof".to_vec(),
        )
        .unwrap();
        let mut peer = UnixStream::connect(endpoint.with_extension("stop")).unwrap();
        cleanup.accept().unwrap();
        peer.write_all(b"!").unwrap();
        drop(peer);
        cleanup.disconnect();
        assert!(cleanup.requested());
        assert!(cleanup.peer().is_none());
        cleanup.confirm();
        assert!(!cleanup.writable());
        drop(cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retries_replace_stalled_recipients_and_proof_waits_for_confirmation() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("c{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let endpoint = root.join("test.sock");
        let mut cleanup = Cleanup::bind(
            &endpoint,
            nix::unistd::Uid::effective().as_raw(),
            b"proof".to_vec(),
        )
        .unwrap();
        let mut last = None;
        for _ in 0..96 {
            let peer = UnixStream::connect(endpoint.with_extension("stop")).unwrap();
            peer.set_nonblocking(true).unwrap();
            cleanup.accept().unwrap();
            assert!(cleanup.reading());
            assert!(!cleanup.requested());
            cleanup.flush();
            let mut peer = peer;
            assert_eq!(
                peer.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            last = Some(peer);
        }
        let mut peer = last.unwrap();
        peer.write_all(b"!").unwrap();
        cleanup.read_request();
        assert!(cleanup.requested());
        cleanup.confirm();
        assert!(cleanup.writable());
        assert!(cleanup.listener().as_fd().try_clone_to_owned().is_ok());
        cleanup.flush();
        let mut proof = [0; 5];
        peer.read_exact(&mut proof).unwrap();
        assert_eq!(&proof, b"proof");
        assert!(cleanup.peer().is_none());
        cleanup.disconnect();
        drop(cleanup);
        assert!(!endpoint.with_extension("stop").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
