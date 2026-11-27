//! Append-only public state for stable Linux mesh revisions.
//!
//! A peer-free legacy snapshot selects a journal through a per-journal token. An older binary
//! reads that snapshot as ordinary JSON and asks the coordinator for fresh policy. It cannot
//! revive grants revoked by a journal record it cannot read.

use super::{State, encode_state, write_public};
use crate::dataplane::{Config, DefaultPolicy};
use infraternal_mesh::public_journal::{COMPACT_BYTES, MAX_BYTES, Token, append_token, read_token};
use infraternal_mesh_node::state_journal::{Delta, encode_frame, replay_bytes};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// File identity and change times invalidate a cached revision on any other writer's update.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    /// Sample the kernel identity and change times of a checked file.
    fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// Last durable revision written by this Store. Normal saves can invalidate it simply by
/// replacing the legacy snapshot, even if a different Store performs the write.
pub(super) struct Cursor {
    anchor: FileStamp,
    journal: FileStamp,
    token: Token,
    version: u64,
    backend: Option<crate::firewall::Backend>,
    log_bytes: usize,
    valid_len: u64,
}

impl Cursor {
    /// Prove this Store still owns the revision without reopening or parsing its checkpoint.
    pub(super) fn matches(
        &self,
        anchor: &Path,
        log: &File,
        version: u64,
        backend: Option<crate::firewall::Backend>,
    ) -> io::Result<bool> {
        Ok(self.version == version
            && self.backend == backend
            && self.journal == FileStamp::of(&log.metadata()?)
            && self.anchor == FileStamp::of(&fs::symlink_metadata(anchor)?))
    }

    /// Append one complete frame, syncing its bytes and length before acknowledging it.
    /// An unsuccessful write is truncated back so a retry can safely append the same revision.
    pub(super) fn append(
        &mut self,
        mut log: File,
        path: &Path,
        delta: &Delta,
        peer_count: usize,
        next: impl FnOnce() -> State,
    ) -> io::Result<()> {
        let frame = encode_frame(delta, peer_count)?;
        if self.log_bytes.saturating_add(frame.len()) > COMPACT_BYTES {
            let updated = write_checkpoint(path, self.token, &next())?;
            self.valid_len = updated.len;
            self.journal = updated;
            self.log_bytes = 0;
        } else {
            if self.valid_len != self.journal.len {
                log.set_len(self.valid_len)?;
            }
            log.seek(SeekFrom::Start(self.valid_len))?;
            if let Err(error) = log.write_all(&frame).and_then(|()| log.sync_data()) {
                log.set_len(self.valid_len)?;
                log.sync_data()?;
                return Err(error);
            }
            self.journal = FileStamp::of(&log.metadata()?);
            self.valid_len = self.journal.len;
            self.log_bytes += frame.len();
        }
        self.version = delta.version();
        Ok(())
    }
}

/// Open the private journal without following a link or waiting on a non-regular file.
pub(super) fn open(path: &Path, writable: bool) -> io::Result<Option<File>> {
    let file = match OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    check_private(&file.metadata()?)?;
    Ok(Some(file))
}

/// Enforce the state directory's owner, link count and 0600 file contract.
fn check_private(meta: &Metadata) -> io::Result<()> {
    if !meta.is_file()
        || meta.uid() != nix::unistd::Uid::effective().as_raw()
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// Read a legacy snapshot as bytes, retaining the optional journal token in its whitespace.
pub(super) fn read_anchor(path: &Path) -> io::Result<Option<(State, Option<Token>)>> {
    let Some(mut file) = open(path, false)? else {
        return Ok(None);
    };
    let mut body = Vec::new();
    file.read_to_end(&mut body)?;
    let state = serde_json::from_slice(&body).map_err(io::Error::other)?;
    Ok(Some((state, read_token(&body))))
}

/// Return the checkpoint and complete records. A partial last frame has no newline and is ignored.
/// Invalid complete records fail closed, including checksum errors in the committed prefix.
pub(super) fn replay(
    anchor: &Path,
    file: File,
    token: Token,
) -> io::Result<Option<(State, Cursor)>> {
    let journal = FileStamp::of(&file.metadata()?);
    let body = bounded_read(file, MAX_BYTES)?;
    let Some(replayed) = replay_bytes(&body, token)? else {
        return Ok(None);
    };
    let state = replayed.state;
    let cursor = Cursor {
        anchor: FileStamp::of(&fs::symlink_metadata(anchor)?),
        journal,
        token,
        version: state
            .config
            .as_ref()
            .ok_or(io::ErrorKind::InvalidData)?
            .version,
        backend: state.backend,
        log_bytes: replayed.log_bytes,
        valid_len: replayed.valid_len,
    };
    Ok(Some((state, cursor)))
}

/// Read at most the supported file size plus a byte to identify overflow.
fn bounded_read(file: File, max: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut body)?;
    if body.len() > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(body)
}

/// Publish a compacted checkpoint before returning its new file identity.
fn write_checkpoint(path: &Path, token: Token, state: &State) -> io::Result<FileStamp> {
    let count = state
        .config
        .as_ref()
        .ok_or(io::ErrorKind::InvalidData)?
        .peers
        .len();
    let mut body = token.to_vec();
    body.push(b'\n');
    body.extend_from_slice(&encode_frame(state, count)?);
    if body.len() > MAX_BYTES - COMPACT_BYTES {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    write_public(path, &body)?;
    Ok(FileStamp::of(&fs::symlink_metadata(path)?))
}

/// Start a fresh journal after proving the caller's base under the Store writer lock. The old
/// public snapshot stays authoritative until the synced journal is selected by the atomic
/// replacement of that snapshot. Until then, the new token cannot match a reader's anchor.
pub(super) fn start(anchor: &Path, journal: &Path, state: &State) -> io::Result<Cursor> {
    let config = state.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
    let mut token = Token::default();
    openssl::rand::rand_bytes(&mut token).map_err(io::Error::other)?;
    let deny = State {
        enabled: state.enabled,
        config: Some(Config {
            version: 0,
            peers: BTreeMap::new(),
            default_policy: DefaultPolicy::Deny,
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
            ..config.clone()
        }),
        authority_reset_pending: false,
        backend: state.backend,
    };
    let (mut body, _) = encode_state(&deny)?;
    append_token(&mut body, token);
    let journal = write_checkpoint(journal, token, state)?;
    write_public(anchor, &body)?;
    Ok(Cursor {
        anchor: FileStamp::of(&fs::symlink_metadata(anchor)?),
        valid_len: journal.len,
        journal,
        token,
        version: config.version,
        backend: state.backend,
        log_bytes: 0,
    })
}
