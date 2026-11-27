//! Append-only public state for stable Linux mesh revisions.
//!
//! A peer-free legacy snapshot selects a journal through a per-journal token. An older binary
//! reads that snapshot as ordinary JSON and asks the coordinator for fresh policy. It cannot
//! revive grants revoked by a journal record it cannot read.

use super::{State, encode_state, write_public};
use crate::{
    dataplane::{Config, DefaultPolicy, PeerPolicy},
    policy::model::NodeId,
};
use infraternal_mesh::public_journal::{
    COMPACT_BYTES, MAX_BYTES, Token, append_token, read_token, split_count, split_header,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// An update to one ordered map. The absent value removes its key.
type Edits<T> = BTreeMap<NodeId, Option<T>>;

/// One stable revision, containing only changes to its peer maps.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Delta {
    /// Exact revision this record follows.
    from: u64,
    /// Accepted revision after the changes.
    to: u64,
    /// Adds, replacements, and removals in the public policies.
    peers: Edits<PeerPolicy>,
    /// Adds, replacements, and removals in the optional names.
    #[cfg(feature = "mesh-dns")]
    names: Edits<String>,
}

impl Delta {
    /// Leave authority, binding, node settings and rotation changes to the ordinary snapshot path.
    pub(super) fn between(old: &Config, next: &Config) -> Option<Self> {
        (old.version < next.version
            && old.local_key.is_some()
            && old.authority_epoch.is_some()
            && same_header(old, next))
        .then(|| Self {
            from: old.version,
            to: next.version,
            peers: edits(&old.peers, &next.peers),
            #[cfg(feature = "mesh-dns")]
            names: edits(&old.peer_names, &next.peer_names),
        })
    }

    /// Replay only a strictly increasing chain, beginning at the journal's checkpoint.
    fn apply(self, state: &mut State) -> io::Result<()> {
        let config = state.config.as_mut().ok_or(io::ErrorKind::InvalidData)?;
        if config.version != self.from || self.to <= self.from {
            return Err(io::ErrorKind::InvalidData.into());
        }
        apply_edits(&mut config.peers, self.peers);
        #[cfg(feature = "mesh-dns")]
        apply_edits(&mut config.peer_names, self.names);
        config.version = self.to;
        Ok(())
    }
}

/// Account for every persisted field outside the peer maps and revision. A new config field must
/// explicitly opt in here before it can cross an append unchanged.
fn same_header(old: &Config, next: &Config) -> bool {
    let Config {
        local_key,
        server,
        authority_epoch,
        rotation_operation,
        node,
        #[cfg(feature = "mesh-dns")]
        name,
        #[cfg(feature = "mesh-dns")]
        dns_suffix,
        version: _,
        addresses,
        default_policy,
        exposure,
        peers: _,
        #[cfg(feature = "mesh-dns")]
            peer_names: _,
    } = old;
    let same = *local_key == next.local_key
        && *server == next.server
        && *authority_epoch == next.authority_epoch
        && rotation_operation.is_none()
        && next.rotation_operation.is_none()
        && *node == next.node
        && *addresses == next.addresses
        && *default_policy == next.default_policy
        && *exposure == next.exposure;
    #[cfg(feature = "mesh-dns")]
    let same = same && *name == next.name && *dns_suffix == next.dns_suffix;
    same
}

/// Merge the two sorted inventories in one pass, copying only changed values.
fn edits<T: Clone + Eq>(old: &BTreeMap<NodeId, T>, next: &BTreeMap<NodeId, T>) -> Edits<T> {
    let mut edits = BTreeMap::new();
    let mut old = old.iter().peekable();
    for (id, value) in next {
        while let Some((old_id, _)) = old.next_if(|(old_id, _)| *old_id < id) {
            edits.insert(*old_id, None);
        }
        if !old
            .next_if(|(old_id, _)| *old_id == id)
            .is_some_and(|(_, previous)| previous == value)
        {
            edits.insert(*id, Some(value.clone()));
        }
    }
    edits.extend(old.map(|(id, _)| (*id, None)));
    edits
}

/// Merge one record's replacements and removals.
fn apply_edits<T>(items: &mut BTreeMap<NodeId, T>, edits: Edits<T>) {
    for (id, item) in edits {
        if let Some(value) = item {
            items.insert(id, value);
        } else {
            items.remove(&id);
        }
    }
}

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
        self.version = delta.to;
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
    let (found, records) = split_header(&body).ok_or(io::ErrorKind::InvalidData)?;
    if token != found {
        return Ok(None);
    }
    let mut frames = records.split_inclusive(|&byte| byte == b'\n');
    let first = frames.next().ok_or(io::ErrorKind::InvalidData)?;
    let (count, mut state) = decode_frame::<State>(first)?;
    check_count(&state, count)?;
    let mut log_bytes = 0;
    for frame in frames.take_while(|frame| frame.ends_with(b"\n")) {
        log_bytes += frame.len();
        if log_bytes > COMPACT_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (count, delta) = decode_frame::<Delta>(frame)?;
        delta.apply(&mut state)?;
        check_count(&state, count)?;
    }
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
        log_bytes,
        valid_len: (body.len() - records.len() + first.len() + log_bytes) as u64,
    };
    Ok(Some((state, cursor)))
}

/// Verify the count the offline status reader sees against the replayed state.
fn check_count(state: &State, count: usize) -> io::Result<()> {
    if state
        .config
        .as_ref()
        .is_some_and(|config| config.peers.len() == count)
    {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
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

/// A frame contains the peer count, a fixed-width checksum, JSON and a final newline. The checksum detects a
/// damaged record even if the filesystem persisted the terminator before all of the payload.
fn encode_frame(value: &impl Serialize, count: usize) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    let mut frame = format!("{count:08x} {:016x} ", checksum(&body)).into_bytes();
    frame.extend_from_slice(&body);
    frame.push(b'\n');
    Ok(frame)
}

/// Verify an entire frame before decoding its JSON.
fn decode_frame<T: serde::de::DeserializeOwned>(frame: &[u8]) -> io::Result<(usize, T)> {
    let fail = || io::Error::from(io::ErrorKind::InvalidData);
    let (count, frame) = split_count(frame).ok_or_else(fail)?;
    let (header, json) = frame.split_at_checked(17).ok_or_else(fail)?;
    let body = json.strip_suffix(b"\n").ok_or_else(fail)?;
    let digest = std::str::from_utf8(&header[..16]).map_err(|_| fail())?;
    if header[16] != b' ' || u64::from_str_radix(digest, 16).map_err(|_| fail())? != checksum(body)
    {
        return Err(fail());
    }
    serde_json::from_slice(body)
        .map(|value| (count, value))
        .map_err(io::Error::other)
}

/// Truncate the existing SHA-256 primitive for detection of storage corruption.
fn checksum(body: &[u8]) -> u64 {
    let [a, b, c, d, e, f, g, h, ..] = openssl::sha::sha256(body);
    u64::from_be_bytes([a, b, c, d, e, f, g, h])
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
    if body.len() > super::MAX_PUBLIC_STATE_BYTES as usize {
        return Err(io::ErrorKind::InvalidData.into());
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
