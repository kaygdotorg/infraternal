//! Mesh state journal frames and replay, shared across host storage adapters.

use crate::{
    dataplane::{Config, PeerPolicy},
    node_state::State,
    policy::model::NodeId,
};
use infraternal_mesh::public_journal::{
    COMPACT_BYTES, MAX_BYTES, Token, split_count, split_header,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io};

/// An update to one ordered map. The absent value removes its key.
type Edits<T> = BTreeMap<NodeId, Option<T>>;

/// One stable revision, containing only changes to its peer maps.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
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
    #[must_use]
    pub fn between(old: &Config, next: &Config) -> Option<Self> {
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

    /// The revision that will be durable after this delta is appended.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.to
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

/// Public state recovered from a checkpoint and its complete records.
pub struct Replay {
    /// The final applied state.
    pub state: State,
    /// Bytes consumed by complete delta frames after the checkpoint.
    pub log_bytes: usize,
    /// End of the last complete frame, where the next append may begin.
    pub valid_len: u64,
}

/// Recover the given journal token's state, ignoring an incomplete last frame.
///
/// # Errors
/// Rejects oversized journals, malformed complete frames, and invalid revision chains.
pub fn replay_bytes(body: &[u8], token: Token) -> io::Result<Option<Replay>> {
    if body.len() > MAX_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let (found, records) = split_header(body).ok_or(io::ErrorKind::InvalidData)?;
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
    Ok(Some(Replay {
        state,
        log_bytes,
        valid_len: (body.len() - records.len() + first.len() + log_bytes) as u64,
    }))
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

/// A frame contains the peer count, a fixed-width checksum, JSON and a final newline. The checksum detects a
/// damaged record even if the filesystem persisted the terminator before all of the payload.
///
/// # Errors
/// Reports a JSON serialization failure.
pub fn encode_frame(value: &impl Serialize, count: usize) -> io::Result<Vec<u8>> {
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
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    u64::from_be_bytes(std::array::from_fn(|index| digest.as_ref()[index]))
}
