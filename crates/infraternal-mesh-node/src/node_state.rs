//! Public node state, authority metadata and the in-memory rotation journal.

use crate::dataplane::Config;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The two owner-selected Linux frontends. The kernel retains policy across host processes.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    /// The nftables command-line frontend.
    Nft,
    /// The direct `nf_tables` netlink frontend.
    NfTables,
}

/// Public runtime state needed to restore mesh intent without storing private key material.
/// The accepted public mesh snapshot saved for restart, with a firewall choice on Linux.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Whether this node should bring up the mesh on restore.
    pub enabled: bool,
    /// The last accepted public coordinator snapshot, when available.
    pub config: Option<Config>,
    /// True after a new authority is fenced and until its first full snapshot is saved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authority_reset_pending: bool,
    /// The firewall frontend recorded by the Linux host.
    #[serde(default)]
    #[cfg(target_os = "linux")]
    pub backend: Option<Backend>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            authority_reset_pending: false,
            #[cfg(target_os = "linux")]
            backend: None,
        }
    }
}

/// A fixed-size local record makes an interrupted key switch retryable.
/// While open it stores predecessor and candidate private keys; completion clears the predecessor
/// private bytes and keeps only its public key for binding checks. The record never enters logs or
/// the public snapshot.
pub struct RotationSecret {
    /// Coordinator UUID for the in-flight rotation.
    pub operation_id: String,
    /// Coordinator sequence that orders this operation.
    pub sequence: u64,
    /// The predecessor private key while the journal is open; its public key after completion.
    pub previous: [u8; 32],
    /// The candidate private key selected by commit intent and retained for retry.
    pub candidate: [u8; 32],
    /// Whether the node durably accepted the request to switch keys.
    pub commit_requested: bool,
    /// The candidate is the retained interface key; `previous` no longer contains private bytes.
    pub completed: bool,
}
impl Drop for RotationSecret {
    fn drop(&mut self) {
        self.previous.zeroize();
        self.candidate.zeroize();
    }
}
impl RotationSecret {
    /// Whether a completed marker authorizes this saved predecessor or candidate binding.
    ///
    /// New markers retain the predecessor's public bytes. Older markers contain zero here and
    /// can therefore authorize only the candidate they already select.
    #[must_use]
    pub fn completed_binding_matches(
        &self,
        bound: crate::policy::model::PublicKey,
        candidate: crate::policy::model::PublicKey,
    ) -> bool {
        self.completed
            && (bound == candidate || (self.previous != [0; 32] && bound.0 == self.previous))
    }
}

/// Authority metadata kept outside the public snapshot (D295 rollback, #382 P2).
///
/// The previous release parses `mesh-public.json` with `deny_unknown_fields`, so the epoch and
/// the reset marker cannot live there: a rolled-back binary would fail to read its own state and
/// leave the node without a mesh. They live in this separate file, which older releases never
/// open. The snapshot file keeps exactly the older shape.
///
/// Writers update the snapshot first and this record second. Readers treat a missing or stale
/// record as harmless: a wrong or missing epoch only makes the next server snapshot count as an
/// authority change, and a reset marker is honoured only over a peer-free deny snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    /// The server authority epoch the saved snapshot came from, if it carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    /// Snapshot metadata retained for exact-base persistence checks, never a continuity proof.
    /// Reset recovery revalidates the operation from the incoming authenticated full snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_operation: Option<crate::dataplane::RotationContinuation>,
    /// True after a new authority was fenced and until its first full snapshot is saved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_pending: bool,
}

/// Move the authority metadata out of a snapshot about to be written, returning the stripped
/// copy for the snapshot file and the record saved beside it.
#[must_use]
pub fn split_authority(
    config: Option<&Config>,
    reset_pending: bool,
) -> (Option<Config>, AuthorityRecord) {
    let mut stripped = config.cloned();
    let epoch = stripped
        .as_mut()
        .and_then(|config| config.authority_epoch.take());
    let rotation_operation = stripped
        .as_mut()
        .and_then(|config| config.rotation_operation.take());
    (
        stripped,
        AuthorityRecord {
            epoch,
            rotation_operation,
            reset_pending,
        },
    )
}

/// Fill a just-read snapshot's authority metadata from its record.
///
/// Values written inline by earlier builds of this change win. The record's epoch applies only
/// to an epoch-less snapshot. Its reset marker applies only when the snapshot is peer-free and
/// deny-by-default, the state a reset writes first; anything else means the record is older
/// than the snapshot, and is ignored.
pub fn merge_authority(
    config: Option<&mut Config>,
    reset_pending: &mut bool,
    record: AuthorityRecord,
) {
    let Some(config) = config else {
        return;
    };
    config.rotation_operation = record.rotation_operation;
    if config.authority_epoch.is_none() {
        config.authority_epoch = record.epoch;
    }
    if record.reset_pending
        && config.peers.is_empty()
        && config.default_policy == crate::dataplane::DefaultPolicy::Deny
    {
        *reset_pending = true;
    }
}
