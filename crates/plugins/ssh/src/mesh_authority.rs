//! The target node's production mesh SSH authority: a pushed snapshot plus the applied mesh view [D235, D319], #221.
//!
//! The server pushes a [`Snapshot`] to each target node: the CA key, the
//! person certificates that are currently valid, and each person's login
//! access grant for this host (computed by the server's single evaluator,
//! `infraternal-server::login_access`). The node's applied mesh configuration
//! supplies the [`MeshView`]: which node owns a mesh address, and whether a
//! peer's inbound policy, the same one the kernel firewall enforces, admits
//! TCP/22. Nothing here reads SSH request text as authority.
//!
//! Invariants (security review):
//! - Missing state refuses: no snapshot, no mesh view, or a snapshot made
//!   for a different node than the mesh says this is. There is no cached
//!   fallback and no default grant.
//! - A snapshot replaces the previous one only if its sequence number is
//!   higher, so a delayed or replayed push can never widen access again.
//! - A certificate is current only if its full digest is registered with the
//!   same person, source node, source address and expiry. The signature alone
//!   is never enough (`mesh_certificate::verify` checks that too).
//! - Network access is the source peer's inbound policy for TCP/22 on this
//!   exact node. Login access is the pushed grant, checked against the UID the
//!   host's account database gives for the requested account, so an account
//!   this host does not have is refused, and "own username" never reaches root.
//! - A [`Guard`] holds the read side of the state lock. Installing a snapshot
//!   takes the write side, so it waits for opens that are still registering
//!   and every later open sees the new snapshot (no revocation race).
//! - Files (SFTP) are refused in slice 1: there is no per-account file
//!   runtime yet (#172), and the daemon must never serve files as itself.

use crate::{
    mesh_admission::{CertificateClaims, CurrentAccess, Refusal},
    mesh_certificate::{CertificateAccess, Identity},
    mesh_login::{Attachment, AuthorizedLogin, LoginAuthority, LoginGuard, SessionKind, Terminal},
};
use infraternal_plugin_api::login_access::{LoginGrant, OrdinaryUids};
use russh::keys::{
    HashAlg,
    ssh_key::{
        Fingerprint,
        public::{Ed25519PublicKey, KeyData},
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, net::IpAddr, sync::Arc};
use tokio::sync::{RwLock, RwLockReadGuard};

/// One currently valid person certificate, identified by its full digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub digest: [u8; 32],
    pub person: String,
    pub source_node: u64,
    pub source_address: IpAddr,
    pub valid_before: u64,
}

/// What the server pushes to one target node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Strictly increasing per server; older snapshots are refused.
    pub sequence: u64,
    /// The mesh node this snapshot was computed for.
    pub node: u64,
    /// The CA's Ed25519 public key.
    pub ca: [u8; 32],
    pub certificates: Vec<Issued>,
    /// Login access grant for this host, by person ID.
    pub grants: BTreeMap<String, LoginGrant>,
}

pub use infraternal_plugin_api::mesh_view::{MeshPeer, MeshView};

/// Resolves an account name to its UID in this host's account database.
pub type AccountLookup = fn(&str) -> Option<u32>;

/// Opens a shell or command in the requested account's login session.
pub trait SessionRuntime: Send + Sync + 'static {
    /// Open a shell or command as `account` for `person`; refuse on any failure.
    fn open(
        &self,
        person: &str,
        account: &str,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> impl Future<Output = Result<Attachment, Refusal>> + Send;
}

/// A snapshot that is not newer than the installed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stale;

/// Why a snapshot was not installed right now.
/// The longest one login may hold the access snapshot: a bound for a hung
/// PAM or user-manager start only. Measured logins take about 2 s (#221
/// comment 79163); a revocation waits at most this long for logins already
/// in flight.
pub const OPEN_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// The installed snapshot with its CA fingerprint computed once.
struct Installed {
    snapshot: Snapshot,
    ca: Fingerprint,
}

/// Everything the authority decides from, behind one lock.
#[derive(Default)]
struct State {
    installed: Option<Arc<Installed>>,
    mesh: Option<Arc<MeshView>>,
    sequence: u64,
}

/// The node's mesh SSH authority; one per infraternal agent.
pub struct Authority<R> {
    state: RwLock<State>,
    runtime: R,
    accounts: AccountLookup,
}

impl<R: SessionRuntime> Authority<R> {
    /// An authority with nothing installed: it refuses until a snapshot and a mesh view arrive.
    #[must_use]
    pub fn new(runtime: R, accounts: AccountLookup) -> Self {
        Self {
            state: RwLock::new(State::default()),
            runtime,
            accounts,
        }
    }

    /// Install a pushed snapshot. Waits its turn on the fair lock: logins
    /// that start after this call queue behind it (J236 P1-1, #221).
    ///
    /// # Errors
    /// Refuses a snapshot whose sequence is not higher than the last one.
    pub async fn install(&self, snapshot: Snapshot) -> Result<(), Stale> {
        let ca = KeyData::Ed25519(Ed25519PublicKey(snapshot.ca)).fingerprint(HashAlg::Sha256);
        let mut state = self.state.write().await;
        if snapshot.sequence <= state.sequence {
            return Err(Stale);
        }
        state.sequence = snapshot.sequence;
        state.installed = Some(Arc::new(Installed { snapshot, ca }));
        Ok(())
    }

    /// Replace the applied mesh view; `None` when the node left the mesh.
    pub async fn set_mesh(&self, mesh: Option<MeshView>) {
        self.state.write().await.mesh = mesh.map(Arc::new);
    }

    /// This node's mesh ID, when the mesh view and snapshot agree on it.
    pub async fn target_node(&self) -> Option<u64> {
        let state = self.state.read().await;
        let mesh = state.mesh.as_ref()?;
        let installed = state.installed.as_ref()?;
        (installed.snapshot.node == mesh.node).then_some(mesh.node)
    }
}

/// One consistent view, held from authentication or channel open until the
/// runtime has registered the session.
pub struct Guard<'a, R> {
    _hold: RwLockReadGuard<'a, State>,
    installed: Arc<Installed>,
    mesh: Arc<MeshView>,
    runtime: &'a R,
    accounts: AccountLookup,
}

impl<R: SessionRuntime> LoginAuthority for Authority<R> {
    type Guard<'a> = Guard<'a, R>;

    async fn current(&self) -> Result<Guard<'_, R>, Refusal> {
        let hold = self.state.read().await;
        let (Some(installed), Some(mesh)) = (hold.installed.clone(), hold.mesh.clone()) else {
            return Err(Refusal::Revoked);
        };
        if installed.snapshot.node != mesh.node {
            return Err(Refusal::Revoked);
        }
        Ok(Guard {
            _hold: hold,
            installed,
            mesh,
            runtime: &self.runtime,
            accounts: self.accounts,
        })
    }
}

impl<R> Guard<'_, R> {
    /// The registered certificate with this full digest, if any.
    fn issued(&self, digest: &[u8; 32]) -> Option<&Issued> {
        self.installed
            .snapshot
            .certificates
            .iter()
            .find(|issued| &issued.digest == digest)
    }
}

impl<R: SessionRuntime> CurrentAccess for Guard<'_, R> {
    fn source_node(&self, address: IpAddr) -> Option<u64> {
        self.mesh
            .peers
            .iter()
            .find(|(_, peer)| peer.addresses.contains(&address))
            .map(|(node, _)| *node)
    }

    fn certificate_current(&self, certificate: &CertificateClaims<'_>) -> bool {
        self.issued(&certificate.fingerprint).is_some_and(|issued| {
            issued.person == certificate.person
                && issued.source_node == certificate.source_node
                && issued.source_address == certificate.source_address
                && issued.valid_before == certificate.valid_before
        })
    }

    fn network_access(&self, source_node: u64, target_node: u64, tcp_port: u16) -> bool {
        tcp_port == 22
            && target_node == self.mesh.node
            && self
                .mesh
                .peers
                .get(&source_node)
                .is_some_and(|peer| peer.ssh_allowed)
    }

    fn login_access(&self, person: &str, target_node: u64, account: &str) -> bool {
        target_node == self.installed.snapshot.node
            && self
                .installed
                .snapshot
                .grants
                .get(person)
                .is_some_and(|grant| {
                    (self.accounts)(account)
                        .is_some_and(|uid| grant.allows(account, uid, OrdinaryUids::host()))
                })
    }
}

impl<R: SessionRuntime> CertificateAccess for Guard<'_, R> {
    fn trusted_ca(&self) -> &Fingerprint {
        &self.installed.ca
    }

    fn identity(&self, certificate_digest: &[u8; 32]) -> Option<Identity> {
        self.issued(certificate_digest).map(|issued| Identity {
            person: issued.person.clone(),
            source_node: issued.source_node,
            source_address: issued.source_address,
        })
    }
}

// Engine traits are async by contract; refusing files needs no await.
#[allow(clippy::unused_async_trait_impl)]
impl<R: SessionRuntime> LoginGuard for Guard<'_, R> {
    type Files = NoFiles;

    async fn open_session(
        &self,
        login: &AuthorizedLogin<'_>,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> Result<Attachment, Refusal> {
        // The guard is held across the login so a revocation cannot slip in
        // between the check and the session; a hung login must not hold it
        // (and so every revocation) forever (J236 P1-1).
        tokio::time::timeout(
            OPEN_BOUND,
            self.runtime
                .open(&login.identity().person, login.account(), kind, terminal),
        )
        .await
        .map_err(|_| Refusal::LoginAccess)?
    }

    async fn open_files(&self, _: &AuthorizedLogin<'_>) -> Result<NoFiles, Refusal> {
        Err(Refusal::LoginAccess)
    }
}

/// The file service in slice 1: never constructed, refuses every request.
pub struct NoFiles;
impl russh_sftp::server::Handler for NoFiles {
    type Error = russh_sftp::protocol::StatusCode;
    fn unimplemented(&self) -> Self::Error {
        Self::Error::OpUnsupported
    }
}

#[cfg(test)]
#[path = "mesh_authority_tests.rs"]
mod tests;
