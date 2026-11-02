//! Connects verified mesh logins to the shared person/session runtime [D235,D240].
//!
//! This module owns no access rules, operating-system login, shell process or
//! filesystem credentials. An authority guard serializes revocation with each
//! open. Implementations must use the same authority and runtime as other shell
//! and file entry points; a successful SSH authentication is never an open token.

use std::{future::Future, net::IpAddr, pin::Pin};

use russh::keys::Certificate;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::{
    mesh_admission::{LoginRequest, Refusal},
    mesh_certificate::{self, CertificateAccess, Identity},
};

/// An asynchronous stream owned by an attachment, never a shell owned by SSH.
pub type Input = Pin<Box<dyn AsyncWrite + Send>>;
/// Session output is read independently of its input and control messages.
pub type Output = Pin<Box<dyn AsyncRead + Send>>;

/// Validated terminal dimensions. Pixel dimensions are optional SSH metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
    pub width_pixels: u16,
    pub height_pixels: u16,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            columns: 80,
            rows: 24,
            width_pixels: 0,
            height_pixels: 0,
        }
    }
}

/// Terminal setup is immutable after a shell/exec open; resize uses control.
#[derive(Clone, Debug)]
pub struct Terminal {
    pub name: String,
    pub size: TerminalSize,
    pub modes: Vec<(russh::Pty, u32)>,
}

/// One channel may request exactly one of these session kinds.
#[derive(Clone, Debug)]
pub enum SessionKind {
    Shell,
    /// Raw command bytes go to the shared runtime, never a daemon-side shell.
    Exec(Vec<u8>),
}

/// Bounded control messages remain separate from blocked terminal input.
#[derive(Debug)]
pub enum Control {
    Resize(TerminalSize),
    Signal(russh::Sig),
}

/// The runtime reports completion after its output streams reach EOF.
#[derive(Clone, Copy, Debug)]
pub enum Exit {
    Status(u32),
}

/// A person-owned session attachment; dropping its streams detaches from the
/// shim. Runtime ownership/lifetime and reattachment remain with the shim.
pub struct Attachment {
    pub input: Input,
    pub output: Output,
    pub errors: Option<Output>,
    pub control: mpsc::Sender<Control>,
    pub exit: oneshot::Receiver<Exit>,
}

/// Constructible only by certificate verification under a current guard.
/// There is deliberately no serializable/reusable authorization token.
pub struct AuthorizedLogin<'guard> {
    _guard: std::marker::PhantomData<&'guard ()>,
    identity: Identity,
    target_node: u64,
    account: String,
}

impl AuthorizedLogin<'_> {
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    #[must_use]
    pub fn target_node(&self) -> u64 {
        self.target_node
    }
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
}

/// Current shared authority plus a session spawner in the target user's runtime.
///
/// The guard must stay held until the runtime registers the session/file handle.
/// Revocation acquires the corresponding write guard and retires existing handles.
/// The runtime must check person ownership on every reattachment. File handlers
/// execute inside that person's target-account context, never as the SSH daemon.
pub trait LoginGuard: CertificateAccess + Send + Sync {
    type Files: russh_sftp::server::Handler + Send + 'static;

    fn open_session(
        &self,
        login: &AuthorizedLogin<'_>,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> impl Future<Output = Result<Attachment, Refusal>> + Send;

    fn open_files(
        &self,
        login: &AuthorizedLogin<'_>,
    ) -> impl Future<Output = Result<Self::Files, Refusal>> + Send;
}

/// No production implementation is provided until the shared login runtime lands.
pub trait LoginAuthority: Send + Sync + 'static {
    type Guard<'a>: LoginGuard
    where
        Self: 'a;

    /// Missing authority or a failed read must refuse, with no cached fallback.
    fn current(&self) -> impl Future<Output = Result<Self::Guard<'_>, Refusal>> + Send;
}

/// Verify under the same guard that will register the new runtime resource.
/// `account` is the requested account; the authority resolves it on this host,
/// refusing nonexistent/noncanonical accounts before evaluating login access.
///
/// # Errors
/// Refuses invalid certificates, stale identity or either missing access rule.
pub fn authorize<'guard>(
    guard: &'guard impl LoginGuard,
    certificate: &Certificate,
    source: IpAddr,
    target_node: u64,
    account: &str,
    now: u64,
) -> Result<AuthorizedLogin<'guard>, Refusal> {
    let identity = mesh_certificate::verify(
        guard,
        certificate,
        LoginRequest {
            source_address: source,
            target_node,
            target_account: account,
        },
        now,
    )?;
    Ok(AuthorizedLogin {
        _guard: std::marker::PhantomData,
        identity,
        target_node,
        account: account.to_owned(),
    })
}
