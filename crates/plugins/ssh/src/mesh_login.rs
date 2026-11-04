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
    /// Width in character cells.
    pub columns: u16,
    /// Height in character cells.
    pub rows: u16,
    /// Width in pixels; 0 if the client did not say.
    pub width_pixels: u16,
    /// Height in pixels; 0 if the client did not say.
    pub height_pixels: u16,
}

/// The classic 80 by 24 terminal with no pixel size.
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
    /// Terminal type the client asked for (the `TERM` value).
    pub name: String,
    /// Initial size.
    pub size: TerminalSize,
    /// Terminal modes the client requested, as opcode and value pairs.
    pub modes: Vec<(russh::Pty, u32)>,
}

/// One channel may request exactly one of these session kinds.
#[derive(Clone, Debug)]
pub enum SessionKind {
    /// An interactive login shell.
    Shell,
    /// Raw command bytes go to the shared runtime, never a daemon-side shell.
    Exec(Vec<u8>),
}

/// Bounded control messages remain separate from blocked terminal input.
#[derive(Debug)]
pub enum Control {
    /// The client changed its window size.
    Resize(TerminalSize),
    /// The client sent a signal for the session's process.
    Signal(russh::Sig),
}

/// The runtime reports completion after its output streams reach EOF.
#[derive(Clone, Copy, Debug)]
pub enum Exit {
    /// The process exit code.
    Status(u32),
}

/// A person-owned session attachment; dropping its streams detaches from the
/// shim. Runtime ownership/lifetime and reattachment remain with the shim.
pub struct Attachment {
    /// Bytes from the client into the session.
    pub input: Input,
    /// Standard output (and, with a terminal, everything the terminal prints).
    pub output: Output,
    /// Separate error stream; `None` when the session has a terminal and merges it.
    pub errors: Option<Output>,
    /// Resize and signal messages, kept apart from blocked input.
    pub control: mpsc::Sender<Control>,
    /// Fires once with the exit status after the output streams end.
    pub exit: oneshot::Receiver<Exit>,
}

/// Constructible only by certificate verification under a current guard.
/// There is deliberately no serializable/reusable authorization token.
pub struct AuthorizedLogin<'guard> {
    /// Ties the value's lifetime to the authority guard, so it cannot outlive a revocation check.
    _guard: std::marker::PhantomData<&'guard ()>,
    /// Who was admitted.
    identity: Identity,
    /// The host being logged into.
    target_node: u64,
    /// The OS account requested.
    account: String,
}

impl AuthorizedLogin<'_> {
    /// The registered identity the certificate resolved to.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Mesh node of the host being logged into.
    #[must_use]
    pub fn target_node(&self) -> u64 {
        self.target_node
    }
    /// Target OS account that login rules allowed.
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
    /// The file-transfer handler type, running as the person in the target account.
    type Files: russh_sftp::server::Handler + Send + 'static;

    /// Start or reattach a shell or command session for an authorized login.
    /// Refuses (e.g. on revocation) with a [`Refusal`].
    fn open_session(
        &self,
        login: &AuthorizedLogin<'_>,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> impl Future<Output = Result<Attachment, Refusal>> + Send;

    /// Create the file-transfer handler for an authorized login.
    fn open_files(
        &self,
        login: &AuthorizedLogin<'_>,
    ) -> impl Future<Output = Result<Self::Files, Refusal>> + Send;
}

/// No production implementation is provided until the shared login runtime lands.
pub trait LoginAuthority: Send + Sync + 'static {
    /// A held read view of current authority; revocation waits for it to drop.
    type Guard<'a>: LoginGuard
    where
        Self: 'a;

    /// Missing authority or a failed read must refuse, with no cached fallback.
    fn current(&self) -> impl Future<Output = Result<Self::Guard<'_>, Refusal>> + Send;
}

/// Verify under the same guard that will register the new runtime resource.
/// `account` is the requested account; the authority resolves it on this host,
/// refusing nonexistent/noncanonical accounts before evaluating login access.
/// The returned value borrows `guard`, so it cannot be kept after the guard is released.
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
