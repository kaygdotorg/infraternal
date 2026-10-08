//! Keeps bootstrap independent of an SSH engine; only the system OpenSSH adapter is selected by the brief.

use crate::{
    auth_order::{AuthProvider, Authentication},
    model::{Destination, Failure, MeshEvidence},
};
use std::{future::Future, path::Path, pin::Pin, sync::Arc};

/// Object-safe asynchronous boundary without adding an async-trait dependency.
pub type Operation<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;

/// Decrypted material has no Debug/Display/serde representation and is erased on drop.
pub struct Secret(Vec<u8>);
impl Secret {
    /// Trusted vault adapters transfer decrypted data only for this operation.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Network-only attempts exclude local identities; later material is requested lazily per attempt.
pub enum Credentials {
    Network,
    Automatic(Arc<dyn AuthProvider>),
    PrivateKey {
        key: Secret,
        passphrase: Option<Secret>,
    },
    Password(Secret),
}

/// Command input is private stdin; neither binary bytes nor secrets enter argv.
pub enum Input<'a> {
    Empty,
    Bytes(&'a [u8]),
    File(&'a Path),
}

/// Outputs are bounded and never automatically logged or serialized.
pub struct CommandOutput {
    pub stdout: Vec<u8>,
}

/// Every implementation must enforce strict host keys and cancellation-safe child cleanup.
pub trait SshTransport: Send + Sync {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>>;
}

/// A session owns ephemeral credentials and cleans them when its final owner drops it.
pub trait SshSession: Send + Sync {
    /// Public method evidence becomes available only after trusted authentication.
    fn authentication(&self) -> Option<Authentication> {
        None
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput>;
}

/// Shell quote trusted generated values; destinations are passed as SSH arguments separately.
#[must_use]
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
