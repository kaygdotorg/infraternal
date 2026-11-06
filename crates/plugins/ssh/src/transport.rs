//! Keeps bootstrap independent of an SSH engine; only the system OpenSSH adapter is selected by the brief.
//!
//! Defines the traits and value types that host provisioning uses to talk to a
//! host: [`SshTransport`] opens an authenticated [`SshSession`] and can confirm a
//! first-contact host key; a session runs commands with a chosen [`Input`] and
//! returns a [`CommandOutput`]. Credentials travel as [`Secret`] values, which
//! cannot be printed, are not serialized for output and are zeroed when dropped.
//! Secrets and binary payloads go through stdin, never argv.

use crate::{
    auth_order::{AuthProvider, Authentication},
    model::{Destination, Failure, MeshEvidence},
};
use std::{future::Future, path::Path, pin::Pin, sync::Arc, time::Duration};

/// Object-safe asynchronous boundary without adding an async-trait dependency.
pub type Operation<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;

/// Decrypted material has no Debug/Display or output serialization and is erased on drop.
pub struct Secret(Vec<u8>);
impl Secret {
    /// Trusted vault adapters transfer decrypted data only for this operation.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Borrow the secret bytes. Callers must not log, print or copy them into argv or the environment.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
/// Overwrites the bytes with zeros before the memory is released.
impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Network-only attempts exclude local identities; later material is requested lazily per attempt.
pub enum Credentials {
    /// Authenticate with the mesh network identity only: no key, password or agent.
    Network,
    /// Try methods in order; the provider hands out each credential only when asked.
    Automatic(Arc<dyn AuthProvider>),
    /// A private key, with its passphrase if it is encrypted.
    PrivateKey {
        /// The private key file contents.
        key: Secret,
        /// Passphrase for `key`.
        passphrase: Option<Secret>,
    },
    /// An account password.
    Password(Secret),
}

/// Command input is private stdin; neither binary bytes nor secrets enter argv.
/// A public payload source has a known frame length before private invitation input.
pub enum PayloadInput<'a> {
    /// The payload is already in memory.
    Bytes(&'a [u8]),
    /// Stream the payload from a file (`path`) whose length `size` in bytes is known up front.
    File { path: &'a Path, size: u64 },
}

impl PayloadInput<'_> {
    /// Wire length is fixed before upload and excludes all subsequent private input.
    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File { size, .. } => *size,
        }
    }
}

/// Bootstrap transfers fail after 30 seconds without acknowledged byte movement.
/// Connection, verification and completion exchanges each receive their own bound.
pub const TRANSFER_IDLE: Duration = Duration::from_secs(30);

/// Public transfer choices never convey authority or diagnostic text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferChoice {
    /// Send the file uncompressed.
    Raw,
    /// Send it gzip-compressed.
    Gzip,
    /// Send it zstd-compressed.
    Zstd,
    /// Do not send anything; the host already has the exact payload.
    Reuse,
}
impl TransferChoice {
    /// Read the host's reply line, such as `TRANSFER gzip\n`. The match is
    /// exact (including the newline); anything else returns `None`.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"TRANSFER raw\n" => Some(Self::Raw),
            b"TRANSFER gzip\n" => Some(Self::Gzip),
            b"TRANSFER zstd\n" => Some(Self::Zstd),
            b"TRANSFER reuse\n" => Some(Self::Reuse),
            _ => None,
        }
    }
    /// The fixed word the staging program prints and selects on.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Reuse => "reuse",
        }
    }
}

/// What is written to a command's stdin.
pub enum Input<'a> {
    /// Public payload whose reader emits exact `PROGRESS <bytes>` receipts.
    /// Local SSH buffering never renews the inactivity deadline.
    Transfer(PayloadInput<'a>),
    /// A fixed public receipt selects a source before any invitation byte is sent.
    Negotiated {
        /// The uncompressed payload.
        raw: PayloadInput<'a>,
        /// Gzip-compressed form, if available.
        gzip: Option<&'a [u8]>,
        /// Zstd-compressed form, if available.
        zstd: Option<&'a [u8]>,
        /// Private invitation sent after the payload; never copied or concatenated.
        invitation: &'a [u8],
        /// Wait for verified staging before exposing private stdin to its reader.
        payload_ack: bool,
        /// An optional check-time encoding hint; private stdin still requires
        /// verified staging. None retains remote transfer selection.
        declared: Option<TransferChoice>,
    },
    /// Public payload first, then private invitation; never concatenate/copy secrets.
    PayloadAndInvitation {
        /// The public payload, sent first.
        payload: PayloadInput<'a>,
        /// The private invitation, sent after it.
        invitation: &'a [u8],
    },
    /// Release a fixed commit command only after authenticated terminal proof.
    Signal(tokio::sync::oneshot::Receiver<()>),
    /// No input; stdin is closed.
    Empty,
    /// These bytes, then end of input.
    Bytes(&'a [u8]),
    /// This file's contents, then end of input.
    File(&'a Path),
}

/// Outputs are bounded and never automatically logged or serialized.
pub struct CommandOutput {
    /// What the command wrote to stdout. Stderr is not kept.
    pub stdout: Vec<u8>,
}

/// The exact live owner capability is rechecked immediately before public pin publication.
pub trait ConfirmationAuthority: Send + Sync {
    /// Succeeds only if the person confirming still holds the right to do so now.
    /// An error aborts the confirmation and nothing is pinned.
    fn authorize(&self) -> Operation<'_, ()>;
}

/// Every implementation must enforce strict host keys and cancellation-safe child cleanup.
pub trait SshTransport: Send + Sync {
    /// Connect and authenticate to `destination`, returning a live session.
    /// An unknown host key fails closed; it is never trusted silently.
    /// `mesh` is public evidence about the destination's network identity.
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>>;
    /// Confirm only a previously observed first-contact key; default engines refuse.
    ///
    /// The two strings are the challenge id from the failed `open` and the
    /// fingerprint the person approved.
    fn confirm_host_key<'a>(
        &'a self,
        _: Destination,
        _: &'a str,
        _: &'a str,
        _: &'a dyn ConfirmationAuthority,
    ) -> Operation<'a, ()> {
        Box::pin(async {
            Err(Failure::unsupported(
                "SSH host-key confirmation is unavailable.",
            ))
        })
    }
}

/// A session owns ephemeral credentials and cleans them when its final owner drops it.
pub trait SshSession: Send + Sync {
    /// True only after this adapter can bridge an authenticated session.
    fn session_bridge(&self) -> bool {
        false
    }
    /// Open a duplex command on this connection, never authenticate a new one.
    fn stream<'a>(&'a self, _: &'a str) -> Operation<'a, crate::duplex::Duplex> {
        Box::pin(async {
            Err(Failure::unsupported(
                "The SSH terminal bridge is unavailable.",
            ))
        })
    }
    /// Authenticate only a fixed read-only check, optionally retaining its
    /// duplex channel for later public setup. Private input is never replayed.
    fn check_stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, (CommandOutput, Option<crate::install::Checked>)> {
        Box::pin(async move {
            self.run(script, Input::Empty)
                .await
                .map(|output| (output, None))
        })
    }
    /// Opt into fixed setup-step receipts; older adapters retain separate steps.
    fn setup_steps(&self) -> bool {
        false
    }
    /// Exact public host lookup used by this authenticated connection, when app-managed.
    fn trust_lookup(&self) -> Option<String> {
        None
    }
    /// Public method evidence becomes available only after trusted authentication.
    fn authentication(&self) -> Option<Authentication> {
        None
    }
    /// Run `script` on the host with `input` on stdin and return its bounded stdout.
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput>;
    /// Run one command under a caller-derived deadline when the adapter supports it.
    /// Adapters without per-command deadlines retain their configured bound.
    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        _timeout: Duration,
    ) -> Operation<'a, CommandOutput> {
        self.run(script, input)
    }
}

/// Shell quote trusted generated values; destinations are passed as SSH arguments separately.
///
/// The result is wrapped in single quotes, with each `'` and `\` replaced by a
/// double-quoted segment so the text survives several levels of shell
/// parsing unchanged and nothing in it is expanded.
#[must_use]
pub fn shell_quote(value: &str) -> String {
    // The supported login shells interpret backslashes differently inside
    // single quotes. Isolate both special characters in double-quoted segments
    // so each nesting level preserves the exact script bytes and no expansion.
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        match character {
            '\'' => quoted.push_str("'\"'\"'"),
            '\\' => quoted.push_str("'\"\\\\\"'"),
            _ => quoted.push(character),
        }
    }
    quoted.push('\'');
    quoted
}

// Input-only private material decoding; no Debug/Display or output serialization.
/// Reads a JSON string of at most 24576 bytes; longer input is refused.
impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Input;
        impl serde::de::Visitor<'_> for Input {
            type Value = Secret;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded credential string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Secret, E> {
                if value.len() > 24576 {
                    return Err(E::custom("credential input exceeds its bound"));
                }
                Ok(Secret::new(value.as_bytes().to_vec()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Secret, E> {
                let secret = Secret::new(value.into_bytes());
                if secret.expose().len() > 24576 {
                    return Err(E::custom("credential input exceeds its bound"));
                }
                Ok(secret)
            }
        }
        deserializer.deserialize_string(Input)
    }
}

#[cfg(test)]
#[path = "transport_secret_tests.rs"]
mod secret_tests;
