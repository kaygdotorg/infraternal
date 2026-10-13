//! Keeps bootstrap independent of an SSH engine; only the system OpenSSH adapter is selected by the brief.

use crate::{
    auth_order::{AuthProvider, Authentication},
    model::{Destination, Failure, MeshEvidence},
};
use std::{future::Future, path::Path, pin::Pin, sync::Arc};

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
/// A public payload source has a known frame length before private invitation input.
pub enum PayloadInput<'a> {
    Bytes(&'a [u8]),
    File { path: &'a Path, size: u64 },
}

/// Public transfer choices never convey authority or diagnostic text.
#[derive(Clone, Copy)]
pub enum TransferChoice {
    Raw,
    Gzip,
    Zstd,
    Reuse,
}
impl TransferChoice {
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
}

pub enum Input<'a> {
    /// A fixed public receipt selects a source before any invitation byte is sent.
    Negotiated {
        raw: PayloadInput<'a>,
        gzip: Option<&'a [u8]>,
        zstd: Option<&'a [u8]>,
        invitation: &'a [u8],
        /// Wait for verified staging before exposing private stdin to its reader.
        payload_ack: bool,
    },
    /// Public payload first, then private invitation; never concatenate/copy secrets.
    PayloadAndInvitation {
        payload: PayloadInput<'a>,
        invitation: &'a [u8],
    },
    /// Release a fixed commit command only after authenticated terminal proof.
    Signal(tokio::sync::oneshot::Receiver<()>),
    Empty,
    Bytes(&'a [u8]),
    File(&'a Path),
}

/// Outputs are bounded and never automatically logged or serialized.
pub struct CommandOutput {
    pub stdout: Vec<u8>,
}

/// The exact live owner capability is rechecked immediately before public pin publication.
pub trait ConfirmationAuthority: Send + Sync {
    fn authorize(&self) -> Operation<'_, ()>;
}

/// Every implementation must enforce strict host keys and cancellation-safe child cleanup.
pub trait SshTransport: Send + Sync {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>>;
    /// Confirm only a previously observed first-contact key; default engines refuse.
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
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput>;
}

/// Shell quote trusted generated values; destinations are passed as SSH arguments separately.
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
