//! The local key socket that lets plain `ssh` sign with a person's mesh certificate [D235], #221.
//!
//! OpenSSH reaches it through `IdentityAgent` in the mesh `ssh_config.d` file.
//! This is a deliberately small subset of the SSH agent protocol
//! (draft-ietf-sshm-ssh-agent): it lists one identity, the person's
//! certificate, and signs with that certificate's in-memory key. It never
//! adds, removes, locks or exports keys.
//!
//! Invariants (security review):
//! - Every message is length-checked before it is read ([`MAX_MESSAGE`]),
//!   every field is bounds-checked, and trailing bytes refuse the message.
//!   A malformed message ends the connection.
//! - Only `REQUEST_IDENTITIES`, `SIGN_REQUEST` and the
//!   `session-bind@openssh.com` extension are understood; everything else
//!   gets `FAILURE`.
//! - A signature is made only for the exact certificate blob this socket
//!   listed. Any other key blob gets `FAILURE`.
//! - Forwarded requests are refused (D235). A connection signs only after it
//!   declared itself with `session-bind@openssh.com` and the forwarding flag
//!   clear; one that never declared itself, or declared forwarding, never
//!   signs. OpenSSH 8.9 and later send that binding, so 8.9 is the minimum
//!   client for mesh SSH (J181 M5 on #221). Without the default-deny an
//!   older client's forwarded request would look like a direct one.
//! - Who may connect is decided before this code runs, by the socket
//!   owner's peer-credential check ([`may_ask`]).

use infraternal_plugin_api::login_access::OrdinaryUids;
use russh::keys::{Certificate, PrivateKey, signature::Signer, ssh_key::Signature};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message read from a client. Real requests are a few kilobytes;
/// a sign request carries a session identifier and a small authentication body.
pub const MAX_MESSAGE: usize = 256 * 1024;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;

/// One person's identity on this machine: the certificate and its key.
pub struct PersonKey {
    pub certificate: Certificate,
    pub key: PrivateKey,
}

/// The asking-process check: may the local account `uid` use the key of the
/// person who added this machine? Only the account the machine was added
/// with (`added_with`, J181 M3: the narrow reading of D235 Q2a until the
/// owner says otherwise), and only when it is an ordinary account: root and
/// system accounts never act as a person.
#[must_use]
pub fn may_ask(uid: u32, added_with: Option<u32>, ordinary: OrdinaryUids) -> bool {
    uid != 0 && ordinary.contains(uid) && added_with == Some(uid)
}

struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }
    fn u32(&mut self) -> Option<u32> {
        let (bytes, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*bytes))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.u32()?).ok()?;
        if length > self.0.len() {
            return None;
        }
        let (string, rest) = self.0.split_at(length);
        self.0 = rest;
        Some(string)
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

/// Per-connection protocol state.
#[derive(Default)]
pub struct Session {
    /// A non-forwarding `session-bind` arrived.
    bound: bool,
    /// Any `session-bind` with the forwarding flag arrived; permanent.
    forwarded: bool,
}

impl Session {
    fn may_sign(&self) -> bool {
        self.bound && !self.forwarded
    }
}

impl Session {
    /// Answer one message body (without its length prefix). `None` means the
    /// message was malformed and the connection must end.
    pub fn answer(&mut self, body: &[u8], identity: Option<&PersonKey>) -> Option<Vec<u8>> {
        let mut fields = Fields(body);
        let kind = fields.byte()?;
        let mut reply = Vec::new();
        match kind {
            REQUEST_IDENTITIES => {
                if !fields.done() {
                    return None;
                }
                reply.push(IDENTITIES_ANSWER);
                match identity {
                    Some(identity) if !self.forwarded => {
                        reply.extend_from_slice(&1_u32.to_be_bytes());
                        put_string(&mut reply, &identity.certificate.to_bytes().ok()?)?;
                        put_string(&mut reply, b"infraternal mesh")?;
                    }
                    _ => reply.extend_from_slice(&0_u32.to_be_bytes()),
                }
            }
            SIGN_REQUEST => {
                let blob = fields.string()?;
                let data = fields.string()?;
                let _flags = fields.u32()?;
                if !fields.done() {
                    return None;
                }
                let signature = identity
                    .filter(|_| self.may_sign())
                    .filter(|identity| {
                        identity
                            .certificate
                            .to_bytes()
                            .is_ok_and(|listed| listed == blob)
                    })
                    .and_then(|identity| {
                        let signature: Signature = identity.key.try_sign(data).ok()?;
                        let mut encoded = Vec::new();
                        put_string(&mut encoded, signature.algorithm().as_str().as_bytes())?;
                        put_string(&mut encoded, signature.as_bytes())?;
                        Some(encoded)
                    });
                match signature {
                    Some(encoded) => {
                        reply.push(SIGN_RESPONSE);
                        put_string(&mut reply, &encoded)?;
                    }
                    None => reply.push(FAILURE),
                }
            }
            EXTENSION => {
                let name = fields.string()?;
                if name == b"session-bind@openssh.com" {
                    let _host_key = fields.string()?;
                    let _session = fields.string()?;
                    let _signature = fields.string()?;
                    let forwarding = fields.byte()?;
                    if !fields.done() {
                        return None;
                    }
                    // Any nonzero flag counts as forwarding: when in doubt, refuse.
                    if forwarding == 0 {
                        self.bound = true;
                    } else {
                        self.forwarded = true;
                    }
                    reply.push(SUCCESS);
                } else {
                    reply.push(FAILURE);
                }
            }
            _ => reply.push(FAILURE),
        }
        Some(reply)
    }
}

/// Serve one accepted connection until the client closes it or sends a
/// malformed message. `identity` is read per message, so a renewed
/// certificate applies to later requests at once.
///
/// # Errors
/// Returns I/O errors and refuses oversized or malformed messages.
pub async fn serve<S, F>(mut stream: S, identity: F) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn() -> Option<std::sync::Arc<PersonKey>>,
{
    let mut session = Session::default();
    let mut body = Vec::new();
    loop {
        let mut length = [0; 4];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_MESSAGE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
        let current = identity();
        let reply = session
            .answer(&body, current.as_deref())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let mut framed = Vec::with_capacity(4 + reply.len());
        put_string(&mut framed, &reply).ok_or(std::io::ErrorKind::InvalidData)?;
        stream.write_all(&framed).await?;
    }
}

#[cfg(test)]
#[path = "mesh_keys_tests.rs"]
mod tests;
