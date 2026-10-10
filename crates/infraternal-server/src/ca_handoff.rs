//! Transfers D168 signing material only through an anonymous socket inherited by the same PID across exec [217], #154.

use crate::ca::{CaError, CaKeySource, CaMaterial};
use crate::ca_memory::MemoryCaSource;
use nix::sys::socket::{getsockopt, setsockopt, sockopt};
use openssl::{
    pkey::{Id, PKey},
    x509::X509,
};
use std::{io::Write, os::unix::net::UnixStream};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"IFCA\x01\0\0\0";
const HEADER: usize = 42;
const MAX_ISSUER: usize = 2048;

/// Prepare stdin for an exec successor. Only this socket's receiving endpoint
/// crosses exec; there is no pathname, token, secret argv or secret environment.
/// The small frame fits the socket buffer before exec, so no courier is needed.
/// # Errors
/// Refuses locked sources, non-Ed25519 material or failed local IPC.
pub fn prepare(source: &dyn CaKeySource) -> Result<UnixStream, CaError> {
    // A handoff must not create a plaintext signing seed in a crash dump or
    // expose its inherited descriptor through same-UID process inspection.
    nix::sys::prctl::set_dumpable(false).map_err(|_| CaError)?;
    let material = source.load()?;
    let frame = encode(&material)?;
    let (mut sender, receiver) = UnixStream::pair().map_err(|_| CaError)?;
    sender
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|_| CaError)?;
    sender.write_all(&frame).map_err(|_| CaError)?;
    // Closing the writer gives an exact EOF boundary, rejects trailing data and
    // releases its descriptor before any subprocess can inherit it.
    drop(sender);
    Ok(receiver)
}

fn encode(material: &CaMaterial) -> Result<Zeroizing<Vec<u8>>, CaError> {
    let key = material.handoff_key();
    if key.id() != Id::ED25519 {
        return Err(CaError);
    }
    let seed = Zeroizing::new(key.raw_private_key().map_err(|_| CaError)?);
    let issuer = material.issuer().to_der().map_err(|_| CaError)?;
    if seed.len() != 32 || issuer.len() > MAX_ISSUER {
        return Err(CaError);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(HEADER + issuer.len()));
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(
        &u16::try_from(issuer.len())
            .map_err(|_| CaError)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&seed);
    frame.extend_from_slice(&issuer);
    Ok(frame)
}

/// Bounded frame parser, also used by the property corpus. No diagnostics may
/// contain frame bytes. Parsed material still requires retained-issuer validation.
/// # Errors
/// Refuses unknown versions, short/oversized/trailing frames or invalid material.
pub fn parse(frame: &[u8]) -> Result<CaMaterial, CaError> {
    if frame.len() < HEADER || frame.len() > HEADER + MAX_ISSUER || &frame[..8] != MAGIC {
        return Err(CaError);
    }
    let length = usize::from(u16::from_be_bytes([frame[8], frame[9]]));
    if length == 0 || length > MAX_ISSUER || frame.len() != HEADER + length {
        return Err(CaError);
    }
    let key =
        PKey::private_key_from_raw_bytes(&frame[10..HEADER], Id::ED25519).map_err(|_| CaError)?;
    let issuer = X509::from_der(&frame[HEADER..]).map_err(|_| CaError)?;
    // Require exact DER consumption; the certificate decoder may accept a
    // valid prefix followed by extra bytes. Never extend the frame implicitly.
    if issuer.to_der().map_err(|_| CaError)? != frame[HEADER..] {
        return Err(CaError);
    }
    let material = CaMaterial::new(key, issuer);
    crate::ca::CertificateAuthority::from_material(material.clone())?;
    Ok(material)
}

/// Import a requested exec handoff from stdin, then replace stdin with /dev/null
/// before the runtime spawns the embedded infraternal agent. Failure stays locked.
/// # Errors
/// Refuses any channel not created by this UID and this same pre-exec PID.
pub fn accept_stdin(source: &MemoryCaSource) -> Result<(), CaError> {
    receive_stdin()?.install(source)
}

/// Validated in-memory import held while retained public configuration loads.
/// Its material can only be installed against the exact retained issuer.
pub struct Received {
    material: CaMaterial,
}
impl Received {
    /// Publish only after the cold source validates the retained issuer.
    /// # Errors
    /// Refuses mismatched public trust or poisoned source state.
    pub fn install(self, source: &MemoryCaSource) -> Result<(), CaError> {
        source.install(self.material)
    }
}

/// Consume and detach stdin before any cold configuration work can fail.
/// # Errors
/// Refuses invalid kernel peer credentials, frames or descriptor cleanup.
pub fn receive_stdin() -> Result<Received, CaError> {
    let input = std::io::stdin();
    let result = nix::sys::prctl::set_dumpable(false)
        .map_err(|_| CaError)
        .and_then(|()| receive(&input));
    let null = std::fs::File::open("/dev/null").map_err(|_| CaError)?;
    nix::unistd::dup2_stdin(null).map_err(|_| CaError)?;
    result.map(|material| Received { material })
}

fn receive(fd: &impl std::os::fd::AsFd) -> Result<CaMaterial, CaError> {
    let peer = getsockopt(fd, sockopt::PeerCredentials).map_err(|_| CaError)?;
    if peer.uid() != nix::unistd::Uid::effective().as_raw()
        || peer.pid() != nix::unistd::Pid::this().as_raw()
    {
        return Err(CaError);
    }
    setsockopt(
        fd,
        sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::new(2, 0),
    )
    .map_err(|_| CaError)?;
    let mut bytes = Zeroizing::new(vec![0; HEADER + MAX_ISSUER + 1]);
    let mut used = 0;
    loop {
        if used == bytes.len() {
            return Err(CaError);
        }
        let count = nix::unistd::read(fd, &mut bytes[used..]).map_err(|_| CaError)?;
        if count == 0 {
            break;
        }
        used += count;
    }
    parse(&bytes[..used])
}

#[cfg(test)]
#[path = "ca_handoff_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ca_handoff_shipping_tests.rs"]
mod shipping_tests;
