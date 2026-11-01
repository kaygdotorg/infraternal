//! Verifies component manifests with the repository's compiled OpenSSH release trust [#281].

use crate::manifest::ComponentManifestVerifier;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::{pkey::{Id, PKey}, sign::Verifier};
use sha2::{Digest, Sha512};
use std::io;

const TRUST: &str = include_str!("../../../../release/allowed_signers");
const NAMESPACE: &[u8] = b"infraternal-release";
const MAX_CHECKSUM_BYTES: usize = 65_536;
const MAX_SIGNATURE_BYTES: usize = 16_384;

/// OpenSSH Ed25519 verifier bound to the release identities shipped with the infraternal agent.
pub struct OpenSshReleaseVerifier;

impl ComponentManifestVerifier for OpenSshReleaseVerifier {
    fn verify(&self, signed_checksums: &[u8], signature: &[u8]) -> io::Result<()> {
        verify_signature(signed_checksums, signature, TRUST)
    }
}

fn verify_signature(sums: &[u8], armor: &[u8], trust: &str) -> io::Result<()> {
    if sums.is_empty() || sums.len() > MAX_CHECKSUM_BYTES || armor.len() > MAX_SIGNATURE_BYTES {
        return Err(refused());
    }
    let text = std::str::from_utf8(armor).map_err(|_| refused())?;
    let body = text
        .strip_prefix("-----BEGIN SSH SIGNATURE-----\n")
        .and_then(|value| value.strip_suffix("-----END SSH SIGNATURE-----\n"))
        .ok_or_else(refused)?;
    let encoded: String = body.lines().collect();
    let decoded = B64.decode(&encoded).map_err(|_| refused())?;
    let mut canonical = String::with_capacity(body.len());
    for line in encoded.as_bytes().chunks(70) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| refused())?);
        canonical.push('\n');
    }
    if canonical != body {
        return Err(refused());
    }

    let mut input = decoded.as_slice();
    if take(&mut input, 6)? != b"SSHSIG" || take(&mut input, 4)? != 1_u32.to_be_bytes() {
        return Err(refused());
    }
    let public = field(&mut input, 51)?;
    let mut key = public;
    if field(&mut key, 11)? != b"ssh-ed25519" {
        return Err(refused());
    }
    let raw_key = field(&mut key, 32)?;
    if raw_key.len() != 32 || !key.is_empty() {
        return Err(refused());
    }
    if field(&mut input, NAMESPACE.len())? != NAMESPACE
        || !field(&mut input, 0)?.is_empty()
        || field(&mut input, 6)? != b"sha512"
    {
        return Err(refused());
    }
    let mut signature = field(&mut input, 83)?;
    if !input.is_empty() || field(&mut signature, 11)? != b"ssh-ed25519" {
        return Err(refused());
    }
    let raw_signature = field(&mut signature, 64)?;
    if raw_signature.len() != 64 || !signature.is_empty() {
        return Err(refused());
    }
    if !is_trusted_key(trust, public) {
        return Err(refused());
    }

    let hash = Sha512::digest(sums);
    let mut message = b"SSHSIG".to_vec();
    for value in [NAMESPACE, b"", b"sha512", hash.as_slice()] {
        message.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        message.extend_from_slice(value);
    }
    let key = PKey::public_key_from_raw_bytes(raw_key, Id::ED25519).map_err(|_| refused())?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(|_| refused())?;
    if verifier
        .verify_oneshot(raw_signature, &message)
        .map_err(|_| refused())?
    {
        Ok(())
    } else {
        Err(refused())
    }
}

fn is_trusted_key(trust: &str, public_blob: &[u8]) -> bool {
    trust.lines().filter(|line| !line.starts_with('#')).any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() == 5
            && fields[0] == "release@infraternal.com"
            && fields[1] == "namespaces=\"infraternal-release\""
            && fields[2] == "ssh-ed25519"
            && B64.decode(fields[3]).is_ok_and(|blob| blob == public_blob)
    })
}

fn take<'a>(input: &mut &'a [u8], size: usize) -> io::Result<&'a [u8]> {
    let value = input.get(..size).ok_or_else(refused)?;
    *input = input.get(size..).ok_or_else(refused)?;
    Ok(value)
}

fn field<'a>(input: &mut &'a [u8], maximum: usize) -> io::Result<&'a [u8]> {
    let length = u32::from_be_bytes(take(input, 4)?.try_into().map_err(|_| refused())?);
    let length = usize::try_from(length).map_err(|_| refused())?;
    if length > maximum {
        return Err(refused());
    }
    take(input, length)
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "component release signature refused",
    )
}

#[cfg(test)]
#[path = "release_signature_tests.rs"]
mod tests;
