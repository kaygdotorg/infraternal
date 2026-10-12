//! Verifies bounded OpenSSH release signatures and hashes an already-open payload [184,224].
//!
//! Trust is compiled in. Parsing consumes every byte, and positional file reads preserve
//! the caller's descriptor offset for the authenticated update handoff (#154).
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::{
    pkey::{Id, PKey},
    sign::Verifier,
};
use sha2::{Digest, Sha256, Sha512};
use std::{fs::File, os::unix::fs::FileExt};

#[cfg(not(feature = "staging-trust"))]
pub(crate) const TRUST: &str = include_str!("../../../release/allowed_signers");
#[cfg(feature = "staging-trust")]
pub(crate) const TRUST: &str = include_str!(concat!(env!("OUT_DIR"), "/staging-trust"));
const NAMESPACE: &[u8] = b"infraternal-release";
const MAX_SUMS: usize = 65_536;
const MAX_SIGNATURE: usize = 1024;

/// Sanitized verification failure; no executable or crypto-engine diagnostics escape.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("the release signature is malformed")]
    Signature,
    #[error("the release signing key is not trusted")]
    Untrusted,
    #[error("the release signature does not match the checksums")]
    Invalid,
    #[error("the release checksums are malformed or do not name this binary")]
    Checksums,
    #[error("the binary does not match the signed checksum")]
    Digest,
    #[error("the binary could not be read")]
    Read,
}

/// Verify the signed manifest, then the named payload through this exact descriptor.
/// The caller must keep the file immutable until use; verification preserves its offset.
/// # Errors
/// Refuses malformed/unknown signatures, ambiguous checksums, mismatches and read failures.
pub fn verify_release_file(
    fd: &File,
    name: &str,
    sums: &[u8],
    sig: &[u8],
) -> Result<(), ReleaseError> {
    verify_with_trust(fd, name, sums, sig, TRUST)
}

pub(crate) fn verify_with_trust(
    fd: &File,
    name: &str,
    sums: &[u8],
    sig: &[u8],
    trust: &str,
) -> Result<(), ReleaseError> {
    let expected = checksum(name, sums)?;
    verify_signature(sums, sig, trust)?;
    verify_digest_expected(fd, expected)
}

pub(crate) fn verify_digest(fd: &File, name: &str, sums: &[u8]) -> Result<(), ReleaseError> {
    verify_digest_expected(fd, checksum(name, sums)?)
}

fn verify_digest_expected(fd: &File, expected: [u8; 32]) -> Result<(), ReleaseError> {
    let metadata = fd.metadata().map_err(|_| ReleaseError::Read)?;
    if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
        return Err(ReleaseError::Read);
    }
    let mut digest = Sha256::new();
    let mut offset = 0;
    let mut buffer = vec![0; 65_536];
    loop {
        let count = match fd.read_at(&mut buffer, offset) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ReleaseError::Read),
        };
        if offset + u64::try_from(count).map_err(|_| ReleaseError::Read)? > metadata.len() {
            return Err(ReleaseError::Read);
        }
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        offset += u64::try_from(count).map_err(|_| ReleaseError::Read)?;
    }
    if offset != metadata.len() {
        return Err(ReleaseError::Read);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != expected {
        return Err(ReleaseError::Digest);
    }
    Ok(())
}

fn checksum(name: &str, sums: &[u8]) -> Result<[u8; 32], ReleaseError> {
    if sums.is_empty() || sums.len() > MAX_SUMS || !sums.ends_with(b"\n") || !valid_name(name) {
        return Err(ReleaseError::Checksums);
    }
    let text = std::str::from_utf8(sums).map_err(|_| ReleaseError::Checksums)?;
    let mut found = None;
    let mut names = std::collections::HashSet::new();
    for line in text.lines() {
        let bytes = line.as_bytes();
        if bytes.len() < 67 || bytes.get(64..66) != Some(b"  ") {
            return Err(ReleaseError::Checksums);
        }
        let filename = line.get(66..).ok_or(ReleaseError::Checksums)?;
        if !valid_name(filename) || !names.insert(filename) {
            return Err(ReleaseError::Checksums);
        }
        let mut hash = [0; 32];
        for (out, pair) in hash.iter_mut().zip(bytes[..64].as_chunks::<2>().0) {
            *out = hex(pair[0])? * 16 + hex(pair[1])?;
        }
        if filename == name {
            found = Some(hash);
        }
    }
    found.ok_or(ReleaseError::Checksums)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v))
}
fn hex(v: u8) -> Result<u8, ReleaseError> {
    match v {
        b'0'..=b'9' => Ok(v - b'0'),
        b'a'..=b'f' => Ok(v - b'a' + 10),
        _ => Err(ReleaseError::Checksums),
    }
}

pub(crate) fn verify_signature(sums: &[u8], armor: &[u8], trust: &str) -> Result<(), ReleaseError> {
    if armor.len() > MAX_SIGNATURE {
        return Err(ReleaseError::Signature);
    }
    let text = std::str::from_utf8(armor).map_err(|_| ReleaseError::Signature)?;
    let body = text
        .strip_prefix("-----BEGIN SSH SIGNATURE-----\n")
        .and_then(|v| v.strip_suffix("-----END SSH SIGNATURE-----\n"))
        .ok_or(ReleaseError::Signature)?;
    let encoded: String = body.lines().collect();
    let decoded = B64.decode(&encoded).map_err(|_| ReleaseError::Signature)?;
    // Require the canonical 70-column armor emitted by ssh-keygen and the Worker.
    // Permissive whitespace handling would silently accept mutated signatures.
    let mut canonical = String::with_capacity(body.len());
    for line in encoded.as_bytes().chunks(70) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| ReleaseError::Signature)?);
        canonical.push('\n');
    }
    if canonical != body {
        return Err(ReleaseError::Signature);
    }
    let mut input = decoded.as_slice();
    if take(&mut input, 6)? != b"SSHSIG" || take(&mut input, 4)? != 1u32.to_be_bytes() {
        return Err(ReleaseError::Signature);
    }
    let public = field(&mut input, 51)?;
    let mut key = public;
    if field(&mut key, 11)? != b"ssh-ed25519" {
        return Err(ReleaseError::Signature);
    }
    let raw = field(&mut key, 32)?;
    if raw.len() != 32 || !key.is_empty() {
        return Err(ReleaseError::Signature);
    }
    if field(&mut input, NAMESPACE.len())? != NAMESPACE
        || !field(&mut input, 0)?.is_empty()
        || field(&mut input, 6)? != b"sha512"
    {
        return Err(ReleaseError::Signature);
    }
    let mut signature = field(&mut input, 83)?;
    if !input.is_empty() || field(&mut signature, 11)? != b"ssh-ed25519" {
        return Err(ReleaseError::Signature);
    }
    let raw_signature = field(&mut signature, 64)?;
    if raw_signature.len() != 64 || !signature.is_empty() {
        return Err(ReleaseError::Signature);
    }
    let trusted = trust
        .lines()
        .filter(|line| !line.starts_with('#'))
        .any(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            parts.len() == 5
                && parts[0] == "release@infraternal.com"
                && parts[1] == "namespaces=\"infraternal-release\""
                && parts[2] == "ssh-ed25519"
                && B64.decode(parts[3]).is_ok_and(|blob| blob == public)
        });
    if !trusted {
        return Err(ReleaseError::Untrusted);
    }
    let hash: [u8; 64] = Sha512::digest(sums).into();
    let mut message = b"SSHSIG".to_vec();
    for value in [NAMESPACE, b"", b"sha512", hash.as_slice()] {
        message.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| ReleaseError::Signature)?
                .to_be_bytes(),
        );
        message.extend_from_slice(value);
    }
    let key =
        PKey::public_key_from_raw_bytes(raw, Id::ED25519).map_err(|_| ReleaseError::Invalid)?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(|_| ReleaseError::Invalid)?;
    if !verifier
        .verify_oneshot(raw_signature, &message)
        .map_err(|_| ReleaseError::Invalid)?
    {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}
fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], ReleaseError> {
    let value = input.get(..size).ok_or(ReleaseError::Signature)?;
    *input = input.get(size..).ok_or(ReleaseError::Signature)?;
    Ok(value)
}
fn field<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], ReleaseError> {
    let size = u32::from_be_bytes(
        take(input, 4)?
            .try_into()
            .map_err(|_| ReleaseError::Signature)?,
    );
    let size = usize::try_from(size).map_err(|_| ReleaseError::Signature)?;
    if size > max {
        return Err(ReleaseError::Signature);
    }
    take(input, size)
}

#[cfg(test)]
#[path = "release_verify_tests.rs"]
mod tests;
