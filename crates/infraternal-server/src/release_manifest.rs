//! Authenticates the hardened signer's canonical release identity and exact payload descriptor [224,226], #157.
use crate::release_verify::{ReleaseError, verify_digest, verify_signature};
use std::fs::File;

/// Verify the full identity-bearing signature with both compiled-in release keys.
/// Returns the authenticated version; the channel is derived from that version [226].
/// # Errors
/// Refuses malformed identity, mismatched channels/signatures, or changed payload bytes.
pub fn verify_release_manifest(
    file: &File,
    name: &str,
    manifest: &[u8],
    signature: &[u8],
) -> Result<String, ReleaseError> {
    verify_manifest_with_trust(
        file,
        name,
        manifest,
        signature,
        crate::release_verify::TRUST,
    )
}

/// Verify with an explicitly supplied trust set. Hosts should use the compiled-in
/// wrapper; this adapter permits independent in-memory signing fixtures and key-rotation validation.
/// # Errors
/// Refuses any noncanonical identity, invalid signature or payload digest.
pub fn verify_manifest_with_trust(
    file: &File,
    name: &str,
    manifest: &[u8],
    signature: &[u8],
    trust: &str,
) -> Result<String, ReleaseError> {
    let (version, sums) = identity(manifest)?;
    verify_signature(manifest, signature, trust)?;
    verify_digest(file, name, sums)?;
    Ok(version.to_owned())
}

fn identity(manifest: &[u8]) -> Result<(&str, &[u8]), ReleaseError> {
    if manifest.len() > 65_536 {
        return Err(ReleaseError::Checksums);
    }
    let text = std::str::from_utf8(manifest).map_err(|_| ReleaseError::Checksums)?;
    let rest = text
        .strip_prefix("infraternal-release-manifest-v1\nversion ")
        .ok_or(ReleaseError::Checksums)?;
    let (version, rest) = rest.split_once('\n').ok_or(ReleaseError::Checksums)?;
    let rest = rest
        .strip_prefix("channel ")
        .ok_or(ReleaseError::Checksums)?;
    let (channel, sums) = rest.split_once('\n').ok_or(ReleaseError::Checksums)?;
    if infraternal_plugin_api::release_version::channel(version) != Some(channel) {
        return Err(ReleaseError::Checksums);
    }
    Ok((version, sums.as_bytes()))
}

#[cfg(test)]
#[path = "release_manifest_tests.rs"]
mod tests;
