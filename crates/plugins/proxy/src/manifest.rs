//! Verifies the signed release metadata before a node accepts Traefik bytes [#281].

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
};

pub const TRAEFIK_VERSION: &str = "3.7.17";
pub const MAX_COMPONENT_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_COMPONENT_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIGNED_RELEASE_METADATA_BYTES: usize = 64 * 1024;
const MAX_RELEASE_SIGNATURE_BYTES: usize = 16 * 1024;
const ALLOWED_SIGNERS: &str = include_str!("../../../../release/allowed_signers");

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    pub component: String,
    pub version: String,
    pub release_version: String,
    pub os: String,
    pub arch: String,
    pub archive_filename: String,
    pub archive_url: String,
    pub mirror_path: String,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub executable: String,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub license: String,
}

impl ComponentManifest {
    /// Check every signed field against the pinned Traefik asset for this node.
    ///
    /// # Errors
    /// Returns an error when the manifest is outside the pinned target or byte policy.
    pub fn validate_for(&self, os: &str, arch: &str) -> io::Result<()> {
        let target_supported =
            matches!(os, "linux" | "darwin") && matches!(arch, "amd64" | "arm64");
        let filename = format!("traefik_v{TRAEFIK_VERSION}_{os}_{arch}.tar.gz");
        let upstream = format!(
            "https://github.com/traefik/traefik/releases/download/v{TRAEFIK_VERSION}/{filename}"
        );
        let mirror_path = format!(
            "components/{}/proxy/{os}/{arch}/{filename}",
            self.release_version
        );
        if !target_supported
            || self.component != "traefik"
            || self.version != TRAEFIK_VERSION
            || self.release_version != self.release_version.trim()
            || !valid_release_version(&self.release_version)
            || self.os != os
            || self.arch != arch
            || self.archive_filename != filename
            || self.archive_url != upstream
            || self.mirror_path != mirror_path
            || self.executable != "traefik"
            || self.license != "MIT"
            || !valid_digest(&self.archive_sha256)
            || !valid_digest(&self.executable_sha256)
            || self.archive_size == 0
            || self.archive_size > MAX_COMPONENT_ARCHIVE_BYTES
            || self.executable_size == 0
            || self.executable_size > MAX_COMPONENT_EXECUTABLE_BYTES
        {
            return Err(invalid_data(
                "component manifest does not match release policy",
            ));
        }
        Ok(())
    }

    /// Stable basename listed in the signed product release checksum file.
    #[must_use]
    pub fn signed_filename(os: &str, arch: &str) -> String {
        format!("proxy-traefik-{os}-{arch}.json")
    }
}

/// A manifest whose bytes are covered by a verified product release signature.
#[derive(Clone, Debug)]
pub struct VerifiedComponentManifest(ComponentManifest);

impl VerifiedComponentManifest {
    /// Read the immutable manifest fields after signature and target validation.
    #[must_use]
    pub const fn manifest(&self) -> &ComponentManifest {
        &self.0
    }
}

/// Verifies the existing SSH signature over a release checksum list.
pub trait ComponentManifestVerifier {
    /// Refuse unless the checksum list has a trusted release signature.
    ///
    /// # Errors
    /// Returns an error when the release signature is missing, malformed or untrusted.
    fn verify(&self, signed_checksums: &[u8], signature: &[u8]) -> io::Result<()>;
}

/// Uses the release pipeline's embedded public signers; no new key or crypto format is introduced.
pub struct OpenSshManifestVerifier;

impl ComponentManifestVerifier for OpenSshManifestVerifier {
    fn verify(&self, signed_checksums: &[u8], signature: &[u8]) -> io::Result<()> {
        if signed_checksums.len() > MAX_SIGNED_RELEASE_METADATA_BYTES
            || signature.is_empty()
            || signature.len() > MAX_RELEASE_SIGNATURE_BYTES
        {
            return Err(invalid_data("release signature input exceeds policy"));
        }
        let allowed_signers = TemporaryFile::write(ALLOWED_SIGNERS.as_bytes())?;
        let signature = TemporaryFile::write(signature)?;
        let mut child = Command::new("ssh-keygen")
            .args([
                "-Y",
                "verify",
                "-f",
                allowed_signers
                    .path
                    .to_str()
                    .ok_or_else(|| invalid_data("temporary allowed-signers path is not UTF-8"))?,
                "-I",
                "release@infraternal.com",
                "-n",
                "infraternal-release",
                "-s",
                signature
                    .path
                    .to_str()
                    .ok_or_else(|| invalid_data("temporary signature path is not UTF-8"))?,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("signature verifier stdin unavailable"))?
            .write_all(signed_checksums);
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if child.wait()?.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "release checksum signature is invalid",
            ))
        }
    }
}

/// Verifies the release signature and manifest digest before parsing signed fields.
///
/// # Errors
/// Returns an error when the signer, signed digest, JSON fields or platform policy is invalid.
pub fn verify_component_manifest(
    manifest_bytes: &[u8],
    manifest_filename: &str,
    signed_checksums: &[u8],
    signature: &[u8],
    os: &str,
    arch: &str,
    verifier: &dyn ComponentManifestVerifier,
) -> io::Result<VerifiedComponentManifest> {
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAX_SIGNED_RELEASE_METADATA_BYTES
        || signed_checksums.len() > MAX_SIGNED_RELEASE_METADATA_BYTES
        || manifest_filename != ComponentManifest::signed_filename(os, arch)
    {
        return Err(invalid_data("component manifest input exceeds policy"));
    }
    verifier.verify(signed_checksums, signature)?;
    let checksums = parse_checksums(signed_checksums)?;
    let manifest_digest = format!("{:x}", Sha256::digest(manifest_bytes));
    if checksums.get(manifest_filename) != Some(&manifest_digest) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "component manifest is not covered by the signed release checksum list",
        ));
    }
    let manifest: ComponentManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| invalid_data("component manifest is invalid JSON"))?;
    manifest.validate_for(os, arch)?;
    Ok(VerifiedComponentManifest(manifest))
}

fn parse_checksums(checksums: &[u8]) -> io::Result<BTreeMap<String, String>> {
    let checksums = std::str::from_utf8(checksums)
        .map_err(|_| invalid_data("release checksum list is not UTF-8"))?;
    let mut parsed = BTreeMap::new();
    for line in checksums.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(digest), Some(name), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(invalid_data("release checksum list has an invalid row"));
        };
        if !valid_digest(digest)
            || name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
            || parsed.insert(name.to_owned(), digest.to_owned()).is_some()
        {
            return Err(invalid_data(
                "release checksum list has an unsafe or duplicate name",
            ));
        }
    }
    Ok(parsed)
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_release_version(version: &str) -> bool {
    let stable = version.split('.').count() == 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    let edge = version
        .strip_prefix("edge-")
        .is_some_and(|value| value.len() == 16 && value.as_bytes().get(8) == Some(&b'T'));
    stable || edge
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn write(bytes: &[u8]) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "infraternal-signature-{}.tmp",
            uuid::Uuid::new_v4()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
