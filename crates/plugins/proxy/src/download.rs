//! Streams a release-signed component bundle from the mirror with verified upstream fallback [#281].

use crate::{
    installer::ComponentInstaller,
    manifest::{
        ComponentManifest, ComponentManifestVerifier, MAX_COMPONENT_ARCHIVE_BYTES,
        VerifiedComponentManifest, verify_component_manifest,
    },
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};
use url::Url;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;

/// A bounded streaming transport for release metadata and component bytes.
pub trait ComponentTransport {
    /// Copy one response body to the supplied sink, refusing data beyond its signed limit.
    ///
    /// # Errors
    /// Returns a transport error, or an invalid-data error when the response exceeds `limit`.
    fn download(&self, url: &Url, limit: u64, output: &mut dyn Write) -> io::Result<()>;
}

/// Streams HTTPS bodies through the host's installed transfer utility without writing them to logs.
///
/// The signed manifest and installer enforce the content identity and byte limit; this adapter
/// contributes HTTPS-only transport and never receives credentials.
pub struct CurlTransport;

impl ComponentTransport for CurlTransport {
    fn download(&self, url: &Url, limit: u64, output: &mut dyn Write) -> io::Result<()> {
        if url.scheme() != "https" || url.host_str().is_none() || limit == 0 {
            return Err(invalid_input(
                "component download requires HTTPS and a positive limit",
            ));
        }
        let mut child = Command::new("curl")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-q",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-redirs",
                "3",
                "--connect-timeout",
                "15",
                "--max-time",
                "300",
                "--max-filesize",
            ])
            .arg(limit.to_string())
            .arg("--url")
            .arg(url.as_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("component transport output unavailable"))?;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = match stdout.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            if count == 0 {
                break;
            }
            if let Err(error) = output.write_all(&buffer[..count]) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTPS component download failed",
            ))
        }
    }
}

/// Acquires signed component metadata from the configured mirror and installs verified bytes.
pub struct ComponentDownloader<T> {
    mirror: Url,
    transport: T,
}

impl<T: ComponentTransport> ComponentDownloader<T> {
    /// Create a downloader rooted at the configured immutable release mirror.
    ///
    /// # Errors
    /// Returns an invalid-input error when the mirror URL is not an HTTPS base URL.
    pub fn new(mut mirror: Url, transport: T) -> io::Result<Self> {
        if mirror.scheme() != "https"
            || mirror.host_str().is_none()
            || !mirror.username().is_empty()
            || mirror.password().is_some()
            || mirror.query().is_some()
            || mirror.fragment().is_some()
        {
            return Err(invalid_input(
                "component mirror must be a plain HTTPS base URL",
            ));
        }
        if !mirror.path().ends_with('/') {
            mirror
                .path_segments_mut()
                .map_err(|()| invalid_input("component mirror URL cannot hold a path"))?
                .push("");
        }
        Ok(Self { mirror, transport })
    }

    /// Verify release metadata, then stream the mirror archive or its signed upstream fallback.
    ///
    /// # Errors
    /// Returns an error when signed metadata, target policy, transport or installation validation fails.
    pub fn install(
        &self,
        installer: &ComponentInstaller,
        release_version: &str,
        os: &str,
        arch: &str,
        manifest_verifier: &dyn ComponentManifestVerifier,
    ) -> io::Result<PathBuf> {
        if !crate::manifest::valid_release_version(release_version) {
            return Err(invalid_input("component release version is invalid"));
        }
        if let Some(executable) =
            installer.find_installed(release_version, os, arch, manifest_verifier)?
        {
            return Ok(executable);
        }
        let release_mirror = self
            .mirror
            .join(&format!("{release_version}/"))
            .map_err(io::Error::other)?;
        let manifest_filename = ComponentManifest::signed_filename(os, arch);
        let manifest_bytes =
            self.fetch_metadata(&release_mirror, &manifest_filename, MAX_MANIFEST_BYTES)?;
        let checksums = self.fetch_metadata(&release_mirror, "SHA256SUMS", MAX_CHECKSUM_BYTES)?;
        let signature =
            self.fetch_metadata(&release_mirror, "SHA256SUMS.sig", MAX_SIGNATURE_BYTES)?;
        let verified_manifest = verify_component_manifest(
            &manifest_bytes,
            &manifest_filename,
            &checksums,
            &signature,
            os,
            arch,
            manifest_verifier,
        )?;
        if verified_manifest.manifest().release_version != release_version {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "component manifest belongs to a different infraternal release",
            ));
        }

        let manifest = verified_manifest.manifest();
        let mirror_archive = release_mirror
            .join(&manifest.mirror_path)
            .map_err(io::Error::other)?;
        let upstream_archive = Url::parse(&manifest.archive_url).map_err(io::Error::other)?;
        match self.install_from(installer, &verified_manifest, &mirror_archive, os, arch) {
            Ok(path) => Ok(path),
            Err(error) if may_use_upstream_fallback(&error) => {
                self.install_from(installer, &verified_manifest, &upstream_archive, os, arch)
            }
            Err(error) => Err(error),
        }
    }

    fn fetch_metadata(&self, release_mirror: &Url, name: &str, limit: u64) -> io::Result<Vec<u8>> {
        let url = release_mirror.join(name).map_err(io::Error::other)?;
        let mut body = BoundedBody::new(limit);
        self.transport.download(&url, limit, &mut body)?;
        if body.bytes.is_empty() {
            return Err(invalid_data("signed component metadata is empty"));
        }
        Ok(body.bytes)
    }

    fn install_from(
        &self,
        installer: &ComponentInstaller,
        manifest: &VerifiedComponentManifest,
        url: &Url,
        os: &str,
        arch: &str,
    ) -> io::Result<PathBuf> {
        installer.install_stream(
            manifest,
            |output| {
                self.transport.download(
                    url,
                    manifest
                        .manifest()
                        .archive_size
                        .min(MAX_COMPONENT_ARCHIVE_BYTES),
                    output,
                )
            },
            os,
            arch,
        )
    }
}

struct BoundedBody {
    limit: u64,
    bytes: Vec<u8>,
}

impl BoundedBody {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            bytes: Vec::new(),
        }
    }
}

impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = u64::try_from(self.bytes.len())
            .ok()
            .and_then(|current| current.checked_add(u64::try_from(bytes.len()).ok()?))
            .ok_or_else(|| invalid_data("component metadata exceeds its byte limit"))?;
        if next > self.limit {
            return Err(invalid_data("component metadata exceeds its byte limit"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("component metadata allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn may_use_upstream_fallback(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported
    )
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
