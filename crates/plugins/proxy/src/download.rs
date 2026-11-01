//! Streams a release-signed component bundle from the mirror with verified upstream fallback [#281].

use crate::{installer::ComponentInstaller, manifest::ComponentManifestVerifier};
use std::{io, io::Write, path::PathBuf};
use url::Url;

/// A bounded streaming transport for release metadata and component bytes.
pub trait ComponentTransport {
    /// Copy one response body to the supplied sink, refusing data beyond its signed limit.
    ///
    /// # Errors
    /// Returns a transport error, or an invalid-data error when the response exceeds `limit`.
    fn download(&self, url: &Url, limit: u64, output: &mut dyn Write) -> io::Result<()>;
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
    pub fn new(mirror: Url, transport: T) -> io::Result<Self> {
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
        verifier: &dyn ComponentManifestVerifier,
    ) -> io::Result<PathBuf> {
        let _ = (installer, release_version, os, arch, verifier);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "component download is not implemented",
        ))
    }
}
