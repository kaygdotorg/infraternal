//! Resolves lockstep cross-architecture SSH payloads from signed releases, with a state-directory cache [220,224,225].
use crate::release_verify::verify_release_file;
use infraternal_plugin_ssh::{
    install::PayloadSource, model::Failure, probe::Architecture, transport::Operation,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

/// One resolver belongs to one server version; no polling or network work runs while SSH is off.
pub(crate) struct ReleasePayload {
    executable: PathBuf,
    local: infraternal_plugin_ssh::install::BinaryPaths,
    cache: PathBuf,
    version: String,
    development: bool,
    origin: String,
    lock: Mutex<()>,
    #[cfg(test)]
    trust: Option<String>,
}
impl ReleasePayload {
    pub(crate) fn new(
        executable: PathBuf,
        local: infraternal_plugin_ssh::install::BinaryPaths,
        state: &Path,
    ) -> Arc<Self> {
        Arc::new(Self {
            executable,
            local,
            cache: state.join("releases"),
            version: env!("CARGO_PKG_VERSION").into(),
            development: env!("INFRATERNAL_RELEASE_BUILD") != "1",
            origin: "https://builds.infraternal.com".into(),
            lock: Mutex::new(()),
            #[cfg(test)]
            trust: None,
        })
    }
    async fn resolve(&self, arch: Architecture) -> Result<PathBuf, Failure> {
        let same = matches!(
            (std::env::consts::ARCH, arch),
            ("x86_64", Architecture::X86_64) | ("aarch64", Architecture::Aarch64)
        );
        if same {
            return Ok(self.executable.clone());
        }
        let label = match arch {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
        };
        let name = format!("infraternal-{label}-musl");
        let fail = |reason: &'static str| {
            let step = match arch {
                Architecture::Aarch64 => infraternal_plugin_ssh::model::InstallStep::GetArm64Binary,
                Architecture::X86_64 => infraternal_plugin_ssh::model::InstallStep::GetX86_64Binary,
            };
            Failure::install(reason).at(step)
        };
        private_directory(&self.cache).map_err(|_| fail("the release cache is unavailable."))?;
        let version_dir = self.cache.join(&self.version);
        private_directory(&version_dir).map_err(|_| fail("the release cache is unavailable."))?;
        let ready = version_dir.join(label);
        if ready.exists() {
            self.verify_cached(&ready, &name).await.map_err(fail)?;
            return Ok(ready.join(name));
        }
        let guard = self.lock.lock().await;
        // Cache hits hash independently; only publication is serialized. A waiter
        // checks again because the first downloader may have populated its cache.
        if ready.exists() {
            drop(guard);
            self.verify_cached(&ready, &name).await.map_err(fail)?;
            return Ok(ready.join(name));
        }
        let staging = Staging(version_dir.join(format!("download-{}", uuid::Uuid::new_v4())));
        private_directory(&staging.0).map_err(|_| fail("the release cache is unavailable."))?;
        let base = format!("{}/releases/{}", self.origin, self.version);
        let result = crate::release_http::download(
            &format!("{base}/SHA256SUMS"),
            &staging.0.join("SHA256SUMS"),
            65_536,
        )
        .await;
        if matches!(result, Err(crate::release_http::DownloadError::Missing)) && self.development {
            return Ok(self.local.get(arch).to_owned());
        }
        result.map_err(|error| fail(error.reason()))?;
        for (file, limit) in [
            ("SHA256SUMS.sig", 1024),
            ("VERSION", 128),
            (name.as_str(), 128 * 1024 * 1024),
        ] {
            crate::release_http::download(&format!("{base}/{file}"), &staging.0.join(file), limit)
                .await
                .map_err(|error| fail(error.reason()))?;
        }
        self.verify_cached(&staging.0, &name).await.map_err(fail)?;
        // A single atomic directory rename publishes payload and signed metadata together.
        // The resolver's lock bounds duplicate downloads to one per architecture/version.
        std::fs::File::open(&staging.0)
            .and_then(|file| file.sync_all())
            .map_err(|_| fail("the release cache could not be saved."))?;
        std::fs::rename(&staging.0, &ready)
            .map_err(|_| fail("the verified binary could not be cached."))?;
        std::fs::File::open(&version_dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| fail("the release cache could not be saved."))?;
        Ok(ready.join(name))
    }
}
impl PayloadSource for ReleasePayload {
    fn get(&self, arch: Architecture) -> Operation<'_, PathBuf> {
        Box::pin(self.resolve(arch))
    }
}
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}
impl ReleasePayload {
    // Conventional octal group/other permission masks make this audit explicit.
    #[allow(clippy::verbose_bit_mask)]
    async fn verify_cached(&self, directory: &Path, name: &str) -> Result<(), &'static str> {
        #[cfg(test)]
        let trust = self.trust.clone();
        let directory = directory.to_owned();
        let name = name.to_owned();
        let expected_version = format!("{}\n", self.version);
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            private_directory(&directory).map_err(|_| "the release cache is unsafe.")?;
            let open = |name: &str| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                    .open(directory.join(name))
            };
            let read = |name: &str, limit: u64| -> Result<Vec<u8>, &'static str> {
                let file = open(name).map_err(|_| "the cached release is incomplete.")?;
                if !file.metadata().is_ok_and(|m| {
                    m.is_file()
                        && m.uid() == nix::unistd::geteuid().as_raw()
                        && m.mode() & 0o077 == 0
                        && m.nlink() == 1
                }) {
                    return Err("the cached release is unsafe.");
                }
                let mut bytes = Vec::new();
                file.take(limit + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "the cached release could not be read.")?;
                if bytes.len() > usize::try_from(limit).map_err(|_| "invalid cache limit")? {
                    return Err("the cached release is oversized.");
                }
                Ok(bytes)
            };
            let sums = read("SHA256SUMS", 65_536)?;
            let sig = read("SHA256SUMS.sig", 1024)?;
            let file = open(&name).map_err(|_| "the cached binary could not be read.")?;
            if !file.metadata().is_ok_and(|m| {
                m.is_file()
                    && m.len() <= 128 * 1024 * 1024
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && m.mode() & 0o077 == 0
                    && m.nlink() == 1
            }) {
                return Err("the cached binary is unsafe.");
            }
            let verify = |file: &std::fs::File, filename: &str| {
                #[cfg(test)]
                if let Some(trust) = &trust {
                    return crate::release_verify::verify_with_trust(
                        file, filename, &sums, &sig, trust,
                    );
                }
                verify_release_file(file, filename, &sums, &sig)
            };
            let version_file =
                open("VERSION").map_err(|_| "the cached release has no signed version.")?;
            if !version_file.metadata().is_ok_and(|m| {
                m.is_file()
                    && m.len() <= 128
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && m.mode() & 0o077 == 0
                    && m.nlink() == 1
            }) {
                return Err("the cached release version is unsafe.");
            }
            verify(&version_file, "VERSION")
                .map_err(|_| "the release version could not be verified.")?;
            // Positional reads verify without changing the offset. Read that same
            // descriptor rather than reopening a path after authentication.
            let mut declared_version = Vec::new();
            version_file
                .take(129)
                .read_to_end(&mut declared_version)
                .map_err(|_| "the cached version could not be read.")?;
            if declared_version != expected_version.as_bytes() {
                return Err("the signed release belongs to another server version.");
            }
            let result = verify(&file, &name);
            result.map_err(|error| match error {
                crate::release_verify::ReleaseError::Signature => {
                    "the release signature is malformed."
                }
                crate::release_verify::ReleaseError::Untrusted => {
                    "the release signing key is not trusted."
                }
                crate::release_verify::ReleaseError::Invalid => {
                    "the release signature does not match the checksums."
                }
                crate::release_verify::ReleaseError::Checksums => {
                    "the signed checksums do not identify this binary."
                }
                crate::release_verify::ReleaseError::Digest => {
                    "the binary does not match the signed checksum."
                }
                crate::release_verify::ReleaseError::Read => "the binary could not be read.",
            })
        })
        .await
        .map_err(|_| "release verification could not finish.")?
    }
}

#[cfg(test)]
#[path = "release_payload_tests.rs"]
mod tests;
