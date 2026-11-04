//! Resolves lockstep SSH and optional session payloads from signed releases, with a state-directory cache [220,224,225,255].
use crate::release_verify::verify_release_file;
use infraternal_plugin_ssh::{
    install::PayloadSource, model::Failure, probe::Architecture, transport::Operation,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

/// Which release binary to fetch.
#[derive(Clone, Copy)]
enum Artifact {
    /// The full binary.
    Full,
    /// The smaller session-only binary. Optional: its absence is not an error.
    Session,
}
impl Artifact {
    /// True if a missing artifact should be tolerated.
    fn optional(self) -> bool {
        matches!(self, Self::Session)
    }
    /// Release asset name for this artifact; `label` is the target label.
    fn name(self, label: &str) -> String {
        match self {
            Self::Full => format!("infraternal-{label}-musl"),
            Self::Session => format!("infraternal-{label}-session-musl"),
        }
    }
}

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
        let cache = state.join("releases");
        // Restart cleanup precedes the first request. An unsafe/unavailable cache
        // remains a plain acquisition failure when resolution is attempted.
        if private_directory(&cache).is_ok() {
            let version = cache.join(infraternal_plugin_api::VERSION);
            let _ = cleanup_downloads(&version);
            let sessions = version.join("session");
            if std::fs::symlink_metadata(&sessions).is_ok() {
                let _ = cleanup_downloads(&sessions);
            }
        }
        Arc::new(Self {
            executable,
            local,
            cache,
            version: infraternal_plugin_api::VERSION.into(),
            development: env!("INFRATERNAL_RELEASE_BUILD") != "1",
            origin: "https://builds.infraternal.com".into(),
            lock: Mutex::new(()),
            #[cfg(test)]
            trust: None,
        })
    }
    async fn resolve(&self, arch: Architecture) -> Result<PathBuf, Failure> {
        self.resolve_artifact(arch, Artifact::Full)
            .await?
            .ok_or_else(|| Failure::install("the verified binary is unavailable."))
    }
    async fn resolve_session(&self, arch: Architecture) -> Result<Option<PathBuf>, Failure> {
        self.resolve_artifact(arch, Artifact::Session).await
    }
    #[allow(clippy::too_many_lines)] // Keep authenticated absence, bounded download and atomic publication ordered.
    async fn resolve_artifact(
        &self,
        arch: Architecture,
        artifact: Artifact,
    ) -> Result<Option<PathBuf>, Failure> {
        let same = matches!(
            (std::env::consts::ARCH, arch),
            ("x86_64", Architecture::X86_64) | ("aarch64", Architecture::Aarch64)
        );
        // A separate session image must be authenticated even on this server's architecture.
        if same && !artifact.optional() {
            return Ok(Some(self.executable.clone()));
        }
        let label = match arch {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
        };
        let name = artifact.name(label);
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
        let version_dir = if artifact.optional() {
            let sessions = version_dir.join("session");
            private_directory(&sessions).map_err(|_| fail("the release cache is unavailable."))?;
            sessions
        } else {
            version_dir
        };
        let ready = version_dir.join(label);
        if std::fs::symlink_metadata(&ready).is_ok() {
            let present = self
                .verify_cached(&ready, &name, artifact, false)
                .await
                .map_err(fail)?;
            return Ok(present.then(|| ready.join(name)));
        }
        let guard = self.lock.lock().await;
        // Cache hits hash independently; only publication is serialized. A waiter
        // checks again because the first downloader may have populated its cache.
        if std::fs::symlink_metadata(&ready).is_ok() {
            drop(guard);
            let present = self
                .verify_cached(&ready, &name, artifact, false)
                .await
                .map_err(fail)?;
            return Ok(present.then(|| ready.join(name)));
        }
        let staging =
            Staging::new(&version_dir).map_err(|_| fail("the release cache is unavailable."))?;
        let base = format!("{}/releases/{}", self.origin, self.version);
        let result = crate::release_http::download(
            &format!("{base}/SHA256SUMS"),
            &staging.path.join("SHA256SUMS"),
            65_536,
        )
        .await;
        if matches!(result, Err(crate::release_http::DownloadError::Missing)) && self.development {
            if artifact.optional() {
                let local = self.local.session_payload(arch)?;
                return Ok((local.as_path() != self.local.get(arch)).then_some(local));
            }
            return Ok(Some(self.local.get(arch).to_owned()));
        }
        result.map_err(|error| fail(error.reason()))?;
        for (file, limit) in [("SHA256SUMS.sig", 1024), ("VERSION", 128)] {
            crate::release_http::download(
                &format!("{base}/{file}"),
                &staging.path.join(file),
                limit,
            )
            .await
            .map_err(|error| fail(error.reason()))?;
        }
        // VERSION verification validates every signed manifest line. Only an
        // authenticated omission permits the optional full-payload fallback.
        let present = if artifact.optional() {
            self.verify_cached(&staging.path, &name, artifact, true)
                .await
                .map_err(fail)?
        } else {
            true
        };
        if present {
            crate::release_http::download(
                &format!("{base}/{name}"),
                &staging.path.join(&name),
                128 * 1024 * 1024,
            )
            .await
            .map_err(|error| fail(error.reason()))?;
            self.verify_cached(&staging.path, &name, artifact, false)
                .await
                .map_err(fail)?;
        }
        // Also collect abandoned work when a resolver is reused after another
        // process stops. Our staging lock keeps this verified candidate alive.
        cleanup_downloads(&version_dir)
            .map_err(|_| fail("the release cache could not be cleaned."))?;
        // A single atomic directory rename publishes payload and signed metadata together.
        // The resolver's lock bounds duplicate downloads to one per architecture/version.
        std::fs::File::open(&staging.path)
            .and_then(|file| file.sync_all())
            .map_err(|_| fail("the release cache could not be saved."))?;
        std::fs::rename(&staging.path, &ready)
            .map_err(|_| fail("the verified binary could not be cached."))?;
        std::fs::File::open(&version_dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| fail("the release cache could not be saved."))?;
        Ok(present.then(|| ready.join(name)))
    }
}
impl PayloadSource for ReleasePayload {
    fn get(&self, arch: Architecture) -> Operation<'_, PathBuf> {
        Box::pin(self.resolve(arch))
    }
    fn session(&self, arch: Architecture) -> Operation<'_, Option<PathBuf>> {
        Box::pin(self.resolve_session(arch))
    }
}
struct Staging {
    path: PathBuf,
    _lock: nix::fcntl::Flock<std::fs::File>,
}
impl Staging {
    fn new(version: &Path) -> std::io::Result<Self> {
        // Serialize creation with cleanup so an empty directory cannot be
        // collected in the gap before its lifetime lock is acquired.
        let _version_lock = lock_directory(version, nix::fcntl::FlockArg::LockExclusive)?;
        let path = version.join(format!("download-{}", uuid::Uuid::new_v4()));
        private_directory(&path)?;
        let lock = lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
        Ok(Self { path, _lock: lock })
    }
}

fn lock_directory(
    path: &Path,
    mode: nix::fcntl::FlockArg,
) -> std::io::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?;
    nix::fcntl::Flock::lock(file, mode).map_err(|(_, error)| error.into())
}

// Only our canonical UUID directories and private, single-link files are
// eligible. A nonblocking lifetime lock distinguishes abandoned work from a
// live downloader, including another process sharing this server state.
// Keep the conventional group/other permission mask explicit for auditing.
#[allow(clippy::verbose_bit_mask)]
fn cleanup_downloads(version: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    private_directory(version)?;
    let _version_lock = lock_directory(version, nix::fcntl::FlockArg::LockExclusive)?;
    for entry in std::fs::read_dir(version)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("download-"))
        else {
            continue;
        };
        if !uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id) {
            continue;
        }
        let path = entry.path();
        if private_directory(&path).is_err() {
            continue;
        }
        let _staging_lock = match lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock)
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        let files = std::fs::read_dir(&path)?.collect::<Result<Vec<_>, _>>()?;
        if !files.iter().all(|file| {
            matches!(
                file.file_name().to_str(),
                Some(
                    "SHA256SUMS"
                        | "SHA256SUMS.sig"
                        | "VERSION"
                        | "infraternal-x86_64-musl"
                        | "infraternal-aarch64-musl"
                        | "infraternal-x86_64-session-musl"
                        | "infraternal-aarch64-session-musl"
                )
            ) && std::fs::symlink_metadata(file.path()).is_ok_and(|m| {
                m.is_file()
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && m.mode() & 0o077 == 0
                    && m.nlink() == 1
            })
        }) {
            continue;
        }
        for file in files {
            std::fs::remove_file(file.path())?;
        }
        std::fs::remove_dir(path)?;
    }
    Ok(())
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
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
    #[allow(clippy::verbose_bit_mask, clippy::too_many_lines)]
    async fn verify_cached(
        &self,
        directory: &Path,
        name: &str,
        artifact: Artifact,
        metadata_only: bool,
    ) -> Result<bool, &'static str> {
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
            if artifact.optional() {
                // VERSION's strict checksum parse authenticated the complete
                // manifest above; presence uses its exact validated filename.
                let advertised = std::str::from_utf8(&sums)
                    .map_err(|_| "the signed checksums are malformed.")?
                    .lines()
                    .any(|line| line.get(66..) == Some(name.as_str()));
                if !advertised {
                    return Ok(false);
                }
                if metadata_only {
                    return Ok(true);
                }
            }
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
            let result = verify(&file, &name);
            result.map(|()| true).map_err(|error| match error {
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
pub(crate) mod tests;
