//! Authenticates a channel pointer's release identity using signed VERSION, with no polling or fallback [224,226].
use crate::{
    descriptor::{EDGE_OPT_IN, STABLE_EMPTY},
    service::ReleaseLookup,
};
use infraternal_plugin_api::Operation;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// A lazy metadata lookup; each call owns bounded private staging and no persistent worker.
pub struct VerifiedLookup {
    state: PathBuf,
    origin: String,
    engine: Arc<dyn ReleaseEngine>,
}
struct Staging {
    path: PathBuf,
    _lock: nix::fcntl::Flock<std::fs::File>,
}
impl Staging {
    fn new(state: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;

        // Serialize creation with restart cleanup so a new empty directory cannot
        // be collected before its lifetime lock is established.
        let (state_lock, metadata) = lock_directory(state, nix::fcntl::FlockArg::LockExclusive)?;
        if !private_state(&metadata) {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let path = state.join(format!("release-check-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let (lock, metadata) = lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
        if !owned_private_staging(&metadata) {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        drop(state_lock);
        Ok(Self { path, _lock: lock })
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
/// Transport and trust are supplied by the host's existing approved engines.
pub trait ReleaseEngine: Send + Sync {
    fn download<'a>(
        &'a self,
        address: &'a str,
        destination: &'a Path,
        max: u64,
    ) -> Operation<'a, Result<(), DownloadError>>;
    /// Verify the signed manifest and exact VERSION descriptor without changing its offset.
    /// # Errors
    /// Refuses unauthenticated metadata or a mismatched VERSION digest.
    fn verify_version(
        &self,
        file: &std::fs::File,
        sums: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str>;
}
/// Fixed public transport errors; no engine diagnostics enter plugin responses.
pub enum DownloadError {
    Missing,
    Refused(&'static str),
}
impl DownloadError {
    fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "this version has no matching release file.",
            Self::Refused(reason) => reason,
        }
    }
}
impl VerifiedLookup {
    /// Bind existing private server state and an HTTPS-capable transport; start no work.
    #[must_use]
    pub fn new(state: PathBuf, origin: String, engine: Arc<dyn ReleaseEngine>) -> Self {
        // Best-effort startup sweep: unsafe or active entries are retained, and
        // a later lookup still reports ordinary storage errors if state is unavailable.
        let _ = cleanup_abandoned_staging(&state);
        Self {
            state,
            origin,
            engine,
        }
    }

    async fn check(&self, channel: &str) -> Result<Value, &'static str> {
        if !matches!(channel, "stable" | "edge") {
            return Err("invalid release channel setting");
        }
        // Random private staging is owned by this future and removed even when a feature switch cancels it.
        let staging = Staging::new(&self.state).map_err(|_| "release check storage unavailable")?;
        let pointer = staging.path.join("pointer.json");
        let result = self
            .engine
            .download(
                &format!("{}/releases/channels/{channel}.json", self.origin),
                &pointer,
                65536,
            )
            .await;
        match result {
            Err(DownloadError::Missing) => {
                return Ok(if channel == "stable" {
                    json!({"channel":channel,"state":"empty","message":STABLE_EMPTY,"next":EDGE_OPT_IN})
                } else {
                    json!({"channel":channel,"state":"empty","message":"no edge release yet"})
                });
            }
            Err(error) => return Err(error.reason()),
            Ok(()) => (),
        }
        let bytes = std::fs::read(&pointer).map_err(|_| "release pointer could not be read")?;
        let version = crate::pointer::parse(&bytes, channel)?;
        let base = format!("{}/releases/{version}", self.origin);
        for (name, limit) in [
            ("SHA256SUMS", 65536),
            ("SHA256SUMS.sig", 1024),
            ("VERSION", 128),
        ] {
            self.engine
                .download(&format!("{base}/{name}"), &staging.path.join(name), limit)
                .await
                .map_err(|e| e.reason())?;
        }
        // Verification reads at most 64 KiB of manifest and 128 bytes of VERSION.
        // Keep this bounded operation in the owning future: a detached blocking worker
        // could outlive runtime disable and race staging cleanup [198].
        let verified = (|| {
            use std::{io::Read, os::unix::fs::OpenOptionsExt};
            let sums = std::fs::read(staging.path.join("SHA256SUMS"))
                .map_err(|_| "release manifest could not be read")?;
            let signature = std::fs::read(staging.path.join("SHA256SUMS.sig"))
                .map_err(|_| "release signature could not be read")?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(staging.path.join("VERSION"))
                .map_err(|_| "release VERSION could not be read")?;
            if !file
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 128)
            {
                return Err("release VERSION is unsafe");
            }
            self.engine.verify_version(&file, &sums, &signature)?;
            // Authentication preserves the offset. Read this same descriptor so pathname replacement cannot change identity.
            let mut declared = Vec::with_capacity(128);
            file.take(129)
                .read_to_end(&mut declared)
                .map_err(|_| "release VERSION could not be read")?;
            if declared != format!("{version}\n").as_bytes() {
                return Err("signed VERSION does not match the release pointer");
            }
            Ok(version)
        })()?;
        Ok(json!({"channel":channel,"state":"verified","version":verified}))
    }
}

fn lock_directory(
    path: &Path,
    mode: nix::fcntl::FlockArg,
) -> std::io::Result<(nix::fcntl::Flock<std::fs::File>, std::fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?;
    let metadata = file.metadata()?;
    let lock = nix::fcntl::Flock::lock(file, mode).map_err(|(_, error)| error)?;
    Ok((lock, metadata))
}

fn private_state(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_dir()
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o022 == 0
}

#[allow(clippy::verbose_bit_mask)]
fn owned_private_staging(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_dir()
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o7777 == 0o700
}

#[allow(clippy::verbose_bit_mask)]
fn owned_private_metadata(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1
    })
}

/// Reclaim only canonical private stage directories whose process lock was released [198,226; #157].
fn cleanup_abandoned_staging(state: &Path) -> std::io::Result<()> {
    let (state_lock, metadata) = lock_directory(state, nix::fcntl::FlockArg::LockExclusive)?;
    if !private_state(&metadata) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    for entry in std::fs::read_dir(state)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("release-check-"))
        else {
            continue;
        };
        if !uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id) {
            continue;
        }
        let path = entry.path();
        let (staging_lock, metadata) =
            match lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(lock) => lock,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::NotADirectory
                            | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
        if !owned_private_staging(&metadata) {
            continue;
        }
        let Ok(files) =
            std::fs::read_dir(&path).and_then(|files| files.collect::<Result<Vec<_>, _>>())
        else {
            continue;
        };
        if !files.iter().all(|file| {
            matches!(
                file.file_name().to_str(),
                Some("pointer.json" | "SHA256SUMS" | "SHA256SUMS.sig" | "VERSION")
            ) && owned_private_metadata(&file.path())
        }) {
            continue;
        }
        for file in files {
            std::fs::remove_file(file.path())?;
        }
        std::fs::remove_dir(path)?;
        drop(staging_lock);
    }
    drop(state_lock);
    Ok(())
}
impl ReleaseLookup for VerifiedLookup {
    fn latest<'a>(&'a self, channel: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        Box::pin(async move {
            tokio::time::timeout(std::time::Duration::from_secs(60), self.check(channel))
                .await
                .map_err(|_| "release check exceeded its time limit")?
        })
    }
}

#[cfg(test)]
#[path = "latest_tests.rs"]
mod tests;
