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
    /// Whether this server runs the update check, or why not; see [`VerifiedLookup::with_updates`].
    updates: Result<(), &'static str>,
    /// The server's updater, when it runs one; see [`VerifiedLookup::with_updater`].
    updater: Option<Arc<crate::update::Updater>>,
}
struct Staging {
    path: PathBuf,
    _lock: nix::fcntl::Flock<std::fs::File>,
}
impl Staging {
    fn new(state: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        // Serialize creation with restart cleanup so a new empty directory cannot
        // be collected before its lifetime lock is established.
        let (state_lock, metadata) = lock_directory(state, nix::fcntl::FlockArg::LockExclusive)?;
        if !private_state(&metadata) {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let path = state.join(format!("release-check-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let (lock, metadata) = lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
        // umask may remove owner execute (0177 turns 0700 into 0600).
        // Set the exact mode through the locked descriptor, never a pathname
        // that could have been replaced. The requested mode never grants public access.
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        lock.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        if !owned_private_staging(&lock.metadata()?) {
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
    /// Verify a whole release with the one signed-release verifier (#211 S1): the
    /// signature over `sums`, the signed `version` file and the `image` named `name`
    /// in `sums`. Returns the signed version. Used by the updater before it keeps a
    /// download; builds without an image verifier refuse.
    /// # Errors
    /// Refuses an untrusted or malformed signature, a list without `VERSION` or
    /// `name`, and any file that does not match its signed digest.
    fn verify_image(
        &self,
        _version: &std::fs::File,
        _image: &std::fs::File,
        _name: &str,
        _sums: &[u8],
        _signature: &[u8],
    ) -> Result<String, &'static str> {
        Err("release images cannot be verified in this build")
    }
}
/// Fixed public transport errors; no engine diagnostics enter plugin responses.
pub enum DownloadError {
    Missing,
    Refused(&'static str),
}
impl DownloadError {
    /// The fixed public sentence for this failure, safe to show to the owner.
    pub(crate) fn reason(&self) -> &'static str {
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
            updates: Err(NO_UPDATER),
            updater: None,
        }
    }

    /// Fetch and authenticate `channel`'s newest release metadata in a private, self-cleaning staging folder.
    async fn check(&self, channel: &str) -> Result<Value, &'static str> {
        if !matches!(channel, "stable" | "edge") {
            return Err("invalid release channel setting");
        }
        // Random private staging is owned by this future and removed even when a feature switch cancels it.
        let staging = Staging::new(&self.state).map_err(|_| "release check storage unavailable")?;
        let Some(verified) =
            fetch_metadata(self.engine.as_ref(), &self.origin, &staging.path, channel).await?
        else {
            return Ok(if channel == "stable" {
                json!({"channel":channel,"state":"empty","message":STABLE_EMPTY,"next":EDGE_OPT_IN})
            } else {
                json!({"channel":channel,"state":"empty","message":"no edge release yet"})
            });
        };
        Ok(json!({"channel":channel,"state":"verified","version":verified}))
    }
}

/// Download a channel's pointer and the release's signed metadata into `directory`
/// and authenticate the announced version.
///
/// `directory` must be a private folder the caller owns; this writes `pointer.json`,
/// `SHA256SUMS`, `SHA256SUMS.sig` and `VERSION` into it and leaves them there, so the
/// updater can keep the same verified files beside the image it stages. Returns
/// `Ok(None)` when the channel has published nothing yet, otherwise the version whose
/// signed `VERSION` matches the pointer.
/// # Errors
/// Fixed public reasons for transport failures, malformed pointers, another channel's
/// pointer, unverifiable metadata and a signed `VERSION` that differs from the pointer.
pub(crate) async fn fetch_metadata(
    engine: &dyn ReleaseEngine,
    origin: &str,
    directory: &Path,
    channel: &str,
) -> Result<Option<String>, &'static str> {
    let pointer = directory.join("pointer.json");
    let result = engine
        .download(
            &format!("{origin}/releases/channels/{channel}.json"),
            &pointer,
            65536,
        )
        .await;
    match result {
        Err(DownloadError::Missing) => return Ok(None),
        Err(error) => return Err(error.reason()),
        Ok(()) => (),
    }
    let bytes = std::fs::read(&pointer).map_err(|_| "release pointer could not be read")?;
    let version = crate::pointer::parse(&bytes, channel)?;
    fetch_signed(engine, origin, directory, &version).await?;
    Ok(Some(version))
}

/// Download one release's signed metadata (`SHA256SUMS`, `SHA256SUMS.sig`, `VERSION`)
/// into the private folder `directory` and check that its signed `VERSION` is exactly
/// `version`. The files stay in `directory` for the caller.
/// # Errors
/// Fixed public reasons for transport failures, unverifiable metadata and a signed
/// `VERSION` that names another release.
pub(crate) async fn fetch_signed(
    engine: &dyn ReleaseEngine,
    origin: &str,
    directory: &Path,
    version: &str,
) -> Result<(), &'static str> {
    let base = format!("{origin}/releases/{version}");
    for (name, limit) in [
        ("SHA256SUMS", 65536),
        ("SHA256SUMS.sig", 1024),
        ("VERSION", 128),
    ] {
        engine
            .download(&format!("{base}/{name}"), &directory.join(name), limit)
            .await
            .map_err(|e| e.reason())?;
    }
    // Verification reads at most 64 KiB of manifest and 128 bytes of VERSION.
    // Keep this bounded operation in the owning future: a detached blocking worker
    // could outlive runtime disable and race staging cleanup [198].
    (|| {
        use std::{io::Read, os::unix::fs::OpenOptionsExt};
        let sums = std::fs::read(directory.join("SHA256SUMS"))
            .map_err(|_| "release manifest could not be read")?;
        let signature = std::fs::read(directory.join("SHA256SUMS.sig"))
            .map_err(|_| "release signature could not be read")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(directory.join("VERSION"))
            .map_err(|_| "release VERSION could not be read")?;
        if !file
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 128)
        {
            return Err("release VERSION is unsafe");
        }
        engine.verify_version(&file, &sums, &signature)?;
        // Authentication preserves the offset. Read this same descriptor so pathname replacement cannot change identity.
        let mut declared = Vec::with_capacity(128);
        file.take(129)
            .read_to_end(&mut declared)
            .map_err(|_| "release VERSION could not be read")?;
        if declared != format!("{version}\n").as_bytes() {
            return Err("signed VERSION does not match the release pointer");
        }
        Ok(())
    })()
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
            std::fs::read_dir(&path).and_then(std::iter::Iterator::collect::<Result<Vec<_>, _>>)
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
/// The status reason for a lookup whose server never said whether it runs the updater.
const NO_UPDATER: &str = "this server does not run the update check";

impl VerifiedLookup {
    /// Give the lookup the server's updater, so the check, apply and cancel actions can
    /// reach it (#211 S5). Without it they answer with the reason updates are off.
    #[must_use]
    pub fn with_updater(mut self, updater: Arc<crate::update::Updater>) -> Self {
        self.updater = Some(updater);
        self
    }

    /// Say whether this server runs the update check (`Ok`) or why not (the reason from
    /// [`crate::update::availability`]), so `release.update.status` can report it
    /// plainly (J725 P3-4). Without this call the status reports updates as off.
    #[must_use]
    pub fn with_updates(mut self, updates: Result<(), &'static str>) -> Self {
        self.updates = updates;
        self
    }
}

impl ReleaseLookup for VerifiedLookup {
    fn latest<'a>(&'a self, channel: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        Box::pin(async move {
            tokio::time::timeout(std::time::Duration::from_secs(60), self.check(channel))
                .await
                .map_err(|_| "release check exceeded its time limit")?
        })
    }
    fn updater(&self) -> Result<Arc<crate::update::Updater>, &'static str> {
        self.updater.clone().ok_or(match self.updates {
            Err(reason) => reason,
            Ok(()) => NO_UPDATER,
        })
    }
    fn update_history(&self) -> Vec<crate::history::Entry> {
        crate::history::read(&self.state)
    }
    /// The data folder's `updates/state.json`, read without a lock (#211 S3), plus
    /// `mode` (`auto` or `off`) and `reason` (why it is off, else null).
    fn update_status(&self) -> Result<Value, &'static str> {
        let mut state = serde_json::to_value(crate::update::status(
            &self.state,
            infraternal_plugin_api::VERSION,
        ))
        .map_err(|_| "updates unavailable")?;
        let (mode, reason) = match self.updates {
            Ok(()) => ("auto", Value::Null),
            Err(reason) => ("off", Value::String(reason.to_owned())),
        };
        state["mode"] = Value::String(mode.to_owned());
        state["reason"] = reason;
        Ok(state)
    }
}

#[cfg(test)]
#[path = "latest_tests.rs"]
mod tests;
