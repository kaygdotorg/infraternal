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
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
        Self {
            state,
            origin,
            engine,
        }
    }

    async fn check(&self, channel: &str) -> Result<Value, &'static str> {
        use std::os::unix::fs::DirBuilderExt;
        if !matches!(channel, "stable" | "edge") {
            return Err("invalid release channel setting");
        }
        // Random private staging is owned by this future and removed even when a feature switch cancels it.
        let path = self
            .state
            .join(format!("release-check-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "release check storage unavailable")?;
        let staging = Staging(path);
        let pointer = staging.0.join("pointer.json");
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
                .download(&format!("{base}/{name}"), &staging.0.join(name), limit)
                .await
                .map_err(|e| e.reason())?;
        }
        // Verification reads at most 64 KiB of manifest and 128 bytes of VERSION.
        // Keep this bounded operation in the owning future: a detached blocking worker
        // could outlive runtime disable and race staging cleanup [198].
        let verified = (|| {
            use std::{io::Read, os::unix::fs::OpenOptionsExt};
            let sums = std::fs::read(staging.0.join("SHA256SUMS"))
                .map_err(|_| "release manifest could not be read")?;
            let signature = std::fs::read(staging.0.join("SHA256SUMS.sig"))
                .map_err(|_| "release signature could not be read")?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(staging.0.join("VERSION"))
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
