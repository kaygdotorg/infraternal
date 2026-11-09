//! Pins one explicitly confirmed SSH key; changed application pins need a fresh observation and atomic confirmation.
//!
//! Host-key trust works in two steps so a key is never trusted by accident:
//!
//! 1. A connection to an unknown host fails with a host-key error. The server
//!    then scans the host's public keys, keeps one, and stores it as a
//!    pending observation (valid 120 seconds, at most 128 at a time) under a
//!    random challenge id. The person is shown the fingerprint.
//! 2. When the person confirms that challenge and fingerprint, the server
//!    re-reads the effective SSH policy, checks nothing changed (same policy,
//!    same previous pin, still no external trust), re-checks the person's live
//!    authority, and only then publishes the key as an application pin: a
//!    public-key file in a private 0700 directory, written to a temporary name,
//!    synced and renamed into place. A challenge can replace only the exact pin
//!    it saw, and works once. Sending the very same confirmation again (a
//!    double-click) answers success without writing anything; any other key is
//!    still refused.
//!
//! Trust configured outside the application (known-hosts files or a lookup
//! command) always wins and is never modified. Pin files contain only public
//! keys. No private key, password or session capability is stored here.
//! Anything malformed, wrongly owned or ambiguous fails closed.

use crate::{
    config::TrustPolicy,
    model::{Destination, Failure, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    process::execute,
    transport::{ConfirmationAuthority, Credentials, Input, Operation, SshSession, SshTransport},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::process::Command;

/// Serializes every pin write and delete in this process, so a compare-and-replace is atomic.
static PUBLICATION: Mutex<()> = Mutex::new(());

/// Delete only an owned application pin; external SSH trust is never changed.
///
/// `root` is the pin directory and `lookup` the host lookup name whose pin goes.
/// A missing directory or pin is success. The directory must be a real 0700
/// directory and the pin a regular 0600 file, both owned by this user (symlinks
/// are not followed), and its content must be exactly the canonical record for
/// `lookup`; otherwise nothing is deleted.
/// # Errors
/// Refuses unsafe ownership, malformed records and filesystem failures.
pub fn forget_pin(root: &std::path::Path, lookup: &str) -> Result<(), Failure> {
    let _publication = lock(&PUBLICATION);
    let path = root.join(format!("{:x}.pub", Sha256::digest(lookup.as_bytes())));
    if !root.try_exists().map_err(|_| unavailable())? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| unavailable())?;
    if !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(unavailable());
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(unavailable()),
    };
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() > 8192
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if public_record(&bytes, lookup).as_deref().map(str::as_bytes) != Some(bytes.as_slice()) {
        return Err(unavailable());
    }
    fs::remove_file(path).map_err(|_| unavailable())?;
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable())
}

/// A first-contact key waiting for a person's confirmation.
struct Observation {
    /// The endpoint it was observed for; a confirmation must name the same one.
    destination: Destination,
    /// The trust policy at observation time; confirmation requires it unchanged.
    policy: TrustPolicy,
    /// Candidate keys as `(SHA256 fingerprint, known-hosts record)`; at most one after selection.
    keys: Vec<(String, String)>,
    /// The application pin that existed then, if any (a changed-key case).
    previous: Option<String>,
    /// When it was observed; expires after 120 seconds.
    received: Instant,
}

/// What a successful confirmation leaves behind, so the same confirmation sent again can be answered.
///
/// A person's second click, or a slow screen that sends the request twice, repeats the very same
/// challenge and fingerprint. Remembering the outcome lets that repeat say "already trusted" instead of
/// failing with the generic error. Only public values live here.
struct Confirmed {
    /// The endpoint that was pinned; a repeat must name the same one.
    destination: Destination,
    /// The fingerprint that was pinned; a repeat for any other key stays refused.
    fingerprint: String,
    /// When the observation was made. A repeat is answered only within the observation's own 120 seconds.
    observed: Instant,
}

/// Shares public pin/challenge custody across every automatic method and batch.
/// No private key, password, session capability or invitation enters this store.
pub struct TrustedOpenSsh {
    /// The system OpenSSH adapter used for connections, key scans and fingerprints.
    ssh: OpenSsh,
    /// Private directory holding the pin files.
    root: PathBuf,
    /// Observations awaiting confirmation, by challenge id.
    pending: Mutex<HashMap<uuid::Uuid, Observation>>,
    /// Challenges already confirmed, by challenge id, kept for the observation's lifetime (at most 128).
    confirmed: Mutex<HashMap<uuid::Uuid, Confirmed>>,
    /// Held for the whole of one confirmation, so identical requests that arrive together take turns:
    /// the first pins the key, the others find it in `confirmed` and answer success.
    confirming: tokio::sync::Mutex<()>,
}
impl TrustedOpenSsh {
    /// Wrap `ssh` with application pin custody under `root`. The directory is
    /// created (0700) on first use, not here.
    #[must_use]
    pub fn new(ssh: OpenSsh, root: PathBuf) -> Self {
        Self {
            ssh,
            root,
            pending: Mutex::new(HashMap::new()),
            confirmed: Mutex::new(HashMap::new()),
            confirming: tokio::sync::Mutex::new(()),
        }
    }

    /// Path of the pin file for `policy`'s lookup name (named by the SHA-256 of the lookup, so the host name never forms a path).
    fn pin(&self, policy: &TrustPolicy) -> PathBuf {
        self.root.join(format!(
            "{:x}.pub",
            Sha256::digest(policy.lookup.as_bytes())
        ))
    }

    /// Create the pin directory if needed and require it to be a real 0700 directory owned by this user.
    fn private_root(&self) -> Result<(), Failure> {
        match fs::DirBuilder::new().mode(0o700).create(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(unavailable()),
        }
        let metadata = fs::symlink_metadata(&self.root).map_err(|_| unavailable())?;
        if !metadata.is_dir()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// The existing application pin for `policy`, as its one-line record, or `None` if there is none.
    ///
    /// Fails closed when the file is not a 0600 regular file owned by this user
    /// (symlinks are not followed), is over 8 KiB, or is not exactly the canonical
    /// record for the lookup name.
    fn recorded(&self, policy: &TrustPolicy) -> Result<Option<String>, Failure> {
        self.private_root()?;
        let path = self.pin(policy);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unavailable()),
        };
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.len() > 8192
        {
            return Err(unavailable());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
        if !text.starts_with(&format!("{} ", policy.lookup))
            || text.lines().count() != 1
            || !text.ends_with('\n')
        {
            return Err(unavailable());
        }
        if public_record(text.as_bytes(), &policy.lookup).as_deref() != Some(text) {
            return Err(unavailable());
        }
        Ok(Some(text.to_owned()))
    }

    /// True if trust for the lookup name already exists outside the application.
    ///
    /// A lookup command counts as trust without being run, because absence
    /// cannot be proven. Otherwise each known-hosts file is searched with
    /// `ssh-keygen -F`; a missing file is skipped, and any other odd result is an error.
    async fn configured_trust(&self, policy: &TrustPolicy) -> Result<bool, Failure> {
        // Let the native engine enforce active command policy; never replace it
        // with a first-contact pin on the strength of a file-only absence check.
        if policy.dynamic_trust {
            return Ok(true);
        }
        for path in &policy.paths {
            match fs::metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(unavailable()),
                Ok(metadata) if !metadata.is_file() => return Err(unavailable()),
                Ok(_) => {}
            }
            let mut query = Command::new(&self.ssh.ssh_keygen);
            query.arg("-F").arg(&policy.lookup).arg("-f").arg(path);
            let result = execute(&mut query, Input::Empty, Duration::from_secs(3)).await?;
            if result.success {
                return Ok(true);
            }
            if !result.stderr.is_empty() {
                return Err(unavailable());
            }
        }
        Ok(false)
    }

    /// Scan the host's public keys and register a pending observation.
    ///
    /// Returns the challenge id, or `None` when external trust already exists,
    /// no usable key was found, or 128 observations are already pending. Keys are
    /// checked (record shape, allowed algorithm, valid fingerprint), preferring
    /// ed25519, then ecdsa, then rsa, and one is kept. Expired observations are
    /// dropped first. Nothing is pinned here.
    async fn observe(
        &self,
        destination: Destination,
        policy: TrustPolicy,
    ) -> Result<Option<uuid::Uuid>, Failure> {
        let previous = self.recorded(&policy)?;
        if self.configured_trust(&policy).await? {
            return Ok(None);
        }
        let mut scan = Command::new(&self.ssh.ssh_keyscan);
        scan.args(["-T", "3", "-t", "ed25519,ecdsa,rsa", "-p"])
            .arg(policy.destination.port().unwrap_or(22).to_string())
            .arg("--")
            .arg(policy.destination.host());
        let result = execute(&mut scan, Input::Empty, Duration::from_secs(5)).await?;
        let mut keys = Vec::new();
        for line in result.stdout.split(|byte| *byte == b'\n').take(16) {
            let Some(record) = public_record(line, &policy.lookup) else {
                continue;
            };
            let key_type = record.split_whitespace().nth(1).ok_or_else(unavailable)?;
            if policy.key_algorithms(key_type).is_none() {
                continue;
            }
            let mut fingerprint = Command::new(&self.ssh.ssh_keygen);
            fingerprint.args(["-l", "-E", "sha256", "-f", "/dev/stdin"]);
            let checked = execute(
                &mut fingerprint,
                Input::Bytes(record.as_bytes()),
                Duration::from_secs(3),
            )
            .await?;
            if !checked.success {
                continue;
            }
            if let Some(value) = std::str::from_utf8(&checked.stdout)
                .ok()
                .and_then(|text| text.split_whitespace().find(|word| valid_fingerprint(word)))
                && !keys.iter().any(|(existing, _)| existing == value)
            {
                keys.push((value.to_owned(), record));
            }
            if keys.len() == 4 {
                break;
            }
        }
        // Selection is independent of keyscan response ordering. The connection
        // is constrained to this family when the exact key is confirmed.
        keys.sort_by_key(|(_, record)| match record.split_whitespace().nth(1) {
            Some("ssh-ed25519") => 0,
            Some("ssh-rsa") => 2,
            _ => 1,
        });
        keys.truncate(1);
        if keys.is_empty() {
            return Ok(None);
        }
        let mut pending = lock(&self.pending);
        pending.retain(|_, value| value.received.elapsed() < Duration::from_secs(120));
        if pending.len() >= 128 {
            return Ok(None);
        }
        let challenge = uuid::Uuid::new_v4();
        pending.insert(
            challenge,
            Observation {
                destination,
                policy,
                keys,
                previous,
                received: Instant::now(),
            },
        );
        Ok(Some(challenge))
    }

    /// Turn a pending observation into an application pin.
    ///
    /// The challenge is consumed even if a later check fails, so a failed one
    /// cannot be retried. Requires: the same destination, under 120 seconds old,
    /// the same effective trust policy, the same previous pin, no external trust,
    /// a fingerprint equal to the observed key's, and a successful live
    /// `authority` check just before publishing. All refusals use one generic
    /// host-key error. The write is atomic (temporary file, sync, rename, sync
    /// directory) and guarded by `PUBLICATION`.
    ///
    /// Confirming is idempotent for a challenge that already succeeded: the same
    /// destination and fingerprint again, within the observation's 120 seconds,
    /// answers success without writing anything, after the live `authority` check
    /// (a repeat is no way around a revoked sign-in). Any other key stays refused.
    async fn confirm(
        &self,
        destination: Destination,
        challenge: &str,
        fingerprint: &str,
        authority: &dyn ConfirmationAuthority,
    ) -> Result<(), Failure> {
        let challenge = uuid::Uuid::parse_str(challenge).map_err(|_| denied())?;
        if !valid_fingerprint(fingerprint) {
            return Err(denied());
        }
        // One confirmation at a time: identical requests that arrive together queue here and then
        // find the first one's outcome below, instead of racing it for the consumed challenge.
        let _turn = self.confirming.lock().await;
        let repeat = lock(&self.confirmed).get(&challenge).map(|done| {
            done.observed.elapsed() < Duration::from_secs(120)
                && done.destination == destination
                && done.fingerprint == fingerprint
        });
        if let Some(same) = repeat {
            if !same {
                return Err(denied());
            }
            authority.authorize().await?;
            return Ok(());
        }
        let observation = lock(&self.pending).remove(&challenge).ok_or_else(denied)?;
        if observation.received.elapsed() >= Duration::from_secs(120)
            || observation.destination != destination
        {
            return Err(denied());
        }
        let configuration =
            crate::openssh::effective_destination(&self.ssh.ssh, &destination).await?;
        let policy = configuration.trust_policy().ok_or_else(denied)?;
        if policy != observation.policy
            || self.recorded(&policy)? != observation.previous
            || self.configured_trust(&policy).await?
        {
            return Err(denied());
        }
        let record = observation
            .keys
            .into_iter()
            .find(|(value, _)| value == fingerprint)
            .map(|(_, record)| record)
            .ok_or_else(denied)?;
        // The live capability is checked after all asynchronous observation work,
        // immediately before atomic publication. No SSH secret is exported here.
        if observation.received.elapsed() >= Duration::from_secs(120) {
            return Err(denied());
        }
        authority.authorize().await?;
        self.private_root()?;
        // Serialize compare-and-replace across this server's concurrent confirmations.
        // A challenge can replace only the exact pin observed, never a later decision.
        let _publication = lock(&PUBLICATION);
        if self.recorded(&policy)? != observation.previous {
            return Err(denied());
        }
        let temporary = self
            .root
            .join(format!("{}.new", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|_| unavailable())?;
            file.write_all(record.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| unavailable())?;
            fs::rename(&temporary, self.pin(&policy)).map_err(|_| unavailable())?;
            fs::File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| unavailable())
        })();
        let _ = fs::remove_file(temporary);
        result?;
        let mut confirmed = lock(&self.confirmed);
        confirmed.retain(|_, done| done.observed.elapsed() < Duration::from_secs(120));
        // The cap only bounds memory: past it a repeat falls back to the generic refusal, as before.
        if confirmed.len() < 128 {
            confirmed.insert(
                challenge,
                Confirmed {
                    destination: observation.destination,
                    fingerprint: fingerprint.to_owned(),
                    observed: observation.received,
                },
            );
        }
        Ok(())
    }
}

impl SshTransport for TrustedOpenSsh {
    /// Connect with strict host keys. If an application pin exists it is used
    /// (restricted to that key's algorithms), unless external trust now also
    /// exists, which is refused as ambiguous. On a host-key failure the error
    /// carries a challenge plus the observed fingerprint and key type, and says
    /// whether it replaces an earlier pin.
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            let mut configuration =
                crate::openssh::effective_destination(&self.ssh.ssh, &destination).await?;
            let policy = configuration.trust_policy();
            if let Some(policy) = &policy
                && let Some(record) = self.recorded(policy)?
            {
                // External trust never silently loses to an application-owned pin.
                // Replacements are limited to explicitly observed application pins.
                if self.configured_trust(policy).await? {
                    return Err(denied());
                }
                let key_type = record.split_whitespace().nth(1).ok_or_else(unavailable)?;
                let algorithms = policy.key_algorithms(key_type).ok_or_else(unavailable)?;
                configuration.configure_pin(&self.pin(policy), &algorithms);
            }
            match self
                .ssh
                .open_configuration(configuration, credentials, mesh)
                .await
            {
                Ok(session) => Ok(session),
                Err(mut failure) => {
                    if failure.kind == FailureKind::HostKey
                        && let Some(policy) = policy
                    {
                        failure.set_host_key_challenge(self.observe(destination, policy).await?);
                        // The shown fingerprint and type come from the same observation
                        // consumed by confirmation, rather than a second scanner's order.
                        failure.fingerprints.clear();
                        if let Some(challenge) = failure.host_key_challenge()
                            && let Some(observation) = lock(&self.pending).get(&challenge)
                            && let Some((fingerprint, record)) = observation.keys.first()
                        {
                            failure.fingerprints.push(fingerprint.clone());
                            failure.host_key_type =
                                record.split_whitespace().nth(1).map(str::to_owned);
                            failure.host_key_changed = observation.previous.is_some();
                        }
                    }
                    Err(failure.at(crate::model::InstallStep::Connect))
                }
            }
        })
    }
    /// Pin the key observed for `challenge` if `fingerprint` matches it; see `confirm` for the checks.
    fn confirm_host_key<'a>(
        &'a self,
        destination: Destination,
        challenge: &'a str,
        fingerprint: &'a str,
        authority: &'a dyn ConfirmationAuthority,
    ) -> Operation<'a, ()> {
        Box::pin(self.confirm(destination, challenge, fingerprint, authority))
    }
}

/// Parse bounded keyscan syntax for the already validated lookup.
/// Cryptographic key validation belongs to the selected SSH engine.
/// Robustness tests call this exact production decoder.
///
/// Accepts exactly three fields (name, key type, base64 key of at most 4096
/// characters) with a supported key type. Returns the canonical line
/// `<lookup> <type> <key>\n`, which replaces whatever name the scan printed.
#[doc(hidden)]
#[must_use]
pub fn public_record(line: &[u8], lookup: &str) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() != 3
        || !matches!(
            fields[1],
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        )
        || fields[2].len() > 4096
        || fields[2].is_empty()
        || !fields[2]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    Some(format!("{lookup} {} {}\n", fields[1], fields[2]))
}
/// True for a SHA-256 fingerprint as printed by OpenSSH: `SHA256:` plus 43 base64 characters.
fn valid_fingerprint(value: &str) -> bool {
    value.len() == 50
        && value.starts_with("SHA256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}
/// The one error for every failed confirmation, so a peer learns nothing about which check failed.
fn denied() -> Failure {
    Failure::new(
        FailureKind::HostKey,
        "The SSH host-key confirmation needs review. Retry the host check.",
    )
}
/// Generic error for unsafe, malformed or unreadable trust state.
fn unavailable() -> Failure {
    Failure::unsupported("The public SSH trust policy is unavailable or ambiguous.")
}
/// Lock a mutex, ignoring poisoning (the guarded data stays valid after a panic elsewhere).
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
