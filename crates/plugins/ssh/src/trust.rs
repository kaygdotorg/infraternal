//! Pins one explicitly confirmed SSH key; changed application pins need a fresh observation and atomic confirmation.

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

struct Observation {
    destination: Destination,
    policy: TrustPolicy,
    keys: Vec<(String, String)>,
    previous: Option<String>,
    received: Instant,
}

/// Shares public pin/challenge custody across every automatic method and batch.
/// No private key, password, session capability or invitation enters this store.
pub struct TrustedOpenSsh {
    ssh: OpenSsh,
    root: PathBuf,
    pending: Mutex<HashMap<uuid::Uuid, Observation>>,
    publication: Mutex<()>,
}
impl TrustedOpenSsh {
    #[must_use]
    pub fn new(ssh: OpenSsh, root: PathBuf) -> Self {
        Self {
            ssh,
            root,
            pending: Mutex::new(HashMap::new()),
            publication: Mutex::new(()),
        }
    }

    fn pin(&self, policy: &TrustPolicy) -> PathBuf {
        self.root.join(format!(
            "{:x}.pub",
            Sha256::digest(policy.lookup.as_bytes())
        ))
    }

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
        let _publication = lock(&self.publication);
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
        Ok(())
    }
}

impl SshTransport for TrustedOpenSsh {
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
                        failure.host_key_challenge = self.observe(destination, policy).await?;
                        // The shown fingerprint and type come from the same observation
                        // consumed by confirmation, rather than a second scanner's order.
                        failure.fingerprints.clear();
                        if let Some(challenge) = failure.host_key_challenge
                            && let Some(observation) = lock(&self.pending).get(&challenge)
                            && let Some((fingerprint, record)) = observation.keys.first()
                        {
                            failure.fingerprints.push(fingerprint.clone());
                            failure.host_key_type =
                                record.split_whitespace().nth(1).map(str::to_owned);
                            failure.host_key_changed = observation.previous.is_some();
                        }
                    }
                    Err(failure)
                }
            }
        })
    }
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
fn valid_fingerprint(value: &str) -> bool {
    value.len() == 50
        && value.starts_with("SHA256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}
fn denied() -> Failure {
    Failure::new(
        FailureKind::HostKey,
        "The SSH host-key confirmation needs review. Retry the host check.",
    )
}
fn unavailable() -> Failure {
    Failure::unsupported("The public SSH trust policy is unavailable or ambiguous.")
}
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
