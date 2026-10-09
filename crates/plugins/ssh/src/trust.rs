//! Records only explicitly confirmed first-contact public host pins; existing/changed/revoked trust cannot be replaced.

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
    received: Instant,
}

/// Shares public pin/challenge custody across every automatic method and batch.
/// No private key, password, session capability or invitation enters this store.
pub struct TrustedOpenSsh {
    ssh: OpenSsh,
    root: PathBuf,
    pending: Mutex<HashMap<uuid::Uuid, Observation>>,
}
impl TrustedOpenSsh {
    #[must_use]
    pub fn new(ssh: OpenSsh, root: PathBuf) -> Self {
        Self {
            ssh,
            root,
            pending: Mutex::new(HashMap::new()),
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

    fn recorded(&self, policy: &TrustPolicy) -> Result<bool, Failure> {
        self.private_root()?;
        let path = self.pin(policy);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
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
        Ok(true)
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
        if self.recorded(&policy)? || self.configured_trust(&policy).await? {
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
            || self.recorded(&policy)?
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
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.pin(&policy))
            .map_err(|_| denied())?;
        if file
            .write_all(record.as_bytes())
            .and_then(|()| file.sync_all())
            .is_err()
        {
            // An incomplete record never authenticates a host; retain it to fail
            // closed for manual recovery instead of racing another confirmation.
            return Err(unavailable());
        }
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable())?;
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
                && self.recorded(policy)?
            {
                // Dedicated pins are immutable. Matching public configuration
                // added later needs review, rather than broadening acceptance.
                if self.configured_trust(policy).await? {
                    return Err(denied());
                }
                configuration.configure_pin(&self.pin(policy));
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
