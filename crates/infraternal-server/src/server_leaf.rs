//! The server's leg-B TLS leaf: short-lived, reissued while the CA is unlocked, and durable before it is served (#559, D168).
//!
//! Every infraternal agent dials the server over QUIC or TCP/TLS and checks the
//! server's certificate (its "leaf") against the machine CA. The leaf's
//! private key sits in plaintext on disk on purpose: reconnects must keep
//! working while the CA is locked after a cold start (D168), so the server
//! needs that key without an administrator. That makes the leaf the one
//! credential a copied state directory still carries, so it must not live
//! long and must be replaced:
//!
//! - **Short life.** A leaf lasts [`LIFETIME`] from its `notBefore`.
//! - **Reissued while unlocked.** The rotation task issues a fresh key and
//!   leaf whenever the CA becomes unlocked (an administrator's unlock, or a
//!   process that starts already unlocked from a warm handoff, D217), and
//!   again at half-life while it stays unlocked. While locked it waits; the
//!   current leaf keeps serving until it expires. Agents' own 7-day
//!   certificates cannot renew while locked either, so the server leaf is
//!   never what ends a locked server's connectivity.
//! - **Strictly newer.** Each leaf's `notBefore` is later than the previous
//!   one's. Agents remember the newest they have accepted and refuse older
//!   ones (`server_leaf_floor` in the remote plugin), which turns any copied
//!   older key into a dead credential once an agent has seen its successor.
//! - **Durable first.** A new leaf is written to disk (one file, atomic
//!   rename, fsync) before any listener serves it, and the old key files are
//!   then removed. A crash at any point leaves either the old or the new pair,
//!   never a mismatch, and a restart never serves a leaf older than one an
//!   agent may already have seen.
//!
//! Storage: `active/remote-leaf.pem` holds the certificate PEM followed by the
//! PKCS#8 key PEM (mode 0600). Directories bootstrapped before #559 hold
//! `remote.pem` and `remote.key` instead; [`load`] reads those until the first
//! rotation replaces them.
//!
//! The same machinery keeps the server node's **relay leaf** (D401 Q3, Q4) in
//! `active/relay-leaf.pem`: a server-purpose leaf for the same name plus one
//! `urn:infraternal:relay:<uuid>` URI SAN, valid [`RELAY_LIFETIME`] and
//! renewed at half-life while the CA is unlocked, like host leaves (D133). It
//! is a separate key, so a stolen relay key never answers a leg-B dial (leg B
//! refuses the relay URI) and the leg-B key never serves relay connections
//! (relay clients require it). [`Rotation::relay`] selects it.
use crate::{
    ca::{CaError, CaKeySource, CaMaterial, CertificateAuthority},
    remote_startup::{private_directory, private_file},
};
use infraternal_agent::remote_tls::Identity;
use openssl::{asn1::Asn1TimeRef, pkey::PKey, x509::X509};
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// How long one server leaf is valid: 30 days (proposed in #559, pending the
/// owner's approval as a decision). Renewal happens at half of it.
pub(crate) const LIFETIME: i64 = 30 * 86_400;
/// How far `notBefore` is set before the issuing time: one day, so an
/// infraternal agent whose clock runs behind the server's (a host without a
/// real-time clock before NTP syncs, a resumed VM) still accepts a leaf the
/// moment it is served. It costs nothing in security: agents order leaves by
/// `notBefore`, and the lifetime is counted from it.
pub(crate) const BACKDATE: i64 = 86_400;
/// An unlock does not reissue a leaf younger than this; it is already fresh
/// (for example the leaf a first-run bootstrap has just created).
const FRESH: i64 = 600;
/// Wait after a failed rotation (storage or signing) before trying again.
const RETRY: Duration = Duration::from_secs(300);
/// Longest single sleep, so a suspended host or a wall-clock jump is noticed
/// within a day. One wakeup a day is the task's whole idle cost.
const LONGEST_SLEEP: Duration = Duration::from_hours(24);

/// The current leaf file.
const FILE: &str = "remote-leaf.pem";
/// The relay leaf file, beside the leg-B leaf in the CA's `active` directory.
const RELAY_FILE: &str = "relay-leaf.pem";
/// How long one relay leaf is valid: 7 days from `notBefore`, renewed at half of it, the
/// same rule as host leaves (D401 Q3, D133).
pub(crate) const RELAY_LIFETIME: i64 = 7 * 86_400;
/// Certificate file written by servers bootstrapped before #559.
const LEGACY_CERTIFICATE: &str = "remote.pem";
/// Key file written by servers bootstrapped before #559.
const LEGACY_KEY: &str = "remote.key";

/// Issue a fresh server key and leaf for `name` from unlocked CA `material`.
///
/// `notBefore` is `now - BACKDATE`, raised to one second after `previous`'s
/// `notBefore` when that is later, so leaves are strictly ordered: an
/// infraternal agent that accepted `previous` accepts the successor.
/// `notAfter` is `notBefore + LIFETIME`, cut to the issuer's own end.
/// # Errors
/// Refuses a successor that would start in the future. That only happens
/// when the clock is now more than `BACKDATE` behind the time `previous` was
/// issued; the server then keeps serving `previous` (agents may already have
/// accepted it, so issuing below it would cut them off) until the clock
/// passes it. Also refuses a window the issuer cannot cover, or a signing
/// failure.
pub(crate) fn issue(
    material: &CaMaterial,
    name: &str,
    previous: Option<&X509>,
    now: i64,
) -> Result<Identity, CaError> {
    issue_leaf(material, name, None, previous, now)
}

/// Issue a fresh relay key and relay leaf for `name` with relay id `relay`, by the same
/// ordering rules as [`issue`] and [`RELAY_LIFETIME`] (D401 Q3). The rotation task issues
/// through [`Rotation::relay`]; this direct form is for tests.
/// # Errors
/// The refusals of [`issue`].
#[cfg(test)]
pub(crate) fn issue_relay(
    material: &CaMaterial,
    name: &str,
    relay: uuid::Uuid,
    previous: Option<&X509>,
    now: i64,
) -> Result<Identity, CaError> {
    issue_leaf(material, name, Some(relay), previous, now)
}

/// [`issue`] for the leg-B leaf (`relay` is `None`) or a relay leaf.
fn issue_leaf(
    material: &CaMaterial,
    name: &str,
    relay: Option<uuid::Uuid>,
    previous: Option<&X509>,
    now: i64,
) -> Result<Identity, CaError> {
    let mut start = now.checked_sub(BACKDATE).ok_or(CaError)?.max(0);
    if let Some(previous) = previous {
        let after = seconds(previous.not_before())?
            .checked_add(1)
            .ok_or(CaError)?;
        start = start.max(after);
    }
    let issuer_start = seconds(material.issuer().not_before())?;
    start = start.max(issuer_start);
    if start > now {
        return Err(CaError);
    }
    let lifetime = if relay.is_some() {
        RELAY_LIFETIME
    } else {
        LIFETIME
    };
    let end = start
        .checked_add(lifetime)
        .ok_or(CaError)?
        .min(seconds(material.issuer().not_after())?);
    let key = PKey::generate_ed25519().map_err(|_| CaError)?;
    let authority = CertificateAuthority::from_material(material.clone())?;
    let certificate = match relay {
        Some(relay) => authority.sign_relay(name, relay, &key, start, end)?,
        None => authority.sign_server(name, &key, start, end)?,
    };
    Ok(Identity { certificate, key })
}

/// When `leaf` should be replaced: half-way through its life, counted from
/// the time it was issued (`notBefore + BACKDATE`).
/// # Errors
/// Refuses unreadable validity times.
pub(crate) fn renew_at(leaf: &X509) -> Result<i64, CaError> {
    let issued = seconds(leaf.not_before())?.saturating_add(BACKDATE);
    let end = seconds(leaf.not_after())?;
    Ok(issued.saturating_add(end.saturating_sub(issued) / 2))
}

/// The encoded leaf file: certificate PEM, then PKCS#8 key PEM. The buffer
/// holds the private key and is wiped when dropped.
/// # Errors
/// Refuses unencodable material.
pub(crate) fn encode(identity: &Identity) -> Result<zeroize::Zeroizing<Vec<u8>>, CaError> {
    let mut bytes = zeroize::Zeroizing::new(identity.certificate.to_pem().map_err(|_| CaError)?);
    let key = zeroize::Zeroizing::new(
        identity
            .key
            .private_key_to_pem_pkcs8()
            .map_err(|_| CaError)?,
    );
    bytes.extend_from_slice(&key);
    Ok(bytes)
}

/// Load the retained server leaf and key from the CA's `active` directory,
/// preferring the current file and falling back to the pre-#559 pair.
/// # Errors
/// Refuses unsafe or malformed files and a key that does not match the leaf.
pub(crate) fn load(directory: &Path) -> Result<Identity, CaError> {
    let (certificate, key) = if directory.join(FILE).symlink_metadata().is_ok() {
        let bytes =
            zeroize::Zeroizing::new(private_file(&directory.join(FILE)).map_err(|_| CaError)?);
        // PEM readers skip blocks of another type, so each finds its own block.
        (
            X509::from_pem(&bytes).map_err(|_| CaError)?,
            PKey::private_key_from_pem(&bytes).map_err(|_| CaError)?,
        )
    } else {
        let key = zeroize::Zeroizing::new(
            private_file(&directory.join(LEGACY_KEY)).map_err(|_| CaError)?,
        );
        (
            X509::from_pem(
                &private_file(&directory.join(LEGACY_CERTIFICATE)).map_err(|_| CaError)?,
            )
            .map_err(|_| CaError)?,
            PKey::private_key_from_pem(&key).map_err(|_| CaError)?,
        )
    };
    if !certificate
        .public_key()
        .map_err(|_| CaError)?
        .public_eq(&key)
    {
        return Err(CaError);
    }
    Ok(Identity { certificate, key })
}

/// Write `identity` as the current leaf of `directory` (the CA's `active`
/// directory), durably and atomically, then remove the pre-#559 key files so
/// the replaced key no longer exists on disk.
/// # Errors
/// Refuses an unsafe directory or any storage failure. On failure the
/// previous leaf is still the current one.
pub(crate) fn publish(directory: &Path, identity: &Identity) -> Result<(), CaError> {
    publish_file(directory, FILE, identity)?;
    let mut removed = false;
    for legacy in [LEGACY_KEY, LEGACY_CERTIFICATE] {
        match std::fs::remove_file(directory.join(legacy)) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CaError),
        }
    }
    if removed {
        std::fs::File::open(directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CaError)?;
    }
    Ok(())
}

/// Write `identity` as the relay leaf of `directory`, durably and atomically (D401 Q3).
/// # Errors
/// Refuses an unsafe directory or any storage failure; the previous relay leaf stays.
pub(crate) fn publish_relay(directory: &Path, identity: &Identity) -> Result<(), CaError> {
    publish_file(directory, RELAY_FILE, identity)
}

/// Load the retained relay leaf and key, if one was ever published.
/// # Errors
/// Refuses an unsafe or malformed file, a key that does not match the leaf, or a leaf
/// without exactly one relay URI.
pub(crate) fn load_relay(directory: &Path) -> Result<Option<(Identity, uuid::Uuid)>, CaError> {
    let path = directory.join(RELAY_FILE);
    if path.symlink_metadata().is_err() {
        return Ok(None);
    }
    let bytes = zeroize::Zeroizing::new(private_file(&path).map_err(|_| CaError)?);
    let certificate = X509::from_pem(&bytes).map_err(|_| CaError)?;
    let key = PKey::private_key_from_pem(&bytes).map_err(|_| CaError)?;
    if !certificate
        .public_key()
        .map_err(|_| CaError)?
        .public_eq(&key)
    {
        return Err(CaError);
    }
    let relay = relay_id(&certificate).ok_or(CaError)?;
    Ok(Some((Identity { certificate, key }, relay)))
}

/// The relay id in a relay leaf's one `urn:infraternal:relay:<uuid>` URI SAN.
pub(crate) fn relay_id(certificate: &X509) -> Option<uuid::Uuid> {
    let mut ids = certificate
        .subject_alt_names()?
        .iter()
        .filter_map(|name| name.uri()?.strip_prefix("urn:infraternal:relay:"))
        .filter_map(|id| uuid::Uuid::parse_str(id).ok())
        .collect::<Vec<_>>();
    (ids.len() == 1).then(|| ids.pop()).flatten()
}

/// Write `identity` as the file `name` in `directory`, durably and atomically.
fn publish_file(directory: &Path, name: &str, identity: &Identity) -> Result<(), CaError> {
    private_directory(directory).map_err(|_| CaError)?;
    let bytes = encode(identity)?;
    let pending = directory.join(format!(".{name}-{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&pending, directory.join(name))?;
        std::fs::File::open(directory)?.sync_all()
    })();
    let _ = std::fs::remove_file(&pending);
    result.map_err(|_| CaError)
}

/// What the rotation task needs besides the listeners: the signer and where
/// and for which name the leaf lives.
pub(crate) struct Rotation {
    /// The CA key source; rotation only signs while it reports unlocked.
    pub(crate) source: Arc<dyn CaKeySource>,
    /// The CA's `active` directory that holds the leaf file.
    pub(crate) directory: PathBuf,
    /// The server name the leaf certifies (the public origin's host).
    pub(crate) name: String,
    /// `Some(id)` keeps the relay leaf with relay id `id` instead of the leg-B leaf.
    pub(crate) relay: Option<uuid::Uuid>,
}

/// Keep the served leaf fresh for as long as the listeners live.
///
/// `current` is the leaf the listeners serve now; `None` (a relay leaf never issued yet)
/// issues one at the first unlocked moment. `serve` installs a new
/// identity into the listeners for new connections; it is called only after
/// the leaf is durable. The task returns when the key source has no lock
/// events or its sender is gone.
pub(crate) async fn run(
    rotation: Rotation,
    current: Option<X509>,
    serve: impl Fn(&Identity) -> std::io::Result<()> + Send + Sync,
) {
    let mut current = if let Some(current) = current {
        current
    } else {
        let Some(first) = first_leaf(&rotation, &serve).await else {
            return;
        };
        first
    };
    let Some(mut locked) = rotation.source.subscribe_locked() else {
        return;
    };
    // Starting unlocked means a warm handoff (D217): treat it as an unlock.
    let mut unlocked_now = true;
    loop {
        if *locked.borrow_and_update() {
            if locked.changed().await.is_err() {
                return;
            }
            unlocked_now = true;
            continue;
        }
        let Ok(now) = crate::runtime::unix_seconds() else {
            return;
        };
        let issued = seconds(current.not_before())
            .map_or(i64::MIN, |not_before| not_before.saturating_add(BACKDATE));
        let due = !renew_at(&current).is_ok_and(|at| now < at);
        let mut wait = None;
        if due || (unlocked_now && now.saturating_sub(issued) >= FRESH) {
            match rotate(&rotation, &current, now, &serve).await {
                Ok(next) => current = next,
                Err(_) => wait = Some(RETRY),
            }
        }
        unlocked_now = false;
        let wait = wait.unwrap_or_else(|| {
            let at = renew_at(&current).unwrap_or(now);
            Duration::from_secs(u64::try_from(at.saturating_sub(now)).unwrap_or(0))
                .clamp(Duration::from_secs(1), LONGEST_SLEEP)
        });
        tokio::select! {
            changed = locked.changed() => {
                if changed.is_err() {
                    return;
                }
                unlocked_now = true;
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Wait for the CA to be unlocked, then issue, persist and serve the first leaf. Returns
/// `None` when the key source has no lock events or its sender is gone.
async fn first_leaf(
    rotation: &Rotation,
    serve: &(impl Fn(&Identity) -> std::io::Result<()> + Send + Sync),
) -> Option<X509> {
    let mut locked = rotation.source.subscribe_locked()?;
    loop {
        if !*locked.borrow_and_update()
            && let Ok(now) = crate::runtime::unix_seconds()
        {
            if let Ok(first) = issue_and_serve(rotation, None, now, serve).await {
                return Some(first);
            }
            tokio::select! {
                changed = locked.changed() => changed.ok()?,
                () = tokio::time::sleep(RETRY) => {}
            }
            continue;
        }
        locked.changed().await.ok()?;
    }
}

/// Issue, persist, then serve one new leaf; returns its certificate.
async fn rotate(
    rotation: &Rotation,
    current: &X509,
    now: i64,
    serve: &(impl Fn(&Identity) -> std::io::Result<()> + Send + Sync),
) -> Result<X509, CaError> {
    issue_and_serve(rotation, Some(current.clone()), now, serve).await
}

/// Issue the next leaf after `previous` (leg-B or relay, by `rotation.relay`), make it
/// durable, then serve it; returns its certificate.
async fn issue_and_serve(
    rotation: &Rotation,
    previous: Option<X509>,
    now: i64,
    serve: &(impl Fn(&Identity) -> std::io::Result<()> + Send + Sync),
) -> Result<X509, CaError> {
    let material = rotation.source.load()?;
    let directory = rotation.directory.clone();
    let name = rotation.name.clone();
    let relay = rotation.relay;
    // Key generation and two fsyncs: keep them off the async workers.
    let identity = tokio::task::spawn_blocking(move || {
        let identity = issue_leaf(&material, &name, relay, previous.as_ref(), now)?;
        if relay.is_some() {
            publish_relay(&directory, &identity)?;
        } else {
            publish(&directory, &identity)?;
        }
        Ok::<_, CaError>(identity)
    })
    .await
    .map_err(|_| CaError)??;
    // The leaf is durable; a failed install here only delays serving it.
    // The next attempt issues a newer one, which agents also accept.
    serve(&identity).map_err(|_| CaError)?;
    Ok(identity.certificate)
}

/// An ASN.1 time as Unix seconds.
fn seconds(time: &Asn1TimeRef) -> Result<i64, CaError> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).map_err(|_| CaError)?;
    let difference = epoch.diff(time).map_err(|_| CaError)?;
    i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or(CaError)
}

/// Tests for issuing, storing and rotating the leaf.
#[cfg(test)]
#[path = "server_leaf_tests.rs"]
mod tests;
