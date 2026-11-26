//! Publishes the first machine issuer, remote TLS identity and wrapped administrator copy as one durable private directory [151][168], #78.
use crate::{
    ca::{CaError, CaMaterial, wrapping::WrappedCa},
    ca_copies::CaCopies,
    ca_memory::MemoryCaSource,
    enrollment::EnrollmentStore,
    remote_runtime::{RemoteHosts, RemoteListeners},
    remote_startup::{private_directory, private_file},
};
use infraternal_agent::remote_tls::Identity;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use std::{
    io::Write,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

/// Configured server coordinates; no initialization or background work occurs at construction.
#[derive(Clone)]
pub struct BootstrapConfig {
    /// Directory that holds the CA state, including the `active` directory once a CA is published.
    pub(crate) directory: PathBuf,
    /// Common name given to the first host identity certificate created at bootstrap.
    pub(crate) name: String,
    /// Address the deferred remote listener binds once the CA is unlocked.
    pub(crate) address: SocketAddr,
    /// True if the remote listeners start only after bootstrap activates them.
    pub(crate) deferred: bool,
}
/// Owns deferred listeners with the router, so disabling/dropping remote leaves no work.
pub(crate) struct BootstrapRuntime {
    /// The configuration this runtime was built from.
    pub(crate) config: BootstrapConfig,
    /// Registry of enrolled remote hosts.
    pub(crate) hosts: RemoteHosts,
    /// Database-backed store for host enrollment and revocation.
    pub(crate) store: EnrollmentStore,
    /// The CA signer; the listeners' leaf rotation signs with it while unlocked (#559).
    source: Arc<MemoryCaSource>,
    /// Listeners to start on activation; `None` once taken or when remote is off.
    listeners: Mutex<Option<RemoteListeners>>,
}
impl BootstrapRuntime {
    /// Construct inactive plugin listener ownership; no work starts here.
    #[must_use]
    pub(crate) fn new(
        config: BootstrapConfig,
        hosts: RemoteHosts,
        store: EnrollmentStore,
        source: Arc<MemoryCaSource>,
    ) -> Self {
        Self {
            config,
            hosts,
            store,
            source,
            listeners: Mutex::new(None),
        }
    }
    /// Activate configured listeners after durable machine trust exists.
    /// # Errors
    /// Refuses invalid retained trust or unavailable configured ports.
    pub(crate) async fn activate(&self) -> Result<(), CaError> {
        if !self.config.deferred {
            return Ok(());
        }
        let mut listeners = self.listeners.lock().await;
        if listeners.is_some() {
            return Ok(());
        }
        let directory = self.config.directory.join("active");
        let retained = directory.clone();
        let (identity, issuer) = tokio::task::spawn_blocking(move || retained_identity(&retained))
            .await
            .map_err(|_| CaError)??;
        let mut started = RemoteListeners::start(
            self.config.address,
            &identity,
            &[issuer],
            self.store.clone(),
            self.hosts.clone(),
        )
        .await
        .map_err(|_| CaError)?;
        started.rotate_server_leaf(
            crate::server_leaf::Rotation {
                source: self.source.clone(),
                directory,
                name: self.config.name.clone(),
                relay: None,
            },
            identity.certificate,
        );
        *listeners = Some(started);
        Ok(())
    }
}

/// Load only durable public trust without reading transport or signing keys.
/// # Errors
/// Refuses unsafe files or an issuer that is not self-signed Ed25519.
pub fn public_issuer(directory: &Path) -> Result<X509, CaError> {
    private_directory(directory).map_err(|_| CaError)?;
    let issuer = X509::from_pem(&private_file(&directory.join("issuer.pem")).map_err(|_| CaError)?)
        .map_err(|_| CaError)?;
    let key = issuer.public_key().map_err(|_| CaError)?;
    if key.id() != openssl::pkey::Id::ED25519 || !issuer.verify(&key).map_err(|_| CaError)? {
        return Err(CaError);
    }
    Ok(issuer)
}
/// Load retained public trust and its private remote TLS leaf identity
/// (current file or the pre-#559 pair, see `server_leaf`).
/// # Errors
/// Refuses unsafe files, invalid certificates or a mismatched leaf key.
pub fn retained_identity(directory: &Path) -> Result<(Identity, X509), CaError> {
    let issuer = public_issuer(directory)?;
    Ok((crate::server_leaf::load(directory)?, issuer))
}
/// Creates `path` with mode 0600, writes `bytes` and flushes to disk. Fails if the file already exists, so nothing is overwritten.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CaError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| CaError)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CaError)
}
/// The caller owns the database writer lock. A retained directory wins even
/// after a crash between directory publication and in-memory installation.
/// Never repair incomplete/unsafe retained state by minting a different issuer.
/// # Errors
/// Refuses retained trust, unsafe directories or failed cryptography/storage.
pub fn publish_first(
    config: &BootstrapConfig,
    member: &str,
    generation: u64,
    salt: &[u8; 32],
    key: &[u8; 32],
    now: i64,
) -> Result<CaMaterial, CaError> {
    private_directory(&config.directory).map_err(|_| CaError)?;
    let active = config.directory.join("active");
    if active.try_exists().map_err(|_| CaError)? {
        return Err(CaError);
    }
    let stage = config
        .directory
        .join(format!(".bootstrap-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&stage)
        .map_err(|_| CaError)?;
    let result = (|| {
        let (material, identity) = generate(&config.name, now)?;
        CaCopies::new(&stage)?.publish(
            member,
            generation,
            &WrappedCa::seal(&material, member, generation, salt, key)?,
        )?;
        write_new(
            &stage.join("issuer.pem"),
            &material.issuer().to_pem().map_err(|_| CaError)?,
        )?;
        write_new(
            &stage.join("remote-leaf.pem"),
            &crate::server_leaf::encode(&identity)?,
        )?;
        std::fs::File::open(&stage)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CaError)?;
        // The SQLite writer lock serializes every authorized provisioning process.
        // Rename exposes either the complete copy set or no issuer at all.
        std::fs::rename(&stage, &active).map_err(|_| CaError)?;
        std::fs::remove_file(config.directory.join("pending")).map_err(|_| CaError)?;
        std::fs::File::open(&config.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CaError)?;
        Ok(material)
    })();
    if stage.exists() {
        let _ = std::fs::remove_dir_all(stage);
    }
    result
}
/// Creates a new CA (valid from `now` for ten years; `now` must be
/// non-negative) and the server's first leg-B leaf for `name`, which lasts
/// `server_leaf::LIFETIME` like every later one (#559). Returns the CA
/// material and the leaf identity; nothing is written to disk.
fn generate(name: &str, now: i64) -> Result<(CaMaterial, Identity), CaError> {
    let end = now
        .checked_add(315_360_000)
        .filter(|_| now >= 0)
        .ok_or(CaError)?;
    let (key, issuer) = generate_issuer(now, end)?;
    let material = CaMaterial::new(key, issuer);
    let identity = crate::server_leaf::issue(&material, name, None, now)?;
    Ok((material, identity))
}

/// Creates a fresh Ed25519 key and a self-signed CA certificate for it, valid from `now` until `end`.
fn generate_issuer(now: i64, end: i64) -> Result<(PKey<openssl::pkey::Private>, X509), CaError> {
    let key = PKey::generate_ed25519().map_err(|_| CaError)?;
    let mut subject = X509NameBuilder::new().map_err(|_| CaError)?;
    subject
        .append_entry_by_text("CN", "infraternal machine certificate authority")
        .map_err(|_| CaError)?;
    let subject = subject.build();
    let mut issuer = X509::builder().map_err(|_| CaError)?;
    issuer.set_version(2).map_err(|_| CaError)?;
    let serial = BigNum::from_slice(uuid::Uuid::new_v4().as_bytes())
        .and_then(|v| v.to_asn1_integer())
        .map_err(|_| CaError)?;
    issuer.set_serial_number(&serial).map_err(|_| CaError)?;
    issuer.set_subject_name(&subject).map_err(|_| CaError)?;
    issuer.set_issuer_name(&subject).map_err(|_| CaError)?;
    issuer.set_pubkey(&key).map_err(|_| CaError)?;
    issuer
        .set_not_before(Asn1Time::from_unix(now).map_err(|_| CaError)?.as_ref())
        .map_err(|_| CaError)?;
    issuer
        .set_not_after(Asn1Time::from_unix(end).map_err(|_| CaError)?.as_ref())
        .map_err(|_| CaError)?;
    issuer
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .map_err(|_| CaError)?,
        )
        .map_err(|_| CaError)?;
    issuer
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|_| CaError)?,
        )
        .map_err(|_| CaError)?;
    issuer
        .sign(&key, MessageDigest::null())
        .map_err(|_| CaError)?;
    let issuer = issuer.build();
    Ok((key, issuer))
}

/// Install only validated material with durable copies; no caller can replace trust.
/// Install durably provisioned material in the configured memory source.
/// # Errors
/// Refuses inconsistent or replaced trust.
pub fn install(source: &Arc<MemoryCaSource>, material: CaMaterial) -> Result<(), CaError> {
    source.provision(material)
}

/// Tests for creating and checking bootstrap certificate material.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that a generated remote leaf survives cold-start chain validation.
    #[test]
    fn generated_remote_leaf_is_verifiable_after_cold_restart() {
        // Leave room between whole-second ASN.1 validity and OpenSSL's live clock check.
        let generated_at = crate::runtime::unix_seconds().unwrap().saturating_sub(60);
        let (material, identity) = generate("bootstrap.example.test", generated_at).unwrap();
        let mut trust = openssl::x509::store::X509StoreBuilder::new().unwrap();
        trust.add_cert(material.issuer().clone()).unwrap();
        let mut params = openssl::x509::verify::X509VerifyParam::new().unwrap();
        params.set_host("bootstrap.example.test").unwrap();
        params
            .set_purpose(openssl::x509::X509PurposeId::SSL_SERVER)
            .unwrap();
        trust.set_param(&params).unwrap();
        let chain = openssl::stack::Stack::new().unwrap();
        let verified = openssl::x509::X509StoreContext::new()
            .unwrap()
            .init(&trust.build(), &identity.certificate, &chain, |context| {
                let verified = context.verify_cert()?;
                // Keep the failure inside the initialized context: verification
                // state is cleared when init returns. Public dates distinguish a
                // clock failure from chain/purpose failures without logging keys.
                assert!(
                    verified,
                    "certificate verification: error={} depth={} generated_at={} verified_at={} root_validity={}..{} leaf_validity={}..{}",
                    context.error(),
                    context.error_depth(),
                    generated_at,
                    crate::runtime::unix_seconds().unwrap(),
                    material.issuer().not_before(),
                    material.issuer().not_after(),
                    identity.certificate.not_before(),
                    identity.certificate.not_after(),
                );
                Ok(verified)
            })
            .unwrap();
        assert!(verified);
    }
}
