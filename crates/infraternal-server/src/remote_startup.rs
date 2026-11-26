//! Loads retained public CA trust for normal CLI startup while the D168 signing source remains cold-locked (#78).

use crate::{
    RemoteService, ServerConfig, ServerError, TlsFault, TlsPart,
    ca_memory::MemoryCaSource,
    remote_http::{EnrollmentEndpoint, EnrollmentService},
};
use infraternal_agent::remote_tls::Identity;
use openssl::{
    pkey::PKey,
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};
use std::{
    io::Read,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Explicit remote listener activation; no CA generation or secret unlock flags.
pub struct RemoteStartup {
    /// Advertised dial-out destination, shared by QUIC and TCP/TLS.
    pub listen: SocketAddr,
    /// Retained public issuer directory; None uses the standard XDG data path.
    pub ca_dir: Option<PathBuf>,
}

impl RemoteStartup {
    /// Build only public verification and server-leaf transport state. The CA key
    /// is never read from disk here; administrator unlock is a separate adapter.
    /// # Errors
    /// Refuses missing/unsafe trust files, mismatched leaf/key, invalid chain/name
    /// or unsupported reverse-proxy trust configuration without regenerating CA.
    pub fn cold_start(&self, config: &ServerConfig) -> Result<RemoteService, ServerError> {
        if self.listen.ip().is_unspecified() || self.listen.port() == 0 {
            return Err(ServerError::InvalidConfiguration);
        }
        crate::runtime::validate_config(config)?;
        let _https = https_identity(config)?;
        let ca_dir = self.ca_dir.clone().map_or_else(default_ca_dir, Ok)?;
        if !ca_dir.is_absolute() {
            return Err(ServerError::InvalidConfiguration);
        }
        if !ca_dir
            .try_exists()
            .map_err(|error| TlsPart::CaDirectory.error(TlsFault::from_io(&error)))?
        {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&ca_dir)
                .map_err(|error| TlsPart::CaDirectory.error(TlsFault::from_io(&error)))?;
        }
        private_directory(&ca_dir).map_err(|fault| TlsPart::CaDirectory.error(fault))?;
        let origin = url::Url::parse(&config.public_origin)
            .map_err(|_| ServerError::InvalidConfiguration)?;
        let name = origin.host_str().ok_or(ServerError::InvalidConfiguration)?;
        if ca_dir.join("active").symlink_metadata().is_ok() {
            self.retained_service(config, ca_dir, name)
        } else if ca_dir.join("issuer.pem").symlink_metadata().is_ok() {
            self.legacy_service(config, ca_dir, name)
        } else {
            self.fresh_service(config, ca_dir, name)
        }
    }
    /// Start the remote service from a retained, versioned CA directory.
    fn retained_service(
        &self,
        config: &ServerConfig,
        ca_dir: PathBuf,
        name: &str,
    ) -> Result<RemoteService, ServerError> {
        let (identity, issuer) = crate::ca_bootstrap::retained_identity(&ca_dir.join("active"))
            .map_err(TlsPart::ActiveCa.failed())?;
        // An expired leaf must not stop the server: the web app and the CA
        // unlock still have to come up, and the first unlock reissues the
        // leaf at once (#559). Chain, purpose and name are still checked.
        verify_server_at_any_time(
            TlsPart::HostCertificate,
            &issuer,
            &identity.certificate,
            name,
        )?;
        let https = https_certificate(config)?;
        let source = Arc::new(if let Some(https) = https {
            MemoryCaSource::cold_start_with_https(issuer.clone(), https)
        } else {
            MemoryCaSource::cold_start_with_system_https(issuer.clone())
        });
        let mut administration = crate::ca_administration::CaAdministrationConfig::new(
            source.clone(),
            ca_dir.join("active"),
        );
        administration.bootstrap = Some(crate::ca_bootstrap::BootstrapConfig {
            directory: ca_dir,
            name: name.to_owned(),
            address: self.listen,
            deferred: false,
        });
        Ok(RemoteService {
            ca_administration: Some(administration),
            enrollment: EnrollmentService {
                source,
                endpoint: EnrollmentEndpoint {
                    ca_der: issuer.to_der().map_err(TlsPart::ActiveCa.failed())?,
                    endpoint: self.listen,
                    server_name: name.to_owned(),
                },
            },
            identity: Some(identity),
            roots: vec![issuer],
            clock_health: Arc::new(crate::clock_health::ClockHealth::default()),
        })
    }
    /// Start the remote service with a new CA, set up on first use.
    fn fresh_service(
        &self,
        config: &ServerConfig,
        ca_dir: PathBuf,
        name: &str,
    ) -> Result<RemoteService, ServerError> {
        // A fresh private CA directory can be configured before the first tap.
        // Refuse incomplete legacy trust; removing an issuer must never create a new CA.
        if std::fs::read_dir(&ca_dir)
            .map_err(|error| TlsPart::CaDirectory.error(TlsFault::from_io(&error)))?
            .next()
            .is_none()
        {
            let marker = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(ca_dir.join("pending"))
                .map_err(TlsPart::PendingMarker.failed())?;
            marker.sync_all().map_err(TlsPart::PendingMarker.failed())?;
            std::fs::File::open(&ca_dir)
                .and_then(|dir| dir.sync_all())
                .map_err(TlsPart::CaDirectory.failed())?;
        }
        if !read_private(TlsPart::PendingMarker, &ca_dir.join("pending"))?.is_empty() {
            return Err(TlsPart::PendingMarker.error(TlsFault::Failed));
        }
        let https = https_certificate(config)?;
        let source = Arc::new(MemoryCaSource::unprovisioned(https));
        let mut administration =
            crate::ca_administration::CaAdministrationConfig::new(source.clone(), ca_dir.clone());
        administration.bootstrap = Some(crate::ca_bootstrap::BootstrapConfig {
            directory: ca_dir,
            name: name.to_owned(),
            address: self.listen,
            deferred: true,
        });
        Ok(RemoteService {
            ca_administration: Some(administration),
            enrollment: EnrollmentService {
                source,
                endpoint: EnrollmentEndpoint {
                    ca_der: vec![],
                    endpoint: self.listen,
                    server_name: name.to_owned(),
                },
            },
            identity: None,
            roots: vec![],
            clock_health: Arc::new(crate::clock_health::ClockHealth::default()),
        })
    }
    /// Start the remote service from a legacy single-issuer CA directory.
    fn legacy_service(
        &self,
        config: &ServerConfig,
        ca_dir: PathBuf,
        name: &str,
    ) -> Result<RemoteService, ServerError> {
        if config.behind_proxy {
            return Err(ServerError::InvalidConfiguration);
        }
        let issuer = certificate_from(TlsPart::Issuer, &ca_dir.join("issuer.pem"))?;
        let public = issuer.public_key().map_err(TlsPart::Issuer.failed())?;
        // Trust anchors are retained independently of signing. Validate their
        // self-signature too: OpenSSL need not check an anchor's signature while
        // verifying a leaf chain.
        let algorithm_ok = match crate::ca::CA_KEY_ALGORITHM {
            crate::ca::CaAlgorithm::Ed25519 => public.id() == openssl::pkey::Id::ED25519,
            crate::ca::CaAlgorithm::P256 => {
                public.id() == openssl::pkey::Id::EC
                    && public.ec_key().is_ok_and(|key| {
                        key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1)
                    })
            }
        };
        if !algorithm_ok
            || issuer
                .subject_name()
                .to_der()
                .map_err(TlsPart::Issuer.failed())?
                != issuer
                    .issuer_name()
                    .to_der()
                    .map_err(TlsPart::Issuer.failed())?
            || !issuer.verify(&public).map_err(TlsPart::Issuer.failed())?
        {
            return Err(TlsPart::Issuer.error(TlsFault::NotIssuer));
        }
        let Identity { certificate, key } = https_identity(config)?
            .ok_or_else(|| TlsPart::Certificate.error(TlsFault::NotConfigured))?;
        verify_server(TlsPart::Certificate, &issuer, &certificate, name)?;
        let source = Arc::new(MemoryCaSource::cold_start(issuer.clone()));
        Ok(RemoteService {
            ca_administration: Some(crate::ca_administration::CaAdministrationConfig::new(
                source.clone(),
                ca_dir,
            )),
            enrollment: EnrollmentService {
                source,
                endpoint: EnrollmentEndpoint {
                    ca_der: issuer.to_der().map_err(TlsPart::Issuer.failed())?,
                    endpoint: self.listen,
                    server_name: name.to_owned(),
                },
            },
            identity: Some(Identity { certificate, key }),
            roots: vec![issuer],
            clock_health: Arc::new(crate::clock_health::ClockHealth::default()),
        })
    }
}

/// Load and cross-check the operator's `--tls-cert` and `--tls-key`, when configured.
fn https_identity(config: &ServerConfig) -> Result<Option<Identity>, ServerError> {
    let Some(tls) = config.tls.as_ref() else {
        return Ok(None);
    };
    let certificate = certificate_from(TlsPart::Certificate, &tls.certificate)?;
    let key = zeroize::Zeroizing::new(read_private(TlsPart::PrivateKey, &tls.private_key)?);
    let key = PKey::private_key_from_pem(&key)
        .map_err(|_| TlsPart::PrivateKey.error(TlsFault::NotPrivateKey))?;
    if !certificate
        .public_key()
        .map_err(TlsPart::Certificate.failed())?
        .public_eq(&key)
    {
        return Err(TlsPart::CertificateAndKey.error(TlsFault::KeyMismatch));
    }
    Ok(Some(Identity { certificate, key }))
}

/// The configured HTTPS certificate alone, which the CA source pins for joining hosts.
fn https_certificate(config: &ServerConfig) -> Result<Option<X509>, ServerError> {
    config
        .tls
        .as_ref()
        .map(|tls| certificate_from(TlsPart::Certificate, &tls.certificate))
        .transpose()
}

/// [`private_file`] with the refusal reported against `part`.
fn read_private(part: TlsPart, path: &Path) -> Result<Vec<u8>, ServerError> {
    private_file(path).map_err(|fault| part.error(fault))
}

/// Read the first PEM certificate of a private file, reporting refusals against `part`.
fn certificate_from(part: TlsPart, path: &Path) -> Result<X509, ServerError> {
    X509::from_pem(&read_private(part, path)?).map_err(|_| part.error(TlsFault::NotCertificate))
}

/// Check that `leaf` chains to `issuer` for the server purpose and `name`, valid now.
/// A refusal is reported against `part`, the leaf that was checked.
fn verify_server(part: TlsPart, issuer: &X509, leaf: &X509, name: &str) -> Result<(), ServerError> {
    verify_server_with(part, issuer, leaf, name, false)
}

/// [`verify_server`] without the validity-time check: the retained leg-B leaf
/// may have expired while the server was down or locked, and only an unlock
/// can replace it (#559).
fn verify_server_at_any_time(
    part: TlsPart,
    issuer: &X509,
    leaf: &X509,
    name: &str,
) -> Result<(), ServerError> {
    verify_server_with(part, issuer, leaf, name, true)
}

/// Shared chain, purpose and name check; `any_time` skips validity dates.
fn verify_server_with(
    part: TlsPart,
    issuer: &X509,
    leaf: &X509,
    name: &str,
    any_time: bool,
) -> Result<(), ServerError> {
    let mut trust = X509StoreBuilder::new().map_err(part.failed())?;
    trust.add_cert(issuer.clone()).map_err(part.failed())?;
    let mut params = X509VerifyParam::new().map_err(part.failed())?;
    if any_time {
        params
            .set_flags(openssl::x509::verify::X509VerifyFlags::NO_CHECK_TIME)
            .map_err(part.failed())?;
    }
    params
        .set_purpose(openssl::x509::X509PurposeId::SSL_SERVER)
        .map_err(part.failed())?;
    if let Ok(ip) = name.parse() {
        params.set_ip(ip).map_err(part.failed())?;
    } else {
        params.set_host(name).map_err(part.failed())?;
    }
    trust.set_param(&params).map_err(part.failed())?;
    let chain = Stack::new().map_err(part.failed())?;
    let mut reason = "";
    let verified = X509StoreContext::new()
        .map_err(part.failed())?
        .init(&trust.build(), leaf, &chain, |context| {
            let verified = context.verify_cert()?;
            reason = context.error().error_string();
            Ok(verified)
        })
        .map_err(part.failed())?;
    if verified {
        Ok(())
    } else {
        Err(part.error(TlsFault::Rejected { reason }))
    }
}

fn default_ca_dir() -> Result<PathBuf, ServerError> {
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or(ServerError::InvalidConfiguration)?;
    Ok(root.join("infraternal/ca"))
}

/// Require an absolute directory owned by this account that nobody else can enter.
/// The error says which of those rules the directory broke.
pub(crate) fn private_directory(path: &Path) -> Result<(), TlsFault> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| TlsFault::from_io(&error))?;
    if metadata.file_type().is_symlink() {
        return Err(TlsFault::SymbolicLink);
    }
    if !path.is_absolute() || !metadata.is_dir() {
        return Err(TlsFault::NotDirectory);
    }
    private_metadata(&metadata)
}

/// The ownership and access rule shared by private files and directories.
fn private_metadata(metadata: &std::fs::Metadata) -> Result<(), TlsFault> {
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(TlsFault::ForeignOwner);
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TlsFault::SharedAccess { mode });
    }
    Ok(())
}

/// The largest private file the server reads.
const PRIVATE_FILE_LIMIT: usize = 8192;

/// Bound reads through a no-follow descriptor; check the opened inode, not an
/// earlier pathname lookup. Public issuer files share the private layout policy.
/// The error says which rule the file broke.
pub(crate) fn private_file(path: &Path) -> Result<Vec<u8>, TlsFault> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| TlsFault::from_io(&error))?;
    let metadata = file.metadata().map_err(|error| TlsFault::from_io(&error))?;
    if !metadata.is_file() {
        return Err(TlsFault::NotFile);
    }
    private_metadata(&metadata)?;
    let too_large = TlsFault::TooLarge {
        limit: PRIVATE_FILE_LIMIT,
    };
    if metadata.len() > PRIVATE_FILE_LIMIT as u64 {
        return Err(too_large);
    }
    let mut bytes = Vec::with_capacity(PRIVATE_FILE_LIMIT);
    file.take(PRIVATE_FILE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsFault::Unreadable)?;
    if bytes.len() > PRIVATE_FILE_LIMIT {
        return Err(too_large);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "remote_startup_tests.rs"]
mod tests;
