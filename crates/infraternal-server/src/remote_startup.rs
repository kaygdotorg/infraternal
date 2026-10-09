//! Loads retained public CA trust for normal CLI startup while the D168 signing source remains cold-locked (#78).

use crate::{
    RemoteService, ServerConfig, ServerError,
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
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
        if self.listen.ip().is_unspecified() || self.listen.port() == 0 || config.behind_proxy {
            return Err(ServerError::InvalidConfiguration);
        }
        let ca_dir = self.ca_dir.clone().map_or_else(default_ca_dir, Ok)?;
        private_directory(&ca_dir)?;
        let issuer = X509::from_pem(&private_file(&ca_dir.join("issuer.pem"))?)
            .map_err(|_| ServerError::TlsConfiguration)?;
        let public = issuer
            .public_key()
            .map_err(|_| ServerError::TlsConfiguration)?;
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
                .map_err(|_| ServerError::TlsConfiguration)?
                != issuer
                    .issuer_name()
                    .to_der()
                    .map_err(|_| ServerError::TlsConfiguration)?
            || !issuer
                .verify(&public)
                .map_err(|_| ServerError::TlsConfiguration)?
        {
            return Err(ServerError::TlsConfiguration);
        }
        let tls = config.tls.as_ref().ok_or(ServerError::TlsConfiguration)?;
        let certificate = X509::from_pem(&private_file(&tls.certificate)?)
            .map_err(|_| ServerError::TlsConfiguration)?;
        let key = PKey::private_key_from_pem(&private_file(&tls.private_key)?)
            .map_err(|_| ServerError::TlsConfiguration)?;
        if !certificate
            .public_key()
            .map_err(|_| ServerError::TlsConfiguration)?
            .public_eq(&key)
        {
            return Err(ServerError::TlsConfiguration);
        }
        let origin = url::Url::parse(&config.public_origin)
            .map_err(|_| ServerError::InvalidConfiguration)?;
        let name = origin.host_str().ok_or(ServerError::InvalidConfiguration)?;
        verify_server(&issuer, &certificate, name)?;
        let source = Arc::new(MemoryCaSource::cold_start(issuer.clone()));
        Ok(RemoteService {
            ca_administration: Some(crate::ca_administration::CaAdministrationConfig::new(
                source.clone(),
                ca_dir,
            )),
            enrollment: EnrollmentService {
                source,
                endpoint: EnrollmentEndpoint {
                    ca_der: issuer.to_der().map_err(|_| ServerError::TlsConfiguration)?,
                    endpoint: self.listen,
                    server_name: name.to_owned(),
                },
            },
            identity: Identity { certificate, key },
            roots: vec![issuer],
        })
    }
}

fn verify_server(issuer: &X509, leaf: &X509, name: &str) -> Result<(), ServerError> {
    let error = || ServerError::TlsConfiguration;
    let mut trust = X509StoreBuilder::new().map_err(|_| error())?;
    trust.add_cert(issuer.clone()).map_err(|_| error())?;
    let mut params = X509VerifyParam::new().map_err(|_| error())?;
    params
        .set_purpose(openssl::x509::X509PurposeId::SSL_SERVER)
        .map_err(|_| error())?;
    if let Ok(ip) = name.parse() {
        params.set_ip(ip).map_err(|_| error())?;
    } else {
        params.set_host(name).map_err(|_| error())?;
    }
    trust.set_param(&params).map_err(|_| error())?;
    let chain = Stack::new().map_err(|_| error())?;
    if !X509StoreContext::new()
        .map_err(|_| error())?
        .init(&trust.build(), leaf, &chain, |context| {
            context.verify_cert()
        })
        .map_err(|_| error())?
    {
        return Err(error());
    }
    Ok(())
}

fn default_ca_dir() -> Result<PathBuf, ServerError> {
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or(ServerError::InvalidConfiguration)?;
    Ok(root.join("infraternal/ca"))
}

pub(crate) fn private_directory(path: &Path) -> Result<(), ServerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ServerError::TlsConfiguration)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ServerError::TlsConfiguration);
    }
    Ok(())
}

/// Bound reads through a no-follow descriptor; check the opened inode, not an
/// earlier pathname lookup. Public issuer files share the private layout policy.
pub(crate) fn private_file(path: &Path) -> Result<Vec<u8>, ServerError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ServerError::TlsConfiguration)?;
    let metadata = file.metadata().map_err(|_| ServerError::TlsConfiguration)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 8192
    {
        return Err(ServerError::TlsConfiguration);
    }
    let mut bytes = Vec::with_capacity(8192);
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError::TlsConfiguration)?;
    if bytes.len() > 8192 {
        return Err(ServerError::TlsConfiguration);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "remote_startup_tests.rs"]
mod tests;
