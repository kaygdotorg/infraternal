//! Implements the operator-only private-stdin join adapter and local identity publication; no capability is accepted in argv [132][133], #78.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use infraternal_agent::{
    remote_client::{self, RemoteIdentity},
    remote_tls::Identity,
};
use infraternal_plugin_remote::enrollment::{JoinInvitation, JoinRequest, JoinResponse, Mode};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder, X509Req, X509StoreContext, store::X509StoreBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    host_id: uuid::Uuid,
    execution_uid: u32,
    endpoint: std::net::SocketAddr,
    server_name: String,
    ca_der: String,
    certificate_der: String,
    key_der: String,
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote infraternal agent operation refused",
    )
}

pub(crate) fn default_data() -> io::Result<PathBuf> {
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(refused)?;
    Ok(root.join("infraternal/agent"))
}

pub(crate) async fn join(url: &str, data: &Path, input: &[u8]) -> io::Result<()> {
    if input.len() > 8192 {
        return Err(refused());
    }
    let invitation: JoinInvitation = serde_json::from_slice(input).map_err(|_| refused())?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if uid != invitation.execution_uid || (invitation.mode == Mode::Rootless) == (uid == 0) {
        return Err(refused());
    }
    prepare(data)?;
    let key = PKey::generate_ed25519().map_err(|_| refused())?;
    let mut csr = X509Req::builder().map_err(|_| refused())?;
    csr.set_subject_name(&X509NameBuilder::new().map_err(|_| refused())?.build())
        .map_err(|_| refused())?;
    csr.set_pubkey(&key).map_err(|_| refused())?;
    csr.sign(&key, MessageDigest::null())
        .map_err(|_| refused())?;
    let request = JoinRequest {
        host_id: invitation.host_id,
        mode: invitation.mode,
        token: invitation.token,
        csr_der: B64.encode(csr.build().to_der().map_err(|_| refused())?),
    };
    let root = X509::from_der(&B64.decode(&invitation.ca_der).map_err(|_| refused())?)
        .map_err(|_| refused())?;
    let https = invitation
        .https_der
        .as_ref()
        .map(|der| {
            B64.decode(der)
                .map_err(|_| refused())
                .and_then(|der| X509::from_der(&der).map_err(|_| refused()))
        })
        .transpose()?;
    if invitation.https_system_roots && https.is_some() {
        return Err(refused());
    }
    let https_root = if invitation.https_system_roots {
        None
    } else {
        Some(https.as_ref().unwrap_or(&root))
    };
    let response = tokio::time::timeout(Duration::from_secs(10), redeem(url, https_root, &request))
        .await
        .map_err(|_| refused())??;
    if response.execution_uid != uid {
        return Err(refused());
    }
    let certificate = X509::from_der(
        &B64.decode(&response.certificate_der)
            .map_err(|_| refused())?,
    )
    .map_err(|_| refused())?;
    if !certificate
        .public_key()
        .map_err(|_| refused())?
        .public_eq(&key)
    {
        return Err(refused());
    }
    let mut trust = X509StoreBuilder::new().map_err(|_| refused())?;
    trust.add_cert(root).map_err(|_| refused())?;
    let mut parameters = openssl::x509::verify::X509VerifyParam::new().map_err(|_| refused())?;
    parameters
        .set_purpose(openssl::x509::X509PurposeId::SSL_CLIENT)
        .map_err(|_| refused())?;
    trust.set_param(&parameters).map_err(|_| refused())?;
    let chain = openssl::stack::Stack::new().map_err(|_| refused())?;
    if !X509StoreContext::new()
        .map_err(|_| refused())?
        .init(&trust.build(), &certificate, &chain, |ctx| {
            ctx.verify_cert()
        })
        .map_err(|_| refused())?
    {
        return Err(refused());
    }
    let stored = StoredIdentity {
        host_id: invitation.host_id,
        execution_uid: uid,
        endpoint: invitation.endpoint,
        server_name: invitation.server_name,
        ca_der: invitation.ca_der,
        certificate_der: response.certificate_der,
        key_der: B64.encode(key.private_key_to_pkcs8().map_err(|_| refused())?),
    };
    publish(data, &serde_json::to_vec(&stored).map_err(|_| refused())?)?;
    Ok(())
}

/// DNS is its own boundary: retain only known public resolver diagnostics.
async fn connect_enrollment(name: &str, port: u16) -> io::Result<tokio::net::TcpStream> {
    let addresses = tokio::net::lookup_host((name, port))
        .await
        .map_err(|error| {
            let message = match error.to_string().as_str() {
                "failed to lookup address information: Temporary failure in name resolution" => {
                    "Join DNS lookup failed: Temporary failure in name resolution."
                }
                "failed to lookup address information: Name or service not known" => {
                    "Join DNS lookup failed: Name or service not known."
                }
                _ => "Join DNS lookup failed.",
            };
            io::Error::new(error.kind(), message)
        })?
        .collect::<Vec<_>>();
    tokio::net::TcpStream::connect(addresses.as_slice())
        .await
        .map_err(|error| io::Error::new(error.kind(), "Join connection failed."))
}

/// CLI output can carry only these authored public contexts, never arbitrary errors.
pub(crate) fn public_error(error: &io::Error) -> &'static str {
    match error.to_string().as_str() {
        "Join DNS lookup failed: Temporary failure in name resolution." => {
            "Join DNS lookup failed: Temporary failure in name resolution."
        }
        "Join DNS lookup failed: Name or service not known." => {
            "Join DNS lookup failed: Name or service not known."
        }
        "Join DNS lookup failed." => "Join DNS lookup failed.",
        "Join connection failed." => "Join connection failed.",
        "Join TLS verification failed." => "Join TLS verification failed.",
        _ => "Remote infraternal agent operation failed",
    }
}

async fn redeem(url: &str, root: Option<&X509>, request: &JoinRequest) -> io::Result<JoinResponse> {
    use http_body_util::BodyExt;
    let url = url::Url::parse(url).map_err(|_| refused())?;
    if url.scheme() != "https"
        || url.path() != "/remote/join"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(refused());
    }
    let name = url.host_str().ok_or_else(refused)?;
    let port = url.port_or_known_default().ok_or_else(refused)?;
    let mut tls = SslConnector::builder(SslMethod::tls_client()).map_err(|_| refused())?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| refused())?;
    tls.set_verify(SslVerifyMode::PEER);
    if let Some(root) = root {
        let mut trust = X509StoreBuilder::new().map_err(|_| refused())?;
        trust.add_cert(root.clone()).map_err(|_| refused())?;
        // The invitation may pin the HTTPS leaf independently of machine trust.
        // Hostname, validity and proof of the corresponding key remain mandatory.
        trust
            .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
            .map_err(|_| refused())?;
        tls.set_cert_store(trust.build());
    } else {
        tls.set_default_verify_paths().map_err(|_| refused())?;
        // Vendored OpenSSL may have a build-time prefix absent on this host.
        // Reuse the operating system's public bundle, never an enrollment TOFU pin.
        for bundle in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        ] {
            if Path::new(bundle).is_file() {
                tls.set_ca_file(bundle).map_err(|_| refused())?;
                break;
            }
        }
    }
    let ssl = tls
        .build()
        .configure()
        .map_err(|_| refused())?
        .into_ssl(name)
        .map_err(|_| refused())?;
    let socket = connect_enrollment(name, port).await?;
    socket.set_nodelay(true)?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| refused())?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Join TLS verification failed.",
            )
        })?;
    // Hyper is the same HTTP engine used by the server; retain its bounded codec.
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| refused())?;
    let task = AbortConnection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let result = async {
        let body = serde_json::to_vec(request).map_err(|_| refused())?;
        let request = hyper::Request::builder()
            .method("POST")
            .uri(url.path())
            .header(
                "host",
                url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
            )
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|_| refused())?;
        let response = sender.send_request(request).await.map_err(|_| refused())?;
        if response.status() != hyper::StatusCode::OK {
            return Err(refused());
        }
        let body = http_body_util::Limited::new(response.into_body(), 8192)
            .collect()
            .await
            .map_err(|_| refused())?
            .to_bytes();
        serde_json::from_slice(&body).map_err(|_| refused())
    }
    .await;
    drop(task);
    result
}

struct AbortConnection(tokio::task::JoinHandle<()>);
impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn prepare(data: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data)?;
    let metadata = std::fs::symlink_metadata(data)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(refused());
    }
    match std::fs::symlink_metadata(data.join("identity.json")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(refused()),
    }
}

fn publish(data: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    prepare(data)?;
    let pending = data.join(format!("identity-{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Do not replace an existing installation. hard_link publishes the exact
        // fsynced inode with atomic no-replace semantics on the same filesystem.
        std::fs::hard_link(&pending, data.join("identity.json"))?;
        std::fs::File::open(data)?.sync_all()
    })();
    let _ = std::fs::remove_file(pending);
    result
}

pub(crate) async fn run(data: &Path, state: Option<PathBuf>) -> io::Result<()> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(data.join("identity.json"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 8192
    {
        return Err(refused());
    }
    let mut bytes = Vec::with_capacity(8192);
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(refused());
    }
    let stored: StoredIdentity = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let identity = RemoteIdentity {
        identity: Identity {
            certificate: X509::from_der(
                &B64.decode(&stored.certificate_der).map_err(|_| refused())?,
            )
            .map_err(|_| refused())?,
            key: PKey::private_key_from_pkcs8(&B64.decode(&stored.key_der).map_err(|_| refused())?)
                .map_err(|_| refused())?,
        },
        roots: vec![
            X509::from_der(&B64.decode(&stored.ca_der).map_err(|_| refused())?)
                .map_err(|_| refused())?,
        ],
        endpoint: stored.endpoint,
        server_name: stored.server_name.clone(),
        execution_uid: stored.execution_uid,
    };
    drop(bytes);
    let installation =
        state
            .as_ref()
            .map(|sessions| infraternal_plugin_remote::uninstall::Context {
                host: stored.host_id.simple().to_string(),
                uid: stored.execution_uid,
                data: data.to_owned(),
                sessions: sessions.clone(),
            });
    let publisher = std::sync::Arc::new(IdentityPublisher {
        data: data.to_owned(),
        stored,
    });
    remote_client::run_with_installation(&identity, state, publisher, installation.as_ref()).await
}

/// The existing installation is the publication boundary; no new key is generated.
struct IdentityPublisher {
    data: PathBuf,
    stored: StoredIdentity,
}
impl infraternal_agent::remote_renewal::CertificatePublisher for IdentityPublisher {
    fn publish(&self, certificate: &X509) -> io::Result<()> {
        use std::{
            io::Write,
            os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        };
        let directory = std::fs::symlink_metadata(&self.data)?;
        let current = std::fs::symlink_metadata(self.data.join("identity.json"))?;
        let uid = nix::unistd::Uid::effective().as_raw();
        if !directory.is_dir()
            || directory.uid() != uid
            || directory.permissions().mode() & 0o077 != 0
            || !current.is_file()
            || current.uid() != uid
            || current.permissions().mode() & 0o077 != 0
        {
            return Err(refused());
        }
        let mut stored = serde_json::to_value(&self.stored).map_err(|_| refused())?;
        stored["certificate_der"] = B64
            .encode(certificate.to_der().map_err(|_| refused())?)
            .into();
        let bytes = serde_json::to_vec(&stored).map_err(|_| refused())?;
        if bytes.len() > 8192 {
            return Err(refused());
        }
        let pending = self
            .data
            .join(format!("identity-{}.pending", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&pending)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&pending, self.data.join("identity.json"))?;
            std::fs::File::open(&self.data)?.sync_all()
        })();
        let _ = std::fs::remove_file(pending);
        result
    }
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;

/// Host uninstall: the independent helper service, or the owner by hand (#235).
///
/// `--bootstrap-uninstall` alone is the transient service the infraternal
/// agent started: it consumes the private plan that agent left.
/// `--bootstrap-uninstall <host>` is the command the server hands the owner
/// when it could not reach the host. Both run the same cleanup, which
/// removes nothing unless this account's `.bootstrap-owner` names the host,
/// retires only this installation's own shells, and leaves kernel objects and
/// files it did not create.
pub(crate) fn uninstall_if_requested() -> Option<std::process::ExitCode> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_none_or(|argument| argument != "--bootstrap-uninstall")
    {
        return None;
    }
    let by_hand = arguments.len() == 3;
    let execute = || -> io::Result<Vec<String>> {
        let home = std::env::var_os("HOME").map_or_else(|| "/".into(), PathBuf::from);
        let uid = nix::unistd::Uid::effective().as_raw();
        let plan = match arguments.as_slice() {
            [_, _] => infraternal_plugin_remote::uninstall::take_plan(&home, uid)?,
            [_, _, host] => infraternal_plugin_remote::uninstall::installation(
                host.to_str().ok_or_else(refused)?,
                &home,
                uid,
            ),
            _ => return Err(refused()),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut report = Vec::new();
        infraternal_agent::block_on_io(
            &runtime,
            Box::pin(async {
                report = infraternal_plugin_remote::uninstall::cleanup(
                    &plan,
                    &home,
                    uid,
                    infraternal_agent::plugins::KERNEL,
                )
                .await?;
                Ok(())
            }),
        )?;
        Ok(report)
    };
    // The helper's output goes to its unit's journal, the owner's to the terminal.
    Some(match execute() {
        Ok(report) => {
            for line in report {
                println!("{line}");
            }
            if by_hand {
                println!("infraternal was removed from this machine.");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            if by_hand {
                eprintln!(
                    "infraternal was not removed: {error}. It removes only the installation infraternal setup made for this host, as the account that installed it."
                );
            }
            std::process::ExitCode::FAILURE
        }
    })
}
