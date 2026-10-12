//! Streams bounded release downloads through the existing Hyper/OpenSSL engines [224,225].
use http_body_util::BodyExt;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::{path::Path, pin::Pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) enum DownloadError {
    Missing,
    Network,
    Http,
    Size,
    Storage,
}
impl DownloadError {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "this version has no matching release file.",
            Self::Network => "the builds host could not be reached securely.",
            Self::Http => "the builds host refused the download.",
            Self::Size => "the release file exceeds its size limit.",
            Self::Storage => "the release file could not be saved.",
        }
    }
}
pub(crate) async fn download(
    address: &str,
    destination: &Path,
    max: u64,
) -> Result<(), DownloadError> {
    tokio::time::timeout(Duration::from_secs(90), fetch(address, destination, max))
        .await
        .map_err(|_| DownloadError::Network)?
}
async fn fetch(address: &str, destination: &Path, max: u64) -> Result<(), DownloadError> {
    let url = url::Url::parse(address).map_err(|_| DownloadError::Network)?;
    let name = url.host_str().ok_or(DownloadError::Network)?;
    let port = url.port_or_known_default().ok_or(DownloadError::Network)?;
    let plaintext_fixture = cfg!(test) && url.scheme() == "http" && name == "127.0.0.1";
    if (!plaintext_fixture && url.scheme() != "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DownloadError::Network);
    }
    let socket = tokio::net::TcpStream::connect((name, port))
        .await
        .map_err(|_| DownloadError::Network)?;
    #[cfg(test)]
    if url.scheme() == "http" && name == "127.0.0.1" {
        return receive(socket, &url, destination, max).await;
    }
    if url.scheme() != "https" || url.username() != "" || url.password().is_some() {
        return Err(DownloadError::Network);
    }
    let mut tls =
        SslConnector::builder(SslMethod::tls_client()).map_err(|_| DownloadError::Network)?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|_| DownloadError::Network)?;
    tls.set_verify(SslVerifyMode::PEER);
    tls.set_default_verify_paths()
        .map_err(|_| DownloadError::Network)?;
    for bundle in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ] {
        if Path::new(bundle).is_file() {
            tls.set_ca_file(bundle)
                .map_err(|_| DownloadError::Network)?;
            break;
        }
    }
    let ssl = tls
        .build()
        .configure()
        .and_then(|config| config.into_ssl(name))
        .map_err(|_| DownloadError::Network)?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, socket).map_err(|_| DownloadError::Network)?;
    Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|_| DownloadError::Network)?;
    receive(stream, &url, destination, max).await
}
async fn receive<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    url: &url::Url,
    destination: &Path,
    max: u64,
) -> Result<(), DownloadError> {
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| DownloadError::Network)?;
    let _connection = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = hyper::Request::builder()
        .uri(url.path())
        .header(
            "host",
            &url[url::Position::BeforeHost..url::Position::AfterPort],
        )
        .header("user-agent", infraternal_plugin_api::RELEASE_USER_AGENT)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|_| DownloadError::Http)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| DownloadError::Network)?;
    match response.status() {
        hyper::StatusCode::NOT_FOUND => return Err(DownloadError::Missing),
        hyper::StatusCode::OK => (),
        _ => return Err(DownloadError::Http),
    }
    let mut body = response.into_body();
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .await
        .map_err(|_| DownloadError::Storage)?;
    let mut received = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| DownloadError::Network)?;
        if let Ok(bytes) = frame.into_data() {
            received = received
                .checked_add(bytes.len().try_into().map_err(|_| DownloadError::Size)?)
                .ok_or(DownloadError::Size)?;
            if received > max {
                return Err(DownloadError::Size);
            }
            file.write_all(&bytes)
                .await
                .map_err(|_| DownloadError::Storage)?;
        }
    }
    file.sync_all().await.map_err(|_| DownloadError::Storage)?;
    Ok(())
}
struct Connection(tokio::task::JoinHandle<()>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
#[path = "release_http_tests.rs"]
mod tests;
