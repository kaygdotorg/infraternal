//! Adapts the remote plugin's removal action to private-stdin HTTPS requests and organized CLI
//! results [16][168][202], #87. The start is the dry run; the finish sends its review, inside the
//! session's admin window (D339).
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    process::ExitCode,
};
use uuid::Uuid;

use crate::cli::output::{CommandResult, CommandState, Exit, emit};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    session: String,
    #[serde(default)]
    review: Option<String>,
}
/// Session cookies and reviews enter only through bounded private stdin.
pub(crate) fn run(server: &str, host: Uuid, finish: bool, retain: bool, machine: bool) -> ExitCode {
    let operation = || -> io::Result<Value> {
        let mut bytes = Vec::new();
        io::stdin().take(32769).read_to_end(&mut bytes)?;
        if bytes.len() > 32768 {
            return Err(denied());
        }
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| denied())?;
        let body = if finish {
            json!({"host_id":host,"review":input.review.ok_or_else(denied)?})
        } else {
            json!({"host_id":host,"uninstall":!retain})
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        crate::block_on(&runtime, async {
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                request(server, &input.session, finish, body),
            )
            .await
            .map_err(|_| denied())?
        })
    };
    match operation() {
        // The review or the result of the hosted action travels in `data`; the
        // sentence says which step the person is on.
        Ok(value) => {
            let (state, message, next) = if finish {
                (
                    CommandState::Ready,
                    value["message"]
                        .as_str()
                        .unwrap_or("The host was removed.")
                        .to_owned(),
                    "",
                )
            } else {
                (
                    CommandState::Pending,
                    "Review what removing this host does.".to_owned(),
                    "To remove it, pass the session and the review on standard input with --finish within two minutes.",
                )
            };
            // The review is for scripts; a person at a terminal needs the sentence, not the capability.
            let data = if machine { value } else { json!({}) };
            let mut result = CommandResult::new("remove-host", state, message, data);
            if !next.is_empty() {
                result = result.with_next_step(next);
            }
            emit(result, machine, Exit::Ok)
        }
        Err(_) => super::output::refuse(
            machine,
            infraternal_plugin_remote::REMOVE.id,
            "Host removal was refused.",
            "Use an owner session signed in within 15 minutes, and a review from its dry run on standard input.",
            Exit::NotAllowed,
        ),
    }
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
async fn request(server: &str, cookie: &str, finish: bool, body: Value) -> io::Result<Value> {
    use http_body_util::BodyExt;
    let url = url::Url::parse(server).map_err(|_| denied())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(denied());
    }
    let name = url.host_str().ok_or_else(denied)?;
    let mut tls = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|_| denied())?;
    tls.set_default_verify_paths().map_err(|_| denied())?;
    let ssl = tls
        .build()
        .configure()
        .map_err(|_| denied())?
        .into_ssl(name)
        .map_err(|_| denied())?;
    let socket =
        tokio::net::TcpStream::connect((name, url.port_or_known_default().ok_or_else(denied)?))
            .await?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| denied())?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|_| denied())?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| denied())?;
    let task = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = hyper::Request::builder()
        .method("POST")
        .uri(if finish {
            "/remote/hosts/remove/finish"
        } else {
            "/remote/hosts/remove/start"
        })
        .header(
            "host",
            url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
        )
        .header("origin", url.origin().ascii_serialization())
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&body).map_err(|_| denied())?,
        )))
        .map_err(|_| denied())?;
    let response = sender.send_request(request).await.map_err(|_| denied())?;
    if response.status() != hyper::StatusCode::OK {
        return Err(denied());
    }
    let bytes = http_body_util::Limited::new(response.into_body(), 32768)
        .collect()
        .await
        .map_err(|_| denied())?
        .to_bytes();
    drop(task);
    serde_json::from_slice(&bytes).map_err(|_| denied())
}
struct Connection(tokio::task::JoinHandle<()>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}
