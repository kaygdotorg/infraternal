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
            let result = command_result(value, finish, machine);
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
/// Present the dry run or final response, keeping structured fields for scripts.
/// Human output hides the private review but includes any manual uninstall command.
fn command_result(value: Value, finish: bool, machine: bool) -> CommandResult<Value> {
    let (state, message, next) = if finish {
        (
            if value["state"] == "pending" {
                CommandState::Pending
            } else {
                CommandState::Ready
            },
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
    // A short pending status must not hide the separate ownership-checked
    // uninstall command. Avoid repeating it when the sentence includes it.
    let manual = value["manual"]
        .as_str()
        .filter(|command| finish && !machine && !command.is_empty() && !message.contains(*command))
        .map(str::to_owned);
    // The review is for scripts; a person at a terminal needs the sentence, not the capability.
    let data = if machine { value } else { json!({}) };
    let mut result = CommandResult::new("remove-host", state, message, data);
    if !next.is_empty() {
        result = result.with_next_step(next);
    }
    if let Some(manual) = manual {
        result = result.with_next_step(manual);
    }
    result
}
/// The TLS client for the removal routes: the connector `sign-in` and the hosted actions use,
/// so all of them trust the host's public CA bundle even when the linked OpenSSL's default paths
/// hold no roots (a vendored build names its build prefix). TLS 1.3, peer and hostname
/// verification, HTTP/1.1 ALPN.
fn removal_tls_connector() -> io::Result<openssl::ssl::SslConnector> {
    crate::remote::outbound_tls_connector(None).map_err(|_| denied())
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
    let ssl = removal_tls_connector()?
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

#[cfg(test)]
mod tests {
    //! Human rendering and transport regressions for reviewed host removal.
    /// Human output must include the structured leftover-install command even
    /// when a pending response has only a short status sentence.
    #[test]
    fn pending_removal_prints_manual_command_for_people() {
        use crate::cli::output::{RenderOptions, render_pretty};
        let command =
            "/usr/local/bin/infraternal --bootstrap-uninstall 0123456789abcdef0123456789abcdef";
        let value = serde_json::json!({"state":"pending", "message":"worker: revoked, cleanup pending.", "manual":command});
        let result = super::command_result(value, true, false);
        let output = render_pretty(
            &result,
            RenderOptions {
                terminal: false,
                color: false,
                width: 100,
            },
        )
        .unwrap();
        assert!(
            output.contains(command),
            "manual uninstall missing from human output: {output}"
        );
        assert_eq!(result.state, crate::cli::output::CommandState::Pending);
        assert_eq!(result.data, serde_json::json!({}));
    }

    /// Found on the test server (#303, J94f): `remove-host` refused every step, its dry run
    /// included, while the same session's browser dry run succeeded. With `SSL_CERT_FILE` set to
    /// the system bundle the same binary removed the host. A vendored OpenSSL's default paths
    /// name its build prefix and hold no roots on the host; J94e fixed the same defect for the
    /// hosted actions (`2f0f4a007`). The child run points OpenSSL's defaults at nothing, so
    /// only explicitly loaded roots count.
    #[test]
    fn removal_trusts_the_host_ca_bundle() {
        let bundles = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        ];
        if !bundles
            .iter()
            .any(|bundle| std::path::Path::new(bundle).is_file())
        {
            return;
        }
        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "host_remove::tests::removal_trust_probe",
                "--ignored",
                "--test-threads=1",
            ])
            .env(
                "SSL_CERT_FILE",
                "/nonexistent/infraternal-no-default-roots.pem",
            )
            .env("SSL_CERT_DIR", "/nonexistent/infraternal-no-default-roots")
            .output()
            .expect("run the trust probe");
        let output = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && output.contains("1 passed"),
            "host removal has no trust roots without OpenSSL's defaults:\n{output}"
        );
    }

    /// Run only by `removal_trusts_the_host_ca_bundle`, with OpenSSL's defaults unset.
    #[test]
    #[ignore = "child of removal_trusts_the_host_ca_bundle"]
    fn removal_trust_probe() {
        let ssl = super::removal_tls_connector()
            .expect("removal TLS connector")
            .configure()
            .expect("TLS configuration")
            .into_ssl("ssh.kayg.org")
            .expect("TLS session");
        assert!(!ssl.ssl_context().cert_store().all_certificates().is_empty());
    }
}
