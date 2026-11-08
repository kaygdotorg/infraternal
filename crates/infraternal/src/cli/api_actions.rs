//! Sends registered CLI actions to their signed-in server over bearer-only HTTPS [16][202][303].

use crate::{
    cli::output::{CommandResult, CommandState, Exit, emit, print_progress},
    sign_in,
};
use clap::ArgMatches;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue},
};
use serde_json::{Value, json};
use std::{collections::HashSet, fmt::Write as _, pin::Pin, process::ExitCode, time::Duration};
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async, tungstenite::Message};
use url::Url;
use zeroize::Zeroizing;

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const ADD_HOST_TIMEOUT: Duration = Duration::from_secs(240);
const MAX_RESPONSE: usize = 256 * 1024;
const MAX_DIAGNOSTIC: usize = 16 * 1024;
const MAX_HOST_PAGES: usize = 24;

struct ActionFailure {
    exit: Exit,
    message: String,
    details: Option<String>,
    data: Value,
}

impl ActionFailure {
    fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
            details: None,
            data: json!({}),
        }
    }

    fn with_details(mut self, details: impl Into<String>, data: Value) -> Self {
        self.details = Some(details.into());
        self.data = data;
        self
    }
}

/// Run one hosted action with the key selected through the existing private credential store.
// Keep key selection, scope enforcement and result emission in one entry path.
pub fn run(
    action: &infraternal_plugin_api::ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let command = action.command.join(" ");
    let Some(definition) = action.hosted else {
        return emit_failure(
            &command,
            ActionFailure::new(
                Exit::NotAllowed,
                "This command is not available through a server key.",
            ),
            json_output,
        );
    };
    let server_override = matches
        .get_one::<String>("server_override")
        .map(String::as_str);
    let credential = match sign_in::load_api_credential(server_override) {
        Ok(credential) => credential,
        Err(error) => {
            return emit_failure(&command, credential_failure(error), json_output);
        }
    };
    let Some(scope) = definition.api_scope else {
        return emit_failure(
            &command,
            ActionFailure::new(Exit::NotAllowed, "This action has no API-key scope."),
            json_output,
        );
    };
    if !credential.scopes.iter().any(|granted| granted == scope) {
        return emit_failure(
            &command,
            ActionFailure::new(
                Exit::NotAllowed,
                format!(
                    "This device key does not include {scope}. Run `infraternal sign-in {} --scope {scope}` and approve with your passkey.",
                    credential.server
                ),
            ),
            json_output,
        );
    }
    let Ok(server) = Url::parse(&credential.server) else {
        return emit_failure(
            &command,
            ActionFailure::new(
                Exit::Usage,
                "The saved server address is invalid. Run sign-in again with an HTTPS origin.",
            ),
            json_output,
        );
    };
    let input = match command_input(definition, matches) {
        Ok(input) => input,
        Err(failure) => return emit_failure(&command, failure, json_output),
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return emit_failure(
            &command,
            ActionFailure::new(
                Exit::Failed,
                "The command could not start its network runtime.",
            ),
            json_output,
        );
    };
    let result = crate::block_on(
        &runtime,
        dispatch(
            &command,
            definition,
            &server,
            &credential.api_key,
            input,
            json_output,
        ),
    );
    match result {
        Ok(data) => emit(
            CommandResult::new(
                &command,
                CommandState::Ready,
                if data["dry_run"] == true {
                    "Dry run: nothing was changed. Run it again without --dry-run to apply."
                } else {
                    success_message(definition.id)
                },
                scrub_value(data, credential.api_key.as_str()),
            ),
            json_output,
            Exit::Ok,
        ),
        Err(failure) => emit_failure(
            &command,
            scrub_failure(failure, credential.api_key.as_str()),
            json_output,
        ),
    }
}

fn credential_failure(error: sign_in::ApiCredentialError) -> ActionFailure {
    match error {
        sign_in::ApiCredentialError::Missing => ActionFailure::new(
            Exit::NotAllowed,
            "This device is not signed in to that server. Run `infraternal sign-in <server>` and approve with your passkey.",
        ),
        sign_in::ApiCredentialError::Ambiguous => ActionFailure::new(
            Exit::Usage,
            "More than one server key is stored. Add `--server https://…` to choose one.",
        ),
        sign_in::ApiCredentialError::InvalidServer => ActionFailure::new(
            Exit::Usage,
            "Use an HTTPS server origin with `--server`, for example `--server https://ssh.kayg.org`.",
        ),
        sign_in::ApiCredentialError::UnsafeStorage => ActionFailure::new(
            Exit::Failed,
            "The saved server key could not be read safely. Check the private CLI credential directory.",
        ),
    }
}

/// Decode CLI arguments into the input expected by the shared hosted action.
fn command_input(
    action: infraternal_plugin_api::ActionDef,
    matches: &ArgMatches,
) -> Result<Value, ActionFailure> {
    match action.id {
        "server.status" | "sessions.list" => Ok(json!({})),
        "remote.host.list" => Ok(json!({
            "after": matches.get_one::<String>("after").cloned(),
        })),
        "remote.host.remove" | "remote.host.forget" => {
            let host = matches
                .get_one::<String>("host_id")
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    ActionFailure::new(
                        Exit::Usage,
                        "The host ID is invalid. Choose an ID from `infraternal hosts list`.",
                    )
                })?;
            Ok(json!({
                "host_id": host,
                "dry_run": matches.get_flag("dry_run"),
                "yes": matches.get_flag("yes"),
            }))
        }
        "ssh.start" => {
            #[cfg(feature = "ssh")]
            {
                let address = matches
                    .get_one::<String>("address")
                    .map(String::as_str)
                    .ok_or_else(|| {
                        ActionFailure::new(Exit::Usage, "Provide an SSH address such as kayg@host.")
                    })?;
                infraternal_plugin_ssh::model::Destination::parse(address).map_err(|_| {
                    ActionFailure::new(
                        Exit::Usage,
                        "Use a valid SSH address such as kayg@host[:port].",
                    )
                })?;
                let root = matches.get_flag("root");
                let target = json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "address": {"kind":"manual","value":address},
                    "mode": if root { "root" } else { "rootless" },
                    "root_consent": root,
                });
                Ok(json!({"action":"start","targets":[target]}))
            }
            #[cfg(not(feature = "ssh"))]
            {
                let _ = matches;
                Err(ActionFailure::new(
                    Exit::NotAllowed,
                    "Host setup is not enabled in this build.",
                ))
            }
        }
        _ => Err(ActionFailure::new(
            Exit::NotAllowed,
            "This shared action is not available through the hosted CLI adapter.",
        )),
    }
}

/// Send hosted actions through their existing review or progress adapter.
async fn dispatch(
    command: &str,
    action: infraternal_plugin_api::ActionDef,
    server: &Url,
    api_key: &str,
    input: Value,
    json_output: bool,
) -> Result<Value, ActionFailure> {
    match action.id {
        "ssh.start" => add_host(command, server, api_key, input, json_output).await,
        "remote.host.list" => list_hosts(server, api_key, input).await,
        "remote.host.remove" | "remote.host.forget" => {
            review_host_change(server, api_key, action.id, input, json_output).await
        }
        _ => post_action(server, api_key, action.id, &input).await,
    }
}

async fn post_action(
    server: &Url,
    api_key: &str,
    action_id: &str,
    input: &Value,
) -> Result<Value, ActionFailure> {
    let path = format!("/v1/actions/{action_id}");
    post_json(server, api_key, &path, input).await
}

/// D28: removal and Forget show their own dry run before the person (or `--yes`) confirms.
/// The mutation repeats the reviewed input with its single-use token, which is never printed.
/// `--dry-run` stops after the review and changes nothing.
async fn review_host_change(
    server: &Url,
    api_key: &str,
    action_id: &str,
    mut input: Value,
    json_output: bool,
) -> Result<Value, ActionFailure> {
    let yes = input
        .as_object_mut()
        .and_then(|fields| fields.remove("yes"))
        .and_then(|yes| yes.as_bool())
        .unwrap_or(false);
    let review_only = input["dry_run"] == true;
    input["dry_run"] = true.into();
    let mut review = post_action(server, api_key, action_id, &input).await?;
    let token = take_review_token(&mut review);
    if review_only {
        return Ok(review);
    }
    let token = token.ok_or_else(|| {
        ActionFailure::new(
            Exit::Failed,
            "The server did not return a review for this action, so nothing changed.",
        )
    })?;
    if !confirm_removal(&review, yes, json_output) {
        return Err(ActionFailure::new(
            Exit::NotAllowed,
            "Nothing changed. Confirm in a terminal, or check the dry run with `--dry-run` and pass `--yes`.",
        )
        .with_details(
            "The action needs a confirmation after its dry run.",
            review,
        ));
    }
    post_action(
        server,
        api_key,
        action_id,
        &confirmed_removal(input, token.as_str()),
    )
    .await
}

/// Take the review token out of a dry run's result so that it is never printed.
fn take_review_token(review: &mut Value) -> Option<Zeroizing<String>> {
    let fields = review.as_object_mut()?;
    fields.remove("review_expires_in");
    match fields.remove("review_token")? {
        Value::String(token) if !token.is_empty() => Some(Zeroizing::new(token)),
        _ => None,
    }
}

/// The real call repeats the reviewed input exactly, as the token is bound to it.
fn confirmed_removal(mut input: Value, token: &str) -> Value {
    input["dry_run"] = false.into();
    input["review_token"] = token.into();
    input
}

/// Show the dry run on stderr and ask. Only a terminal can answer; `--json` and pipes need
/// `--yes`. The action label and effect come from the server and are made terminal-safe.
fn confirm_removal(review: &Value, yes: bool, json_output: bool) -> bool {
    use std::io::{BufRead, IsTerminal, Read, Write};
    let label = terminal_safe(review["label"].as_str().unwrap_or("Change this host"));
    if !json_output {
        eprintln!("Dry run: {label}");
        if let Some(effect) = review["effect"].as_str() {
            eprintln!("{}", terminal_safe(effect));
        }
    }
    if yes {
        return true;
    }
    if json_output || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return false;
    }
    eprint!("{label}? Type yes to confirm: ");
    if std::io::stderr().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .take(128)
        .read_line(&mut answer)
        .is_ok()
        && answer.trim() == "yes"
}

async fn list_hosts(server: &Url, api_key: &str, input: Value) -> Result<Value, ActionFailure> {
    let mut after = input
        .get("after")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut seen = HashSet::new();
    let mut hosts = Vec::new();
    for _ in 0..MAX_HOST_PAGES {
        let page =
            post_action(server, api_key, "remote.host.list", &json!({"after":after})).await?;
        let page_hosts = page["hosts"].as_array().ok_or_else(|| {
            ActionFailure::new(Exit::Failed, "The server returned an invalid host list.")
        })?;
        hosts.extend(page_hosts.iter().cloned());
        match page.get("next") {
            Some(Value::Null) => return Ok(json!({"hosts":hosts,"next":null})),
            Some(Value::String(cursor)) if !cursor.is_empty() && seen.insert(cursor.clone()) => {
                after = Some(cursor.clone());
            }
            _ => {
                return Err(ActionFailure::new(
                    Exit::Failed,
                    "The server returned an invalid host-list cursor.",
                ));
            }
        }
    }
    let cursor = after.unwrap_or_default();
    Err(ActionFailure::new(
        Exit::Partial,
        "The host list reached its bounded page limit before it was complete.",
    )
    .with_details(
        format!("Continue with `infraternal hosts list --after {cursor}`."),
        json!({"hosts":hosts,"next":cursor}),
    ))
}

async fn add_host(
    command: &str,
    server: &Url,
    api_key: &str,
    input: Value,
    json_output: bool,
) -> Result<Value, ActionFailure> {
    let result = tokio::time::timeout(
        ADD_HOST_TIMEOUT,
        add_host_stream(command, server, api_key, input, json_output),
    )
    .await
    .map_err(|_| {
        ActionFailure::new(
            Exit::Partial,
            "Host setup is still running, but the progress stream timed out.",
        )
    })??;
    Ok(result)
}

// Keep progress, captured failure detail and stream closure handling in one loop.
async fn add_host_stream(
    command: &str,
    server: &Url,
    api_key: &str,
    input: Value,
    json_output: bool,
) -> Result<Value, ActionFailure> {
    let request = Request::builder()
        .method("GET")
        .uri(websocket_url(server))
        .header(HOST, host_header(server))
        .header(
            AUTHORIZATION,
            bearer_header(api_key).map_err(|()| {
                ActionFailure::new(Exit::Failed, "The saved server key is invalid.")
            })?,
        );
    let request = request.body(()).map_err(|_| {
        ActionFailure::new(
            Exit::Failed,
            "The host setup request could not be prepared.",
        )
    })?;
    let stream = tls_stream(server).await.map_err(|()| {
        ActionFailure::new(
            Exit::Unreachable,
            "The server could not be reached securely.",
        )
    })?;
    let (mut socket, _) = client_async(request, stream)
        .await
        .map_err(|error| match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                status_failure(response.status())
            }
            _ => ActionFailure::new(
                Exit::Unreachable,
                "The secure host setup stream could not be opened.",
            ),
        })?;
    let request = serde_json::to_string(&input).map_err(|_| {
        ActionFailure::new(Exit::Failed, "The host setup request could not be encoded.")
    })?;
    socket
        .send(Message::Text(request.into()))
        .await
        .map_err(|_| {
            ActionFailure::new(
                Exit::Unreachable,
                "The host setup request could not be sent.",
            )
        })?;
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                let mut event: Value = serde_json::from_str(text.as_str()).map_err(|_| {
                    ActionFailure::new(
                        Exit::Failed,
                        "The server returned an invalid host setup event.",
                    )
                })?;
                event = scrub_value(event, api_key);
                let step = event["step"].as_str().unwrap_or_default();
                let message = event["message"]
                    .as_str()
                    .unwrap_or("Host setup is continuing.")
                    .to_owned();
                let mut progress = CommandResult::new(
                    command,
                    CommandState::Running,
                    terminal_safe(&message),
                    event.clone(),
                );
                progress = progress.with_body(format!(
                    "{}  {}",
                    step_label(step),
                    terminal_safe(&message)
                ));
                print_progress(&progress, json_output, false);
                if step.eq_ignore_ascii_case("done") {
                    return Ok(event);
                }
                if step.eq_ignore_ascii_case("failed") {
                    return Err(host_setup_failure(event));
                }
                if event.get("error").is_some() {
                    return Err(bootstrap_event_failure(event));
                }
            }
            Ok(Message::Ping(bytes)) => {
                socket.send(Message::Pong(bytes)).await.map_err(|_| {
                    ActionFailure::new(
                        Exit::Unreachable,
                        "The host setup stream stopped responding.",
                    )
                })?;
            }
            Ok(Message::Close(_) | Message::Binary(_)) | Err(_) => {
                return Err(ActionFailure::new(
                    Exit::Partial,
                    "The host setup stream ended before the server confirmed completion.",
                ));
            }
            Ok(Message::Pong(_) | Message::Frame(_)) => {}
        }
    }
    Err(ActionFailure::new(
        Exit::Partial,
        "The host setup stream ended before the server confirmed completion.",
    ))
}

fn host_setup_failure(event: Value) -> ActionFailure {
    let failure = &event["failure"];
    let reason = failure["message"]
        .as_str()
        .or_else(|| event["message"].as_str())
        .unwrap_or("The remote host setup failed.");
    let mut details = terminal_safe(reason);
    if let Some(stderr) = failure["captured_stderr"]
        .as_str()
        .filter(|text| !text.is_empty())
    {
        details.push_str("\n\nCaptured remote setup stderr:\n");
        details.push_str(&terminal_safe(stderr));
    }
    let exit = match failure["kind"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "unreachable" => Exit::Unreachable,
        _ => Exit::Failed,
    };
    ActionFailure::new(exit, "Host setup failed.").with_details(details, event)
}

fn bootstrap_event_failure(event: Value) -> ActionFailure {
    let (exit, message) = match event["error"].as_str().unwrap_or_default() {
        "rate_limited" => (
            Exit::NotAllowed,
            "The server rate limit blocked this host setup action. Wait a minute before retrying.",
        ),
        "unauthorized" => (
            Exit::NotAllowed,
            "The saved server key is no longer authorized. Sign in again with hosts:write.",
        ),
        _ => (Exit::Failed, "The server refused the host setup request."),
    };
    let details = event["error"]
        .as_str()
        .map(terminal_safe)
        .unwrap_or_default();
    ActionFailure::new(exit, message).with_details(details, event)
}

async fn post_json(
    server: &Url,
    api_key: &str,
    path: &str,
    body: &Value,
) -> Result<Value, ActionFailure> {
    tokio::time::timeout(HTTP_TIMEOUT, post_json_inner(server, api_key, path, body))
        .await
        .map_err(|_| ActionFailure::new(Exit::Unreachable, "The server request timed out."))?
}

async fn post_json_inner(
    server: &Url,
    api_key: &str,
    path: &str,
    body: &Value,
) -> Result<Value, ActionFailure> {
    let stream = tls_stream(server).await.map_err(|()| {
        ActionFailure::new(
            Exit::Unreachable,
            "The server could not be reached securely.",
        )
    })?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| {
                ActionFailure::new(
                    Exit::Unreachable,
                    "The secure server request could not start.",
                )
            })?;
    let task = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let body = serde_json::to_vec(body)
        .map_err(|_| ActionFailure::new(Exit::Failed, "The action input could not be encoded."))?;
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(HOST, host_header(server))
        .header(
            AUTHORIZATION,
            bearer_header(api_key).map_err(|()| {
                ActionFailure::new(Exit::Failed, "The saved server key is invalid.")
            })?,
        )
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|_| {
            ActionFailure::new(Exit::Failed, "The server request could not be prepared.")
        })?;
    let response = sender.send_request(request).await.map_err(|_| {
        ActionFailure::new(
            Exit::Unreachable,
            "The server did not answer the action request.",
        )
    })?;
    let status = response.status();
    if !status.is_success() && status != StatusCode::BAD_REQUEST {
        return Err(status_failure(status));
    }
    let bytes = Limited::new(response.into_body(), MAX_RESPONSE)
        .collect()
        .await
        .map_err(|_| {
            ActionFailure::new(
                Exit::Failed,
                "The server returned an oversized action result.",
            )
        })?
        .to_bytes();
    drop(task);
    if status == StatusCode::BAD_REQUEST {
        return Err(bad_request_failure(&bytes));
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        ActionFailure::new(
            Exit::Failed,
            "The server returned an invalid action result.",
        )
    })
}

/// A 400 names a refused review (D28) by a fixed code; any other 400 stays generic.
fn bad_request_failure(body: &[u8]) -> ActionFailure {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body["error"].as_str().map(str::to_owned));
    match code.as_deref() {
        Some("review_required" | "review_invalid") => ActionFailure::new(
            Exit::Failed,
            "The removal review expired or was already used, so nothing was removed. Run the command again to see a new dry run.",
        ),
        _ => status_failure(StatusCode::BAD_REQUEST),
    }
}

fn status_failure(status: StatusCode) -> ActionFailure {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            let (message, exit) = sign_in::invalid_api_key_diagnostic();
            ActionFailure::new(exit, message)
        }
        StatusCode::TOO_MANY_REQUESTS => ActionFailure::new(
            Exit::NotAllowed,
            "This server key has reached its action limit. Wait a minute, then retry.",
        ),
        StatusCode::NOT_FOUND => ActionFailure::new(
            Exit::NotFound,
            "The requested action or host was not found. Check the action name or host ID.",
        ),
        StatusCode::REQUEST_TIMEOUT
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::BAD_GATEWAY
        | StatusCode::GATEWAY_TIMEOUT => ActionFailure::new(
            Exit::Unreachable,
            "The server is unavailable. Check its address and network, then try again.",
        ),
        _ => ActionFailure::new(Exit::Failed, "The server could not complete this action."),
    }
}

async fn tls_stream(server: &Url) -> Result<tokio_openssl::SslStream<TcpStream>, ()> {
    let name = server.host_str().ok_or(())?;
    let port = server.port_or_known_default().ok_or(())?;
    let ssl = hosted_tls_connector()?
        .configure()
        .map_err(|_| ())?
        .into_ssl(name)
        .map_err(|_| ())?;
    let socket = TcpStream::connect((name, port)).await.map_err(|_| ())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| ())?;
    Pin::new(&mut stream).connect().await.map_err(|_| ())?;
    Ok(stream)
}

/// The TLS client for hosted actions: the connector `sign-in` uses, so both trust the host's
/// public CA bundle even when the linked OpenSSL's default paths hold no roots (a vendored
/// build names its build prefix). TLS 1.3, peer and hostname verification, HTTP/1.1 ALPN.
fn hosted_tls_connector() -> Result<openssl::ssl::SslConnector, ()> {
    crate::remote::outbound_tls_connector(None).map_err(|_| ())
}

fn bearer_header(api_key: &str) -> Result<HeaderValue, ()> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(7 + api_key.len()));
    bytes.extend_from_slice(b"Bearer ");
    bytes.extend_from_slice(api_key.as_bytes());
    HeaderValue::from_bytes(&bytes).map_err(|_| ())
}

fn host_header(server: &Url) -> String {
    server[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
}

fn websocket_url(server: &Url) -> String {
    format!("wss://{}{}/v1/bootstrap/ws", host_header(server), "")
}

fn step_label(step: &str) -> &'static str {
    match step.to_ascii_lowercase().as_str() {
        "check" => "Check",
        "install" => "Install",
        "facts" => "Facts",
        "connect" => "Connect",
        "done" => "Done",
        "failed" => "Failed",
        _ => "Setup",
    }
}

/// Describe the completed hosted action without implying machine cleanup after Forget.
fn success_message(action_id: &str) -> &'static str {
    match action_id {
        "server.status" => "The server status was read.",
        "remote.host.list" => "The server host list was read.",
        "sessions.list" => "The server session list was read.",
        "remote.host.remove" => "The host was removed.",
        "remote.host.forget" => "The host was forgotten here. The machine itself was not changed.",
        "ssh.start" => "Host setup completed.",
        _ => "The hosted action completed.",
    }
}

fn emit_failure(command: &str, failure: ActionFailure, json_output: bool) -> ExitCode {
    let state = match failure.exit {
        Exit::NotAllowed => CommandState::Refused,
        Exit::Unreachable => CommandState::Unknown,
        Exit::Ok => CommandState::Ready,
        _ => CommandState::Failed,
    };
    let mut result = CommandResult::new(command, state, failure.message, failure.data);
    if let Some(details) = failure.details {
        result = result.with_details(details.clone()).with_body(details);
    }
    emit(result, json_output, failure.exit)
}

/// Redact before `terminal_safe` truncates: a key cut at the length bound would otherwise
/// leave its prefix unmatched and printed.
fn scrub_failure(mut failure: ActionFailure, api_key: &str) -> ActionFailure {
    failure.message = redact(&failure.message, api_key);
    failure.details = failure
        .details
        .map(|details| terminal_safe(&redact(&details, api_key)));
    failure.data = scrub_value(failure.data, api_key);
    failure
}

fn scrub_value(mut value: Value, api_key: &str) -> Value {
    match &mut value {
        Value::String(text) => *text = terminal_safe(&redact(text, api_key)),
        Value::Array(items) => {
            for item in items {
                *item = scrub_value(std::mem::replace(item, Value::Null), api_key);
            }
        }
        Value::Object(fields) => {
            // Keys come from the server too and are printed by the human renderer.
            *fields = std::mem::take(fields)
                .into_iter()
                .map(|(key, item)| {
                    (
                        terminal_safe(&redact(&key, api_key)),
                        scrub_value(item, api_key),
                    )
                })
                .collect();
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    value
}

fn redact(text: &str, api_key: &str) -> String {
    if api_key.is_empty() {
        text.to_owned()
    } else {
        text.replace(api_key, "[redacted]")
    }
}

fn terminal_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len().min(MAX_DIAGNOSTIC));
    for character in text.chars() {
        if safe.len() >= MAX_DIAGNOSTIC {
            break;
        }
        // A bare carriage return would let remote output overwrite the line it follows, and
        // bidi controls or invisible format characters would reorder or hide what is read.
        if character == '\n'
            || character == '\t'
            || !(character.is_control() || invisible(character))
        {
            safe.push(character);
        } else {
            let _ = write!(safe, "\\u{{{:04x}}}", u32::from(character));
        }
    }
    safe
}

/// Unicode format (Cf) characters that reorder or hide text, plus the line and paragraph
/// separators: bidi embeddings, overrides and isolates, zero-width characters, the BOM,
/// interlinear annotation marks and tag characters.
fn invisible(character: char) -> bool {
    matches!(
        u32::from(character),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Exit, bootstrap_event_failure, host_setup_failure, scrub_failure, scrub_value,
        status_failure,
    };
    use hyper::StatusCode;
    use serde_json::json;

    #[test]
    fn expired_or_revoked_key_uses_the_shared_d303_diagnostic() {
        let failure = status_failure(StatusCode::FORBIDDEN);
        let (message, exit) = super::sign_in::invalid_api_key_diagnostic();
        assert_eq!(failure.exit, exit);
        assert_eq!(failure.message, message);
        assert_eq!(failure.exit, Exit::NotAllowed);
    }

    /// D28: the dry run's token is taken out of what is printed, and the real call repeats the
    /// reviewed input with it. Without a terminal or `--yes` nothing is confirmed.
    #[test]
    fn removal_sends_the_reviewed_input_with_its_token_and_never_prints_it() {
        let mut review = json!({
            "dry_run": true, "host": "host.example", "review_token": "fixture-review-token",
            "review_expires_in": 120,
        });
        let token = super::take_review_token(&mut review).expect("token");
        assert_eq!(review, json!({"dry_run": true, "host": "host.example"}));
        let input = json!({"host_id": "00000000-0000-0000-0000-000000000001", "dry_run": true});
        assert_eq!(
            super::confirmed_removal(input, token.as_str()),
            json!({
                "host_id": "00000000-0000-0000-0000-000000000001",
                "dry_run": false,
                "review_token": "fixture-review-token",
            })
        );
        assert!(
            !super::confirm_removal(&review, false, true),
            "--json needs --yes"
        );
        assert!(super::confirm_removal(&review, true, true));
    }

    #[test]
    fn a_refused_review_says_nothing_was_removed() {
        for code in ["review_required", "review_invalid"] {
            let failure = super::bad_request_failure(json!({"error": code}).to_string().as_bytes());
            assert!(failure.message.contains("nothing was removed"), "{code}");
        }
        let failure = super::bad_request_failure(b"{}");
        assert_eq!(
            failure.message,
            status_failure(StatusCode::BAD_REQUEST).message
        );
    }

    /// Found on the test server (#303, J94e): `sign-in` reached it but every hosted action
    /// said "could not be reached securely". Shipping builds link a vendored OpenSSL whose
    /// default paths name its build prefix, so they hold no roots on the host. Hosted actions
    /// must load the host's public CA bundle, the same trust `sign-in` uses. The child run
    /// points OpenSSL's defaults at nothing, so only explicitly loaded roots count.
    #[test]
    fn hosted_actions_trust_the_host_ca_bundle() {
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
                "cli::api_actions::tests::hosted_trust_probe",
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
            "hosted actions have no trust roots without OpenSSL's defaults:\n{output}"
        );
    }

    /// Run only by `hosted_actions_trust_the_host_ca_bundle`, with OpenSSL's defaults unset.
    #[test]
    #[ignore = "child of hosted_actions_trust_the_host_ca_bundle"]
    fn hosted_trust_probe() {
        let ssl = super::hosted_tls_connector()
            .expect("hosted TLS connector")
            .configure()
            .expect("TLS configuration")
            .into_ssl("ssh.kayg.org")
            .expect("TLS session");
        assert!(!ssl.ssl_context().cert_store().all_certificates().is_empty());
    }

    #[test]
    fn rate_limited_bootstrap_event_uses_d303_not_allowed() {
        let failure = bootstrap_event_failure(json!({"error":"rate_limited"}));
        assert_eq!(failure.exit, Exit::NotAllowed);
        assert!(failure.message.contains("Wait a minute"));
        assert_eq!(failure.data, json!({"error":"rate_limited"}));
    }

    #[test]
    fn add_host_failure_keeps_captured_stderr_and_redacts_key_material() {
        let key = "fixture-api-key-never-print";
        let failure = host_setup_failure(json!({
            "step":"failed",
            "message":"Remote setup failed",
            "failure":{
                "kind":"install",
                "message":"SSH command failed",
                "captured_stderr":format!("Permission denied for {key}")
            }
        }));
        let failure = scrub_failure(failure, key);
        let details = failure.details.unwrap();
        assert!(details.contains("Captured remote setup stderr:"));
        assert!(details.contains("Permission denied for [redacted]"));
        assert!(!details.contains(key));
        assert!(!serde_json::to_string(&failure.data).unwrap().contains(key));
    }

    /// J137 P3-2: server-supplied text cannot reorder or hide what the operator reads. Bidi
    /// overrides, invisible format characters and escapes are shown as code points, in
    /// values and in object keys alike.
    #[test]
    fn bidi_invisible_and_escape_characters_are_escaped_in_values_and_keys() {
        let key = "fixture-api-key-never-print";
        let failure = host_setup_failure(json!({
            "step":"failed",
            "message":"Remote setup failed",
            "failure":{
                "kind":"install",
                "message":"SSH command failed",
                "captured_stderr":format!("ok\u{202e}txt.exe \u{1b}[2J\u{2066}x\u{200b}y\u{feff}z {key}")
            }
        }));
        let details = scrub_failure(failure, key).details.unwrap();
        for hidden in ['\u{202e}', '\u{1b}', '\u{2066}', '\u{200b}', '\u{feff}'] {
            assert!(!details.contains(hidden), "{hidden:?} reached the terminal");
        }
        assert!(details.contains("\\u{202e}"));
        assert!(details.contains("\\u{001b}"));
        assert!(!details.contains(key));

        let data = scrub_value(
            json!({format!("na\u{202e}me\u{1b}]0;{key}"): {"inner\u{2069}": "v\u{2028}"}}),
            key,
        );
        let printed = serde_json::to_string(&data).unwrap();
        for hidden in ['\u{202e}', '\u{1b}', '\u{2069}', '\u{2028}'] {
            assert!(
                !printed.contains(hidden),
                "{hidden:?} survived in {printed}"
            );
        }
        assert!(!printed.contains(key));
    }
}
