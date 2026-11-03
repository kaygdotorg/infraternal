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
use tokio::{net::TcpStream, time::Instant};
use tokio_tungstenite::{client_async, tungstenite::Message};
use url::Url;
use zeroize::Zeroizing;

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const ADD_HOST_TIMEOUT: Duration = Duration::from_secs(240);
const APPROVAL_POLL: Duration = Duration::from_secs(10);
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
#[allow(clippy::too_many_lines)] // Keep key selection, scope enforcement and result emission in one entry path.
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
                success_message(definition.id),
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

fn command_input(
    action: infraternal_plugin_api::ActionDef,
    matches: &ArgMatches,
) -> Result<Value, ActionFailure> {
    match action.id {
        "server.status" | "sessions.list" => Ok(json!({})),
        "remote.host.list" => Ok(json!({
            "after": matches.get_one::<String>("after").cloned(),
        })),
        "remote.host.remove" => {
            let host = matches
                .get_one::<String>("host_id")
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    ActionFailure::new(
                        Exit::Usage,
                        "The host ID is invalid. Choose an ID from `infraternal hosts list`.",
                    )
                })?;
            Ok(json!({"host_id":host,"uninstall":true}))
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
        "remote.host.remove" => remove_host(command, server, api_key, input, json_output).await,
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

#[allow(clippy::too_many_lines)] // Keep progress, captured failure detail and stream closure handling in one loop.
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

async fn remove_host(
    command: &str,
    server: &Url,
    api_key: &str,
    input: Value,
    json_output: bool,
) -> Result<Value, ActionFailure> {
    let start = post_action(server, api_key, "remote.host.remove", &input).await?;
    let request_id = start["request_id"].as_str().ok_or_else(|| {
        ActionFailure::new(
            Exit::Failed,
            "The server did not return a removal request ID.",
        )
    })?;
    let code = start["user_code"].as_str().ok_or_else(|| {
        ActionFailure::new(
            Exit::Failed,
            "The server did not return a removal approval code.",
        )
    })?;
    let link = removal_approval_link(server, code);
    let approval = json!({
        "server": server.origin().ascii_serialization(),
        "code": code,
        "verification_url": link,
        "action": start["action"],
        "expires_in_seconds": start["expires_in"],
    });
    let mut progress = CommandResult::new(
        command,
        CommandState::Pending,
        "This removal needs a fresh owner passkey tap.",
        approval.clone(),
    )
    .with_next_step("Open the link, review what will be removed, and approve with your passkey.")
    .with_body(format!(
        "Open this link and approve the displayed removal with your passkey:\n{link}\n\nCode: {code}"
    ));
    if json_output {
        "Waiting for the owner to approve this removal with a fresh passkey tap."
            .clone_into(&mut progress.message);
    }
    print_progress(&progress, json_output, false);

    let lifetime = start["expires_in"].as_u64().unwrap_or(300).clamp(1, 600);
    let deadline = Instant::now() + Duration::from_secs(lifetime);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(expired_removal_failure(approval));
        }
        tokio::time::sleep(APPROVAL_POLL.min(deadline - now)).await;
        let status = post_json(
            server,
            api_key,
            "/v1/actions/remote.host.remove/status",
            &json!({"request_id":request_id}),
        )
        .await
        .map_err(|failure| {
            ActionFailure::new(
                Exit::Partial,
                "The removal started, but the CLI could not confirm its final result.",
            )
            .with_details(failure.message, approval.clone())
        })?;
        if let Some(result) = removal_status_result(status, &approval)? {
            return Ok(result);
        }
    }
}

fn removal_approval_link(server: &Url, code: &str) -> String {
    let mut link = server.clone();
    link.query_pairs_mut().append_pair("action_code", code);
    link.to_string()
}

fn expired_removal_failure(approval: Value) -> ActionFailure {
    ActionFailure::new(
        Exit::NotAllowed,
        "The removal was declined or its passkey approval expired. Start a new removal request if it is still needed.",
    )
    .with_details("No removal is executed without a fresh passkey approval.", approval)
}

fn removal_status_result(status: Value, approval: &Value) -> Result<Option<Value>, ActionFailure> {
    match status["state"].as_str() {
        Some("complete") => Ok(Some(status["result"].clone())),
        Some("denied") => Err(ActionFailure::new(
            Exit::NotAllowed,
            "The removal was declined or its passkey approval expired. Start a new removal request if it is still needed.",
        )
        .with_details("No removal is executed without a fresh passkey approval.", approval.clone())),
        Some("pending") => Ok(None),
        _ => Err(ActionFailure::new(
            Exit::Partial,
            "The removal request returned an unknown state; check the host before retrying.",
        )
        .with_details("The server returned an invalid removal status.", status)),
    }
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
    if !status.is_success() {
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
    serde_json::from_slice(&bytes).map_err(|_| {
        ActionFailure::new(
            Exit::Failed,
            "The server returned an invalid action result.",
        )
    })
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
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|_| ())?;
    builder.set_default_verify_paths().map_err(|_| ())?;
    let ssl = builder
        .build()
        .configure()
        .map_err(|_| ())?
        .into_ssl(name)
        .map_err(|_| ())?;
    let socket = TcpStream::connect((name, port)).await.map_err(|_| ())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| ())?;
    Pin::new(&mut stream).connect().await.map_err(|_| ())?;
    Ok(stream)
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

fn success_message(action_id: &str) -> &'static str {
    match action_id {
        "server.status" => "The server status was read.",
        "remote.host.list" => "The server host list was read.",
        "sessions.list" => "The server session list was read.",
        "remote.host.remove" => "The host removal was approved and completed.",
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
            for item in fields.values_mut() {
                *item = scrub_value(std::mem::replace(item, Value::Null), api_key);
            }
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
        // A bare carriage return would let remote output overwrite the line it follows.
        if character == '\n' || character == '\t' || !character.is_control() {
            safe.push(character);
        } else {
            let _ = write!(safe, "\\u{{{:04x}}}", u32::from(character));
        }
    }
    safe
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
        Exit, bootstrap_event_failure, expired_removal_failure, host_setup_failure,
        removal_approval_link, removal_status_result, scrub_failure, status_failure,
    };
    use hyper::StatusCode;
    use serde_json::json;
    use url::Url;

    #[test]
    fn removal_link_opens_the_action_approval_page() {
        let server = Url::parse("https://ssh.example.test/").unwrap();
        assert_eq!(
            removal_approval_link(&server, "A_b-c123"),
            "https://ssh.example.test/?action_code=A_b-c123"
        );
    }

    #[test]
    fn approval_expiry_is_a_fresh_passkey_refusal() {
        let failure = expired_removal_failure(json!({"code":"A_b-c123"}));
        assert_eq!(failure.exit, Exit::NotAllowed);
        assert!(failure.message.contains("approval expired"));
        assert!(failure.details.unwrap().contains("fresh passkey approval"));
    }

    #[test]
    fn refused_passkey_approval_uses_d303_not_allowed() {
        let approval = json!({"code":"A_b-c123"});
        let failure = removal_status_result(json!({"state":"denied"}), &approval).unwrap_err();
        assert_eq!(failure.exit, Exit::NotAllowed);
        assert!(failure.message.contains("declined"));
        assert_eq!(failure.data, approval);
    }

    #[test]
    fn expired_or_revoked_key_uses_the_shared_d303_diagnostic() {
        let failure = status_failure(StatusCode::FORBIDDEN);
        let (message, exit) = super::sign_in::invalid_api_key_diagnostic();
        assert_eq!(failure.exit, exit);
        assert_eq!(failure.message, message);
        assert_eq!(failure.exit, Exit::NotAllowed);
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
}
