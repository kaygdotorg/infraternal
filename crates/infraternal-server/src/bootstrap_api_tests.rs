//! Exercises bootstrap WebSocket authority using a real software passkey and real loopback sockets.
#![allow(clippy::unwrap_used)]

use super::*;
use futures_util::{SinkExt, Stream, StreamExt};
use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Resolved},
    install::{BinaryPaths, JoinMaterial},
    model::{Destination, Failure, MeshEvidence},
    probe::Check,
    transport::{Credentials, Operation, SshSession, SshTransport},
};
use sqlx::sqlite::SqlitePoolOptions;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message as ClientMessage, client::IntoClientRequest},
};

const ORIGIN: &str = "https://auth.example.test";
const BYTES: [u8; 16384] = [b'a'; 16384];
const LONG: &str = match std::str::from_utf8(&BYTES) {
    Ok(text) => text,
    Err(_) => panic!("constant UTF8"),
};
struct Rejected(AtomicUsize, &'static str);
impl Backend for Rejected {
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            assert!(
                authority.session().is_some() || authority.api_key_hash().is_some(),
                "bootstrap lost its browser or scoped-key identity"
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Failure::install(self.1)
                .with_captured_setup_stderr(b"captured remote setup diagnostic"))
        })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { panic!("rejected admission must not enroll") })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
}
fn impossible<'a>() -> Operation<'a, ()> {
    Box::pin(async { panic!("rejected admission has no remote identity") })
}

/// Resolves an initial check, then holds a later confirmation lookup until released.
struct ConfirmationLookup {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}
impl Backend for ConfirmationLookup {
    fn resolve<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
            Ok(Resolved {
                destination: Destination::parse("user@fixture").unwrap(),
                credentials: Credentials::Network,
                mesh: MeshEvidence::default(),
            })
        })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { panic!("unconfirmed host trust must not enroll") })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        impossible()
    }
}

/// Returns only a synthetic public observation; no SSH connection or pin publication occurs.
struct PublicChallenge(uuid::Uuid);
impl SshTransport for PublicChallenge {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            let mut failure = Failure::new(
                infraternal_plugin_ssh::model::FailureKind::HostKey,
                "The fixture host key needs confirmation.",
            );
            failure.set_host_key_challenge(Some(self.0));
            failure
                .fingerprints
                .push(format!("SHA256:{}", "a".repeat(43)));
            Err(failure)
        })
    }
}

#[tokio::test]
async fn logout_interrupts_a_stalled_host_key_confirmation_lookup() {
    confirmation_interrupt(false).await;
}

#[tokio::test]
async fn component_off_interrupts_a_stalled_host_key_confirmation_lookup() {
    confirmation_interrupt(true).await;
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn scoped_api_key_can_open_the_bootstrap_action_stream_without_a_cookie_or_origin() {
    let (auth, owner, _, _, address, server, pool, _) = fixture(false).await;
    let token = "fixture-bootstrap-api-key-never-print";
    let now = now().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'j94-cli','[\"hosts:write\"]',?,?,0)")
        .bind(crate::auth::hash(token))
        .bind(owner)
        .bind(now)
        .bind(now + 3600)
        .execute(&pool)
        .await
        .unwrap();

    let mut request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let connection = connect_async(request).await;
    assert!(
        connection.is_ok(),
        "a live hosts:write key should authorize the cookie-free action stream"
    );
    if let Ok((mut socket, _)) = connection {
        let _ = socket.close(None).await;
    }
    server.abort();
    drop(auth);
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn each_bootstrap_action_message_uses_the_shared_api_key_rate_limit() {
    let (auth, owner, _, _, address, server, pool, _) = fixture(false).await;
    let token = "fixture-bootstrap-rate-key-never-print";
    let now = now().unwrap();
    let token_hash = crate::auth::hash(token);
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'j94-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&owner)
        .bind(now)
        .bind(now + 3600)
        .execute(&pool)
        .await
        .unwrap();

    let mut request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut socket, _) = connect_async(request).await.unwrap();

    // The connection consumes one admission; each new action message must consume another.
    for _ in 0..29 {
        socket
            .send(ClientMessage::Text("not json".into()))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(response.to_text().unwrap()).unwrap();
        assert_eq!(event["error"], "invalid bootstrap request");
    }

    socket
        .send(ClientMessage::Text("not json".into()))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(response.to_text().unwrap()).unwrap();
    assert_eq!(event["error"], "rate_limited");

    let row: (String, String, String, String) = sqlx::query_as(
        "SELECT key_id,person_id,action_id,state FROM api_action_audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            token_hash,
            owner,
            "ssh.start".to_owned(),
            "denied".to_owned()
        )
    );
    assert!(!serde_json::to_string(&row).unwrap().contains(token));
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM api_action_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit_count, 30, "every API-key action message is audited");
    let _ = socket.close(None).await;
    server.abort();
    drop(auth);
}

/// J137 P3-7: only the owner can add hosts, so a non-owner key never holds one of the
/// shared bootstrap sockets the owner's own add-host needs.
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_non_owner_key_cannot_hold_a_bootstrap_socket() {
    let (auth, _, _, _, address, server, pool, api) = fixture(false).await;
    let token = "fixture-member-bootstrap-key-never-print";
    let now = now().unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('member','member',0,'x','member','Member')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'member','j94-cli','[\"hosts:write\"]',?,?,0)")
        .bind(crate::auth::hash(token))
        .bind(now)
        .bind(now + 3600)
        .execute(&pool)
        .await
        .unwrap();
    let mut request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    rejection(request, StatusCode::FORBIDDEN).await;
    assert_eq!(api.sockets.available_permits(), 16);
    server.abort();
    drop(auth);
}

/// J137 P3-5: a key-driven add-host audits every target it names, and keeps a target id
/// only when it is a valid host identifier.
#[cfg(feature = "remote")]
#[tokio::test]
async fn key_driven_add_host_audits_every_target() {
    let (auth, owner, _, _, address, server, pool, _) = fixture(false).await;
    let token = "fixture-bootstrap-targets-key-never-print";
    let now = now().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'j94-cli','[\"hosts:write\"]',?,?,0)")
        .bind(crate::auth::hash(token))
        .bind(&owner)
        .bind(now)
        .bind(now + 3600)
        .execute(&pool)
        .await
        .unwrap();
    let mut request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut socket, _) = connect_async(request).await.unwrap();
    let start = serde_json::json!({"action":"start","targets":[
        {"id":"first-host","address":{"kind":"manual","value":"user@one"}},
        {"id":"second-host","address":{"kind":"manual","value":"user@two"}},
        {"id":"bad id\u{202e}","address":{"kind":"manual","value":"user@three"}}
    ]});
    socket
        .send(ClientMessage::Text(start.to_string().into()))
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    let mut targets: Vec<Option<String>> = Vec::new();
    for _ in 0..200 {
        targets = sqlx::query_scalar(
            "SELECT target_id FROM api_action_audit WHERE action_id='ssh.start' ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        if targets.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        targets,
        [
            Some("first-host".to_owned()),
            Some("second-host".to_owned()),
            None
        ]
    );
    let _ = socket.close(None).await;
    server.abort();
    drop(auth);
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn captured_setup_stderr_is_exposed_only_on_key_driven_bootstrap_events() {
    let (auth, owner, cookie, _, address, server, pool, _) = fixture(false).await;
    let token = "fixture-bootstrap-stderr-key-never-print";
    let now = now().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'j94-cli','[\"hosts:write\"]',?,?,0)")
        .bind(crate::auth::hash(token))
        .bind(owner)
        .bind(now)
        .bind(now + 3600)
        .execute(&pool)
        .await
        .unwrap();

    let start = serde_json::json!({"action":"start","targets":[{"id":"stderr-host","address":{"kind":"manual","value":"user@fixture"}}]});
    let mut key_request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    key_request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut key_socket, _) = connect_async(key_request).await.unwrap();
    key_socket
        .send(ClientMessage::Text(start.to_string().into()))
        .await
        .unwrap();
    let key_event = failed_event(&mut key_socket).await;
    assert_eq!(
        key_event["failure"]["captured_stderr"],
        "captured remote setup diagnostic"
    );

    let (mut browser_socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    browser_socket
        .send(ClientMessage::Text(start.to_string().into()))
        .await
        .unwrap();
    let browser_event = failed_event(&mut browser_socket).await;
    assert!(browser_event["failure"].get("captured_stderr").is_none());
    assert!(
        !browser_event
            .to_string()
            .contains("captured remote setup diagnostic")
    );

    let _ = key_socket.close(None).await;
    let _ = browser_socket.close(None).await;
    server.abort();
    drop(auth);
}

async fn failed_event<S>(socket: &mut S) -> serde_json::Value
where
    S: Stream<Item = Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(response.to_text().unwrap()).unwrap();
        if event["step"] == "failed" {
            return event;
        }
    }
}

async fn confirmation_interrupt(component_off: bool) {
    let (auth, _, cookie, _, _, original_server, _, _) = fixture(false).await;
    original_server.abort();
    let backend = Arc::new(ConfirmationLookup {
        calls: AtomicUsize::new(0),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let challenge = uuid::Uuid::new_v4();
    let api = Arc::new(Api {
        auth: auth.clone(),
        #[cfg(feature = "remote")]
        action_guard: ActionGuard::new(auth.clone(), auth.pool().clone()),
        runner: Bootstrap::new(
            Arc::new(PublicChallenge(challenge)),
            backend.clone(),
            BinaryPaths {
                x86_64: "unused".into(),
                aarch64: "unused".into(),
            },
        ),
        #[cfg(feature = "remote")]
        setup_sockets: Arc::new(Semaphore::new(128)),
        sockets: Arc::new(Semaphore::new(16)),
        ssh_key: Arc::new(UnavailableSshKey),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/bootstrap/ws", get(upgrade))
        .with_state(api.clone());
    let serving = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"start","targets":[{"id":"one","address":{"kind":"manual","value":"user@fixture"}}]}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = socket.next().await.unwrap().unwrap();
            let event: serde_json::Value =
                serde_json::from_str(response.to_text().unwrap()).unwrap();
            if event["step"] == "failed" {
                break;
            }
        }
    })
    .await
    .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"confirm-host-key","target":"one","challenge":challenge,"fingerprint":format!("SHA256:{}", "a".repeat(43))}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), backend.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    if component_off {
        use infraternal_plugin_api::ComponentPlugin;
        tokio::time::timeout(Duration::from_secs(2), api.runner.set_enabled(false))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(api.runner.status().active_work, 0);
    } else {
        auth.logout(cookie.split_once('=').unwrap().1)
            .await
            .unwrap();
    }
    let retired = tokio::time::timeout(Duration::from_secs(2), async {
        while api.sockets.available_permits() != 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    // Release the owned fixture lookup even on a failed assertion.
    backend.release.add_permits(1);
    let _ = socket.close(None).await;
    serving.abort();
    assert!(
        retired.is_ok(),
        "revoked bootstrap retained its socket during confirmation lookup"
    );
}

/// A replay (or any different request) sent during a pending confirmation gets the busy error and keeps the batch alive.
#[tokio::test]
async fn a_client_request_during_a_pending_confirmation_keeps_the_batch() {
    // A well-formed request that arrives while a confirmation lookup is pending
    // (a replay, a retry of another host or a different confirmation) must wait its
    // turn. Closing the socket drops the Batch, which cancels every host in it.
    pending_confirmation_with(|_| serde_json::json!({"action":"replay","after":0}), true).await;
}

/// A repeat of the confirmation in flight (a double-click) gets no busy error: the first one's reply answers both.
#[tokio::test]
async fn an_identical_confirmation_during_a_pending_one_is_not_refused_as_busy() {
    // A double-click resends the very same confirmation while the first is still
    // looking up. It must not get the busy error (the screen reads any error as a
    // failure); the one reply to the first confirmation answers both.
    pending_confirmation_with(
        |challenge| serde_json::json!({"action":"confirm-host-key","target":"one","challenge":challenge,"fingerprint":format!("SHA256:{}", "a".repeat(43))}),
        false,
    )
    .await;
}

/// Starts a batch whose host-key confirmation lookup is held open, sends `second` meanwhile, and checks the
/// socket survives and still answers the first confirmation. `busy_expected` says whether `second` must get
/// the busy error (a different request) or no error at all (an identical confirmation).
async fn pending_confirmation_with(
    second: impl FnOnce(&uuid::Uuid) -> serde_json::Value,
    busy_expected: bool,
) {
    let (auth, _, cookie, _, _, original_server, _, _) = fixture(false).await;
    original_server.abort();
    let backend = Arc::new(ConfirmationLookup {
        calls: AtomicUsize::new(0),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let challenge = uuid::Uuid::new_v4();
    let api = Arc::new(Api {
        auth: auth.clone(),
        #[cfg(feature = "remote")]
        action_guard: ActionGuard::new(auth.clone(), auth.pool().clone()),
        runner: Bootstrap::new(
            Arc::new(PublicChallenge(challenge)),
            backend.clone(),
            BinaryPaths {
                x86_64: "unused".into(),
                aarch64: "unused".into(),
            },
        ),
        #[cfg(feature = "remote")]
        setup_sockets: Arc::new(Semaphore::new(128)),
        sockets: Arc::new(Semaphore::new(16)),
        ssh_key: Arc::new(UnavailableSshKey),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/bootstrap/ws", get(upgrade))
        .with_state(api.clone());
    let serving = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"start","targets":[{"id":"one","address":{"kind":"manual","value":"user@fixture"}}]}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = socket.next().await.unwrap().unwrap();
            let event: serde_json::Value =
                serde_json::from_str(response.to_text().unwrap()).unwrap();
            if event["step"] == "failed" {
                break;
            }
        }
    })
    .await
    .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"confirm-host-key","target":"one","challenge":challenge,"fingerprint":format!("SHA256:{}", "a".repeat(43))}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), backend.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    socket
        .send(ClientMessage::Text(second(&challenge).to_string().into()))
        .await
        .unwrap();
    if busy_expected {
        let busy = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let busy: serde_json::Value = serde_json::from_str(busy.to_text().unwrap()).unwrap();
        assert_eq!(
            busy["error"],
            "host-key confirmation busy; retry after confirmation"
        );
    } else {
        // Nothing may arrive while the lookup is held: a reply now would be the busy error.
        let early = tokio::time::timeout(Duration::from_millis(300), socket.next()).await;
        assert!(
            early.is_err(),
            "an identical confirmation got a reply while the first was pending: {early:?}"
        );
    }
    // A busy response must leave the actual lookup pending and able to answer.
    backend.release.add_permits(1);
    // The confirmation answers (confirmed or refused) on the same live socket.
    let answered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match socket.next().await {
                Some(Ok(ClientMessage::Text(text))) => {
                    let reply: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if reply.get("host_key_confirmed").is_some() || reply.get("error").is_some() {
                        return true;
                    }
                }
                Some(Ok(ClientMessage::Ping(_) | ClientMessage::Pong(_))) => {}
                _ => return false,
            }
        }
    })
    .await;
    let _ = socket.close(None).await;
    serving.abort();
    assert_eq!(
        answered,
        Ok(true),
        "a queued client request closed the socket and cancelled the batch mid-confirmation"
    );
}
struct NoSsh;
impl SshTransport for NoSsh {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { panic!("rejected backend must not open SSH") })
    }
}
#[allow(clippy::type_complexity)]
async fn fixture(
    stalled: bool,
) -> (
    Auth,
    String,
    String,
    Arc<Rejected>,
    SocketAddr,
    tokio::task::JoinHandle<()>,
    sqlx::SqlitePool,
    Arc<Api>,
) {
    // Reuse auth fixtures' serial gate: their process-wide Argon2 budget is
    // intentionally two slots. Socket/backpressure checks run after release.
    let guard = crate::auth::tests::SERIAL.lock().await;
    let pool = SqlitePoolOptions::new()
        .test_before_acquire(false)
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    let mut setup = String::new();
    auth.bootstrap(now().unwrap(), |banner| {
        setup = banner.lines().nth(1).unwrap().into();
    })
    .await
    .unwrap();
    let (owner, cookie) =
        crate::auth::tests::register_over_http(&crate::auth::router(auth.clone()), &setup).await;
    drop(guard);
    let backend = Arc::new(Rejected(
        AtomicUsize::new(0),
        if stalled {
            LONG
        } else {
            "Read-only admission fixture rejected the host."
        },
    ));
    let runner = Bootstrap::new(
        Arc::new(NoSsh),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let api = Arc::new(Api {
        auth: auth.clone(),
        #[cfg(feature = "remote")]
        action_guard: ActionGuard::new(auth.clone(), auth.pool().clone()),
        runner,
        ssh_key: Arc::new(UnavailableSshKey),
        #[cfg(feature = "remote")]
        setup_sockets: Arc::new(Semaphore::new(128)),
        sockets: Arc::new(Semaphore::new(16)),
    });
    let app = Router::new().route("/v1/bootstrap/ws", get(upgrade));
    #[cfg(feature = "remote")]
    let app = app.route("/v1/bootstrap/setup/ws", get(setup_api::upgrade));
    let app = app.with_state(api.clone());
    let serving = tokio::spawn(async move {
        use axum::serve::ListenerExt;
        let listener = listener.tap_io(|socket| {
            nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::SndBuf, &4096).unwrap();
        });
        axum::serve(listener, app).await.unwrap();
    });
    (auth, owner, cookie, backend, address, serving, pool, api)
}
fn request(
    address: SocketAddr,
    origin: &str,
    cookie: Option<&str>,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut request = format!("ws://{address}/v1/bootstrap/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", origin.parse().unwrap());
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert("Cookie", cookie.parse().unwrap());
    }
    request
}
async fn rejection(request: tokio_tungstenite::tungstenite::http::Request<()>, status: StatusCode) {
    match connect_async(request).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), status);
        }
        _ => panic!("unexpected bootstrap handshake admission"),
    }
}

/// A cookie together with an API key is one request claiming two authorities, so it is refused
/// in every build (#303, J234 P3-1). A build without the `remote` feature used to ignore the key
/// and admit the request as the cookie's session.
#[tokio::test]
async fn a_cookie_with_an_api_key_is_refused_in_every_build() {
    let (auth, _, cookie, _, address, server, _, _) = fixture(false).await;
    let mut both = request(address, ORIGIN, Some(&cookie));
    both.headers_mut().insert(
        "Authorization",
        "Bearer fixture-cookie-pair-key-never-print"
            .parse()
            .unwrap(),
    );
    rejection(both, StatusCode::UNAUTHORIZED).await;
    // The same cookie alone still opens the socket: the refusal is the pair's, not the cookie's.
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    let _ = socket.close(None).await;
    server.abort();
    drop(auth);
}

#[tokio::test]
async fn origin_owner_unlock_and_whole_request_consent_are_required() {
    let (_, owner, cookie, backend, address, serving, pool, _) = fixture(false).await;
    rejection(request(address, ORIGIN, None), StatusCode::UNAUTHORIZED).await;
    rejection(
        request(address, "https://foreign.example.test", Some(&cookie)),
        StatusCode::FORBIDDEN,
    )
    .await;
    rejection(
        request(address, ORIGIN, Some(&format!("{cookie}; {cookie}"))),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let mut duplicates = request(address, ORIGIN, Some(&cookie));
    duplicates
        .headers_mut()
        .append("Cookie", cookie.parse().unwrap());
    rejection(duplicates, StatusCode::UNAUTHORIZED).await;
    let mut duplicates = request(address, ORIGIN, Some(&cookie));
    duplicates
        .headers_mut()
        .append("Origin", ORIGIN.parse().unwrap());
    rejection(duplicates, StatusCode::FORBIDDEN).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    let root = serde_json::json!({"action":"start","targets":[{"id":"one","address":{"kind":"manual","value":"root@fixture"},"mode":"root","root_consent":false}]});
    socket
        .send(ClientMessage::Text(root.to_string().into()))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(response.to_text().unwrap().contains("explicit consent"));
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    let invalid = serde_json::json!({"action":"start","password":"synthetic-marker","targets":[]});
    socket
        .send(ClientMessage::Text(invalid.to_string().into()))
        .await
        .unwrap();
    let response = socket.next().await.unwrap().unwrap();
    assert!(!response.to_text().unwrap().contains("synthetic-marker"));
    // Mutate only this in-memory test database; neither ordinary membership nor
    // pending local unlock grants bootstrap authority.
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    rejection(
        request(address, ORIGIN, Some(&cookie)),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET unlocked=0")
        .execute(&pool)
        .await
        .unwrap();
    rejection(
        request(address, ORIGIN, Some(&cookie)),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    serving.abort();
}

#[tokio::test]
async fn admission_stream_is_ordered_and_logout_retires_an_idle_socket() {
    let (auth, _, cookie, backend, address, serving, _, _) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    let start = serde_json::json!({"action":"start","targets":[{"id":"one","address":{"kind":"manual","value":"user@fixture"}}]});
    socket
        .send(ClientMessage::Text(start.to_string().into()))
        .await
        .unwrap();
    for (sequence, step) in [(1, "check"), (2, "failed")] {
        let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(response.to_text().unwrap()).unwrap();
        assert_eq!(event["sequence"], sequence);
        assert_eq!(event["step"], step);
    }
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap();
    assert!(!matches!(closed, Some(Ok(ClientMessage::Text(_)))));
    serving.abort();
}

#[tokio::test]
async fn revocation_interrupts_a_stalled_progress_send() {
    progress_interrupt(false).await;
}

#[tokio::test]
async fn component_off_interrupts_a_stalled_progress_send() {
    progress_interrupt(true).await;
}

async fn progress_interrupt(component_off: bool) {
    let (auth, _, cookie, backend, address, serving, _, api) = fixture(true).await;
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    nix::sys::socket::setsockopt(&stream, nix::sys::socket::sockopt::RcvBuf, &4096).unwrap();
    let (mut socket, _) =
        tokio_tungstenite::client_async(request(address, ORIGIN, Some(&cookie)), stream)
            .await
            .unwrap();
    let targets: Vec<_> = (0..100).map(|id| serde_json::json!({"id":format!("host{id}"),"address":{"kind":"manual","value":"user@fixture"}})).collect();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"start","targets":targets})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while backend.0.load(Ordering::SeqCst) != 100 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Do not read progress: the small real TCP windows stall the server sender.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(api.sockets.available_permits(), 15);
    if component_off {
        use infraternal_plugin_api::ComponentPlugin;
        tokio::time::timeout(Duration::from_secs(2), api.runner.set_enabled(false))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(api.runner.status().active_work, 0);
    } else {
        auth.logout(cookie.split_once('=').unwrap().1)
            .await
            .unwrap();
    }
    let retired = tokio::time::timeout(Duration::from_secs(2), async {
        while api.sockets.available_permits() != 16 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    serving.abort();
    assert!(
        retired.is_ok(),
        "revoked bootstrap retained its socket after interrupting a send"
    );
}

#[tokio::test]
async fn control_frames_do_not_cancel_bootstrap_or_starve_progress() {
    let (_, _, cookie, backend, address, serving, _, _) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Pong(Vec::new().into()))
        .await
        .unwrap();
    let start = serde_json::json!({"action":"start","targets":[{"id":"one","address":{"kind":"manual","value":"user@fixture"}}]});
    socket
        .send(ClientMessage::Text(start.to_string().into()))
        .await
        .unwrap();
    let progress = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(
        matches!(progress, Some(Ok(ClientMessage::Text(_)))),
        "control frame retired the live bootstrap socket"
    );
    socket
        .send(ClientMessage::Ping(b"keepalive".to_vec().into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(ClientMessage::Pong(bytes))) if bytes.as_ref() == b"keepalive" => break,
                Some(Ok(ClientMessage::Text(_))) => {}
                _ => panic!("missing heartbeat reply"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    serving.abort();
}

#[tokio::test]
async fn settings_public_key_requires_exact_origin_and_live_unlocked_owner() {
    use crate::ssh_key::{PublicSshKey, SshKeyError, SshKeyMaterial, SshKeySource};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    struct PublicOnly;
    impl SshKeySource for PublicOnly {
        fn public_key(&self) -> Result<PublicSshKey, SshKeyError> {
            Ok(PublicSshKey {
                public_key: "ssh-ed25519 fixture-public-only".into(),
                fingerprint: "SHA256:fixture-public-only".into(),
                locked: true,
            })
        }
        fn load(&self) -> Result<SshKeyMaterial, SshKeyError> {
            panic!("public API loaded private material")
        }
    }
    let (auth, _, cookie, _, _, serving, pool, api) = fixture(false).await;
    let app = router_with_ssh_key(&auth, api.runner.clone(), Arc::new(PublicOnly));
    let request = |origin: &str, cookie: Option<&str>| {
        let mut builder = Request::builder()
            .uri("/v1/bootstrap/ssh-key")
            .header(header::ORIGIN, origin);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Body::empty()).unwrap()
    };
    for (origin, capability, status) in [
        (ORIGIN, None, StatusCode::UNAUTHORIZED),
        (
            "https://foreign.example.test",
            Some(cookie.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (ORIGIN, Some(cookie.as_str()), StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(request(origin, capability))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        if status == StatusCode::OK {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["locked"], true);
            assert_eq!(value.as_object().unwrap().len(), 3);
            assert_eq!(value["public_key"], "ssh-ed25519 fixture-public-only");
        }
    }
    let mut duplicate = request(ORIGIN, Some(&cookie));
    duplicate
        .headers_mut()
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut duplicate = request(ORIGIN, Some(&cookie));
    duplicate
        .headers_mut()
        .append(header::COOKIE, cookie.parse().unwrap());
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut browser_request = request(ORIGIN, Some(&cookie));
    *browser_request.method_mut() = axum::http::Method::POST;
    assert_eq!(
        app.clone().oneshot(browser_request).await.unwrap().status(),
        StatusCode::OK
    );
    let unavailable = router(&auth, api.runner.clone());
    assert_eq!(
        unavailable
            .oneshot(request(ORIGIN, Some(&cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE sessions SET unlocked=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(ORIGIN, Some(&cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE sessions SET unlocked=1")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(ORIGIN, Some(&cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET owner=1")
        .execute(&pool)
        .await
        .unwrap();
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    assert_eq!(
        app.oneshot(request(ORIGIN, Some(&cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    serving.abort();
}

#[tokio::test]
async fn host_key_confirmation_rechecks_the_exact_live_owner_capability() {
    let (auth, owner, cookie, _, _, serving, pool, _) = fixture(false).await;
    let proof = LiveConfirmation {
        auth: auth.clone(),
        owner: owner.clone(),
        token: Secret::new(cookie.split_once('=').unwrap().1.as_bytes().to_vec()),
    };
    proof.authorize().await.unwrap();
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    assert!(proof.authorize().await.is_err());
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    proof.authorize().await.unwrap();
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    assert!(proof.authorize().await.is_err());
    serving.abort();
}

#[tokio::test]
async fn component_off_retires_idle_sockets_and_refuses_new_admission() {
    use axum::{body::Body, http::Request as HttpRequest};
    use infraternal_plugin_api::{ComponentPlugin, PluginState};
    use tower::ServiceExt;
    let (auth, owner, cookie, _, address, serving, _, api) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(api.sockets.available_permits(), 15);
    tokio::time::timeout(Duration::from_secs(2), api.runner.set_enabled(false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(api.sockets.available_permits(), 16);
    assert_eq!(api.runner.status().state, PluginState::Off);
    assert_eq!(api.runner.status().active_work, 0);
    let response = router(&auth, api.runner.clone())
        .oneshot(
            HttpRequest::builder()
                .uri("/v1/bootstrap/ssh-key")
                .header(header::ORIGIN, ORIGIN)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        auth.bootstrap_owner(cookie.split_once('=').unwrap().1, now().unwrap())
            .await
            .is_ok_and(|current| current == owner)
    );
    let refused = matches!(connect_async(request(address, ORIGIN, Some(&cookie))).await, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused);
    let _ = socket.close(None).await;
    api.runner.set_enabled(true).await.unwrap();
    let (mut replacement, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(api.sockets.available_permits(), 15);
    api.runner.set_enabled(false).await.unwrap();
    let _ = replacement.close(None).await;
    serving.abort();
}

#[tokio::test]
async fn split_cookie_fields_preserve_bootstrap_owner_authority() {
    let (_, _, cookie, _, address, serving, _, api) = fixture(false).await;
    for session_first in [false, true] {
        let fields = if session_first {
            [cookie.as_str(), "ceremony=unrelated"]
        } else {
            ["ceremony=unrelated", cookie.as_str()]
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
        for field in fields {
            headers.append(header::COOKIE, field.parse().unwrap());
        }
        // Settings and bootstrap upgrades share this admission adapter; check
        // live SQLite authority and the real socket without printing capabilities.
        assert!(authenticate_headers(&api, &headers).await.is_ok());
        let mut upgrade = request(address, ORIGIN, None);
        for field in fields {
            upgrade
                .headers_mut()
                .append(header::COOKIE, field.parse().unwrap());
        }
        let (mut socket, _) = connect_async(upgrade).await.unwrap();
        socket.close(None).await.unwrap();
    }
    for invalid in [
        cookie.parse().unwrap(),
        "__Host-infraternal=short".parse().unwrap(),
        axum::http::HeaderValue::from_bytes(b"other=\xff").unwrap(),
    ] {
        for invalid_first in [false, true] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
            let valid = cookie.parse().unwrap();
            let fields = if invalid_first {
                [invalid.clone(), valid]
            } else {
                [valid, invalid.clone()]
            };
            for field in fields {
                headers.append(header::COOKIE, field);
            }
            assert!(matches!(
                authenticate_headers(&api, &headers).await,
                Err(StatusCode::UNAUTHORIZED)
            ));
        }
    }
    serving.abort();
}

#[test]
fn start_fresh_request_is_bound_to_a_target_and_public_challenge() {
    let challenge = uuid::Uuid::new_v4();
    let request: Request = serde_json::from_value(serde_json::json!({
        "action": "start-fresh", "target": "host-one", "challenge": challenge,
    }))
    .unwrap();
    assert!(
        matches!(request, Request::StartFresh {target, challenge: observed} if target == "host-one" && observed == challenge)
    );
    for value in [
        serde_json::json!({"action":"start-fresh","target":"host-one"}),
        serde_json::json!({"action":"start-fresh","target":"host-one","challenge":challenge,"path":"/foreign"}),
    ] {
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
}

#[cfg(feature = "remote")]
#[path = "bootstrap_setup_api_tests.rs"]
mod setup_status_tests;

// Bootstrap admission-to-subscription regressions for #240.
#[tokio::test]
async fn bootstrap_logout_before_subscription_closes_idle_upgrade() {
    revoked_before_subscription(SocketMode::Bootstrap).await;
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn setup_logout_before_subscription_closes_idle_upgrade() {
    revoked_before_subscription(SocketMode::Setup).await;
}

async fn revoked_upgrade(
    State(api): State<Arc<Api>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    mode: SocketMode,
) -> Response {
    let (owner, token) = authenticate_headers(&api, &headers).await.unwrap();
    let token = Secret::new(token.as_bytes().to_vec());
    // Commit in the exact gap after admission but before run installs its receiver.
    api.auth
        .logout(std::str::from_utf8(token.expose()).unwrap())
        .await
        .unwrap();
    let activity = api.runner.activity().unwrap();
    let permit = api.sockets.clone().acquire_owned().await.unwrap();
    upgrade_admitted(
        ws,
        api,
        owner,
        token,
        activity,
        permit,
        super::UpgradeContext {
            mode,
            #[cfg(feature = "remote")]
            api_key: None,
        },
    )
}

async fn revoked_before_subscription(mode: SocketMode) {
    let (_, _, cookie, _, _, original, _, api) = fixture(false).await;
    original.abort();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/v1/bootstrap/ws",
            get(move |state, headers, ws| revoked_upgrade(state, headers, ws, mode)),
        )
        .with_state(api);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    server.abort();
    assert!(
        closed.is_ok(),
        "logout before subscription left an idle bootstrap socket open"
    );
    assert!(!matches!(closed.unwrap(), Some(Ok(ClientMessage::Text(_)))));
}

#[tokio::test]
async fn review_account_scope_logout_after_subscription_retires_idle_bootstrap() {
    let (auth, _, cookie, backend, address, serving, _, _) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    // A response fences run's subscription and entry read before this logout.
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"review-invalid"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap(),
        Some(Ok(ClientMessage::Text(_)))
    ));
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    serving.abort();
    assert!(
        closed.is_ok(),
        "logout after subscription left bootstrap open"
    );
    assert!(!matches!(closed.unwrap(), Some(Ok(ClientMessage::Text(_)))));
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn review_account_scope_lost_bootstrap_source_retires_instead_of_spinning() {
    let (auth, owner, cookie, _, address, serving, _, api) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"review-invalid"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap(),
        Some(Ok(ClientMessage::Text(_)))
    ));
    let source = auth.revocation_events(&owner);
    source.close_source_for_test();
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    // An upgrade has its own task. Retire it even when the source-loss assertion
    // fails; aborting only the listener would leave the fixture's loop alive.
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while api.sockets.available_permits() != 16 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    serving.abort();
    assert!(
        closed.is_ok(),
        "lost revocation source retained bootstrap instead of failing closed"
    );
    assert!(matches!(
        closed.unwrap(),
        Some(Ok(ClientMessage::Close(Some(frame)))) if u16::from(frame.code) == 1013
    ));
}

#[tokio::test]
async fn review_r2_restored_bootstrap_source_still_reports_unavailable() {
    let (auth, owner, cookie, _, address, serving, _, api) = fixture(false).await;
    let (mut socket, _) = connect_async(request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"review-invalid"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap(),
        Some(Ok(ClientMessage::Text(_)))
    ));
    let source = auth.revocation_events(&owner);
    source.close_source_for_test();
    // Restore the registry synchronously before the upgrade gets another executor turn.
    // The old cursor must remember source loss even when a new source is available.
    let replacement = auth.revocation_events(&owner);
    assert!(source.has_changed().is_err());
    assert!(!replacement.has_changed().unwrap());
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    // An upgrade has its own task. Retire it even when the source-loss assertion
    // fails; aborting only the listener would leave the fixture's loop alive.
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while api.sockets.available_permits() != 16 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    serving.abort();
    assert!(
        closed.is_ok(),
        "lost revocation source retained bootstrap instead of failing closed"
    );
    assert!(matches!(
        closed.unwrap(),
        Some(Ok(ClientMessage::Close(Some(frame)))) if u16::from(frame.code) == 1013
    ));
}
