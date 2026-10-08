//! Exercises bootstrap WebSocket authority using a real software passkey and real loopback sockets.
#![allow(clippy::unwrap_used)]

use super::*;
use futures_util::{SinkExt, StreamExt};
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
                authority.session().is_some(),
                "browser batch lost its live session capability"
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Failure::install(self.1))
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
        runner,
        ssh_key: Arc::new(UnavailableSshKey),
        sockets: Arc::new(Semaphore::new(16)),
    });
    let app = Router::new()
        .route("/v1/bootstrap/ws", get(upgrade))
        .with_state(api.clone());
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
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
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
