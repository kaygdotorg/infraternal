//! Exercises declared native routing on the real SQLite-authenticated production WebSocket router [D208,D232,#146].
use super::*;
use infraternal_protocol::desktop::{Delivery, Message as Desktop};

#[tokio::test]
async fn native_bulk_keeps_authenticated_control_live_and_logout_retires_worker() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    state.plugins = crate::plugins::PluginRuntime::new(
        vec![Arc::new(crate::plugins::retirement_tests::NativeEcho(
            100 * 1024,
        ))],
        "server",
    )
    .with_store(f.auth.pool.clone())
    .await
    .unwrap();
    let runtime = state.plugins.clone();
    runtime.set_enabled("desktop", true).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, crate::websocket::router(state)).into_future());
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 8,
            client_info: "native-routing",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        1,
        &Frame::Desktop(Desktop::Attach {
            session_id: &[9; 16],
            delivery: Delivery::Reliable,
        }),
    )
    .await;
    let video = read_client_frame(&mut socket).await;
    let decoded = decode_muxed_frame(&video).unwrap();
    assert_eq!(decoded.stream_id, 1);
    assert!(
        matches!(decoded.frame, Frame::Desktop(Desktop::Video { bytes, .. }) if bytes.len() == 100 * 1024)
    );
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 146,
            sent_us: 1,
        },
    )
    .await;
    let pong = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&pong).unwrap().frame,
        Frame::Pong { nonce: 146, .. }
    ));
    assert_eq!(runtime.active_workers("desktop"), 1);
    f.auth.logout(&f.session).await.unwrap();
    let next = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .unwrap();
    assert!(matches!(next, None | Some(Ok(Message::Close(_)) | Err(_))));
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.active_workers("desktop") != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server.abort();
    f.auth.pool.close().await;
}

// A held worker keeps its request receiver registered after the authorization
// scope exits, isolating the socket's response from ordinary worker teardown.
type TestSocketHost = Arc<dyn infraternal_plugin_api::SocketHost>;
type HostReady = tokio::sync::oneshot::Sender<TestSocketHost>;
struct ScopeProbe {
    ready: std::sync::Mutex<Option<HostReady>>,
    ended: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<std::result::Result<(), ()>>>>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl infraternal_plugin_api::Plugin for ScopeProbe {
    fn descriptor(&self) -> &'static infraternal_plugin_api::PluginDescriptor {
        &infraternal_plugin_desktop::server_manifest::DESCRIPTOR
    }
    fn run(
        &self,
        host: TestSocketHost,
        requests: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        _: infraternal_plugin_api::ReplySender,
        _: infraternal_plugin_api::SubscriptionRegistry,
    ) -> infraternal_plugin_api::Operation<'static, ()> {
        let ready = self.ready.lock().unwrap().take();
        let ended = self.ended.lock().unwrap().take();
        let release = self.release.lock().unwrap().take();
        Box::pin(async move {
            let admitted = host.clone();
            let result = host
                .authorized(Box::pin(async move {
                    if let Some(ready) = ready {
                        let _ = ready.send(admitted);
                    }
                    std::future::pending().await
                }))
                .await;
            if let Some(ended) = ended {
                let _ = ended.send(result);
            }
            if let Some(release) = release {
                let _ = release.await;
            }
            drop(requests);
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep ordinary failure, SQL refusal and fresh reconnect on one actual socket fixture.
async fn native_authority_read_failure_retires_socket_instead_of_only_its_worker() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (agent, _peer) = UnixStream::pair().unwrap();
    let mut state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(agent),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_millis(250));
    let (ready, admitted) = tokio::sync::oneshot::channel();
    let (ended, stopped) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    state.plugins = crate::plugins::PluginRuntime::new(
        vec![Arc::new(ScopeProbe {
            ready: std::sync::Mutex::new(Some(ready)),
            ended: std::sync::Mutex::new(Some(ended)),
            release: std::sync::Mutex::new(Some(released)),
        })],
        "server",
    )
    .with_store(f.auth.pool.clone())
    .await
    .unwrap();
    let runtime = state.plugins.clone();
    runtime.set_enabled("desktop", true).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, crate::websocket::router(state)).into_future());
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 8,
            client_info: "authority-scope",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        1,
        &Frame::Desktop(Desktop::Attach {
            session_id: &[8; 16],
            delivery: Delivery::Reliable,
        }),
    )
    .await;
    let host = tokio::time::timeout(Duration::from_secs(3), admitted)
        .await
        .unwrap()
        .unwrap();
    let authority = host.authority();
    assert!(authority.permits());
    // A backend operation may fail without invalidating its authenticated caller.
    assert_eq!(host.authorized(Box::pin(async { Err(()) })).await, Err(()));
    assert!(
        authority.permits(),
        "ordinary operation error retired a valid socket"
    );
    // This fixture has one non-pinging in-memory SQLite connection. Holding it
    // forces a real bounded authority read to fail after admission, without
    // revoking the login or relying on scheduler load to reproduce the defect.
    let held = f.auth.pool.acquire().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), stopped)
            .await
            .unwrap()
            .unwrap(),
        Err(())
    );
    assert!(
        !authority.permits(),
        "failed authority scope left shared socket admission live"
    );
    drop(held);
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .unwrap();
    assert!(
        matches!(closed, None | Some(Ok(Message::Close(_)) | Err(_))),
        "authority loss did not retire the transport"
    );
    // The fresh handshake with this same cookie below proves the login was
    // preserved, using the server clock rather than the fixture registration clock.
    let (mut replacement, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut replacement).await;
    client_ws_send(
        &mut replacement,
        0,
        &Frame::Hello {
            version: 1,
            caps: 8,
            client_info: "authority-replacement",
        },
    )
    .await;
    read_welcome(&mut replacement).await;
    client_ws_send(
        &mut replacement,
        0,
        &Frame::Ping {
            nonce: 1464,
            sent_us: 0,
        },
    )
    .await;
    let pong = read_client_frame(&mut replacement).await;
    assert!(matches!(
        decode_muxed_frame(&pong).unwrap().frame,
        Frame::Pong { nonce: 1464, .. }
    ));
    replacement.close(None).await.unwrap();
    let _ = release.send(());
    runtime.set_enabled("desktop", false).await.unwrap();
    server.abort();
    f.auth.pool.close().await;
}
