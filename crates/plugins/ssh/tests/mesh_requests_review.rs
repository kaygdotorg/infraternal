//! Independently verify request refusal and reply ordering at the SSH boundary.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
#[path = "common/mesh_runtime.rs"]
mod runtime;

use infraternal_plugin_ssh::mesh_server::{config, serve};
use russh::{ChannelMsg, client, keys::PublicKeyOrCertificate};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

struct Client;
#[allow(clippy::unused_async_trait_impl)]
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect() -> (
    Arc<runtime::Authority>,
    client::Handle<Client>,
    tokio::task::JoinHandle<()>,
) {
    let ca = runtime::key();
    let user = runtime::key();
    let cert = runtime::certificate(
        &ca,
        &user,
        runtime::now() - 1,
        runtime::now() + 3600,
        "person-1",
    );
    let authority = runtime::Authority::new(&ca, &cert);
    let current = Arc::clone(&authority);
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = tokio::spawn(async move {
        let _ = serve(
            current,
            "127.0.0.1".parse().unwrap(),
            9,
            Arc::new(config(runtime::key())),
            server_io,
        )
        .await;
    });
    let mut client = client::connect_stream(Arc::new(client::Config::default()), client_io, Client)
        .await
        .unwrap();
    assert!(
        client
            .authenticate_openssh_cert("operator", Arc::new(user), cert)
            .await
            .unwrap()
            .success()
    );
    (authority, client, server)
}

async fn result(channel: &mut russh::Channel<client::Msg>) -> Option<bool> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Some(true),
            Some(ChannelMsg::Failure) => return Some(false),
            Some(ChannelMsg::Close) | None => return None,
            _ => (),
        }
    }
}

#[tokio::test]
async fn environment_request_with_reply_is_explicitly_refused() {
    let (_authority, client, server) = connect().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .set_env(true, "REVIEW_VALUE", "ordinary")
        .await
        .unwrap();
    let reply = timeout(Duration::from_secs(2), result(&mut channel)).await;
    client
        .disconnect(russh::Disconnect::ByApplication, "done", "")
        .await
        .unwrap();
    drop(client);
    server.await.unwrap();
    assert!(
        matches!(reply, Ok(Some(false))),
        "environment request was not explicitly refused: {reply:?}"
    );
}

#[tokio::test]
async fn x11_request_with_reply_is_explicitly_refused() {
    let (_authority, client, server) = connect().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00000000", 0)
        .await
        .unwrap();
    let reply = timeout(Duration::from_secs(2), result(&mut channel)).await;
    client
        .disconnect(russh::Disconnect::ByApplication, "done", "")
        .await
        .unwrap();
    drop(client);
    server.await.unwrap();
    assert!(
        matches!(reply, Ok(Some(false))),
        "X11 request was not explicitly refused: {reply:?}"
    );
}

#[tokio::test]
async fn resize_during_pending_shell_preserves_the_shell_reply() {
    timeout(Duration::from_secs(10), async {
        let (authority, client, server) = connect().await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert_eq!(result(&mut channel).await, Some(true));
        // Block registration, then use a second channel as a protocol ordering
        // barrier. The shell cannot finish until the no-reply resize is parsed.
        let guard = authority.rules.write().await;
        channel.request_shell(true).await.unwrap();
        channel.window_change(100, 30, 0, 0).await.unwrap();
        let mut barrier = client.channel_open_session().await.unwrap();
        barrier
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert_eq!(result(&mut barrier).await, Some(true));
        drop(guard);
        let first = channel.wait().await;
        client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        drop(client);
        server.await.unwrap();
        assert!(
            matches!(first, Some(ChannelMsg::Success)),
            "shell response was superseded by resize: {first:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn later_refusals_keep_their_order_behind_pending_shell() {
    timeout(Duration::from_secs(10), async {
        let (authority, client, server) = connect().await;
        let mut channel = client.channel_open_session().await.unwrap();
        let guard = authority.rules.write().await;
        channel.request_shell(true).await.unwrap();
        channel.set_env(false, "IGNORED", "value").await.unwrap();
        channel.set_env(true, "REFUSED", "value").await.unwrap();
        channel
            .exec(true, b"second session".to_vec())
            .await
            .unwrap();
        let mut barrier = client.channel_open_session().await.unwrap();
        barrier.set_env(true, "BARRIER", "value").await.unwrap();
        assert_eq!(result(&mut barrier).await, Some(false));
        drop(guard);
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
        assert!(matches!(
            channel.wait().await,
            Some(ChannelMsg::Data { .. })
        ));
        client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        drop(client);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn held_authority_cannot_accumulate_unbounded_request_replies() {
    timeout(Duration::from_secs(10), async {
        let (authority, client, server) = connect().await;
        let mut channel = client.channel_open_session().await.unwrap();
        let guard = authority.rules.write().await;
        channel.request_shell(true).await.unwrap();
        for _ in 0..65 {
            if channel.set_env(true, "REFUSED", "value").await.is_err() {
                break;
            }
        }
        // Completion while the authority is still held proves the connection
        // refused the bounded backlog instead of retaining or waiting for it.
        server.await.unwrap();
        while let Some(message) = channel.wait().await {
            assert!(!matches!(message, ChannelMsg::Data { .. }));
        }
        assert!(authority.opened.lock().unwrap().is_empty());
        drop(guard);
        drop(client);
    })
    .await
    .unwrap();
}
