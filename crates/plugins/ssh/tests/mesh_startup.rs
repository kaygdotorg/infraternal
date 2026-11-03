//! Check optimistic startup, negotiation fallback and certificate proof against the real engine.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
#[path = "common/mesh_runtime.rs"]
mod runtime;

use futures_util::FutureExt;
use infraternal_plugin_ssh::{
    mesh_admission::Refusal,
    mesh_login::LoginAuthority,
    mesh_server::{config, serve},
};
use russh::{
    ChannelMsg, client,
    keys::{Algorithm, Certificate, EcdsaCurve, PrivateKey, PublicKey, PublicKeyOrCertificate},
};
use std::{borrow::Cow, sync::Arc, time::Duration};
use tokio::time::timeout;

struct Client(PublicKey);
#[allow(clippy::unused_async_trait_impl)]
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.public_key().key_data() == self.0.key_data())
    }
}

async fn start<A: LoginAuthority>(
    authority: Arc<A>,
    mode: u8,
) -> (
    Result<client::Handle<Client>, russh::Error>,
    tokio::task::JoinHandle<()>,
) {
    let host = runtime::key();
    let trusted = if mode == 4 {
        runtime::key().public_key().clone()
    } else {
        host.public_key().clone()
    };
    let mut server_config = config(host);
    if mode == 2 {
        // The first client method is unsupported here: the server must discard
        // the guessed packet and complete the negotiated exchange instead.
        server_config.preferred.kex.to_mut().remove(0);
    }
    if mode == 5 {
        server_config.preferred.kex.to_mut().retain(|name| {
            ![
                russh::kex::MLKEM768X25519_SHA256,
                russh::kex::CURVE25519,
                russh::kex::CURVE25519_PRE_RFC_8731,
            ]
            .contains(name)
        });
    }
    let mut client_config = client::Config {
        optimistic_startup: mode != 0,
        channel_buffer_size: if mode == 6 { 1 } else { 100 },
        ..Default::default()
    };
    if mode == 3 {
        // Even with the same exchange method, differing first host-key choices
        // invalidate the guess and require another initial exchange packet.
        client_config.preferred.host_key_certificates = Cow::Borrowed(&[]);
        client_config.preferred.key = Cow::Owned(vec![
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ed25519,
        ]);
    }
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = tokio::spawn(async move {
        let result = serve(
            authority,
            "127.0.0.1".parse().unwrap(),
            9,
            Arc::new(server_config),
            server_io,
        )
        .await;
        if let Err(error) = result {
            eprintln!("startup server mode {mode}: {error}");
        }
    });
    (
        client::connect_stream(Arc::new(client_config), client_io, Client(trusted)).await,
        server,
    )
}

fn identity(expired: bool) -> (Arc<runtime::Authority>, PrivateKey, Certificate) {
    let ca = runtime::key();
    let user = runtime::key();
    let end = if expired {
        runtime::now() - 1
    } else {
        runtime::now() + 3600
    };
    let cert = runtime::certificate(&ca, &user, runtime::now() - 3600, end, "person-1");
    (runtime::Authority::new(&ca, &cert), user, cert)
}

#[tokio::test(start_paused = true)]
async fn optimistic_startup_and_negotiation_fallbacks_reach_the_prompt() {
    // Every peer and transport runs in memory on this runtime. Virtual time
    // bounds a stuck protocol state without timing debug cryptography on a busy host.
    timeout(Duration::from_secs(30), async {
        for mode in [0, 1, 2, 3, 5] {
            let (authority, user, certificate) = identity(false);
            let observed = Arc::clone(&authority);
            eprintln!("startup mode {mode}: connecting");
            let (client, server) = start(authority, mode).await;
            let mut client = client.unwrap_or_else(|error| panic!("startup mode {mode}: {error}"));
            assert!(client.authenticate_openssh_cert("operator", Arc::new(user), certificate).await.unwrap().success(), "mode {mode}");
            eprintln!("startup mode {mode}: authenticated");
            let mut channel = client.channel_open_session().await.unwrap();
            channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
            channel.request_shell(true).await.unwrap();
            for _ in 0..2 {
                assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)), "mode {mode}");
            }
            assert!(matches!(channel.wait().await, Some(ChannelMsg::Data { data }) if data.as_ref() == b"ready\n"));
            eprintln!("startup mode {mode}: prompt received");
            client.rekey_soon().await.unwrap();
            channel.data(b"x".as_slice()).await.unwrap();
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => { assert_eq!(data.as_ref(), b"x"); break; }
                    Some(ChannelMsg::WindowAdjusted { .. }) => (),
                    other => panic!("mode {mode}: unexpected event after rekey {other:?}"),
                }
            }
            eprintln!("startup mode {mode}: echo after rekey received");
            assert_eq!(observed.opened.lock().unwrap().len(), 1);
            client.disconnect(russh::Disconnect::ByApplication, "done", "").await.unwrap();
            drop(client);
            server.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn optimistic_startup_keeps_host_trust_certificate_time_and_key_proof() {
    timeout(Duration::from_secs(30), async {
        let (authority, _, _) = identity(false);
        let (client, server) = start(authority, 4).await;
        assert!(client.is_err(), "unknown host key was accepted");
        server.await.unwrap();
        for expired in [false, true] {
            let (authority, user, certificate) = identity(expired);
            let observed = Arc::clone(&authority);
            let (client, server) = start(authority, 1).await;
            let mut client = client.unwrap();
            let proof = if expired { user } else { runtime::key() };
            assert!(
                !client
                    .authenticate_openssh_cert("operator", Arc::new(proof), certificate)
                    .await
                    .unwrap()
                    .success()
            );
            assert!(observed.opened.lock().unwrap().is_empty());
            client
                .disconnect(russh::Disconnect::ByApplication, "done", "")
                .await
                .unwrap();
            drop(client);
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn optimistic_failed_login_can_retry_without_opening_a_session() {
    timeout(Duration::from_secs(15), async {
        let (authority, user, certificate) = identity(false);
        let observed = Arc::clone(&authority);
        let (client, server) = start(authority, 1).await;
        let mut client = client.unwrap();
        assert!(!client.authenticate_openssh_cert("operator", Arc::new(runtime::key()), certificate.clone()).await.unwrap().success());
        assert!(observed.opened.lock().unwrap().is_empty());
        assert!(client.authenticate_openssh_cert("operator", Arc::new(user), certificate).await.unwrap().success());
        let mut channel = client.channel_open_session().await.unwrap();
        channel.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
        channel.request_shell(true).await.unwrap();
        for _ in 0..2 {
            assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
        }
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Data { data }) if data.as_ref() == b"ready\n"));
        assert_eq!(observed.opened.lock().unwrap().len(), 1);
        client.disconnect(russh::Disconnect::ByApplication, "done", "").await.unwrap();
        drop(client);
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn pipelined_shell_waits_for_current_access_before_its_reply() {
    timeout(Duration::from_secs(15), async {
        let (authority, user, certificate) = identity(false);
        let observed = Arc::clone(&authority);
        let (client, server) = start(authority, 1).await;
        let mut client = client.unwrap();
        assert!(
            client
                .authenticate_openssh_cert("operator", Arc::new(user), certificate)
                .await
                .unwrap()
                .success()
        );
        let mut channel = client.channel_open_session().await.unwrap();
        let mut rules = observed.rules.write().await;
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel.set_env(true, "REFUSED", "value").await.unwrap();
        // The second channel proves all three earlier requests were parsed
        // while registration was still waiting for the current access view.
        let mut barrier = client.channel_open_session().await.unwrap();
        barrier.set_env(true, "BARRIER", "value").await.unwrap();
        assert!(matches!(barrier.wait().await, Some(ChannelMsg::Failure)));
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
        assert!(channel.wait().now_or_never().is_none());
        assert!(observed.opened.lock().unwrap().is_empty());
        rules.login = false;
        drop(rules);
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
        while let Some(message) = channel.wait().await {
            assert!(!matches!(
                message,
                ChannelMsg::Success | ChannelMsg::Data { .. }
            ));
            if matches!(message, ChannelMsg::Close) {
                break;
            }
        }
        assert!(observed.opened.lock().unwrap().is_empty());
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
async fn pipelined_setup_retains_replies_with_a_one_message_reader() {
    timeout(Duration::from_secs(15), async {
        let (authority, user, certificate) = identity(false);
        let observed = Arc::clone(&authority);
        let (client, server) = start(authority, 6).await;
        let mut client = client.unwrap();
        assert!(
            client
                .authenticate_openssh_cert("operator", Arc::new(user), certificate)
                .await
                .unwrap()
                .success()
        );
        let mut first = client.channel_open_session().await.unwrap();
        let mut second = client.channel_open_session().await.unwrap();
        for (index, channel) in [&mut first, &mut second].into_iter().enumerate() {
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap();
            channel.request_shell(true).await.unwrap();
            channel.set_env(true, "REFUSED", "value").await.unwrap();
            // Leave this reader paused until its runtime registration finishes.
            // A one-message queue cannot hold both setup replies and prompt data.
            while observed.opened.lock().unwrap().len() <= index {
                tokio::task::yield_now().await;
            }
            for _ in 0..2 {
                assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
            }
            let mut ready = false;
            let mut refused = false;
            while !ready || !refused {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        assert_eq!(data.as_ref(), b"ready\n");
                        assert!(!ready);
                        ready = true;
                    }
                    Some(ChannelMsg::Failure) => {
                        assert!(!refused);
                        refused = true;
                    }
                    other => panic!("unexpected setup reply: {other:?}"),
                }
            }
        }
        assert_eq!(observed.opened.lock().unwrap().len(), 2);
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

struct HeldAuthority {
    authority: Arc<runtime::Authority>,
    entered: tokio::sync::Notify,
    proceed: tokio::sync::Semaphore,
}
impl LoginAuthority for HeldAuthority {
    type Guard<'a> = runtime::Guard<'a>;
    async fn current(&self) -> Result<Self::Guard<'_>, Refusal> {
        self.entered.notify_one();
        let _permit = self.proceed.acquire().await.unwrap();
        self.authority.current().await
    }
}

#[tokio::test]
async fn optimistic_authentication_waits_for_the_current_access_view() {
    timeout(Duration::from_secs(15), async {
        let (authority, user, certificate) = identity(false);
        let held = Arc::new(HeldAuthority {
            authority,
            entered: tokio::sync::Notify::new(),
            proceed: tokio::sync::Semaphore::new(0),
        });
        let (client, server) = start(Arc::clone(&held), 1).await;
        let mut client = client.unwrap();
        let authentication = tokio::spawn(async move {
            let result = client
                .authenticate_openssh_cert("operator", Arc::new(user), certificate)
                .await;
            (client, result)
        });
        held.entered.notified().await;
        assert!(
            !authentication.is_finished(),
            "authentication replied before current access was read"
        );
        assert!(held.authority.opened.lock().unwrap().is_empty());
        // Refuse access while the signed request is already in progress.
        held.authority.rules.write().await.login = false;
        held.proceed.add_permits(1);
        let (client, result) = authentication.await.unwrap();
        assert!(!result.unwrap().success());
        assert!(held.authority.opened.lock().unwrap().is_empty());
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
