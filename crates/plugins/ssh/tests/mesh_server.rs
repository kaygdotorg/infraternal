//! Real-engine admission and channel checks against a test person runtime.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "common/mesh_runtime.rs"]
mod runtime;
use infraternal_plugin_ssh::{
    mesh_login::{Control, LoginAuthority, SessionKind},
    mesh_server::config,
};
use russh::{
    ChannelMsg, client,
    keys::{Certificate, PrivateKey, PublicKeyOrCertificate},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
struct Client;
#[allow(clippy::unused_async_trait_impl)]
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
async fn connect<A: LoginAuthority>(
    authority: Arc<A>,
    cert: Certificate,
    key: PrivateKey,
) -> (client::Handle<Client>, tokio::task::JoinHandle<()>, bool) {
    connect_as(authority, cert, key, "operator").await
}
async fn connect_as<A: LoginAuthority>(
    authority: Arc<A>,
    cert: Certificate,
    key: PrivateKey,
    account: &str,
) -> (client::Handle<Client>, tokio::task::JoinHandle<()>, bool) {
    let (mut client, server) = transport(authority).await;
    let accepted = client
        .authenticate_openssh_cert(account, Arc::new(key), cert)
        .await
        .unwrap()
        .success();
    (client, server, accepted)
}
async fn transport<A: LoginAuthority>(
    authority: Arc<A>,
) -> (client::Handle<Client>, tokio::task::JoinHandle<()>) {
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = tokio::spawn(async move {
        let _ = infraternal_plugin_ssh::mesh_server::serve(
            authority,
            "127.0.0.1".parse().unwrap(),
            9,
            Arc::new(config(runtime::key())),
            server_io,
        )
        .await;
    });
    let client = client::connect_stream(Arc::new(client::Config::default()), client_io, Client)
        .await
        .unwrap();
    (client, server)
}
async fn success(channel: &mut russh::Channel<client::Msg>) -> bool {
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Success => return true,
            ChannelMsg::Failure | ChannelMsg::Close => return false,
            _ => (),
        }
    }
    false
}

#[tokio::test]
async fn pty_exec_eof_and_files_use_the_authorized_person_runtime() {
    timeout(Duration::from_secs(30), async {
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
        let (client, server, accepted) = connect(Arc::clone(&authority), cert, user).await;
        assert!(accepted);
        let mut shell = client.channel_open_session().await.unwrap();
        shell
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(success(&mut shell).await);
        shell.request_shell(true).await.unwrap();
        assert!(success(&mut shell).await);
        let ready = loop {
            if let Some(ChannelMsg::Data { data }) = shell.wait().await {
                break data;
            }
        };
        assert_eq!(&ready[..], b"ready\n");
        shell.window_change(100, 30, 0, 0).await.unwrap();
        shell.window_change(0, 40, 0, 0).await.unwrap();
        shell.signal(russh::Sig::INT).await.unwrap();
        shell.exec(true, b"second request".to_vec()).await.unwrap();
        assert!(!success(&mut shell).await);
        let mut exec = client.channel_open_session().await.unwrap();
        exec.exec(true, b"echo".to_vec()).await.unwrap();
        assert!(success(&mut exec).await);
        exec.data(&b"bytes\n"[..]).await.unwrap();
        exec.eof().await.unwrap();
        let mut received = Vec::new();
        let mut status = None;
        while let Some(message) = exec.wait().await {
            match message {
                ChannelMsg::Data { data } => received.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => (),
            }
        }
        assert_eq!(received, b"bytes\n");
        assert_eq!(status, Some(0));
        let mut files = client.channel_open_session().await.unwrap();
        files.request_subsystem(true, "sftp").await.unwrap();
        assert!(success(&mut files).await);
        let sftp = russh_sftp::client::SftpSession::new(files.into_stream())
            .await
            .unwrap();
        let mut file = sftp.create("/sample").await.unwrap();
        file.write_all(b"file bytes").await.unwrap();
        file.shutdown().await.unwrap();
        drop(file);
        let mut file = sftp.open("/sample").await.unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"file bytes");
        drop(file);
        sftp.close().await.unwrap();
        {
            let opened = authority.opened.lock().unwrap();
            assert_eq!(opened.len(), 2);
            assert!(
                opened
                    .iter()
                    .all(|open| open.person == "person-1" && open.account == "operator")
            );
            assert!(matches!(opened[0].kind, SessionKind::Shell));
            assert_eq!(opened[0].terminal.as_ref().unwrap().size.columns, 80);
            assert!(matches!(&opened[1].kind,SessionKind::Exec(command) if command==b"echo"));
            let controls = authority.controls.lock().unwrap();
            assert!(
                controls
                    .iter()
                    .any(|c| matches!(c,Control::Resize(size) if size.columns==100))
            );
            assert!(
                controls
                    .iter()
                    .any(|c| matches!(c, Control::Signal(russh::Sig::INT)))
            );
            assert!(controls.iter().any(|control| matches!(control, Control::Resize(size) if size.columns == 100 && size.rows == 40)));
        }
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
async fn certificates_and_current_authority_refuse_identity_substitution() {
    timeout(Duration::from_secs(30), async {
        let ca = runtime::key();
        let wrong_ca = runtime::key();
        for case in 0..9 {
            let user = runtime::key();
            let now = runtime::now();
            let mut cert = runtime::certificate(
                if case == 0 { &wrong_ca } else { &ca },
                &user,
                if case == 1 { now - 3600 } else { now - 1 },
                if case == 1 { now - 1 } else { now + 3600 },
                if case == 2 { "person-2" } else { "person-1" },
            );
            if case == 8 {
                cert = runtime::certificate_at_source(
                    &ca,
                    &user,
                    now - 1,
                    now + 3600,
                    "person-1",
                    true,
                    "127.0.0.2",
                );
            }
            let authority = runtime::Authority::new(&ca, &cert);
            {
                let mut rules = authority.rules.write().await;
                match case {
                    3 => rules.current = false,
                    4 => rules.network = false,
                    5 => rules.login = false,
                    _ => (),
                }
            }
            let offered_key = if case == 6 {
                runtime::key()
            } else {
                user.clone()
            };
            let account = if case == 7 {
                "another-person"
            } else {
                "operator"
            };
            let (mut client, server, accepted) =
                connect_as(Arc::clone(&authority), cert, offered_key, account).await;
            assert!(!accepted, "case {case}");
            if case == 0 {
                assert!(
                    !client
                        .authenticate_publickey(
                            "operator",
                            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(user), None)
                        )
                        .await
                        .unwrap()
                        .success()
                );
            }
            assert!(authority.opened.lock().unwrap().is_empty());
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
async fn new_channel_rechecks_revocation_and_forwarding_is_refused() {
    timeout(Duration::from_secs(30), async {
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
        let (client, server, accepted) = connect(Arc::clone(&authority), cert, user).await;
        assert!(accepted);
        assert!(
            client
                .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1234)
                .await
                .is_err()
        );
        assert!(client.tcpip_forward("127.0.0.1", 0).await.is_err());
        let mut channel = client.channel_open_session().await.unwrap();
        channel.agent_forward(true).await.unwrap();
        assert!(!success(&mut channel).await);
        authority.rules.write().await.current = false;
        channel.request_shell(true).await.unwrap();
        assert!(!success(&mut channel).await);
        let mut files = client.channel_open_session().await.unwrap();
        files.request_subsystem(true, "sftp").await.unwrap();
        assert!(!success(&mut files).await);
        assert!(authority.opened.lock().unwrap().is_empty());
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
async fn certificate_without_terminal_permission_refuses_pty() {
    timeout(Duration::from_secs(10), async {
        let ca = runtime::key();
        let user = runtime::key();
        let cert = runtime::certificate_options(
            &ca,
            &user,
            runtime::now() - 1,
            runtime::now() + 3600,
            "person-1",
            false,
        );
        let authority = runtime::Authority::new(&ca, &cert);
        let (client, server, accepted) = connect(authority, cert, user).await;
        assert!(accepted);
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(!success(&mut channel).await);
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
async fn waiting_for_authority_does_not_block_protocol_controls() {
    timeout(Duration::from_secs(10), async {
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
        let (client, server, accepted) = connect(Arc::clone(&authority), cert, user).await;
        assert!(accepted);
        let guard = authority.rules.write().await;
        let mut shell = client.channel_open_session().await.unwrap();
        shell.request_shell(true).await.unwrap();
        let mut control = client.channel_open_session().await.unwrap();
        control
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(success(&mut control).await);
        drop(guard);
        assert!(success(&mut shell).await);
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
async fn cancelling_the_connection_releases_its_authority() {
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
    let (client, server, accepted) = connect(Arc::clone(&authority), cert, user).await;
    assert!(accepted);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert_eq!(
        Arc::strong_count(&authority),
        1,
        "cancelled connection retained a detached protocol worker"
    );
    drop(client);
}

struct WatchedAuthority {
    inner: Arc<runtime::Authority>,
    retired: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Drop for WatchedAuthority {
    fn drop(&mut self) {
        if let Some(retired) = self.retired.take() {
            let _ = retired.send(());
        }
    }
}
impl LoginAuthority for WatchedAuthority {
    type Guard<'a> = runtime::Guard<'a>;
    async fn current(
        &self,
    ) -> Result<Self::Guard<'_>, infraternal_plugin_ssh::mesh_admission::Refusal> {
        self.inner.current().await
    }
}
#[tokio::test]
async fn cancelling_an_active_attachment_releases_its_runtime_open_future() {
    timeout(Duration::from_secs(10), async {
        let ca = runtime::key();
        let user = runtime::key();
        let cert = runtime::certificate(
            &ca,
            &user,
            runtime::now() - 1,
            runtime::now() + 3600,
            "person-1",
        );
        let (retired, retirement) = tokio::sync::oneshot::channel();
        let authority = Arc::new(WatchedAuthority {
            inner: runtime::Authority::new(&ca, &cert),
            retired: Some(retired),
        });
        let (client, server, accepted) = connect(authority, cert, user).await;
        assert!(accepted);
        let mut channel = client.channel_open_session().await.unwrap();
        channel.request_shell(true).await.unwrap();
        assert!(success(&mut channel).await);
        loop {
            if let Some(ChannelMsg::Data { data }) = channel.wait().await {
                assert_eq!(&data[..], b"ready\n");
                break;
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        retirement.await.unwrap();
        drop(channel);
        drop(client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_authenticated_connection_cannot_be_rebound_to_another_person() {
    timeout(Duration::from_secs(10), async {
        let ca = runtime::key();
        let user = runtime::key();
        let now = runtime::now();
        let mut builder = russh::keys::ssh_key::certificate::Builder::new(
            vec![1; 32],
            user.public_key(),
            now - 1,
            now + 3600,
        )
        .unwrap();
        builder.valid_principal("person-1").unwrap();
        builder.valid_principal("person-2").unwrap();
        builder
            .critical_option("source-address", "127.0.0.1/32")
            .unwrap();
        let cert = builder.sign(&ca).unwrap();
        let authority = runtime::Authority::new(&ca, &cert);
        let (client, server, accepted) = connect(Arc::clone(&authority), cert, user).await;
        assert!(accepted);
        // Both signed principals remain valid. Changing current registration
        // must not turn an authenticated person-1 connection into person-2.
        authority.rules.write().await.person = "person-2".into();
        let mut shell = client.channel_open_session().await.unwrap();
        shell.request_shell(true).await.unwrap();
        assert!(!success(&mut shell).await);
        let mut files = client.channel_open_session().await.unwrap();
        files.request_subsystem(true, "sftp").await.unwrap();
        assert!(!success(&mut files).await);
        assert!(authority.opened.lock().unwrap().is_empty());
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
async fn unsigned_method_discovery_advertises_only_implemented_authentication() {
    timeout(Duration::from_secs(10), async {
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
        let guard = authority.rules.write().await;
        let (mut client, server) = transport(Arc::clone(&authority)).await;
        let result = client.authenticate_none("operator").await.unwrap();
        let client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } = result
        else {
            panic!("unsigned discovery authenticated");
        };
        assert!(!partial_success);
        assert_eq!(&*remaining_methods, &[russh::MethodKind::PublicKey]);
        assert!(authority.opened.lock().unwrap().is_empty());
        drop(guard);
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
