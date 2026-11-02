//! Exercise consumer credit with the real SSH engine and bounded runtime pipes.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_ssh::mesh_flow::{Ingress, RECEIVE_WINDOW};
use russh::{
    Channel, ChannelId, ChannelMsg, client,
    keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::timeout,
};

struct Peer {
    id: ChannelId,
    input: Ingress,
    handle: server::Handle,
    output: infraternal_plugin_ssh::mesh_login::Input,
}
struct Server {
    streams: mpsc::Sender<Peer>,
    input: HashMap<ChannelId, Ingress>,
}
#[allow(clippy::unused_async_trait_impl)]
impl server::Handler for Server {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = channel.id();
        // The callback is the sole data receiver. Keeping an unread engine
        // receiver would block dispatch before it reaches that callback.
        let output = Box::pin(channel.make_writer());
        drop(channel);
        let input = Ingress::default();
        self.input.insert(id, input.clone());
        self.streams
            .try_send(Peer {
                id,
                input,
                handle: session.handle(),
                output,
            })
            .unwrap();
        reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.input[&id]
            .push(data)
            .map_err(|_| russh::Error::Inconsistent)
    }
    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.input[&id].eof().unwrap();
        Ok(())
    }
    async fn exec_request(
        &mut self,
        id: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(id)
    }
}
struct Client(Arc<AtomicUsize>);
#[allow(clippy::unused_async_trait_impl)]
impl client::Handler for Client {
    type Error = russh::Error;
    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
fn key() -> PrivateKey {
    PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .unwrap()
}

#[tokio::test]
async fn slow_consumer_holds_credit_without_blocking_control_and_recovers() {
    timeout(Duration::from_secs(30), async {
        let (streams, mut rx) = mpsc::channel(4);
        let (server_io, client_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            server::run_stream(
                Arc::new(server::Config {
                    keys: vec![key()],
                    window_size: RECEIVE_WINDOW,
                    maximum_packet_size: RECEIVE_WINDOW / 4,
                    manual_receive_window: std::env::var_os("MESH_TEST_AUTOMATIC_CREDIT").is_none(),
                    channel_buffer_size: 1,
                    event_buffer_size: 2,
                    limits: russh::Limits::new(256 * 1024, 256 * 1024, Duration::from_hours(1)),
                    ..Default::default()
                }),
                server_io,
                Server {
                    streams,
                    input: HashMap::new(),
                },
            )
            .await
            .unwrap()
            .await
            .unwrap();
        });
        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            client_io,
            Client(Arc::clone(&exchanges)),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "operator",
                    PrivateKeyWithHashAlg::new(Arc::new(key()), None)
                )
                .await
                .unwrap()
                .success()
        );
        let channel = client.channel_open_session().await.unwrap();
        let Peer {
            id,
            input,
            handle,
            output: _,
        } = rx.recv().await.unwrap();
        let mut writer = channel.make_writer();
        let bytes = vec![42; 8 * 1024 * 1024];
        let expected = bytes.len();
        let sender = tokio::spawn(async move {
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        // A second request is an ordering barrier: callback processing stays
        // available while the first channel's consumer has not started.
        let mut control = client.channel_open_session().await.unwrap();
        let _ = rx.recv().await.unwrap();
        control.exec(true, b"control".to_vec()).await.unwrap();
        loop {
            if matches!(control.wait().await, Some(ChannelMsg::Success)) {
                break;
            }
        }
        assert!(!sender.is_finished());
        // Feed into a deliberately small runtime pipe, then drain it. Successful
        // completion proves a slow consumer pauses rather than disconnects.
        let (runtime, mut reader) = tokio::io::duplex(1024);
        let pump = tokio::spawn(async move {
            input
                .forward(runtime, |amount| {
                    let handle = handle.clone();
                    async move {
                        handle
                            .consumed(id, amount)
                            .await
                            .map_err(std::io::Error::other)
                    }
                })
                .await
                .unwrap();
        });
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), expected);
        assert!(received.iter().all(|byte| *byte == 42));
        sender.await.unwrap();
        pump.await.unwrap();
        assert!(exchanges.load(Ordering::Relaxed) > 1);
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
async fn byte_bound_includes_tiny_packets_and_eof_is_ordered() {
    let queue = Ingress::default();
    for _ in 0..RECEIVE_WINDOW {
        queue.push(&[7]).unwrap();
    }
    assert!(queue.push(&[8]).is_err());
    queue.eof().unwrap();
    assert!(queue.push(&[8]).is_err());
    let (writer, mut reader) = tokio::io::duplex(1024);
    let credits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&credits);
    let task = tokio::spawn(async move {
        queue
            .forward(writer, |amount| {
                credits.lock().unwrap().push(amount);
                async { Ok(()) }
            })
            .await
            .unwrap();
    });
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    task.await.unwrap();
    assert_eq!(bytes, vec![7; RECEIVE_WINDOW as usize]);
    let credits = observed.lock().unwrap();
    eprintln!(
        "CREDIT accepted={} updates={}",
        credits.iter().sum::<u32>(),
        credits.len()
    );
    assert_eq!(&*credits, &[RECEIVE_WINDOW / 2, RECEIVE_WINDOW / 2]);
}

#[tokio::test]
async fn flood_output_waits_for_a_slow_reader_then_completes() {
    timeout(Duration::from_secs(30), async {
        let (streams, mut peers) = mpsc::channel(4);
        let (server_io, client_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            server::run_stream(
                Arc::new(server::Config {
                    keys: vec![key()],
                    window_size: RECEIVE_WINDOW,
                    maximum_packet_size: RECEIVE_WINDOW / 4,
                    manual_receive_window: true,
                    channel_buffer_size: 1,
                    event_buffer_size: 2,
                    limits: russh::Limits::new(256 * 1024, 256 * 1024, Duration::from_hours(1)),
                    ..Default::default()
                }),
                server_io,
                Server {
                    streams,
                    input: HashMap::new(),
                },
            )
            .await
            .unwrap()
            .await
            .unwrap();
        });
        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut client = client::connect_stream(
            Arc::new(client::Config {
                window_size: RECEIVE_WINDOW,
                channel_buffer_size: 1,
                ..Default::default()
            }),
            client_io,
            Client(Arc::clone(&exchanges)),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "operator",
                    PrivateKeyWithHashAlg::new(Arc::new(key()), None)
                )
                .await
                .unwrap()
                .success()
        );
        let channel = client.channel_open_session().await.unwrap();
        let Peer {
            mut output,
            handle,
            id,
            ..
        } = peers.recv().await.unwrap();
        // Invalid credit cannot enlarge a new channel's advertised window.
        assert!(handle.consumed(id, 1).await.is_err());
        assert!(handle.consumed(id, 0).await.is_err());
        let (progress, started) = tokio::sync::oneshot::channel();
        let flood = tokio::spawn(async move {
            output
                .write_all(&vec![5; RECEIVE_WINDOW as usize])
                .await
                .unwrap();
            progress.send(()).unwrap();
            for _ in 1..128 {
                output
                    .write_all(&vec![5; RECEIVE_WINDOW as usize])
                    .await
                    .unwrap();
            }
            output.shutdown().await.unwrap();
        });
        started.await.unwrap();
        assert!(!flood.is_finished());
        let mut stream = channel.into_stream();
        let mut received = vec![0; 128 * RECEIVE_WINDOW as usize];
        stream.read_exact(&mut received).await.unwrap();
        assert!(received.iter().all(|byte| *byte == 5));
        flood.await.unwrap();
        assert!(exchanges.load(Ordering::Relaxed) > 1);
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
async fn eof_returns_a_short_consumed_credit_remainder() {
    let input = Ingress::default();
    input.push(b"abc").unwrap();
    input.eof().unwrap();
    let mut credits = Vec::new();
    input
        .forward(tokio::io::sink(), |amount| {
            credits.push(amount);
            async { Ok(()) }
        })
        .await
        .unwrap();
    assert_eq!(credits, vec![3]);
}
