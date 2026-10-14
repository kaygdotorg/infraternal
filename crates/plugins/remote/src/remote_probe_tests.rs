//! Proves queued probes do not expire before the endpoint can emit their encrypted datagrams [215,263], #201.
use super::*;
use crate::{
    remote_path_socket::PathSocket,
    remote_tls::tests::{leaf, root},
};
use quinn::{
    AsyncUdpSocket, Runtime as _, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::IoSliceMut,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};

#[derive(Debug)]
struct HeldSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    until: Arc<Mutex<tokio::time::Instant>>,
}
#[derive(Debug)]
struct HeldPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    until: Arc<Mutex<tokio::time::Instant>>,
    delay: Pin<Box<tokio::time::Sleep>>,
}
impl UdpPoller for HeldPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let until = *self.until.lock().unwrap();
        self.delay.as_mut().reset(until);
        if std::future::Future::poll(self.delay.as_mut(), cx).is_pending() {
            return Poll::Pending;
        }
        self.inner.as_mut().poll_writable(cx)
    }
}
impl AsyncUdpSocket for HeldSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HeldPoller {
            inner: self.inner.clone().create_io_poller(),
            until: self.until.clone(),
            delay: Box::pin(tokio::time::sleep(Duration::ZERO)),
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if tokio::time::Instant::now() < *self.until.lock().unwrap() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

#[tokio::test]
async fn a_queued_probe_cannot_expire_before_the_socket_emits_it() {
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let physical = server.local_addr().unwrap();
    let logical = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), physical.port());
    let until = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let socket = Arc::new(HeldSocket {
        inner: quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap(),
        until: until.clone(),
    });
    let path = PathSocket::new(socket, logical);
    path.use_mesh(physical);
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(client_config(&leaf(&ca, false), &[ca.certificate]).unwrap());
    let (dial, accept) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
        server.accept().await.unwrap().await
    });
    let dial = dial.unwrap();
    let accept = accept.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    *until.lock().unwrap() = tokio::time::Instant::now() + Duration::from_millis(200);
    let result = tokio::time::timeout(
        Duration::from_millis(400),
        path_interrupted(
            &dial,
            &path,
            Duration::from_millis(100),
            Duration::from_millis(50),
        ),
    )
    .await;
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    drop(accept);
    assert!(
        result.is_err(),
        "a healthy path was declared dead while its probe was queued: {result:?}"
    );
}

#[tokio::test]
async fn enrolled_copy_replies_cannot_keep_a_dead_mesh_path_alive() {
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let logical = server.local_addr().unwrap();
    let socket = quinn::TokioRuntime
        .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let path = PathSocket::new(socket, logical);
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(client_config(&leaf(&ca, false), &[ca.certificate]).unwrap());
    let (dial, accept) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
        server.accept().await.unwrap().await
    });
    let dial = dial.unwrap();
    let accept = accept.unwrap();
    // This bound socket absorbs mesh packets but never answers. The retained
    // enrolled server still authenticates and acknowledges encrypted copies.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let before = authenticated_frames(&dial);
    path.use_mesh(blackhole.local_addr().unwrap());
    path.set_backup(true);
    client.rebind_abstract(path.alias()).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        path_interrupted(
            &dial,
            &path,
            Duration::from_millis(20),
            Duration::from_millis(300),
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut),
        "enrolled copies masked the dead mesh path: {result:?}"
    );
    assert_eq!(path.mesh_datagrams(), 0);
    assert_ne!(
        before,
        authenticated_frames(&dial),
        "the enrolled path must have authenticated replies"
    );
    assert!(
        dial.close_reason().is_none(),
        "detection must keep the connection"
    );
    drop(accept);
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
}

/// Test-only causal reordering: every held mesh packet is released only after
/// its identical ciphertext has crossed the enrolled receive boundary. Nothing
/// is forged, discarded, or promoted into authenticated routing authority.
#[derive(Debug, Default)]
struct CopyFirstState {
    armed: bool,
    enrolled: std::collections::HashSet<Vec<u8>>,
    held: Option<(RecvMeta, Vec<u8>)>,
    reader: Option<std::task::Waker>,
    delivered: usize,
}

#[derive(Debug, Default)]
struct CopyFirstGate {
    state: Mutex<CopyFirstState>,
}

#[derive(Clone, Copy, Debug)]
enum CopyFirstRole {
    Client,
    Enrolled,
    Mesh,
}

#[derive(Debug)]
struct CopyFirstSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<CopyFirstGate>,
    role: CopyFirstRole,
}
impl AsyncUdpSocket for CopyFirstSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if matches!(self.role, CopyFirstRole::Client) {
            // Model one enrolled host and one mesh source at the same UDP port.
            let source =
                if transmit.destination.ip() == "127.0.0.1".parse::<std::net::IpAddr>().unwrap() {
                    "127.0.0.3"
                } else {
                    "127.0.0.4"
                };
            return self.inner.try_send(&Transmit {
                src_ip: Some(source.parse().unwrap()),
                ..*transmit
            });
        }
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if !matches!(self.role, CopyFirstRole::Mesh) {
            let result = self.inner.poll_recv(cx, bufs, meta);
            if matches!(self.role, CopyFirstRole::Enrolled)
                && let Poll::Ready(Ok(count)) = &result
            {
                let mut state = self.gate.state.lock().unwrap();
                for (buf, packet) in bufs.iter().zip(meta.iter()).take(*count) {
                    for datagram in buf[..packet.len].chunks(packet.stride.max(1)) {
                        state.enrolled.insert(datagram.to_vec());
                    }
                }
                if let Some(reader) = state.reader.take() {
                    reader.wake();
                }
            }
            return result;
        }
        let mut state = self.gate.state.lock().unwrap();
        if !state.armed {
            drop(state);
            return self.inner.poll_recv(cx, bufs, meta);
        }
        if state.held.is_none() {
            // One held receive is sufficient: later mesh traffic remains in its
            // real socket until this packet's enrolled twin crosses the gate.
            match self.inner.poll_recv(cx, &mut bufs[..1], &mut meta[..1]) {
                Poll::Ready(Ok(1)) => {
                    state.held = Some((meta[0], bufs[0][..meta[0].len].to_vec()));
                }
                other => return other,
            }
        }
        let ready = state.held.as_ref().is_some_and(|(packet, bytes)| {
            bytes
                .chunks(packet.stride.max(1))
                .all(|datagram| state.enrolled.contains(datagram))
        });
        if !ready {
            state.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let (packet, bytes) = state.held.take().unwrap();
        bufs[0][..bytes.len()].copy_from_slice(&bytes);
        meta[0] = packet;
        state.delivered += 1;
        drop(state);
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

/// An enrolled backup winning the receive race must not strand the healthy
/// mesh guard when the identical real mesh original subsequently arrives.
/// Eight authenticated application exchanges are causal completion barriers;
/// the outer timeout only diagnoses a stuck fixture, never a healthy result.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn copy_first_real_mesh_originals_do_not_strand_the_authenticated_mesh_guard() {
    use crate::remote_bindings::Bindings;
    let ca = root();
    let gate = Arc::new(CopyFirstGate::default());
    let wrap = |address: &str, role| {
        Arc::new(CopyFirstSocket {
            inner: quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind(address).unwrap())
                .unwrap(),
            gate: gate.clone(),
            role,
        }) as Arc<dyn AsyncUdpSocket>
    };
    let primary = wrap("127.0.0.1:0", CopyFirstRole::Enrolled);
    let logical = primary.local_addr().unwrap();
    let mesh = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), logical.port());
    let bindings = Bindings::new(primary);
    let lease = bindings
        .lease(wrap(&mesh.to_string(), CopyFirstRole::Mesh))
        .unwrap();
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap()),
        bindings.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let client_socket = wrap("0.0.0.0:0", CopyFirstRole::Client);
    let port = client_socket.local_addr().unwrap().port();
    let path = PathSocket::new(client_socket, logical);
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(client_config(&leaf(&ca, false), &[ca.certificate]).unwrap());
    let (dial, accepted) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
        server.accept().await.unwrap().await
    });
    let dial = dial.unwrap();
    let accepted = accepted.unwrap();
    // Install trusted tuple aliases only after mutual TLS completes.
    let peer = bindings
        .route_peer(
            std::net::SocketAddr::new("127.0.0.3".parse().unwrap(), port),
            std::net::SocketAddr::new("127.0.0.4".parse().unwrap(), port),
        )
        .unwrap();
    peer.set_backup(true);
    path.use_mesh(mesh);
    path.set_backup(true);
    dial.send_datagram(bytes::Bytes::from_static(b"initial-mesh-proof"))
        .unwrap();
    assert_eq!(
        &accepted.read_datagram().await.unwrap()[..],
        b"initial-mesh-proof"
    );
    accepted
        .send_datagram(bytes::Bytes::from_static(b"initial-mesh-answer"))
        .unwrap();
    assert_eq!(
        &dial.read_datagram().await.unwrap()[..],
        b"initial-mesh-answer"
    );
    assert!(path.mesh_datagrams() > 0);
    gate.state.lock().unwrap().armed = true;
    let authenticated_before = authenticated_frames(&dial);
    let (mut client_send, mut client_receive) = dial.open_bi().await.unwrap();
    let exchanges = async {
        // Reliable stream bytes are completion barriers; the intentionally
        // small, unreliable DATAGRAM receive queue belongs to watchdog probes.
        client_send.write_all(&[1]).await.unwrap();
        let (mut server_send, mut server_receive) = accepted.accept_bi().await.unwrap();
        for value in 1_u8..=8 {
            if value != 1 {
                client_send.write_all(&[value]).await.unwrap();
            }
            let mut request = [0; 1];
            server_receive.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [value]);
            server_send.write_all(&[value, value]).await.unwrap();
            let mut reply = [0; 2];
            client_receive.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [value, value]);
        }
    };
    // Production backed-path constants: do not extend its detection budget.
    let guard = path_interrupted(
        &dial,
        &path,
        Duration::from_millis(15),
        Duration::from_millis(30),
    );
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            biased;
            result = guard => Some(result),
            () = exchanges => None,
        }
    })
    .await;
    if outcome.is_err() {
        let state = gate.state.lock().unwrap();
        eprintln!(
            "copy_first_stuck enrolled_fingerprints={} mesh_delivered={} held_bytes={:?} retained={:?} client_tx={:?} server_tx={:?}",
            state.enrolled.len(),
            state.delivered,
            state.held.as_ref().map(|(_, bytes)| bytes.len()),
            bindings.retained_history().unwrap(),
            dial.stats().frame_tx,
            accepted.stats().frame_tx
        );
    }
    let outcome = outcome.expect("causal application exchanges or the guard must complete");
    // Require delivery before the guard/exchange race ended. Waiting for a
    // later release here could disguise an artificially unavailable mesh.
    assert!(gate.state.lock().unwrap().delivered > 0);
    assert_ne!(authenticated_before, authenticated_frames(&dial));
    assert!(dial.close_reason().is_none());
    assert!(accepted.close_reason().is_none());
    if outcome.is_some() {
        let state = gate.state.lock().unwrap();
        eprintln!(
            "copy_first_diagnostic enrolled_fingerprints={} mesh_delivered={} held_bytes={:?} retained={:?} client_tx={:?} server_tx={:?}",
            state.enrolled.len(),
            state.delivered,
            state.held.as_ref().map(|(_, bytes)| bytes.len()),
            bindings.retained_history().unwrap(),
            dial.stats().frame_tx,
            accepted.stats().frame_tx
        );
    }
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    drop((peer, lease));
    assert!(
        outcome.is_none(),
        "copy-first delivery stranded a live authenticated mesh path: {outcome:?}"
    );
}
