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
    proof_attempts: Option<Arc<Mutex<Vec<tokio::time::Instant>>>>,
    pass_proofs: bool,
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
        if let Some(proofs) = &self.proof_attempts
            && crate::remote_path_proof::path_probe_header(transmit.contents).is_some()
        {
            proofs.lock().unwrap().push(tokio::time::Instant::now());
            if !self.pass_proofs {
                return Ok(());
            }
        }
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
    let bindings = crate::remote_bindings::Bindings::new(
        quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap(),
    );
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap()),
        bindings.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let physical = server.local_addr().unwrap();
    let logical = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), physical.port());
    let until = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let socket = Arc::new(HeldSocket {
        proof_attempts: None,
        pass_proofs: false,
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
    let _proof = bindings.connection_proof(&accept).unwrap();
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

/// Losing a request must leave repeated recovery attempts inside the reserved
/// response margin, even when adaptive ordinary polling becomes much slower.
/// Virtual time checks scheduling decisions; this is no latency measurement.
#[tokio::test]
async fn lost_path_proof_spends_its_reserved_retry_margin() {
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let logical = server.local_addr().unwrap();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let path = PathSocket::new(
        Arc::new(HeldSocket {
            inner: quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            until: Arc::new(Mutex::new(tokio::time::Instant::now())),
            proof_attempts: Some(proofs.clone()),
            pass_proofs: false,
        }),
        logical,
    );
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
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    path.use_mesh(blackhole.local_addr().unwrap());
    let margin = Duration::from_millis(30);
    let allowance = path.proof_allowance(dial.rtt(), margin);
    tokio::time::pause();
    let guard = path_interrupted(&dial, &path, Duration::from_millis(15), margin);
    tokio::pin!(guard);
    // Poll the real guard while only its logical timer advances. Every physical
    // challenge is deliberately lost, so neither QUIC nor a backup can answer.
    let result = loop {
        tokio::select! {
            result = &mut guard => break result,
            () = tokio::time::sleep(Duration::from_millis(1)) => {},
        }
    };
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let attempts = proofs.lock().unwrap();
    let first = attempts[0];
    let retries = attempts
        .iter()
        .filter(|at| {
            let age = at.duration_since(first);
            age >= allowance.saturating_sub(margin) && age < allowance
        })
        .count();
    assert!(
        retries >= 3,
        "ordinary polling skipped the retry margin: {attempts:?}"
    );
    drop(attempts);
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    drop(accepted);
}

/// Real authenticated responses must not turn a healthy path's measured RTT
/// into its polling period. Virtual time checks scheduling, not network latency.
#[tokio::test]
async fn healthy_path_proofs_keep_the_configured_polling_interval() {
    let ca = root();
    let primary = quinn::TokioRuntime
        .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let logical = primary.local_addr().unwrap();
    let bindings = crate::remote_bindings::Bindings::new(primary);
    let physical = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), logical.port());
    let _binding = bindings
        .lease(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind(physical).unwrap())
                .unwrap(),
        )
        .unwrap();
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap()),
        bindings.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let path = PathSocket::new(
        Arc::new(HeldSocket {
            inner: quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            until: Arc::new(Mutex::new(tokio::time::Instant::now())),
            proof_attempts: Some(proofs.clone()),
            pass_proofs: true,
        }),
        logical,
    );
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
    let _proof = bindings.connection_proof(&accepted).unwrap();
    path.use_mesh(physical);
    tokio::time::pause();
    let guard = tokio::spawn({
        let dial = dial.clone();
        let path = path.clone();
        async move {
            path_interrupted(
                &dial,
                &path,
                Duration::from_millis(15),
                Duration::from_millis(30),
            )
            .await
        }
    });
    // Include the first conservative response window, then observe repeated
    // healthy challenges after this tuple has supplied its own RTT samples.
    for _ in 0..400 {
        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }
    assert!(!guard.is_finished(), "healthy authenticated path exited");
    guard.abort();
    assert!(guard.await.unwrap_err().is_cancelled());
    let count = proofs.lock().unwrap().len();
    assert!(
        count <= 28,
        "healthy proofs bypassed the 15 ms polling interval: {count}"
    );
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
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

/// Invalid packets at the selected tuple must not borrow authenticated progress
/// from the enrolled backup to satisfy a mesh-path proof (#201, D215).
#[tokio::test]
#[ignore = "Perf VM only: real socket scheduling and path-response deadline."]
async fn review_invalid_mesh_packets_cannot_borrow_enrolled_authentication() {
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
    let invalid = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    path.use_mesh(invalid.local_addr().unwrap());
    path.set_backup(true);
    let reflected = tokio::spawn(async move {
        let mut packet = vec![0; 65536];
        loop {
            let (_, source) = invalid.recv_from(&mut packet).await.unwrap();
            // These bytes are never a valid encrypted QUIC response. Do not
            // echo ciphertext: that would obscure which path authenticates.
            invalid.send_to(&[0; 32], source).await.unwrap();
        }
    });
    // Authentication is deliberately independent of the path guard's probe
    // implementation: the enrolled peer continues emitting valid traffic.
    let enrolled = accept.clone();
    let enrolled_progress = tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_millis(20));
        loop {
            ticks.tick().await;
            enrolled
                .send_datagram(bytes::Bytes::from_static(&[1]))
                .unwrap();
        }
    });
    let before = authenticated_frames(&dial);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        path_interrupted(
            &dial,
            &path,
            Duration::from_millis(20),
            Duration::from_millis(300),
        ),
    )
    .await;
    enrolled_progress.abort();
    let _ = enrolled_progress.await;
    reflected.abort();
    let _ = reflected.await;
    assert!(
        path.mesh_datagrams() > 0,
        "invalid-path control did not deliver UDP"
    );
    assert_ne!(
        before,
        authenticated_frames(&dial),
        "enrolled backup did not authenticate"
    );
    assert!(dial.close_reason().is_none() && accept.close_reason().is_none());
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    assert!(
        matches!(result, Ok(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut),
        "invalid mesh packets combined with enrolled authentication satisfied the path guard: {result:?}"
    );
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
            // The gate orders identical QUIC ciphertext; an independent path
            // challenge has no enrolled twin and must retain ordinary delivery.
            bytes.starts_with(b"\x80ip1")
                || bytes
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
        if !bytes.starts_with(b"\x80ip1") {
            state.delivered += 1;
        }
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
async fn copy_first_real_mesh_originals_do_not_strand_the_authenticated_mesh_guard() {
    copy_first_guard(false, None).await;
}

/// Retained legacy emission control: progress comes from QUIC acknowledgements
/// and encrypted copies. Production physical health uses session-bound replies.
#[tokio::test]
#[ignore = "Physical 15ms/30ms guard comparison on the perf VM under its benchmark lock."]
async fn copy_first_ack_only_probes_keep_authenticated_mesh_guard_live() {
    copy_first_guard(true, None).await;
}

/// Compare only the requested delayed-ACK bound on the pinned perf VM. The
/// default regression remains separate; this prototype selects no policy.
#[tokio::test]
#[ignore = "ACK-delay hypothesis comparison on the quiet perf VM under its benchmark lock."]
async fn copy_first_ack_only_requested_ack_delay_five_ms_comparison() {
    copy_first_guard(true, Some(Duration::from_millis(5))).await;
}

async fn copy_first_guard(ack_only: bool, requested_ack_delay: Option<Duration>) {
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
    let mut config = client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
    if let Some(delay) = requested_ack_delay {
        // Reuse every existing client transport setting. Only this test asks
        // the peer to shorten delayed ACKs; the guard still uses 15ms/30ms.
        let mut transport = transport_with_liveness(
            u32::try_from(infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS).unwrap(),
            Duration::from_secs(15),
            Duration::from_secs(60),
            true,
        );
        let mut frequency = quinn::AckFrequencyConfig::default();
        frequency.max_ack_delay(Some(delay));
        // With the extension absent, pinned quinn-proto acknowledges the first
        // reordered packet. Preserve that behavior rather than the extension's
        // default threshold of two. Ack-eliciting threshold remains one.
        frequency.reordering_threshold(1u32.into());
        Arc::get_mut(&mut transport)
            .unwrap()
            .ack_frequency_config(Some(frequency));
        config.transport_config(transport);
    }
    client.set_default_client_config(config);
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
    let _proof = bindings.connection_proof(&accepted).unwrap();
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
    let exchanges = async {
        if ack_only {
            for _ in 0..8 {
                assert_eq!(&accepted.read_datagram().await.unwrap()[..], &[0]);
            }
            return;
        }
        let (mut client_send, mut client_receive) = dial.open_bi().await.unwrap();
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
    let guard = async {
        if ack_only {
            quic_path_interrupted(
                &dial,
                &path,
                Duration::from_millis(15),
                Duration::from_millis(30),
            )
            .await
        } else {
            path_interrupted(
                &dial,
                &path,
                Duration::from_millis(15),
                Duration::from_millis(30),
            )
            .await
        }
    };
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
    if outcome.is_none() {
        assert_ne!(authenticated_before, authenticated_frames(&dial));
    }
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
    if let Some(delay) = requested_ack_delay {
        let requested = dial.stats().frame_tx.ack_frequency;
        let received = accepted.stats().frame_rx.ack_frequency;
        eprintln!(
            "ack_delay_comparison requested_delay_us={} ack_frequency_sent={requested} ack_frequency_received={received} guard_outcome={outcome:?}",
            delay.as_micros()
        );
        assert!(
            requested > 0 && received > 0,
            "comparison must deliver the negotiated ACK request"
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
