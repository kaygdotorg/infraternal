//! Forged QUIC Initials against the host-link listener, and what a real host
//! pays to reconnect while they arrive (#572 finding 2).
//!
//! An off-path attacker can send Initials with any source address but never
//! sees the replies. The tests model that with relays: each relay forwards one
//! real client's datagrams to the listener from its own address and drops every
//! reply, so the listener sees a well-formed Initial from a peer that never
//! answers, not even a Retry.
use super::*;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{net::UdpSocket, task::JoinSet};

/// Forwards client datagrams to `server` from `source` and never answers.
/// Returns the address clients should dial.
async fn black_hole_relay(
    tasks: &mut JoinSet<()>,
    source: IpAddr,
    server: SocketAddr,
    forwarded: Arc<AtomicUsize>,
) -> SocketAddr {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = UdpSocket::bind(SocketAddr::new(source, 0)).await.unwrap();
    let address = front.local_addr().unwrap();
    tasks.spawn(async move {
        let mut buffer = vec![0; 65_536];
        let mut first = true;
        while let Ok((length, _)) = front.recv_from(&mut buffer).await {
            if back.send_to(&buffer[..length], server).await.is_err() {
                return;
            }
            if std::mem::take(&mut first) {
                forwarded.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    address
}

/// Forwards both directions between one client and `server` from `source`,
/// delaying each datagram by `delay` (half the round trip it adds).
async fn delay_relay(
    tasks: &mut JoinSet<()>,
    source: IpAddr,
    server: SocketAddr,
    delay: Duration,
) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind(SocketAddr::new(source, 0)).await.unwrap());
    let address = front.local_addr().unwrap();
    let client = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
    let (to_server, from_server) = (front.clone(), back.clone());
    let seen = client.clone();
    tasks.spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((length, peer)) = to_server.recv_from(&mut buffer).await {
            *seen.lock().unwrap() = Some(peer);
            let datagram = buffer[..length].to_vec();
            let back = back.clone();
            tokio::spawn(async move {
                // sleep: the relay's whole purpose is a fixed one-way delay.
                tokio::time::sleep(delay).await;
                let _ = back.send_to(&datagram, server).await;
            });
        }
    });
    tasks.spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((length, _)) = from_server.recv_from(&mut buffer).await {
            let Some(peer) = *client.lock().unwrap() else {
                continue;
            };
            let datagram = buffer[..length].to_vec();
            let front = front.clone();
            tokio::spawn(async move {
                // sleep: the relay's whole purpose is a fixed one-way delay.
                tokio::time::sleep(delay).await;
                let _ = front.send_to(&datagram, peer).await;
            });
        }
    });
    address
}

/// The listener under test, an enrolled host's identity and trust root, and
/// the listener's admission limits.
async fn listener() -> (
    RemoteListeners,
    Identity,
    X509,
    Arc<crate::remote_accept::Limits>,
) {
    let (server, node, root, _) = identities();
    let (store, _pool, _host, _) = super::revocation::admitted_store(&node, &root).await;
    let limits = crate::remote_accept::Limits::new();
    let (listeners, _) = RemoteListeners::start_with_limits(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        RemoteHosts::default(),
        limits.clone(),
        None,
    )
    .await
    .unwrap();
    (listeners, node, root, limits)
}

/// Start 48 forged handshakes, four from each of 12 addresses, and wait until
/// the listener has seen all of them. The returned values must stay alive.
async fn forge_initials(
    server: SocketAddr,
    node: &Identity,
    root: &X509,
    limits: &crate::remote_accept::Limits,
) -> (JoinSet<()>, Vec<quinn::Endpoint>) {
    let mut tasks = JoinSet::new();
    let mut endpoints = Vec::new();
    let forwarded = Arc::new(AtomicUsize::new(0));
    for index in 0..48_u8 {
        let source = IpAddr::from([127, 0, 1, 10 + index / 4]);
        let relay = black_hole_relay(&mut tasks, source, server, forwarded.clone()).await;
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(
            remote_quic::client_config(node, std::slice::from_ref(root)).unwrap(),
        );
        let connecting = endpoint.connect(relay, "localhost").unwrap();
        tasks.spawn(async move {
            let _ = connecting.await;
        });
        endpoints.push(endpoint);
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while forwarded.load(Ordering::SeqCst) < 48 || limits.anonymous_in_use() < 24 {
            // sleep: polls relay counters the listener's accept loop cannot signal.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("forged Initials reached the listener");
    // sleep: the accept loop may still be draining Initials already received.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (tasks, endpoints)
}

/// Time a real host's QUIC handshake to `server` (here, a relay in front of it).
async fn host_handshake(
    server: SocketAddr,
    node: &Identity,
    root: &X509,
) -> Result<(Duration, quinn::Connection), String> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(node, std::slice::from_ref(root)).unwrap(),
    );
    let started = std::time::Instant::now();
    let connection = tokio::time::timeout(
        Duration::from_secs(4),
        endpoint.connect(server, "localhost").unwrap(),
    )
    .await
    .map_err(|_| "handshake timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    Ok((started.elapsed(), connection))
}

/// 48 forged Initials no longer take every anonymous lane: past half, new
/// unvalidated Initials get a Retry, which the forgers never answer, and a
/// real host completes its handshake through the free half. Before the fix
/// the forgers held all 48 lanes and the host was refused.
#[tokio::test]
async fn forged_initials_leave_lanes_for_a_real_host() {
    let (listeners, node, root, limits) = listener().await;
    let server = listeners.local_addr().unwrap();
    let forged = forge_initials(server, &node, &root, &limits).await;
    let held = limits.anonymous_in_use();
    assert!(
        held <= 25,
        "unvalidated Initials took {held} of 48 lanes under pressure"
    );
    let mut relays = JoinSet::new();
    let host = delay_relay(
        &mut relays,
        IpAddr::from([127, 0, 2, 1]),
        server,
        Duration::ZERO,
    )
    .await;
    let (elapsed, connection) = host_handshake(host, &node, &root)
        .await
        .expect("a real host must still connect while Initials are forged");
    eprintln!("host handshake under forged Initials: {elapsed:?}");
    drop((connection, forged, relays, listeners));
}

/// Reconnect latency for a real host over a 50 ms round trip: on an idle
/// listener, and while 48 forged Initials arrive. Prints METRIC lines; the
/// expected difference is one round trip, and only under pressure.
#[tokio::test]
#[ignore = "latency diagnostic for #572; run explicitly"]
async fn host_reconnect_latency_with_and_without_forged_initials() {
    const SAMPLES: usize = 15;
    let one_way = Duration::from_millis(25);
    let (listeners, node, root, limits) = listener().await;
    let server = listeners.local_addr().unwrap();
    let mut relays = JoinSet::new();
    let mut idle = Vec::new();
    for index in 0..SAMPLES {
        let source = IpAddr::from([127, 0, 2, u8::try_from(index + 1).unwrap()]);
        let host = delay_relay(&mut relays, source, server, one_way).await;
        let (elapsed, connection) = host_handshake(host, &node, &root).await.unwrap();
        idle.push(elapsed);
        connection.close(0u32.into(), b"");
    }
    let forged = forge_initials(server, &node, &root, &limits).await;
    let mut pressured = Vec::new();
    let mut refused = 0;
    for index in 0..SAMPLES {
        let source = IpAddr::from([127, 0, 3, u8::try_from(index + 1).unwrap()]);
        let host = delay_relay(&mut relays, source, server, one_way).await;
        match host_handshake(host, &node, &root).await {
            Ok((elapsed, connection)) => {
                pressured.push(elapsed);
                connection.close(0u32.into(), b"");
            }
            Err(_) => refused += 1,
        }
    }
    let median = |samples: &mut Vec<Duration>| {
        samples.sort();
        samples.get(samples.len() / 2).copied()
    };
    println!(
        "METRIC name=host_quic_handshake_idle rtt_ms=50 samples={SAMPLES} median={:?} max={:?}",
        median(&mut idle),
        idle.last()
    );
    println!(
        "METRIC name=host_quic_handshake_forged rtt_ms=50 samples={SAMPLES} connected={} refused={refused} median={:?} max={:?}",
        pressured.len(),
        median(&mut pressured),
        pressured.last()
    );
    drop((forged, relays, listeners));
}
