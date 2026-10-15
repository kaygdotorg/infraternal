//! Independently checks healthy-path detection at D170's 1,000-node design point (#201).
//!
//! Run these ignored tests only on the perf VM under its shared lock. The control
//! uses the production keepalive and adaptive detector before path switching;
//! the candidate uses the fast detector without server alias bookkeeping.
use super::*;
use crate::remote_tls::tests::{leaf, root};
use quinn::{AsyncUdpSocket, Runtime as _};
use std::{future::Future, net::SocketAddr, time::Duration};

const NODES: usize = 1000;

// Keep admission, retained guard failures and cleanup in one lifecycle.
#[allow(clippy::too_many_lines)]
async fn healthy_cohort<P, F, Fut>(
    label: &str,
    fast: bool,
    wrap: impl Fn(std::net::UdpSocket, SocketAddr) -> (Arc<dyn AsyncUdpSocket>, P),
    watch: F,
) where
    P: Send + 'static,
    F: Fn(quinn::Connection, P) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let load_before = std::fs::read_to_string("/proc/loadavg").unwrap();
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let listener = server.clone();
    let accepting = tokio::spawn(async move {
        let mut pending = tokio::task::JoinSet::new();
        let mut accepted = Vec::new();
        while accepted.len() < NODES {
            tokio::select! {
                incoming = listener.accept(), if pending.len() < 64 => {
                    pending.spawn(async move { incoming.unwrap().await.unwrap() });
                }
                result = pending.join_next(), if !pending.is_empty() => {
                    accepted.push(result.unwrap().unwrap());
                }
            }
        }
        accepted
    });
    let identity = leaf(&ca, false);
    let config = if fast {
        client_config(&identity, &[ca.certificate]).unwrap()
    } else {
        client_config_with_liveness(
            &identity,
            &[ca.certificate],
            Duration::from_millis(100),
            Duration::from_secs(60),
        )
        .unwrap()
    };
    let mut clients = Vec::new();
    let mut dialing = tokio::task::JoinSet::new();
    let mut watchers = tokio::task::JoinSet::new();
    let mut connections = Vec::new();
    for index in 0..NODES {
        let (socket, state) = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), address);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(config.clone());
        let pending = endpoint.connect(address, "localhost").unwrap();
        clients.push(endpoint);
        dialing.spawn(async move { (index, pending.await.unwrap(), state) });
        if dialing.len() >= 8 {
            let (index, connection, state) = dialing.join_next().await.unwrap().unwrap();
            let guard = watch(connection.clone(), state);
            watchers.spawn(async move { (index, guard.await) });
            connections.push(connection);
        }
    }
    while let Some(result) = dialing.join_next().await {
        let (index, connection, state) = result.unwrap();
        let guard = watch(connection.clone(), state);
        watchers.spawn(async move { (index, guard.await) });
        connections.push(connection);
    }
    let accepted = accepting.await.unwrap();
    // Keep every successful TLS connection and watchdog, including early exits.
    // No failed guard is restarted before or during the 31 observation windows.
    for _ in 0..31 {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut failures = Vec::new();
    while let Some(result) = watchers.try_join_next() {
        let (index, result) = result.unwrap();
        failures.push(serde_json::json!({"node":index,"state":format!("{result:?}")}));
    }
    let live = connections
        .iter()
        .filter(|c| c.close_reason().is_none())
        .count();
    let report = serde_json::json!({
        "profile":label,"nodes":NODES,"live":live,"guard_exits":failures.len(),
        "failures":failures,"load_before":load_before.trim(),
        "load_after":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        "scope":"loopback mTLS pairs, not daemons; four runtime workers; direct path; 31x250ms windows",
    });
    if let Some(output) = std::env::var_os("INFRATERNAL_REVIEW_OUTPUT") {
        std::fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!(
        "review_mesh_health profile={label} nodes={NODES} live={live} guard_exits={}",
        failures.len()
    );
    watchers.abort_all();
    for client in clients {
        client.close(0u32.into(), b"");
    }
    server.close(0u32.into(), b"");
    drop(accepted);
    assert_eq!(live, NODES, "healthy TLS connections closed");
    assert!(
        failures.is_empty(),
        "healthy paths were declared interrupted: {} of {NODES}",
        failures.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Perf VM only: production adaptive detector at 1000 mTLS connections."]
async fn review_production_adaptive_health_at_design_scale() {
    healthy_cohort(
        "production_adaptive_100ms_keepalive",
        false,
        |socket, _| (quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(), ()),
        |connection, ()| async move {
            PeerFreshness::new(&connection)
                .interrupted_adaptive(&connection)
                .await
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Perf VM only: fast detector at 1000 mTLS connections."]
async fn review_fast_mesh_health_at_design_scale() {
    healthy_cohort(
        "fast_mesh_15ms_30ms",
        true,
        |socket, address| {
            let path = crate::remote_path_socket::PathSocket::from_udp(
                socket,
                address,
                &quinn::TokioRuntime,
            )
            .unwrap();
            path.use_mesh(address);
            (path.clone() as Arc<dyn AsyncUdpSocket>, path)
        },
        |connection, path| async move {
            path_interrupted(
                &connection,
                &path,
                Duration::from_millis(15),
                Duration::from_millis(30),
            )
            .await
        },
    )
    .await;
}
