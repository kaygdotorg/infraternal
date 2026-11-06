//! Independently checks healthy-path detection at D170's 1,000-node design point (#201).
//!
//! Run these ignored tests only on the perf VM under its shared lock. The control
//! uses the production keepalive and adaptive detector before path switching;
//! direct and distinct-tuple candidates retain their actual responder topology.
use super::*;
use crate::remote_tls::tests::{leaf, root};
use quinn::{AsyncUdpSocket, Runtime as _};
use std::{future::Future, net::SocketAddr, time::Duration};

const NODES: usize = 1000;

// Keep admission, retained guard failures and cleanup in one lifecycle.
async fn healthy_cohort<P, F, Fut>(
    label: &str,
    fast: bool,
    aliased: bool,
    wrap: impl Fn(std::net::UdpSocket, SocketAddr, SocketAddr) -> (Arc<dyn AsyncUdpSocket>, P),
    watch: F,
) where
    P: Send + 'static,
    F: Fn(quinn::Connection, P) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let load_before = std::fs::read_to_string("/proc/loadavg").unwrap();
    let ca = root();
    let config = server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap();
    let (server, bindings, _lease) = if aliased {
        let primary = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let address = primary.local_addr().unwrap();
        let bindings = crate::remote_bindings::Bindings::new(primary);
        let mesh = SocketAddr::new("127.0.0.2".parse().unwrap(), address.port());
        let lease = bindings
            .lease(
                quinn::TokioRuntime
                    .wrap_udp_socket(std::net::UdpSocket::bind(mesh).unwrap())
                    .unwrap(),
            )
            .unwrap();
        let server = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            bindings.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        (server, Some(bindings), Some(lease))
    } else {
        // Preserve the independent review's original bare server endpoint.
        (
            quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap(),
            None,
            None,
        )
    };
    let address = server.local_addr().unwrap();
    let mesh = SocketAddr::new("127.0.0.2".parse().unwrap(), address.port());
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
                    let connection = result.unwrap().unwrap();
                    let route = aliased.then(|| bindings.as_ref().unwrap().connection_proof(&connection).unwrap());
                    accepted.push((connection, route));
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
        let (socket, state) = wrap(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            address,
            if aliased { mesh } else { address },
        );
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
        "profile":label,"distinct_mesh_tuple":aliased,"nodes":NODES,"live":live,"guard_exits":failures.len(),
        "failures":failures,"load_before":load_before.trim(),
        "load_after":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        "scope":"loopback mTLS pairs, not daemons; four runtime workers; direct or explicitly reported distinct-tuple path; 31x250ms windows",
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
        false,
        |socket, _, _| (quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(), ()),
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
        "single_tuple_adaptive_100ms",
        true,
        false,
        |socket, address, physical| {
            let path = crate::remote_path_socket::PathSocket::from_udp(
                socket,
                address,
                &quinn::TokioRuntime,
            )
            .unwrap();
            path.use_mesh(physical);
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

/// Keep the original direct control and independently qualify authenticated
/// physical replies; changing the direct control cannot substitute for this gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Perf VM only: distinct physical tuple health at 1000 mTLS connections."]
async fn authenticated_mesh_health_at_design_scale() {
    healthy_cohort(
        "authenticated_distinct_tuple",
        true,
        true,
        |socket, address, physical| {
            let path = crate::remote_path_socket::PathSocket::from_udp(
                socket,
                address,
                &quinn::TokioRuntime,
            )
            .unwrap();
            path.use_mesh(physical);
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

/// Compare cadence without replacing the ordinary production interval. This is
/// a measured candidate, not a waiver for the retained 15ms control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Perf VM only: authenticated physical health at 100ms cadence."]
async fn authenticated_mesh_health_at_design_scale_100ms() {
    healthy_cohort(
        "authenticated_distinct_tuple_100ms",
        true,
        true,
        |socket, address, physical| {
            let path = crate::remote_path_socket::PathSocket::from_udp(
                socket,
                address,
                &quinn::TokioRuntime,
            )
            .unwrap();
            path.use_mesh(physical);
            (path.clone() as Arc<dyn AsyncUdpSocket>, path)
        },
        |connection, path| async move {
            path_interrupted(
                &connection,
                &path,
                Duration::from_millis(100),
                Duration::from_millis(30),
            )
            .await
        },
    )
    .await;
}
