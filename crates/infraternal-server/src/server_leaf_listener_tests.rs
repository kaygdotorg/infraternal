//! Real QUIC and TCP/TLS listeners serving a rotated server leaf, and an older copied leaf refused by an infraternal agent's floor (#559).
use super::*;
use infraternal_agent::server_leaf_floor::ServerLeafFloor;

/// The server leaf a TCP/TLS dial to `address` is shown.
async fn tcp_leaf(address: SocketAddr, node: &Identity, root: &X509) -> X509 {
    let config = remote_tls::client_config(node, std::slice::from_ref(root)).unwrap();
    remote_tls::dial(address, "localhost", &config)
        .await
        .unwrap()
        .peer_leaf
        .unwrap()
}

/// A QUIC connection to `address` and the server leaf it was shown.
async fn quic_leaf(
    address: SocketAddr,
    node: &Identity,
    root: &X509,
) -> (quinn::Endpoint, quinn::Connection, X509) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(node, std::slice::from_ref(root)).unwrap(),
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let leaf = remote_quic::peer_leaf(&connection).unwrap();
    (endpoint, connection, leaf)
}

/// The DER bytes of `certificate`, for exact comparisons.
fn der(certificate: &X509) -> Vec<u8> {
    certificate.to_der().unwrap()
}

/// Unix seconds now.
fn now() -> i64 {
    crate::runtime::unix_seconds().unwrap()
}

/// After a rotation every new QUIC and TCP/TLS handshake gets the new leaf,
/// while a connection made before it is left alone.
#[tokio::test]
async fn rotated_leaf_reaches_new_quic_and_tcp_handshakes_only() {
    let (_, node, root, material) = identities();
    let old = crate::server_leaf::issue(&material, "localhost", None, now() - 3 * 86_400).unwrap();
    let new =
        crate::server_leaf::issue(&material, "localhost", Some(&old.certificate), now()).unwrap();
    let (store, _pool, _, _) = super::revocation::admitted_store(&node, &root).await;
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &old,
        std::slice::from_ref(&root),
        store,
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let address = listeners.local_addr().unwrap();
    assert_eq!(
        der(&tcp_leaf(address, &node, &root).await),
        der(&old.certificate)
    );
    let (_before_endpoint, before, leaf) = quic_leaf(address, &node, &root).await;
    assert_eq!(der(&leaf), der(&old.certificate));

    listeners.install_server_leaf(&new).unwrap();
    assert_eq!(
        der(&tcp_leaf(address, &node, &root).await),
        der(&new.certificate)
    );
    let (_after_endpoint, _after, leaf) = quic_leaf(address, &node, &root).await;
    assert_eq!(der(&leaf), der(&new.certificate));
    assert!(
        before.close_reason().is_none(),
        "rotation must not close an established connection"
    );
}

/// The #559 attack: a copy of the server's state directory taken before a
/// rotation serves the old, still unexpired, CA-signed leaf from elsewhere.
/// An infraternal agent with no history accepts it (the residual window up to
/// the first rotation it sees); once it has seen the successor it refuses the
/// copy, on QUIC and TCP/TLS alike.
#[tokio::test]
async fn copied_older_leaf_is_refused_once_the_agent_has_seen_its_successor() {
    let (_, node, root, material) = identities();
    let old = crate::server_leaf::issue(&material, "localhost", None, now() - 3 * 86_400).unwrap();
    let new =
        crate::server_leaf::issue(&material, "localhost", Some(&old.certificate), now()).unwrap();
    let (store, _pool, _, _) = super::revocation::admitted_store(&node, &root).await;
    let server = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &new,
        std::slice::from_ref(&root),
        store.clone(),
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let impostor = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &old,
        std::slice::from_ref(&root),
        store,
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let impostor_address = impostor.local_addr().unwrap();

    let floor = ServerLeafFloor::default();
    floor
        .admit(&der(&tcp_leaf(impostor_address, &node, &root).await))
        .expect("chain and name checks alone accept the copied leaf");
    floor
        .admit(&der(
            &tcp_leaf(server.local_addr().unwrap(), &node, &root).await
        ))
        .unwrap();
    let refused = floor
        .admit(&der(&tcp_leaf(impostor_address, &node, &root).await))
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    let (_endpoint, connection, _) = quic_leaf(impostor_address, &node, &root).await;
    assert!(floor.admit_quic(&connection).is_err());
}
