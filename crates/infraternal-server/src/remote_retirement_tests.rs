//! Real mTLS regressions and registry-scale diagnostics for retiring revoked host actors without terminating shims [134][167], #78.

use super::*;

#[tokio::test]
async fn revoked_host_releases_its_registry_entry_and_retained_actor() {
    let (store, _pool, host, _fingerprint, listeners, actor, peer, _observed) =
        admitted_tcp().await;
    assert_eq!(listeners.diagnostic_hosts.0.lock().await.len(), 1);
    store.revoke("owner", host, now().unwrap()).await.unwrap();
    let retired = tokio::time::timeout(Duration::from_millis(300), async {
        while !listeners.diagnostic_hosts.0.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    peer.abort();
    assert!(
        retired.is_ok(),
        "revoked host retained its capped registry slot"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            actor.open(crate::embedded::TerminalSize {
                cols: 80,
                rows: 24,
                px_w: 0,
                px_h: 0,
            })
        )
        .await
        .is_ok_and(|result| result.is_err()),
        "a retained browser actor waited indefinitely after host retirement"
    );
}

async fn connect_host(
    address: SocketAddr,
    config: &openssl::ssl::SslConnector,
) -> remote_tls::Connection {
    let connection = remote_tls::dial(address, "localhost", config)
        .await
        .unwrap();
    Transmit::default()
        .send(
            &connection.channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "registry diagnostic",
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        Receive::default()
            .next(&connection.channel)
            .await
            .unwrap()
            .frame,
        Frame::Hello { version: 1, .. }
    ));
    connection
}

#[tokio::test]
async fn old_expiry_cannot_remove_a_fresh_tls_replacement() {
    let (server, host, root, material) = identities();
    let (store, pool, id, predecessor) = admitted_store(&host, &root).await;
    let instant = now().unwrap();
    sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=? WHERE fingerprint=?")
        .bind(instant - 604_798)
        .bind(instant + 2)
        .bind(predecessor.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listeners.local_addr().unwrap();
    let first = connect_host(
        address,
        &remote_tls::client_config(&host, std::slice::from_ref(&root)).unwrap(),
    )
    .await;
    let mut request = X509Req::builder().unwrap();
    request
        .set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    request.set_pubkey(&host.key).unwrap();
    request.sign(&host.key, MessageDigest::null()).unwrap();
    let csr = crate::csr::ValidatedCsr::parse(&request.build().to_der().unwrap()).unwrap();
    let renewed_at = now().unwrap();
    let signed = crate::ca::CertificateAuthority::from_material(material)
        .unwrap()
        .sign_host(id, &csr, renewed_at)
        .unwrap();
    store
        .renew(&predecessor, &signed.record, renewed_at)
        .await
        .unwrap();
    let successor = Identity {
        certificate: X509::from_der(&signed.der).unwrap(),
        key: host.key,
    };
    let second = connect_host(
        address,
        &remote_tls::client_config(&successor, &[root]).unwrap(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        hosts.0.lock().await.len(),
        1,
        "old expiry removed the freshly admitted generation"
    );
    assert!(hosts.actor(id).await.is_some());
    store.revoke("owner", id, now().unwrap()).await.unwrap();
    tokio::time::timeout(Duration::from_millis(300), async {
        while !hosts.0.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fresh generation did not retire on host revocation");
    drop((first, second));
}

async fn enrolled_clients(
    store: &EnrollmentStore,
    pool: &sqlx::SqlitePool,
    host: &Identity,
    material: crate::ca::CaMaterial,
) -> Vec<(Uuid, openssl::ssl::SslConnector)> {
    let instant = now().unwrap();
    let root = material.issuer().clone();
    let authority = crate::ca::CertificateAuthority::from_material(material).unwrap();
    let mut request = X509Req::builder().unwrap();
    request
        .set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    request.set_pubkey(&host.key).unwrap();
    request.sign(&host.key, MessageDigest::null()).unwrap();
    let csr = crate::csr::ValidatedCsr::parse(&request.build().to_der().unwrap()).unwrap();
    let mut clients = Vec::new();
    for index in 1..=1000u128 {
        let id = Uuid::from_u128(index + 100);
        // Public fixture records isolate registry/transport retention from
        // permission/setup cost. Each admitted identity is genuinely signed.
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootless',1002,?)")
            .bind(id.as_bytes().as_slice()).bind(instant).execute(pool).await.unwrap();
        let key_digest = openssl::sha::sha256(&host.key.raw_public_key().unwrap());
        let token = store
            .issue("owner", id, crate::enrollment::Mode::Rootless, instant, &key_digest)
            .await
            .unwrap();
        let signed = authority.sign_host(id, &csr, instant).unwrap();
        store
            .redeem(
                token.secret(),
                id,
                crate::enrollment::Mode::Rootless,
                instant,
                &signed.record,
            )
            .await
            .unwrap();
        let identity = Identity {
            certificate: X509::from_der(&signed.der).unwrap(),
            key: host.key.clone(),
        };
        clients.push((
            id,
            remote_tls::client_config(&identity, std::slice::from_ref(&root)).unwrap(),
        ));
    }
    clients
}

/// Actual TCP/mTLS pairs and server actors at D170's design point. Configured
/// client credentials and server listener/ledger are allocated before baseline;
/// this delta excludes PTYs/shims and is not full-daemon or pinned acceptance.
#[tokio::test]
#[ignore = "1000-host registry diagnostic; optimized, FD limit8192, no own build/browser overlap"]
async fn registry_retention_at_1000_actual_tls_hosts() {
    let (server, host, root, material) = identities();
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let clients = enrolled_clients(&store, &pool, &host, material).await;
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        &[root],
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listeners.local_addr().unwrap();
    let baseline = guard_rss();
    let mut peers = Vec::new();
    let mut timings = Vec::new();
    for (_, config) in &clients {
        let start = std::time::Instant::now();
        peers.push(connect_host(address, config).await);
        timings.push(start.elapsed().as_micros());
    }
    assert_eq!(hosts.0.lock().await.len(), 1000);
    let retained = guard_rss();
    timings.sort_unstable();
    println!(
        "registry_diagnostic actual_hosts=1000 transport=tcp_mtls credentials_preallocated=true baseline_rss_kib={baseline} retained_rss_kib={retained} delta_at1000_kib={} handshake_and_hello_p50_us={} p99_us={} load={} machine={}",
        retained.saturating_sub(baseline),
        timings[499],
        timings[989],
        std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim()
    );
    let start = std::time::Instant::now();
    for (id, _) in &clients {
        store.revoke("owner", *id, now().unwrap()).await.unwrap();
    }
    let retired = tokio::time::timeout(Duration::from_secs(5), async {
        while !hosts.0.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    println!(
        "registry_retirement remaining_hosts={} all_revocations_and_cleanup_us={} cleanup_completed={} retained_client_peers={}",
        hosts.0.lock().await.len(),
        start.elapsed().as_micros(),
        retired.is_ok(),
        peers.len()
    );
    // Keep diagnostic output on the failing baseline; the active regression
    // above enforces cleanup without conflating measurement with acceptance.
}
