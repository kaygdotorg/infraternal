//! Real TCP/mTLS regressions for event-driven revocation and current attachment authority [134], #78.

use super::*;

pub(crate) async fn admitted_store(
    host: &Identity,
    root: &X509,
) -> (EnrollmentStore, sqlx::SqlitePool, Uuid, [u8; 32]) {
    let fingerprint = openssl::sha::sha256(&host.certificate.to_der().unwrap());
    let (store, pool, host_id) = crate::enrollment::authority::tests::enrolled().await;
    let instant = now().unwrap();
    let key_digest = openssl::sha::sha256(&host.key.raw_public_key().unwrap());
    let token = store
        .issue("owner", host_id, crate::enrollment::Mode::Rootless, instant, &key_digest)
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            host_id,
            crate::enrollment::Mode::Rootless,
            instant,
            &crate::enrollment::CertificateRecord {
                fingerprint,
                issuer_fingerprint: openssl::sha::sha256(&root.to_der().unwrap()),
                public_key: host.key.raw_public_key().unwrap().try_into().unwrap(),
                not_before: instant,
                not_after: instant + 604_800,
            },
        )
        .await
        .unwrap();
    (store, pool, host_id, fingerprint)
}

async fn admitted_tcp() -> (
    EnrollmentStore,
    sqlx::SqlitePool,
    Uuid,
    [u8; 32],
    RemoteListeners,
    EmbeddedAgent,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
) {
    let (server, host, root, _) = identities();
    let (store, pool, host_id, fingerprint) = admitted_store(&host, &root).await;
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
    let config = remote_tls::client_config(&host, &[root]).unwrap();
    let (input_seen, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(address, "localhost", &config)
            .await
            .unwrap();
        respond(&connection.channel).await;
        let mut receive = Receive::default();
        let attached = receive.next(&connection.channel).await.unwrap();
        assert!(matches!(attached.frame, Frame::AttachTerm { .. }));
        let writer = attached.stream_id;
        Transmit::default()
            .send(&connection.channel, writer, &Frame::Ack { in_seq_acked: 0 })
            .await
            .unwrap();
        let next = receive.next(&connection.channel).await;
        if let Ok(decoded) = next
            && let Frame::Input { bytes, .. } = decoded.frame
        {
            let _ = input_seen.send(bytes.to_vec());
        }
        std::future::pending::<()>().await;
    });
    let actor = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(actor) = hosts.actor(host_id).await {
                break actor;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (
        store,
        pool,
        host_id,
        fingerprint,
        listeners,
        actor,
        peer,
        observed,
    )
}

#[tokio::test]
async fn revocation_must_cancel_input_on_existing_tls_transport() {
    let (store, _pool, host, fingerprint, _listeners, actor, peer, observed) = admitted_tcp().await;
    let session = tokio::time::timeout(
        Duration::from_secs(2),
        actor.open(crate::embedded::TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let attachment = actor.attach(session, 0, 0, 42).await.unwrap();
    let (handle, mut output) = attachment.split();
    assert!(matches!(
        output.recv().await,
        Some(crate::embedded::TerminalOutput::Ack { .. })
    ));
    store.revoke("owner", host, now().unwrap()).await.unwrap();
    assert!(store.admit(&fingerprint, now().unwrap()).await.is_err());
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"after-revoke",
        },
        &mut wire,
    )
    .unwrap();
    let _ = handle.send_frame(bytes::Bytes::from(wire)).await;
    let received = tokio::time::timeout(Duration::from_millis(300), observed).await;
    peer.abort();
    assert!(
        !matches!(received, Ok(Ok(_))),
        "revoked host received terminal input on its existing mutual-TLS connection"
    );
}

#[tokio::test]
async fn expired_identity_must_refuse_new_attachment_on_existing_transport() {
    let (store, pool, _host, fingerprint, _listeners, actor, peer, _observed) =
        admitted_tcp().await;
    let session = tokio::time::timeout(
        Duration::from_secs(2),
        actor.open(crate::embedded::TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=? WHERE fingerprint=?")
        .bind(now().unwrap() - 604_801)
        .bind(now().unwrap() - 1)
        .bind(fingerprint.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.admit(&fingerprint, now().unwrap()).await.is_err());
    let attachment = actor.attach(session, 0, 0, 42).await;
    peer.abort();
    assert!(
        attachment.is_err(),
        "expired ledger identity retained terminal attachment authority"
    );
}

/// An idle QUIC peer must be cancelled without waiting for terminal activity or
/// its transport heartbeat. The same ledger event closes all native streams.
#[tokio::test]
async fn revocation_closes_admitted_idle_quic_connection() {
    use infraternal_agent::remote_native::NativeChannel;
    let (server, host, root, _) = identities();
    let (store, _pool, id, _fingerprint) = admitted_store(&host, &root).await;
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
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(remote_quic::client_config(&host, &[root]).unwrap());
    let connection = endpoint
        .connect(listeners.local_addr().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (send, receive) = connection.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    let mut transmit = Transmit::default();
    transmit
        .send(
            &control,
            0,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "test",
            },
        )
        .await
        .unwrap();
    Receive::default().next(&control).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while hosts.actor(id).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    store.revoke("owner", id, now().unwrap()).await.unwrap();
    assert!(hosts.actor(id).await.is_none());
    let closed = tokio::time::timeout(Duration::from_millis(300), connection.closed())
        .await
        .expect("revoked idle QUIC connection waited for transport activity");
    assert!(matches!(
        closed,
        quinn::ConnectionError::ApplicationClosed(_)
    ));
}

/// Exercise the actual expiry wait with a short public-ledger fixture, without
/// changing production certificate lifetime or polling the connected transport.
#[tokio::test]
async fn admitted_guard_expires_and_prior_revocation_cannot_reregister() {
    let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let instant = now().unwrap();
    sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=? WHERE fingerprint=?")
        .bind(instant - 604_798)
        .bind(instant + 2)
        .bind([1u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    assert!(guard.permits());
    tokio::time::timeout(Duration::from_secs(4), guard.cancelled())
        .await
        .unwrap();
    assert!(!guard.permits());
    store.revoke("owner", host, now().unwrap()).await.unwrap();
    assert!(
        crate::remote_guard::AuthorityGuard::admit(store, [1; 32])
            .await
            .is_err()
    );
}

/// Component-only bookkeeping measurement; no TLS/daemon/PTY scale claim.
#[tokio::test]
#[ignore = "guard component diagnostic; run alone without builds or browser measurements"]
async fn guard_bookkeeping_at_1000_hosts() {
    use std::hint::black_box;
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let instant = now().unwrap();
    let mut fingerprints = Vec::new();
    let mut transaction = pool.begin().await.unwrap();
    for index in 1..=1000u128 {
        let host = Uuid::from_u128(index + 100);
        let mut fingerprint = [0u8; 32];
        fingerprint[..16].copy_from_slice(host.as_bytes());
        fingerprints.push(fingerprint);
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootless',1002,?)")
            .bind(host.as_bytes().as_slice()).bind(instant).execute(&mut *transaction).await.unwrap();
        // Placeholder public fingerprints isolate guard allocations after a
        // trusted admission boundary; crypto/ledger storage is not this metric.
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(?,?,?,?,?,?)")
            .bind(fingerprint.as_slice()).bind(host.as_bytes().as_slice()).bind([9u8;32].as_slice()).bind([3u8;32].as_slice())
            .bind(instant).bind(instant+604_800).execute(&mut *transaction).await.unwrap();
    }
    transaction.commit().await.unwrap();
    let before = guard_rss();
    let mut guards = Vec::new();
    for fingerprint in fingerprints {
        guards.push(
            crate::remote_guard::AuthorityGuard::admit(store.clone(), fingerprint)
                .await
                .unwrap(),
        );
    }
    let retained = guard_rss();
    let start = std::time::Instant::now();
    for _ in 0..1_000_000 {
        black_box(true);
    }
    let baseline_ns = start.elapsed().as_nanos();
    let start = std::time::Instant::now();
    for _ in 0..1_000_000 {
        assert!(black_box(guards[0].permits()));
    }
    let guarded_ns = start.elapsed().as_nanos();
    let start = std::time::Instant::now();
    for _ in 0..100 {
        guards[0].admit_operation().await.unwrap();
    }
    println!(
        "guard_diagnostic component_only=true hosts=1000 baseline_rss_kib={before} retained_rss_kib={retained} delta_at1000_kib={} baseline_check_total_ns={baseline_ns} guarded_check_total_ns={guarded_ns} check_n=1000000 ledger_admission_n=100 ledger_admission_total_us={} machine={} load={}",
        retained.saturating_sub(before),
        start.elapsed().as_micros(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
fn guard_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[path = "remote_retirement_tests.rs"]
mod retirement;

#[path = "remote_login_revocation_tests.rs"]
mod login_revocation;
