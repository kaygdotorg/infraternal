//! Independent review regressions replayed against live host authority, #78.

use super::*;

// Independent review regressions for current host authority, #78.
async fn review_admitted_tcp() -> (
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
    let fingerprint = openssl::sha::sha256(&host.certificate.to_der().unwrap());
    let (store, pool, host_id) = crate::enrollment::authority::tests::enrolled().await;
    let instant = now().unwrap();
    let key_digest = openssl::sha::sha256(&host.key.raw_public_key().unwrap());
    let token = store
        .issue(
            "owner",
            host_id,
            crate::enrollment::Mode::Rootless,
            instant,
            &key_digest,
        )
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
async fn review_revocation_must_cancel_input_on_existing_tls_transport() {
    let (store, _pool, host, fingerprint, _listeners, actor, peer, observed) =
        review_admitted_tcp().await;
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
async fn review_expired_identity_must_refuse_new_attachment_on_existing_transport() {
    let (store, pool, _host, fingerprint, _listeners, actor, peer, _observed) =
        review_admitted_tcp().await;
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
// Fence the real post-COMMIT/pre-notification window with a test-only pause, #78.
#[tokio::test]
async fn committed_tombstone_cannot_forward_input_before_finalizer_returns() {
    let (store, pool, host, _, _listeners, actor, peer, observed) = review_admitted_tcp().await;
    let session = actor
        .open(crate::embedded::TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    let attachment = actor.attach(session, 0, 0, 42).await.unwrap();
    let (handle, mut output) = attachment.split();
    assert!(matches!(
        output.recv().await,
        Some(crate::embedded::TerminalOutput::Ack { .. })
    ));
    let pause = std::sync::Arc::new(crate::remote_guard::PublicationPause::default());
    *store.1.publication_pause.lock().unwrap() = Some(pause.clone());
    let finalizer = tokio::spawn(async move { store.revoke("owner", host, now().unwrap()).await });
    tokio::time::timeout(Duration::from_secs(2), pause.committed.notified())
        .await
        .unwrap();
    let tombstoned: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(tombstoned);
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"after-durable-tombstone",
        },
        &mut wire,
    )
    .unwrap();
    let _ = handle.send_frame(bytes::Bytes::from(wire)).await;
    let received = tokio::time::timeout(Duration::from_millis(300), observed).await;
    pause.release.notify_one();
    finalizer.await.unwrap().unwrap();
    peer.abort();
    assert!(
        !matches!(received, Ok(Ok(_))),
        "input passed after SQLite COMMIT while cancellation publication was pending"
    );
}
// A mechanism microbenchmark, separate from real transport/fleet acceptance.
#[tokio::test]
#[ignore = "write-fence CPU diagnostic; run release alone, not whole-transport evidence"]
async fn admitted_frame_write_fence_cost() {
    const FRAMES: u128 = 1_000_000;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=?")
        .bind(now)
        .bind(now + 604_800)
        .execute(&pool)
        .await
        .unwrap();
    let guard = crate::remote_guard::AuthorityGuard::admit(store, [1; 32])
        .await
        .unwrap();
    let mut reference = Vec::new();
    let mut fenced = Vec::new();
    for _ in 0..11 {
        let before = Instant::now();
        for _ in 0..FRAMES {
            std::hint::black_box(guard.permits());
        }
        reference.push(before.elapsed().as_nanos() / FRAMES);
        let before = Instant::now();
        for _ in 0..FRAMES {
            drop(std::hint::black_box(guard.write_permit().await.unwrap()));
        }
        fenced.push(before.elapsed().as_nanos() / FRAMES);
    }
    reference.sort_unstable();
    fenced.sort_unstable();
    let added = std::mem::size_of::<crate::remote_guard::Revocation>()
        - std::mem::size_of::<tokio::sync::watch::Sender<bool>>()
        + std::mem::size_of::<tokio::sync::RwLock<()>>()
        + 2 * std::mem::size_of::<usize>();
    println!(
        "write_fence_micro rounds=11 frames_per_round={FRAMES} reference_p50_ns={} fenced_p50_ns={} fenced_p99_ns={} added_struct_bytes_per_host={added} added_struct_bytes_at1000={} allocator_and_transport_rss_excluded=true machine={} load={}",
        reference[5],
        fenced[5],
        fenced[10],
        added * 1000,
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
