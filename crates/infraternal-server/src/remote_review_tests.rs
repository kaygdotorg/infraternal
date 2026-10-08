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
    let token = store
        .issue("owner", host_id, crate::enrollment::Mode::Rootless, instant)
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
