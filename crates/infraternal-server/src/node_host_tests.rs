//! Checks enrolled ownership and revocation before native I/O using the real SQLite admission ledger [D12,D232].
use super::*;
use crate::enrollment::{CertificateRecord, Mode};
#[cfg(feature = "desktop")]
use infraternal_protocol::{
    Frame,
    desktop::{Delivery, Message},
    encode_frame_into,
};

async fn node(
    owner: &str,
) -> (
    EnrolledNode,
    crate::enrollment::EnrollmentStore,
    tokio::sync::mpsc::Sender<crate::remote_link::RemoteLink>,
) {
    let (store, pool, id) = crate::enrollment::authority::tests::enrolled().await;
    let now = crate::websocket::now_seconds().unwrap();
    let key_digest = openssl::sha::sha256(&[3u8; 32]);
    let token = store
        .issue("owner", id, Mode::Rootless, now, &key_digest)
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            id,
            Mode::Rootless,
            now,
            &CertificateRecord {
                fingerprint: [2; 32],
                issuer_fingerprint: [9; 32],
                public_key: [3; 32],
                not_before: now,
                not_after: now + 604_800,
            },
        )
        .await
        .unwrap();
    let admission = AuthorityGuard::admit(store.clone(), [2; 32]).await.unwrap();
    let (actor, accepts) = EmbeddedAgent::remote(1002);
    (
        EnrolledNode::new(
            id,
            owner.into(),
            pool,
            actor,
            Arc::new(RwLock::new(admission)),
        ),
        store,
        accepts,
    )
}

#[cfg(feature = "desktop")]
fn opening() -> Vec<u8> {
    let mut opening = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: &[7; 16],
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    opening
}

#[tokio::test]
async fn current_revocation_prevents_polling_forwarded_work() {
    let (node, store, _accepts) = node("owner").await;
    assert!(node.permits());
    store
        .revoke("owner", node.id, crate::websocket::now_seconds().unwrap())
        .await
        .unwrap();
    assert!(!node.permits());
    let polled = std::sync::atomic::AtomicBool::new(false);
    assert!(
        node.authorized(Box::pin(async {
            polled.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }))
        .await
        .is_err()
    );
    assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
    assert!(node.call("desktop.windows", b"{}").await.is_err());
}

#[cfg(feature = "desktop")]
#[tokio::test]
async fn foreign_owner_never_reserves_writer_or_calls_native_actor() {
    let (node, _store, _accepts) = node("foreign").await;
    assert!(node.call("desktop.windows", b"{}").await.is_err());
    assert!(
        node.open(&infraternal_plugin_desktop::server::WIRE, &opening())
            .await
            .is_err()
    );
    let clock: i64 = sqlx::query_scalar("SELECT value FROM wire_writer_clock WHERE singleton=1")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(clock, 0);
}

#[cfg(feature = "desktop")]
#[tokio::test]
async fn failed_native_open_keeps_its_committed_writer_reservation() {
    let (node, _store, accepts) = node("owner").await;
    // There is no transport to open. End actor supervision explicitly rather
    // than relying on a test timeout to simulate connection failure.
    drop(accepts);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            node.open(&infraternal_plugin_desktop::server::WIRE, &opening())
        )
        .await
        .unwrap()
        .is_err()
    );
    let clock: i64 = sqlx::query_scalar("SELECT value FROM wire_writer_clock WHERE singleton=1")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(clock, 1);
}
