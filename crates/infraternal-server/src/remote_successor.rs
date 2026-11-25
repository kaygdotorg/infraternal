//! The private lane of a root upgrade's successor, and the two outboxes that
//! finish a promotion on the host (D376, #399; J415 R2 and R5).
//!
//! A successor is the root infraternal agent a promotion installed. Until the
//! handover it is *not* the host: it never enters the host registry, plugin
//! routing, inventory or mesh, and its link carries only the proof calls in
//! [`PROOF_ACTIONS`] (the link enforces this, see `remote_link`). The
//! promotion's driver takes its actor from [`Successors::wait`], proves it,
//! commits the handover, and then [`Successors::release`]s it; the successor
//! reconnects and is admitted the ordinary way, as the now-rootful host.
//!
//! The outboxes are durable rows in `remote_host_promotions.cleanup`, so a
//! lost link or a server restart only delays them:
//! - **uninstall**: an abandoned successor reconnects, is admitted for this
//!   one call ([`deliver_uninstall`]), removes itself, and its receipt
//!   revokes its certificate.
//! - **retire**: the new root infraternal agent, on its ordinary admission,
//!   is asked to retire the rootless install ([`retire_predecessor`]).
use crate::{embedded::EmbeddedAgent, remote_guard::AuthorityGuard, remote_link::RemoteLink};
use std::{collections::HashMap, io, sync::Mutex, time::Duration};
use tokio::sync::watch;
use uuid::Uuid;

/// The only calls a successor's link carries before its handover: the
/// facts that prove who and what it is (`executionUid`, the host id).
pub(crate) const PROOF_ACTIONS: &[&str] = &["host.facts.read"];

/// The control action that asks a root infraternal agent to retire the
/// rootless install it replaced, then leave standby (R5). Implemented by
/// `infraternal_agent::privilege_agent`.
pub(crate) const TAKE_OVER: &str = "privilege.take_over";

/// The control action that asks an abandoned successor to roll back its
/// install transaction, then uninstall itself (J465 P1). Implemented by
/// `infraternal_agent::privilege_take_over::abandon`.
pub(crate) const ABANDON: &str = "privilege.abandon";

/// The host's cleanup unit permits 250 seconds; reserve another 50 seconds for its receipt.
const ABANDON_RECEIPT_BOUND: Duration = Duration::from_secs(300);

/// Whether the host confirmed that transaction-bound abandonment cleanup finished.
fn abandon_completed(reply: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(reply).is_ok_and(|reply| reply["completed"] == true)
}

/// Successors that are connected and waiting for their promotion's driver,
/// keyed by promotion. Each entry owns its actor; the lane task holds the
/// link until the driver releases it, the promotion ends, or the link drops.
#[derive(Default)]
pub(crate) struct Successors(Mutex<HashMap<Uuid, Slot>>);

/// One waiting successor.
struct Slot {
    /// The private actor, once connected.
    actor: watch::Sender<Option<EmbeddedAgent>>,
    /// Flipped to true by [`Successors::release`].
    released: watch::Sender<bool>,
    /// Which lane task published `actor`, so a stale task never clears a
    /// reconnect's entry.
    owner: Option<Uuid>,
}

impl Slot {
    /// An empty slot.
    fn new() -> Self {
        Self {
            actor: watch::channel(None).0,
            released: watch::channel(false).0,
            owner: None,
        }
    }
}

#[cfg(any(feature = "ssh", test))]
impl Successors {
    /// Wait up to `bound` for `attempt`'s successor to connect, and return
    /// its private actor.
    ///
    /// # Errors
    /// `TimedOut` when it hasn't connected in time.
    pub(crate) async fn wait(&self, attempt: Uuid, bound: Duration) -> io::Result<EmbeddedAgent> {
        let mut actor = {
            let mut slots = self.0.lock().map_err(|_| io::ErrorKind::Other)?;
            if slots.len() >= 64 && !slots.contains_key(&attempt) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            slots
                .entry(attempt)
                .or_insert_with(Slot::new)
                .actor
                .subscribe()
        };
        let found = tokio::time::timeout(bound, actor.wait_for(Option::is_some))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
            .clone();
        found.ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    /// Let `attempt`'s successor go (after its handover, or on failure). Its
    /// link closes; after a handover it reconnects as the host.
    pub(crate) fn release(&self, attempt: Uuid) {
        if let Ok(mut slots) = self.0.lock()
            && let Some(slot) = slots.remove(&attempt)
        {
            slot.released.send_replace(true);
        }
    }
}

/// Run a successor's link, admitted for proof or for its own uninstall.
///
/// Proof: publish its private actor for the promotion's driver, then hold
/// the link until the driver releases it, the guard ends (abandonment,
/// removal, deadline) or the link drops. Uninstall: see [`deliver_uninstall`].
pub(crate) async fn deliver(
    successors: &Successors,
    authority: AuthorityGuard,
    link: RemoteLink,
) -> io::Result<()> {
    let successor = authority
        .successor_authority()
        .cloned()
        .ok_or(io::ErrorKind::PermissionDenied)?;
    if successor.purpose == crate::enrollment::promotion::SuccessorPurpose::Uninstall {
        return deliver_uninstall(authority, link, successor.attempt).await;
    }
    let lane = Uuid::new_v4();
    let (actor, accepts) = EmbeddedAgent::remote(0);
    let mut inventory = actor.session_inventory();
    accepts
        .try_send(link.authorize(authority.clone()))
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    let mut released = {
        let mut slots = successors.0.lock().map_err(|_| io::ErrorKind::Other)?;
        if slots.len() >= 64 && !slots.contains_key(&successor.attempt) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let slot = slots.entry(successor.attempt).or_insert_with(Slot::new);
        slot.actor.send_replace(Some(actor.clone()));
        slot.owner = Some(lane);
        slot.released.subscribe()
    };
    tokio::select! {
        biased;
        _ = released.wait_for(|released| *released) => {},
        () = authority.cancelled() => {},
        _ = inventory.wait_for(|state| matches!(state, crate::embedded::SessionInventoryState::Unavailable)) => {},
    }
    // A reconnect replaces this entry; only clear it if it is still ours.
    if let Ok(mut slots) = successors.0.lock()
        && slots
            .get(&successor.attempt)
            .is_some_and(|slot| slot.owner == Some(lane))
    {
        slots.remove(&successor.attempt);
    }
    drop(actor);
    Ok(())
}

/// The uninstall outbox (R5): an abandoned successor removes itself, and
/// only its acceptance retires the entry and revokes its certificate. A lost
/// or refused answer leaves the entry for its next reconnect.
///
/// When the promotion recorded its install transaction, the successor is
/// asked to [`ABANDON`] it: roll that transaction back first, then
/// uninstall. A plain uninstall refuses while the install's journal is open,
/// which is exactly the state a relay that died mid-install leaves (J465 P1).
async fn deliver_uninstall(
    authority: AuthorityGuard,
    link: RemoteLink,
    attempt: Uuid,
) -> io::Result<()> {
    let store = authority.store();
    let host = authority.identity.host;
    let (actor, accepts) = EmbeddedAgent::remote(0);
    accepts
        .try_send(link.authorize(authority))
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    let accepted = match store.install_transaction(attempt).await.ok().flatten() {
        Some(transaction) => {
            let input = serde_json::to_vec(&serde_json::json!({
                "host": host.simple().to_string(),
                "transaction": transaction.simple().to_string(),
            }))
            .map_err(io::Error::other)?;
            let reply =
                tokio::time::timeout(ABANDON_RECEIPT_BOUND, actor.privilege_call(ABANDON, input))
                    .await;
            matches!(&reply, Ok(Ok(bytes)) if abandon_completed(bytes))
        }
        None => matches!(
            tokio::time::timeout(
                Duration::from_mins(1),
                crate::remote_removal::ask_uninstall(&actor, host),
            )
            .await,
            Ok(crate::remote_removal::UninstallReply::Accepted(_))
        ),
    };
    if accepted {
        store
            .confirm_successor_uninstall(
                attempt,
                crate::runtime::unix_seconds().map_err(io::Error::other)?,
            )
            .await
            .map_err(io::Error::other)?;
    }
    Ok(())
}

/// The retire outbox (R5): ask `host`'s new root infraternal agent to retire
/// the rootless install it replaced and leave standby, then record the
/// receipt. Runs on every ordinary admission while the entry is pending, so
/// it happens at least once; the host side is idempotent.
pub(crate) async fn retire_predecessor(
    store: crate::enrollment::EnrollmentStore,
    actor: EmbeddedAgent,
    host: Uuid,
) {
    let Ok(Some((attempt, from_uid))) = store.pending_retirement(host).await else {
        return;
    };
    let Ok(input) = serde_json::to_vec(&serde_json::json!({
        "attempt": attempt.simple().to_string(),
        "host": host.simple().to_string(),
        "fromUid": from_uid,
    })) else {
        return;
    };
    // The host stops the rootless unit as that account, so allow it time.
    let reply = tokio::time::timeout(
        Duration::from_mins(2),
        actor.privilege_call(TAKE_OVER, input),
    )
    .await;
    if let Ok(Ok(bytes)) = reply
        && serde_json::from_slice::<serde_json::Value>(&bytes)
            .is_ok_and(|reply| reply["retired"] == true)
    {
        let _ = store.confirm_retirement(attempt).await;
    }
}

#[cfg(test)]
mod tests {
    //! The durable outbox is consumed only by a completed cleanup receipt.
    use super::*;

    /// Starting a cleanup worker is not enough to retire the server's outbox entry.
    #[test]
    fn uninstall_outbox_requires_completed_abandonment() {
        assert!(!abandon_completed(br#"{"accepted":true}"#));
        assert!(!abandon_completed(br#"{"completed":false}"#));
        assert!(abandon_completed(br#"{"completed":true}"#));
    }

    /// Keep the uninstall outbox pending while host cleanup takes its full 250-second bound.
    #[tokio::test]
    async fn abandon_outbox_waits_past_host_bound_for_receipt() {
        use crate::{
            enrollment::{
                CertificateRecord,
                authority::tests::enrolled,
                promotion::{Bound, Method, Settled, SuccessorPurpose},
            },
            remote_guard::AuthorityGuard,
            remote_link::RemoteLink,
        };
        use infraternal_agent::{
            remote_quic, remote_tls,
            transport::{Receive, Transmit},
        };
        use infraternal_protocol::Frame;
        use sha2::Digest;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::{net::TcpListener, sync::oneshot};
        use uuid::Uuid;

        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let (store, pool, host) = enrolled().await;
        sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=?")
            .bind(now - 10)
            .bind(now + 604_790)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES ('s','owner','fixture',?,?,1)")
            .bind(now + 3600)
            .bind(now - 5)
            .execute(&pool)
            .await
            .unwrap();

        let attempt = Uuid::from_u128(0x522);
        let transaction = Uuid::from_u128(0xa);
        store
            .begin_promotion(
                "s",
                host,
                attempt,
                Method::Sudo,
                Bound {
                    from_uid: 1002,
                    from_fingerprint: [1; 32],
                    link_generation: Uuid::from_u128(5),
                },
                now,
            )
            .await
            .unwrap();
        store.reserve_try("s", attempt, true, now).await.unwrap();
        store
            .settle_try(attempt, Settled::Rooted, now + 1)
            .await
            .unwrap();
        let key = [8; 32];
        let key_digest: [u8; 32] = sha2::Sha256::digest(key).into();
        let token = store
            .issue_successor_token(attempt, &key_digest, now)
            .await
            .unwrap();
        store
            .redeem_successor(
                token.secret(),
                host,
                now,
                &CertificateRecord {
                    fingerprint: [7; 32],
                    issuer_fingerprint: [9; 32],
                    public_key: crate::identity_key::IdentityKey::Ed25519(key),
                    not_before: now,
                    not_after: now + 604_800,
                },
            )
            .await
            .unwrap();
        store
            .record_install_transaction(attempt, transaction)
            .await
            .unwrap();
        store.abandon_promotion(attempt, now + 2).await.unwrap();
        let authority = AuthorityGuard::admit_transport(store.clone(), [7; 32])
            .await
            .unwrap();
        assert_eq!(
            authority.successor_authority().unwrap().purpose,
            SuccessorPurpose::Uninstall
        );

        let (server_identity, host_identity, root, _) = crate::remote_runtime::tests::identities();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_config =
            remote_tls::server_config(&server_identity, std::slice::from_ref(&root)).unwrap();
        let host_config = remote_tls::client_config(&host_identity, &[root]).unwrap();
        let (peer_ready, ready) = oneshot::channel();
        let (call_seen, saw_call) = oneshot::channel();
        let (release_receipt, wait_for_receipt) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = remote_tls::dial(address, "localhost", &host_config)
                .await
                .unwrap();
            let mut receive = Receive::default();
            Transmit::default()
                .send(
                    &connection.channel,
                    0,
                    &Frame::Hello {
                        version: 1,
                        caps: remote_quic::REMOTE_WRITER_BINDING,
                        client_info: "test",
                    },
                )
                .await
                .unwrap();
            assert!(matches!(
                receive.next(&connection.channel).await.unwrap().frame,
                Frame::Hello { .. }
            ));
            let _ = peer_ready.send(());

            let mut call_seen = Some(call_seen);
            let mut wait_for_receipt = wait_for_receipt;
            let mut call_id = None;
            loop {
                tokio::select! {
                    decoded = receive.next(&connection.channel) => {
                        let decoded = match decoded {
                            Ok(decoded) => decoded,
                            Err(error)
                                if call_id.is_some()
                                    && error.kind() == std::io::ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(error) => panic!("unexpected peer transport error: {error}"),
                        };
                        match decoded.frame {
                            Frame::Call { call_id: id, action_id, input_json } => {
                                assert_eq!(action_id, ABANDON);
                                let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
                                assert_eq!(input["host"], host.simple().to_string());
                                assert_eq!(input["transaction"], transaction.simple().to_string());
                                call_id = Some(id);
                                let _ = call_seen.take().unwrap().send(());
                            }
                            Frame::Ping { nonce, sent_us } => {
                                Transmit::default()
                                    .send(&connection.channel, 0, &Frame::Pong { nonce, sent_us })
                                    .await
                                    .unwrap();
                            }
                            other => panic!("unexpected server frame: {other:?}"),
                        }
                    }
                    _ = &mut wait_for_receipt => {
                        let call_id = call_id.expect("the cleanup call arrived before its receipt");
                        Transmit::default()
                            .send(
                                &connection.channel,
                                0,
                                &Frame::Result {
                                    call_id,
                                    ok: true,
                                    json: br#"{"completed":true}"#,
                                },
                            )
                            .await
                            .unwrap();
                        break;
                    }
                }
            }
        });

        let (socket, _) = listener.accept().await.unwrap();
        let connection = remote_tls::accept(socket, &server_config).await.unwrap();
        let link = RemoteLink::tcp(connection.channel).await.unwrap();
        let delivery = tokio::spawn(deliver_uninstall(authority, link, attempt));
        ready.await.unwrap();
        saw_call.await.unwrap();

        let cleanup = || async {
            sqlx::query_scalar::<_, String>(
                "SELECT cleanup FROM remote_host_promotions WHERE attempt=?",
            )
            .bind(attempt.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        assert_eq!(cleanup().await, "uninstall");
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(251)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(
            !delivery.is_finished(),
            "the outbox driver stopped waiting before cleanup returned its receipt"
        );
        tokio::time::resume();
        assert_eq!(cleanup().await, "uninstall");

        release_receipt.send(()).unwrap();
        delivery.await.unwrap().unwrap();
        peer.await.unwrap();
        assert_eq!(cleanup().await, "done");
    }
}
