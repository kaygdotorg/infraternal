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
    let reply = tokio::time::timeout(
        Duration::from_mins(1),
        crate::remote_removal::ask_uninstall(&actor, host),
    )
    .await;
    if let Ok(crate::remote_removal::UninstallReply::Accepted(_)) = reply {
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
