//! Resolves enrolled host ownership and durable native writer identities without retaining browser login authority [D12,D198,D232].
use crate::{embedded::EmbeddedAgent, remote_guard::AuthorityGuard};
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation,
    streams::{NodeHost, WireLane, WireStreamDef},
};
use sqlx::SqlitePool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// An enrolled remote host as seen by its terminals: who owns it, its stored
/// identity, and the live admission guard that is checked before work is allowed.
pub(crate) struct EnrolledNode {
    /// Host identifier.
    id: Uuid,
    /// `id` as text, kept to avoid formatting it for every call.
    text: String,
    /// User id of the owner that enrolled the host.
    owner: String,
    /// Database handle for durable writer identities.
    pool: SqlitePool,
    /// Handle for talking to the host's infraternal agent.
    actor: EmbeddedAgent,
    /// Shared slot holding the host's current admission guard. It is read again on every call, so a guard swapped in elsewhere applies at once.
    admission: Arc<RwLock<AuthorityGuard>>,
}

#[cfg(test)]
#[path = "node_host_tests.rs"]
mod tests;
impl EnrolledNode {
    /// Builds the view for an enrolled host from its id, `owner`, database `pool`, `actor` and shared `admission` guard.
    pub(crate) fn new(
        id: Uuid,
        owner: String,
        pool: SqlitePool,
        actor: EmbeddedAgent,
        admission: Arc<RwLock<AuthorityGuard>>,
    ) -> Self {
        Self {
            id,
            text: id.to_string(),
            owner,
            pool,
            actor,
            admission,
        }
    }
    /// The host's current admission guard (a clone; cheap).
    fn current(&self) -> AuthorityGuard {
        self.admission
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    /// Checks in the database that this owner still owns the host and it is not revoked. Any error counts as `Err`, so it fails closed.
    async fn owns(&self) -> Result<(), ()> {
        let owns: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL)")
            .bind(self.id.as_bytes().as_slice()).bind(&self.owner).fetch_one(&self.pool).await.map_err(|_| ())?;
        owns.then_some(()).ok_or(())
    }
}
impl NodeHost for EnrolledNode {
    /// Host id as text.
    fn id(&self) -> &str {
        &self.text
    }
    /// User id of the owner.
    fn owner_id(&self) -> &str {
        &self.owner
    }
    /// True while the host's admission guard still allows work. Reads memory only.
    fn permits(&self) -> bool {
        self.current().permits()
    }
    /// Runs `operation` while holding the host's write permit. The result is returned only if the guard still permits at the end, and the operation is dropped if the guard is cancelled.
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let guard = self.current();
            let _permit = guard.write_permit().await.map_err(|_| ())?;
            tokio::select! { biased;
                () = guard.cancelled() => Err(()),
                result = operation => if guard.permits() { result } else { Err(()) },
            }
        })
    }
    /// Calls a named `action` on the host's infraternal agent and returns its reply. Refuses action names over 128 bytes or inputs over the plugin API limit, hosts that are revoked or no longer owned, and gives up after 5 seconds or on cancellation. All failures are `Err(())`.
    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
        Box::pin(async move {
            if action.len() > 128 || input.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
                return Err(());
            }
            let guard = self.current();
            guard.admit_operation().await.map_err(|_| ())?;
            self.owns().await?;
            tokio::select! { biased;
                () = guard.cancelled() => Err(()),
                result = tokio::time::timeout(std::time::Duration::from_secs(5), self.actor.call(action.to_owned(), input.to_vec())) => result.map_err(|_| ())?.map_err(|_| ()),
            }
        })
    }
    /// Opens a wire stream whose first frame is `opening`. The frame must be well-formed, exactly fill the buffer, carry the stream type's tag and (when required) a valid identity. The stream id is reserved in the database under the writer lock after re-checking ownership; the reservation is spent even if the network open then fails. Any failure is `Err(())`.
    fn open<'a>(
        &'a self,
        definition: &'static WireStreamDef,
        opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        Box::pin(async move {
            definition.validate().map_err(|_| ())?;
            let frame = infraternal_protocol::decode_frame(opening).map_err(|_| ())?;
            // The type follows the validated variable-length size prefix.
            let tag = opening
                .iter()
                .position(|byte| byte & 0x80 == 0)
                .and_then(|last| opening.get(last + 1));
            if frame.wire_len != opening.len() || tag != Some(&definition.opening_tag) {
                return Err(());
            }
            if definition
                .opening_identity
                .is_some_and(|identity| identity(opening).is_none())
            {
                return Err(());
            }
            let guard = self.current();
            guard.admit_operation().await.map_err(|_| ())?;
            let mut tx = self.pool.begin().await.map_err(|_| ())?;
            // Take SQLite's writer lock before checking ownership; a committed
            // reservation is consumed even when the subsequent network open fails.
            sqlx::query("UPDATE wire_writer_clock SET value=value WHERE singleton=1")
                .execute(&mut *tx)
                .await
                .map_err(|_| ())?;
            let owns: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL)")
                .bind(self.id.as_bytes().as_slice()).bind(&self.owner).fetch_one(&mut *tx).await.map_err(|_| ())?;
            if !owns {
                return Err(());
            }
            let stream = crate::wire_identity::reserve(&mut tx)
                .await
                .map_err(|_| ())?;
            tx.commit().await.map_err(|_| ())?;
            let _permit = guard.write_permit().await.map_err(|_| ())?;
            tokio::select! { biased;
                () = guard.cancelled() => Err(()),
                result = self.actor.open_wire(definition, stream, Bytes::copy_from_slice(opening)) => result.map_err(|_| ()),
            }
        })
    }
}
