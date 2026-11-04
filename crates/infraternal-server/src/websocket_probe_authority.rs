//! Non-renewing authority for content-free socket proofs, watched by committed revocation and absolute expiry [D81, D265], #199.

use super::{AuthorityMiss, WebSocketState, probe_deadline};
use tokio::time::Instant;

/// This lease authorizes only content-free Ping/Pong bookkeeping. Payloads, application requests
/// and backend rebinds retain fresh authority reads in their existing gates.
pub(crate) struct Lease {
    revoked: crate::auth::AccountSubscription,
    expiry: Instant,
}

impl Lease {
    /// Starts a lease for `user`'s session `token`. It subscribes to revocation first
    /// and reads the session expiry second, so a revocation committing in between is
    /// still seen. Fails if the session has no valid authority now.
    pub(crate) async fn new(state: &WebSocketState, user: &str, token: &str) -> Result<Self, ()> {
        // Subscribe before SQL so a commit racing the read remains observable.
        let revoked = state.auth.revocation_events(user);
        let expiry = probe_deadline(state, user, token).await.map_err(|_| ())?;
        Ok(Self { revoked, expiry })
    }

    /// Share the completed handshake's absolute expiry without renewing it.
    pub(crate) fn deadline(&self) -> Instant {
        self.expiry
    }

    /// Re-reads the session expiry from the database and clears the pending revocation flag. Fails if authority is gone.
    async fn refresh(
        &mut self,
        state: &WebSocketState,
        user: &str,
        token: &str,
    ) -> Result<(), AuthorityMiss> {
        self.revoked.borrow_and_update();
        self.expiry = probe_deadline(state, user, token).await?;
        Ok(())
    }

    /// Drives `operation` while watching for revocation and expiry. If revocation was
    /// signalled or the expiry passed, authority is re-read first; the same re-read
    /// happens mid-flight and again before the result is returned. The result is
    /// returned only if authority still holds. A closed revocation source counts as
    /// `Unavailable`, so a write never goes ahead without its watcher.
    pub(crate) async fn run<T>(
        &mut self,
        state: &WebSocketState,
        user: &str,
        token: &str,
        operation: impl std::future::Future<Output = Result<T, ()>>,
    ) -> Result<T, AuthorityMiss> {
        if self
            .revoked
            .has_changed()
            .map_err(|_| AuthorityMiss::Unavailable)?
            || Instant::now() >= self.expiry
        {
            self.refresh(state, user, token).await?;
        }
        tokio::pin!(operation);
        loop {
            tokio::select! {
                biased;
                changed = self.revoked.changed() => {
                    changed.map_err(|_| AuthorityMiss::Unavailable)?;
                    self.refresh(state, user, token).await?;
                }
                () = tokio::time::sleep_until(self.expiry) => {
                    // Authorized activity elsewhere may extend the persisted expiry.
                    // An idle proof never performs that renewal itself.
                    self.refresh(state, user, token).await?;
                }
                result = &mut operation => {
                    // A ready write cannot bypass a concurrently committed generation.
                    if self.revoked.has_changed().map_err(|_| AuthorityMiss::Unavailable)? || Instant::now() >= self.expiry {
                        self.refresh(state, user, token).await?;
                    }
                    return result.map_err(|()| AuthorityMiss::Unavailable);
                }
            }
        }
    }
}

#[cfg(test)]
mod review_closed_watch {
    //! A lost notification source is unavailable authority, without a guarded write (#240).

    use super::*;
    use crate::auth::tests::socket_clock::FrozenSocketTime;
    use crate::websocket::writer_tests::busy_edges::{TOKEN, fixture};

    #[tokio::test(start_paused = true)]
    async fn closed_revocation_watch_is_unavailable_and_never_polls_the_write() {
        let _clock = FrozenSocketTime::new().await;
        let (state, user) = fixture().await;
        let mut lease = Lease::new(&state, &user, TOKEN).await.unwrap();
        // Production keeps the source for this subscription's entire lifetime.
        // Close only the test account's source to exercise unexpected loss.
        lease.revoked.close_source_for_test();
        let mut wrote = false;
        let result = lease
            .run(&state, &user, TOKEN, async {
                wrote = true;
                Ok::<(), ()>(())
            })
            .await;
        assert_eq!(result, Err(AuthorityMiss::Unavailable));
        assert!(!wrote);
    }
}

#[cfg(test)]
mod review_r2_restore {
    //! A replacement source cannot repair an old proof cursor after revocation (#240).

    use super::*;
    use crate::auth::tests::socket_clock::FrozenSocketTime;
    use crate::websocket::writer_tests::busy_edges::{TOKEN, fixture};

    #[tokio::test(start_paused = true)]
    async fn review_r2_revoked_lease_with_restored_source_never_polls_work() {
        let _clock = FrozenSocketTime::new().await;
        let (state, user) = fixture().await;
        let mut lease = Lease::new(&state, &user, TOKEN).await.unwrap();
        lease.revoked.close_source_for_test();
        let replacement = state.auth.revocation_events(&user);
        state.auth.logout(TOKEN).await.unwrap();
        assert!(replacement.has_changed().unwrap());
        let mut wrote = false;
        let result = lease
            .run(&state, &user, TOKEN, async {
                wrote = true;
                Ok::<(), ()>(())
            })
            .await;
        assert_eq!(result, Err(AuthorityMiss::Unavailable));
        assert!(!wrote);
    }
}
