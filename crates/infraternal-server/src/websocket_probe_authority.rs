//! Non-renewing authority for content-free server probes, watched by committed revocation and absolute expiry [D81, D265], #199.

use super::{WebSocketState, probe_deadline};
use tokio::{sync::watch, time::Instant};

/// This lease authorizes only server Ping bookkeeping. Payloads, browser requests
/// and backend rebinds retain fresh authority reads in their existing gates.
pub(crate) struct Lease {
    revoked: watch::Receiver<()>,
    expiry: Instant,
}

impl Lease {
    pub(crate) async fn new(state: &WebSocketState, user: &str, token: &str) -> Result<Self, ()> {
        // Subscribe before SQL so a commit racing the read remains observable.
        let revoked = state.auth.revocation_events();
        let expiry = probe_deadline(state, user, token).await?;
        Ok(Self { revoked, expiry })
    }

    async fn refresh(&mut self, state: &WebSocketState, user: &str, token: &str) -> Result<(), ()> {
        self.revoked.borrow_and_update();
        self.expiry = probe_deadline(state, user, token).await?;
        Ok(())
    }

    pub(crate) async fn run<T>(
        &mut self,
        state: &WebSocketState,
        user: &str,
        token: &str,
        operation: impl std::future::Future<Output = Result<T, ()>>,
    ) -> Result<T, ()> {
        if self.revoked.has_changed().map_err(|_| ())? || Instant::now() >= self.expiry {
            self.refresh(state, user, token).await?;
        }
        tokio::pin!(operation);
        loop {
            tokio::select! {
                biased;
                changed = self.revoked.changed() => {
                    changed.map_err(|_| ())?;
                    self.refresh(state, user, token).await?;
                }
                () = tokio::time::sleep_until(self.expiry) => {
                    // Authorized activity elsewhere may extend the persisted expiry.
                    // An idle proof never performs that renewal itself.
                    self.refresh(state, user, token).await?;
                }
                result = &mut operation => {
                    // A ready write cannot bypass a concurrently committed generation.
                    if self.revoked.has_changed().map_err(|_| ())? || Instant::now() >= self.expiry {
                        self.refresh(state, user, token).await?;
                    }
                    return result;
                }
            }
        }
    }
}
