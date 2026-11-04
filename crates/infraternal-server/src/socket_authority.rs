//! Projects one authenticated socket's lifetime into nonsecret plugin authority [D40,D198,D208].
use infraternal_plugin_api::{Operation, SocketHost, streams::Authority};
use std::sync::{Arc, Weak};
use tokio::sync::watch;

/// Admission is owned by the WebSocket host and its existing auth watchdog.
/// This projection performs no database reads and starts no task or timer.
/// Socket drop withdraws it before workers are cancelled, including workers
/// retaining the same host while a native input write is pending.
pub(crate) struct SocketAuthority {
    live: watch::Sender<bool>,
    host: Option<Weak<dyn SocketHost>>,
}
impl SocketAuthority {
    /// Creates the authority for a newly admitted socket. It holds only a weak reference to `host`, so it never keeps the socket state alive.
    pub(crate) fn admitted(host: Weak<dyn SocketHost>) -> Arc<Self> {
        Arc::new(Self {
            live: watch::channel(true).0,
            host: Some(host),
        })
    }
    /// Test-only authority with no host, so only [`SocketAuthority::withdraw`] ends it.
    #[cfg(test)]
    fn fixture() -> Arc<Self> {
        Arc::new(Self {
            live: watch::channel(true).0,
            host: None,
        })
    }
    /// Ends this socket's authority for good. Every pending and future `authorized` call fails and `cancelled` completes. Safe to call twice.
    pub(crate) fn withdraw(&self) {
        self.live.send_replace(false);
    }
}
impl Authority for SocketAuthority {
    /// True while the socket has not been withdrawn and (if it has a host) the host still exists. Reads memory only.
    fn permits(&self) -> bool {
        *self.live.borrow()
            && self
                .host
                .as_ref()
                .is_none_or(|host| host.strong_count() != 0)
    }
    /// Runs `operation` through the socket host's own authority check. Fails with `Err(())` if authority is already gone, the host has been dropped, or authority is withdrawn while it waits.
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.permits() {
                return Err(());
            }
            let host = self.host.as_ref().and_then(Weak::upgrade).ok_or(())?;
            // A strong host exists only for this bounded forwarding operation.
            // The retained session stores a weak lease, not WebSocketState.
            tokio::select! { biased;
                () = self.cancelled() => Err(()),
                result = host.authorized(operation) => result,
            }
        })
    }
    /// Completes when authority is withdrawn. Returns immediately if it already was.
    fn cancelled(&self) -> Operation<'_, ()> {
        let mut live = self.live.subscribe();
        Box::pin(async move {
            // Subscription precedes the predicate check: a withdrawal between
            // permit inspection and polling cannot strand a blocked writer.
            let _ = live.wait_for(|live| !*live).await;
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn independent_sockets_do_not_inherit_each_others_authority() {
        let first = SocketAuthority::fixture();
        let second = SocketAuthority::fixture();
        let cancelled = first.cancelled();
        first.withdraw();
        tokio::time::timeout(std::time::Duration::from_secs(1), cancelled)
            .await
            .unwrap();
        assert!(!first.permits());
        assert!(second.permits());
        first.cancelled().await;
    }
}
