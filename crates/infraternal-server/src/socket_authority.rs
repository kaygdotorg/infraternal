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
    pub(crate) fn admitted(host: Weak<dyn SocketHost>) -> Arc<Self> {
        Arc::new(Self {
            live: watch::channel(true).0,
            host: Some(host),
        })
    }
    #[cfg(test)]
    fn fixture() -> Arc<Self> {
        Arc::new(Self {
            live: watch::channel(true).0,
            host: None,
        })
    }
    pub(crate) fn withdraw(&self) {
        self.live.send_replace(false);
    }
}
impl Authority for SocketAuthority {
    fn permits(&self) -> bool {
        *self.live.borrow()
            && self
                .host
                .as_ref()
                .is_none_or(|host| host.strong_count() != 0)
    }
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
