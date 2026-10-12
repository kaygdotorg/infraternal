//! Issues public configurations over authenticated node channels and committed Access changes [163,166,169,198].
use crate::{
    api::{MeshApiError, MeshService},
    configuration,
    dataplane::Identity,
    store::{Snapshot, Store},
};
use infraternal_plugin_api::node_channel::NodeChannel;
use std::sync::Arc;
type ServerListener = Option<(
    std::net::IpAddr,
    Box<dyn infraternal_plugin_api::server_path::ListenerLease>,
)>;

/// Keep a working listener until its replacement is actually bound.
async fn update_listener(
    channel: &dyn NodeChannel,
    address: std::net::IpAddr,
    listener: &mut ServerListener,
) {
    if listener
        .as_ref()
        .is_none_or(|(current, _)| *current != address)
        && let Ok(Some(lease)) = channel.listen_server(address).await
    {
        *listener = Some((address, lease));
    }
}
/// One event-driven worker belongs to the generic plugin lifecycle; disabling
/// aborts and joins it. A disconnect never deletes durable mesh membership.
// Keep acknowledged-version recovery and source invalidation in one event loop.
#[allow(clippy::too_many_lines)]
pub async fn run(
    store: Store,
    service: MeshService,
    channel: Arc<dyn NodeChannel>,
    work: Arc<tokio::sync::Semaphore>,
) {
    let mut revisions = service.subscribe();
    let mut notices = channel.changes();
    let mut binding = None;
    let mut installed: Option<Snapshot> = None;
    let mut refresh_identity = true;
    let mut listener: ServerListener = None;
    loop {
        if refresh_identity || binding.is_none() {
            refresh_identity = false;
            let identity = channel
                .call("mesh.identity", b"{}".to_vec())
                .await
                .ok()
                .and_then(|reply| {
                    serde_json::from_slice::<Option<Identity>>(&reply)
                        .ok()
                        .flatten()
                })
                .filter(|identity| identity.public_key.0 != [0; 32] && identity.port != 0);
            if let Some(identity) = identity {
                let ip = channel.observed_ip();
                let endpoint =
                    (!ip.is_unspecified()).then(|| std::net::SocketAddr::new(ip, identity.port));
                let attached = {
                    let Ok(_permit) = work.acquire().await else {
                        return;
                    };
                    store
                        .attach(
                            channel.id(),
                            identity.public_key,
                            endpoint,
                            channel.is_server(),
                        )
                        .await
                };
                if let Ok((node, updated)) = attached {
                    binding = Some(node);
                    if updated {
                        let Ok(_permit) = work.acquire().await else {
                            return;
                        };
                        service.invalidate_dataplane().await;
                    }
                } else {
                    binding = None;
                    installed = None;
                }
            } else {
                binding = None;
                installed = None;
            }
        }
        let config = if let Some(node) = binding {
            match work.acquire().await {
                Ok(_permit) => match store
                    .snapshot()
                    .await
                    .and_then(|snapshot| snapshot.config(node).map(|config| (config, snapshot)))
                {
                    Ok(config) => Some(config),
                    Err(MeshApiError::NotFound) => {
                        // A deleted binding can be re-enrolled before this worker
                        // sees the notification. Re-query once; the tombstone
                        // still rejects attachment unless the owner enrolled it.
                        binding = None;
                        installed = None;
                        continue;
                    }
                    Err(_) => None,
                },
                Err(_) => return,
            }
        } else {
            None
        };
        if let Some((config, snapshot)) = config {
            let old = installed
                .as_ref()
                .and_then(|snapshot| snapshot.config(config.node).ok());
            // Liveness and management-role edits advance inventory revision but
            // do not change packet policy. Keep the node's acknowledged version
            // as the delta base, avoiding an unchanged snapshot/fsync per node.
            let changed = old.as_ref().is_none_or(|old| {
                old.server != config.server
                    || old.node != config.node
                    || old.addresses != config.addresses
                    || old.default_policy != config.default_policy
                    || old.peers != config.peers
            });
            if changed {
                let was_delta = old.is_some();
                let Ok(chunks) = configuration::chunks(old.as_ref(), &config) else {
                    return;
                };
                let mut failed = false;
                for mut chunk in chunks {
                    if !channel.supports_server_paths() {
                        chunk.server = None;
                    }
                    let Ok(input) = serde_json::to_vec(&chunk) else {
                        return;
                    };
                    let reply = channel
                        .call("mesh.configure", input)
                        .await
                        .ok()
                        .and_then(|reply| serde_json::from_slice::<serde_json::Value>(&reply).ok());
                    if !reply.is_some_and(|reply| {
                        !chunk.last
                            || reply["applied"] == true && reply["version"] == config.version
                    }) {
                        failed = true;
                        break;
                    }
                }
                installed = if failed { None } else { Some(snapshot) };
                // A refused delta needs a snapshot now, not a future unrelated
                // edit. A failed snapshot waits for a source change rather than spinning.
                if failed && was_delta {
                    continue;
                }
            }
        }
        if binding.is_none() {
            // Local off and membership removal own listener teardown too.
            listener = None;
        } else if channel.is_server()
            && let Some(snapshot) = &installed
            && let Some(node) = binding
            && let Ok(config) = snapshot.config(node)
        {
            let address = std::net::IpAddr::V4(config.addresses.ipv4);
            update_listener(channel.as_ref(), address, &mut listener).await;
        }
        // No retry timer or heartbeat. Reconnect, local up/down, or committed
        // policy change is the only wakeup. Closed sources retire the worker.
        tokio::select! {
            result=notices.changed()=> {if result.is_err() {return;}refresh_identity=true;installed=None;},
            result=revisions.recv()=>if matches!(result,Err(tokio::sync::broadcast::error::RecvError::Closed)) {return;},
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::policy::model::PublicKey;
    use infraternal_plugin_api::PluginOperation;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    struct Lease(Arc<AtomicUsize>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    struct Channel {
        server: bool,
        leases: Arc<AtomicUsize>,
        refuse_listener: AtomicBool,
        listened: tokio::sync::Notify,
        notices: Mutex<Option<tokio::sync::watch::Sender<()>>>,
        enabled: AtomicBool,
        refuse_delta: AtomicBool,
        queried: tokio::sync::Notify,
        applied: tokio::sync::Semaphore,
        frames: Mutex<Vec<(Option<u64>, u64, bool)>>,
    }
    impl Channel {
        fn new() -> Arc<Self> {
            Self::with_server(false)
        }
        fn with_server(server: bool) -> Arc<Self> {
            let (notices, _) = tokio::sync::watch::channel(());
            Arc::new(Self {
                server,
                leases: Arc::default(),
                refuse_listener: AtomicBool::new(false),
                listened: tokio::sync::Notify::new(),
                notices: Mutex::new(Some(notices)),
                enabled: AtomicBool::new(true),
                refuse_delta: AtomicBool::new(false),
                queried: tokio::sync::Notify::new(),
                applied: tokio::sync::Semaphore::new(0),
                frames: Mutex::new(Vec::new()),
            })
        }
        fn changed(&self) {
            self.notices
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send_replace(());
        }
        async fn wait(&self) {
            tokio::time::timeout(std::time::Duration::from_secs(5), self.applied.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
    }
    impl NodeChannel for Channel {
        fn id(&self) -> &'static str {
            if self.server { "server" } else { "host" }
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::new(192, 0, 2, 1).into()
        }
        fn is_server(&self) -> bool {
            self.server
        }
        fn supports_server_paths(&self) -> bool {
            self.server
        }
        fn listen_server(
            &self,
            _address: std::net::IpAddr,
        ) -> PluginOperation<'_, Option<Box<dyn infraternal_plugin_api::server_path::ListenerLease>>>
        {
            Box::pin(async move {
                if self.refuse_listener.load(Ordering::Acquire) {
                    return Err("Listener refused.");
                }
                self.leases.fetch_add(1, Ordering::AcqRel);
                self.listened.notify_one();
                Ok(Some(Box::new(Lease(self.leases.clone()))
                    as Box<
                        dyn infraternal_plugin_api::server_path::ListenerLease,
                    >))
            })
        }
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            self.notices.lock().unwrap().as_ref().unwrap().subscribe()
        }
        fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
            let action = action.to_owned();
            Box::pin(async move {
                if action == "mesh.identity" {
                    self.queried.notify_one();
                    return serde_json::to_vec(&self.enabled.load(Ordering::Acquire).then_some(
                        Identity {
                            public_key: PublicKey([if self.server { 1 } else { 2 }; 32]),
                            port: 44000,
                        },
                    ))
                    .map_err(|_| "encoding failed");
                }
                assert_eq!(action, "mesh.configure");
                assert!(input.len() <= infraternal_plugin_api::MAX_ACTION_BYTES);
                if !self.server {
                    assert!(
                        serde_json::from_slice::<serde_json::Value>(&input)
                            .unwrap()
                            .get("server")
                            .is_none()
                    );
                }
                let chunk: crate::dataplane::Chunk = serde_json::from_slice(&input).unwrap();
                self.frames
                    .lock()
                    .unwrap()
                    .push((chunk.from_version, chunk.version, chunk.last));
                if chunk.from_version.is_some() && self.refuse_delta.swap(false, Ordering::AcqRel) {
                    return Err("stale version");
                }
                if chunk.last {
                    self.applied.add_permits(1);
                }
                Ok(serde_json::to_vec(
                    &serde_json::json!({"applied":chunk.last,"version":chunk.version}),
                )
                .unwrap())
            })
        }
    }
    async fn service() -> MeshService {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../../infraternal-server/migrations")
            .run(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
        let service = MeshService::new(pool);
        service
            .dataplane()
            .attach("server", PublicKey([1; 32]), None, true)
            .await
            .unwrap();
        service
    }
    #[tokio::test]
    async fn refused_listener_replacement_preserves_the_current_lease() {
        let channel = Channel::with_server(true);
        let old = "127.0.0.1".parse().unwrap();
        let new = "127.0.0.2".parse().unwrap();
        let mut listener = None;
        update_listener(channel.as_ref(), old, &mut listener).await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.refuse_listener.store(true, Ordering::Release);
        update_listener(channel.as_ref(), new, &mut listener).await;
        assert_eq!(listener.as_ref().unwrap().0, old);
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.refuse_listener.store(false, Ordering::Release);
        update_listener(channel.as_ref(), new, &mut listener).await;
        assert_eq!(listener.as_ref().unwrap().0, new);
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        drop(listener);
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn server_listener_belongs_to_applied_enabled_worker() {
        let service = service().await;
        let channel = Channel::with_server(true);
        channel.enabled.store(false, Ordering::Release);
        let task = tokio::spawn(run(
            service.dataplane(),
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.listened.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.enabled.store(false, Ordering::Release);
        channel.changed();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while channel.leases.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.listened.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
    }
    #[tokio::test]
    async fn refused_delta_recovers_immediately_and_closed_channel_retires_worker() {
        let service = service().await;
        let store = service.dataplane();
        let channel = Channel::new();
        let task = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let (node, _) = store
            .attach(
                "host",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let before = store.config(node).await.unwrap();
        channel.refuse_delta.store(true, Ordering::Release);
        let next = if before.default_policy == crate::dataplane::DefaultPolicy::Allow {
            crate::dataplane::DefaultPolicy::Deny
        } else {
            crate::dataplane::DefaultPolicy::Allow
        };
        service
            .execute(
                "owner",
                "mesh.default.set",
                &serde_json::to_vec(
                    &serde_json::json!({"default_policy":next,"expected_revision":before.version}),
                )
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        channel.wait().await;
        let frames = channel.frames.lock().unwrap().clone();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0, None);
        assert_eq!(frames[1].0, Some(before.version));
        assert_eq!(frames[2].0, None);
        assert_eq!(frames[1].1, frames[2].1);
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn explicit_off_waits_for_up_and_reconnect_requests_a_snapshot() {
        let service = service().await;
        let channel = Channel::new();
        channel.enabled.store(false, Ordering::Release);
        let task = tokio::spawn(run(
            service.dataplane(),
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        // The query notification fences scheduling without a polling loop.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .unwrap();
        assert!(channel.frames.lock().unwrap().is_empty());
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        channel.changed();
        channel.wait().await;
        assert!(
            channel
                .frames
                .lock()
                .unwrap()
                .iter()
                .all(|frame| frame.0.is_none())
        );
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn removed_binding_can_attach_only_after_authorized_reenrollment() {
        let service = service().await;
        let store = service.dataplane();
        let channel = Channel::new();
        let task = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let (old, _) = store
            .attach(
                "host",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        service
            .execute(
                "owner",
                "mesh.node.delete",
                &serde_json::to_vec(&serde_json::json!({"node_id":old.0})).unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        assert!(
            store
                .attach("host", PublicKey([2; 32]), None, false)
                .await
                .is_err()
        );
        service
            .execute(
                "owner",
                "mesh.node.enroll",
                &serde_json::to_vec(
                    &serde_json::json!({"name":"reenrolled","public_key":PublicKey([2;32])}),
                )
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        channel.wait().await;
        let (new, _) = store
            .attach(
                "host",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        assert_ne!(old, new);
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
