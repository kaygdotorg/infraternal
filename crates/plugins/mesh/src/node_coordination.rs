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
// Probe before advertising an extension. Strict older nodes reject the probe,
// then answer the ordinary request without enabling a new representation.
async fn read_identity(channel: &dyn NodeChannel) -> Option<Identity> {
    #[cfg(feature = "mesh-dns-spike")]
    let probe = br#"{"compact_access":true,"dns_names":true}"#.to_vec();
    #[cfg(not(feature = "mesh-dns-spike"))]
    let probe = br#"{"compact_access":true}"#.to_vec();
    let reply = match channel.call("mesh.identity", probe).await {
        Ok(reply) => reply,
        Err(_) => channel.call("mesh.identity", b"{}".to_vec()).await.ok()?,
    };
    serde_json::from_slice::<Option<Identity>>(&reply)
        .ok()
        .flatten()
        .filter(|identity| identity.public_key.0 != [0; 32] && identity.port != 0)
}

/// The hostname the machine's infraternal agent reports in its host facts, when it reports one.
/// Only names a node the host record cannot name (store.rs `attach_named`, #236); any failure reads as none.
async fn read_hostname(channel: &dyn NodeChannel) -> Option<String> {
    let reply = channel
        .call("host.facts.read", br#"{"includeLive":false}"#.to_vec())
        .await
        .ok()?;
    let facts: serde_json::Value = serde_json::from_slice(&reply).ok()?;
    facts["hostname"].as_str().map(str::to_owned)
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
    let mut compact_access = false;
    #[cfg(feature = "mesh-dns-spike")]
    let mut dns_names = false;
    let mut listener: ServerListener = None;
    let mut transport_port = None;
    let mut peer_route: Option<(
        std::net::SocketAddr,
        Box<dyn infraternal_plugin_api::server_path::ListenerLease>,
    )> = None;
    loop {
        if refresh_identity || binding.is_none() {
            refresh_identity = false;
            let identity = read_identity(channel.as_ref()).await;
            if let Some(identity) = identity {
                compact_access = identity.compact_access;
                #[cfg(feature = "mesh-dns-spike")]
                {
                    dns_names = identity.dns_names;
                }
                transport_port = if !channel.is_server() && channel.supports_server_paths() {
                    // Status is extensible; keep the strict identity response
                    // unchanged for older coordinators. The control channel
                    // authenticates these public local socket coordinates.
                    channel
                        .call("mesh.status", b"{}".to_vec())
                        .await
                        .ok()
                        .and_then(|reply| serde_json::from_slice::<serde_json::Value>(&reply).ok())
                        .and_then(|reply| reply["server_link"]["source_port"].as_u64())
                        .and_then(|port| u16::try_from(port).ok())
                        .filter(|port| *port != 0)
                } else {
                    None
                };
                let reported = read_hostname(channel.as_ref()).await;
                let ip = channel.observed_ip();
                let endpoint =
                    (!ip.is_unspecified()).then(|| std::net::SocketAddr::new(ip, identity.port));
                let attached = {
                    let Ok(_permit) = work.acquire().await else {
                        return;
                    };
                    store
                        .attach_named(
                            channel.id(),
                            identity.public_key,
                            endpoint,
                            channel.is_server(),
                            reported.as_deref(),
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
                #[cfg(feature = "mesh-dns-spike")]
                let names_changed = old.name != config.name || old.peer_names != config.peer_names;
                #[cfg(not(feature = "mesh-dns-spike"))]
                let names_changed = false;
                old.server != config.server
                    || old.node != config.node
                    || names_changed
                    || old.addresses != config.addresses
                    || old.default_policy != config.default_policy
                    || old.peers != config.peers
            });
            if changed {
                if !channel.is_server()
                    && let Some(port) = transport_port.filter(|port| *port != 0)
                {
                    let address = std::net::SocketAddr::new(config.addresses.ipv4.into(), port);
                    if peer_route
                        .as_ref()
                        .is_none_or(|(current, _)| *current != address)
                    {
                        // Retire the old mapping before registering the new one;
                        // the live enrolled connection remains authoritative.
                        peer_route = None;
                        if let Ok(Some(lease)) = channel.route_peer(address).await {
                            peer_route = Some((address, lease));
                        }
                    }
                }
                let was_delta = old.is_some();
                // Never send additive fields to an older strict receiver. A
                // refused compact delta still retries the original full snapshot.
                let encoded = if compact_access {
                    crate::access_updates::chunks(old.as_ref(), &config)
                } else {
                    configuration::chunks(old.as_ref(), &config)
                };
                let Ok(chunks) = encoded else {
                    return;
                };
                let mut failed = false;
                for mut chunk in chunks {
                    if !channel.supports_server_paths() {
                        chunk.server = None;
                    }
                    #[cfg(feature = "mesh-dns-spike")]
                    if !dns_names {
                        chunk.name = None;
                        chunk.peer_names.clear();
                    }
                    let Ok(input) = serde_json::to_vec(&chunk) else {
                        return;
                    };
                    #[cfg(feature = "cutoff-measure")]
                    let ack = crate::cutoff_measure::Stage::new(config.node, config.version, "ack");
                    let reply = channel
                        .call("mesh.configure", input)
                        .await
                        .ok()
                        .and_then(|reply| serde_json::from_slice::<serde_json::Value>(&reply).ok());
                    #[cfg(feature = "cutoff-measure")]
                    drop(ack);
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
            peer_route = None;
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
        legacy_host_facts: bool,
        path_capable: AtomicBool,
        leases: Arc<AtomicUsize>,
        refuse_listener: AtomicBool,
        listened: tokio::sync::Notify,
        notices: Mutex<Option<tokio::sync::watch::Sender<()>>>,
        enabled: AtomicBool,
        refuse_delta: AtomicBool,
        queried: tokio::sync::Notify,
        applied: tokio::sync::Semaphore,
        frames: Mutex<Vec<(Option<u64>, u64, bool)>>,
        hostname: Option<&'static str>,
    }
    impl Channel {
        fn new() -> Arc<Self> {
            Self::with_server(false)
        }
        fn with_server(server: bool) -> Arc<Self> {
            Self::named(server, None)
        }
        fn named(server: bool, hostname: Option<&'static str>) -> Arc<Self> {
            let (notices, _) = tokio::sync::watch::channel(());
            Arc::new(Self {
                server,
                legacy_host_facts: false,
                path_capable: AtomicBool::new(server),
                leases: Arc::default(),
                refuse_listener: AtomicBool::new(false),
                listened: tokio::sync::Notify::new(),
                notices: Mutex::new(Some(notices)),
                enabled: AtomicBool::new(true),
                refuse_delta: AtomicBool::new(false),
                queried: tokio::sync::Notify::new(),
                applied: tokio::sync::Semaphore::new(0),
                frames: Mutex::new(Vec::new()),
                hostname,
            })
        }
        fn legacy() -> Arc<Self> {
            let mut channel = Self::named(false, None);
            Arc::get_mut(&mut channel)
                .expect("new test channel is uniquely owned")
                .legacy_host_facts = true;
            channel
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
            if self.server {
                "server"
            } else {
                "00000000-0000-4000-8000-000000000001"
            }
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::new(192, 0, 2, 1).into()
        }
        fn is_server(&self) -> bool {
            self.server
        }
        fn supports_server_paths(&self) -> bool {
            self.path_capable.load(Ordering::Acquire)
        }
        fn route_peer(
            &self,
            address: std::net::SocketAddr,
        ) -> PluginOperation<'_, Option<Box<dyn infraternal_plugin_api::server_path::ListenerLease>>>
        {
            Box::pin(async move {
                assert!(!self.server);
                assert_eq!(address.port(), 43210);
                assert_ne!(address.ip(), self.observed_ip());
                self.leases.fetch_add(1, Ordering::AcqRel);
                Ok(Some(Box::new(Lease(self.leases.clone()))
                    as Box<
                        dyn infraternal_plugin_api::server_path::ListenerLease,
                    >))
            })
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
                    // Model the strict legacy request parser to exercise fallback.
                    if input != b"{}" {
                        return Err("unsupported identity probe");
                    }
                    self.queried.notify_one();
                    return serde_json::to_vec(&self.enabled.load(Ordering::Acquire).then_some(
                        Identity {
                            compact_access: false,
                            #[cfg(feature = "mesh-dns-spike")]
                            dns_names: false,
                            public_key: PublicKey([if self.server { 1 } else { 2 }; 32]),
                            port: 44000,
                        },
                    ))
                    .map_err(|_| "encoding failed");
                }
                if action == "mesh.status" {
                    return Ok(br#"{"server_link":{"source_port":43210}}"#.to_vec());
                }
                if action == "host.facts.read" {
                    if self.legacy_host_facts {
                        // A release-4-era infraternal agent returns the old shape without `hostname`.
                        return Ok(br#"{"os":"Linux"}"#.to_vec());
                    }
                    return self
                        .hostname
                        .map(|name| format!(r#"{{"hostname":"{name}"}}"#).into_bytes())
                        .ok_or("host facts disabled");
                }
                assert_eq!(action, "mesh.configure");
                if !self.server && self.supports_server_paths() {
                    assert_eq!(
                        self.leases.load(Ordering::Acquire),
                        1,
                        "routing must be ready before configuration publishes the path"
                    );
                }
                assert!(input.len() <= infraternal_plugin_api::MAX_ACTION_BYTES);
                if !self.server && !self.supports_server_paths() {
                    assert!(
                        serde_json::from_slice::<serde_json::Value>(&input)
                            .unwrap()
                            .get("server")
                            .is_none()
                    );
                }
                let chunk: crate::dataplane::Chunk = serde_json::from_slice(&input).unwrap();
                #[cfg(feature = "mesh-dns-spike")]
                {
                    assert!(chunk.name.is_none());
                    assert!(chunk.peer_names.is_empty());
                }
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
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
            .bind(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap().as_bytes().as_slice())
            .execute(&pool).await.unwrap();
        let service = MeshService::new(pool);
        service
            .dataplane()
            .attach("server", PublicKey([1; 32]), None, true)
            .await
            .unwrap();
        service
    }
    async fn names(service: &MeshService) -> Vec<String> {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let snapshot = service
            .list("owner", crate::api::MeshFilter::default(), now)
            .await
            .unwrap();
        snapshot
            .nodes
            .into_iter()
            .map(|node| node.node.host)
            .collect()
    }
    async fn attach_once(service: &MeshService, channel: Arc<Channel>) {
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        worker.abort();
        let _ = worker.await;
    }
    /// Owner report 2026-10-17 (#236): minipc01 appeared as "mesh-<host id>" and the server as "server".
    #[tokio::test]
    async fn placeholder_names_become_the_machines_names() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        // Enrolled before names were known: the node carries a placeholder.
        service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        assert_eq!(names(&service).await, ["server", "unnamed"]);
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@minipc01')")
            .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
            .execute(&service.pool_for_tests())
            .await
            .unwrap();
        // The host record wins over what the machine reports.
        attach_once(&service, Channel::named(false, Some("other-name"))).await;
        attach_once(&service, Channel::named(true, Some("monitor01"))).await;
        assert_eq!(names(&service).await, ["monitor01", "minipc01"]);
    }
    /// A release-4-era host added by IP provides no usable name; a migrated UUID placeholder must become `unnamed`.
    #[tokio::test]
    async fn legacy_host_daemon_and_ip_record_do_not_leave_a_uuid_mesh_name() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        sqlx::query(
            "UPDATE mesh_nodes SET name=?,name_source='placeholder',name_claim=NULL WHERE dataplane_host=?",
        )
        .bind(format!("mesh-{host}"))
        .bind(host)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        attach_once(&service, Channel::legacy()).await;

        assert_eq!(names(&service).await, ["server", "unnamed"]);
    }
    #[tokio::test]
    async fn a_reported_hostname_names_a_host_added_by_address() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
        .execute(&service.pool_for_tests())
        .await
        .unwrap();
        attach_once(&service, Channel::named(false, Some("minipc01"))).await;
        assert_eq!(names(&service).await, ["server", "minipc01"]);
    }
    #[tokio::test]
    async fn two_hosts_reporting_the_same_hostname_receive_distinct_names() {
        let service = service().await;
        let first = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let second = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let pool = service.pool_for_tests();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(first.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
            .bind(second.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.218')",
        )
        .bind(second.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        service
            .dataplane()
            .attach_named(
                &first.to_string(),
                PublicKey([2; 32]),
                None,
                false,
                Some("minipc01"),
            )
            .await
            .unwrap();
        service
            .dataplane()
            .attach_named(
                &second.to_string(),
                PublicKey([3; 32]),
                None,
                false,
                Some("minipc01"),
            )
            .await
            .unwrap();

        assert_eq!(names(&service).await, ["server", "minipc01", "minipc01-2"]);
    }
    #[tokio::test]
    async fn a_name_a_person_chose_is_kept() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        let (node, _) = service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        service
            .execute(
                "owner",
                "mesh.node.rename",
                &serde_json::to_vec(&serde_json::json!({"node_id":node.0,"name":"lab"})).unwrap(),
                1,
            )
            .await
            .unwrap();
        attach_once(&service, Channel::named(false, Some("minipc01"))).await;
        assert_eq!(names(&service).await, ["server", "lab"]);
    }
    #[tokio::test]
    async fn peer_route_precedes_configuration_and_retires_with_the_node() {
        let service = service().await;
        let channel = Channel::new();
        channel.path_capable.store(true, Ordering::Release);
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.enabled.store(false, Ordering::Release);
        channel.changed();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while channel.leases.load(Ordering::Acquire) != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let _ = worker.await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
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
                "00000000-0000-4000-8000-000000000001",
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
                "00000000-0000-4000-8000-000000000001",
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
                .attach(
                    "00000000-0000-4000-8000-000000000001",
                    PublicKey([2; 32]),
                    None,
                    false
                )
                .await
                .is_err()
        );
        service
            .execute(
                "owner",
                "mesh.node.enroll",
                &serde_json::to_vec(
                    &serde_json::json!({"name":"reenrolled","public_key":PublicKey([2;32]),"host_id":"00000000-0000-4000-8000-000000000001"}),
                )
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        channel.wait().await;
        let (new, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
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
