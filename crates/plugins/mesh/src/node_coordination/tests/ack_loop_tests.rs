//! Regression checks for receipt write amplification and self-published rotation wakeups (#537).
use super::*;

/// Build the shipping migrated schema on a real WAL database, outside the checkout.
async fn file_service() -> (std::path::PathBuf, MeshService) {
    let directory = std::env::temp_dir().join(format!("ack-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(directory.join("mesh.sqlite"))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    (directory, service_on_pool(pool).await)
}

/// Count every receipt mutation, including unchanged indexed UPSERTs, in its committing transaction.
async fn count_receipt_writes(pool: &sqlx::SqlitePool) {
    sqlx::raw_sql("CREATE TABLE ack_writes(v INTEGER); CREATE TRIGGER ack_insert AFTER INSERT ON mesh_node_applied BEGIN INSERT INTO ack_writes VALUES(1); END; CREATE TRIGGER ack_update AFTER UPDATE ON mesh_node_applied BEGIN INSERT INTO ack_writes VALUES(1); END;")
        .execute(pool).await.unwrap();
}

/// A supported node whose cleanup refuses to finish, matching the production trigger.
struct StuckFinish {
    /// Ordinary authenticated configuration channel.
    inner: Arc<Channel>,
    /// Actual finish attempt instants, used to check the five-second retry deadline.
    attempts: Mutex<Vec<tokio::time::Instant>>,
    /// Event barrier for finish calls, independent of scheduler speed.
    finished: tokio::sync::Semaphore,
}

impl NodeChannel for StuckFinish {
    /// Preserve the authenticated host identity of the wrapped node.
    fn id(&self) -> &str {
        self.inner.id()
    }
    /// Preserve the observed source address.
    fn observed_ip(&self) -> std::net::IpAddr {
        self.inner.observed_ip()
    }
    /// Identify the embedded server worker when present.
    fn is_server(&self) -> bool {
        self.inner.is_server()
    }
    /// Share the wrapped node's channel notices.
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.inner.changes()
    }
    /// Accept the candidate commit but refuse cleanup; other actions use the ordinary fixture.
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
        if action == "mesh.rotation.commit" {
            return Box::pin(async {
                Ok(
                    serde_json::to_vec(&serde_json::json!({"public_key": PublicKey([3; 32])}))
                        .unwrap(),
                )
            });
        }
        if action == "mesh.rotation.finish" {
            return Box::pin(async {
                self.attempts
                    .lock()
                    .unwrap()
                    .push(tokio::time::Instant::now());
                self.finished.add_permits(1);
                Err("finish receipt unavailable")
            });
        }
        self.inner.call(action, input)
    }
}

/// Coalescing an already committed peer receipt cannot lose the expired-overlap transition.
#[tokio::test]
async fn coalesced_peer_progress_is_read_before_overlap_retires() {
    let (directory, service) = file_service().await;
    let store = service.dataplane();
    let pool = service.pool_for_tests();
    let (node, _, operation) = rotating_node(
        &service,
        "00000000-0000-4000-8000-000000000001",
        PublicKey([2; 32]),
    )
    .await;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
    let nanos = clock.tv_sec() * 1_000_000_000 + clock.tv_nsec();
    let revision = store
        .start_rotation_overlap(
            node,
            &operation.operation_id,
            PublicKey([3; 32]),
            100,
            boot.trim(),
            nanos,
        )
        .await
        .unwrap();
    let server = store.node_for_host("server").await.unwrap();
    let live = [node, server].into_iter().collect();
    let channel = StuckFinish {
        inner: Channel::candidate(),
        attempts: Mutex::default(),
        finished: tokio::sync::Semaphore::new(0),
    };
    let identity = Identity {
        compact_access: false,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: true,
        authority_epoch: true,
        rotation_continuity: true,
        public_key: PublicKey([2; 32]),
        port: 44000,
    };
    assert!(
        crate::rotation::drive(&store, &service, &channel, node, &identity, &live)
            .await
            .is_some()
    );
    sqlx::query("UPDATE mesh_node_key_rotation SET rotation_monotonic=? WHERE node_id=?")
        .bind(nanos - 121_000_000_000)
        .bind(i64::try_from(node.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        crate::rotation::drive(&store, &service, &channel, node, &identity, &live).await,
        None
    );
    let mut own = service.subscribe_rotation_progress();
    let mut peer = service.subscribe_rotation_progress();
    assert!(store.acknowledge_applied(server, revision).await.unwrap());
    service.rotation_applied(&mut peer);
    assert!(store.acknowledge_applied(node, revision).await.unwrap());
    service.rotation_applied(&mut own);
    assert!(!own.has_changed().unwrap());
    assert_eq!(
        crate::rotation::drive(&store, &service, &channel, node, &identity, &live).await,
        Some(std::time::Duration::ZERO)
    );
    assert_eq!(
        rotation_row(&service, i64::try_from(node.0).unwrap())
            .await
            .2
            .as_deref(),
        Some("retiring")
    );
    // Events committed after the pass must remain visible to its next select.
    service.rotation_applied(&mut peer);
    assert!(own.has_changed().unwrap());
    println!(
        "ACK_OVERLAP minimum_overlap_preserved=true missing_peer_waits=true coalesced_peer_seen=true later_progress_pending=true"
    );
    pool.close().await;
    std::fs::remove_dir_all(directory).unwrap();
}

/// Read Linux process CPU ticks and disk write accounting for the focused before/after receipt run.
fn process_counters() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .map_or("", |(_, rest)| rest)
        .split_whitespace()
        .collect();
    let ticks = [11, 12]
        .into_iter()
        .filter_map(|index| fields.get(index)?.parse::<u64>().ok())
        .sum();
    let io = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
    let writes = io
        .lines()
        .find_map(|line| line.strip_prefix("write_bytes: ")?.parse().ok())
        .unwrap_or(0);
    (ticks, writes)
}

/// Quiet views settle after one receipt per worker, even while cleanup retries indefinitely.
#[tokio::test]
async fn unchanged_views_do_not_loop_acknowledgments() {
    let mut violations = Vec::new();
    for workers in [1_u32, 2] {
        for pending in [false, true] {
            let (directory, service) = file_service().await;
            let store = service.dataplane();
            let pool = service.pool_for_tests();
            if workers == 2 {
                store
                    .attach_named_with_probed_capabilities(
                        "server",
                        PublicKey([1; 32]),
                        Some("192.0.2.1:44000".parse().unwrap()),
                        true,
                        None,
                        Some(true),
                        Some(true),
                    )
                    .await
                    .unwrap();
            }
            let (node, _) = store
                .attach_named_with_probed_capabilities(
                    "00000000-0000-4000-8000-000000000001",
                    PublicKey([3; 32]),
                    Some("192.0.2.1:44000".parse().unwrap()),
                    false,
                    None,
                    Some(true),
                    Some(true),
                )
                .await
                .unwrap();
            let revision = store.config(node).await.unwrap().version;
            if pending {
                sqlx::query("UPDATE mesh_node_key_rotation SET rotation_phase='cleanup',operation_id='00000000-0000-4000-8000-000000000537',sequence=1,rotation_started_at=100,rotation_boot_id='fixture',rotation_monotonic=1,rotation_revision=?,local_committed=1 WHERE node_id=?")
                    .bind(i64::try_from(revision + 1).unwrap()).bind(i64::try_from(node.0).unwrap())
                    .execute(&pool).await.unwrap();
                sqlx::query("UPDATE mesh_state SET revision=revision+1")
                    .execute(&pool)
                    .await
                    .unwrap();
                assert!(store.snapshot().await.unwrap().acknowledgments_required());
            }
            count_receipt_writes(&pool).await;
            let mut progress = service.subscribe_rotation_progress();
            let channel = Arc::new(StuckFinish {
                inner: Channel::candidate(),
                attempts: Mutex::default(),
                finished: tokio::sync::Semaphore::new(0),
            });
            let work = Arc::new(tokio::sync::Semaphore::new(1));
            let mut tasks = vec![tokio::spawn(run(
                store.clone(),
                service.clone(),
                channel.clone(),
                work.clone(),
            ))];
            let mut channels = vec![channel.inner.clone()];
            if workers == 2 {
                let mut server = Channel::named(true, None);
                let inner = Arc::get_mut(&mut server).unwrap();
                inner.key_rotation = true;
                inner.probe_answers.store(true, Ordering::Release);
                inner.path_capable.store(false, Ordering::Release);
                tasks.push(tokio::spawn(run(
                    store.clone(),
                    service.clone(),
                    server.clone(),
                    work,
                )));
                channels.push(server);
            }
            for configured in &channels {
                configured.wait().await;
            }
            let counters = process_counters();
            let started = std::time::Instant::now();
            // sleep: measure absence of autonomous receipt commits over a fixed quiet window.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let first_window = started.elapsed().as_secs_f64();
            let initial: i64 = sqlx::query_scalar("SELECT count(*) FROM ack_writes")
                .fetch_one(&pool)
                .await
                .unwrap();
            let notifications = *progress.borrow_and_update();
            let (ticks, writes) = process_counters();
            let wal_bytes = std::fs::metadata(directory.join("mesh.sqlite-wal"))
                .unwrap()
                .len();
            println!(
                "ACK_IO workers={workers} pending={pending} seconds={first_window:.3} cpu_ticks={} disk_write_bytes={} wal_bytes={wal_bytes}",
                ticks.saturating_sub(counters.0),
                writes.saturating_sub(counters.1)
            );
            // Inject one external source event and verify it does not restart the progress chain.
            service.rotation_applied(&mut progress);
            channels[0].changed();
            channels[0].wait().await;
            // sleep: observe whether an external delivery starts another acknowledgment loop.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let after: i64 = sqlx::query_scalar("SELECT count(*) FROM ack_writes")
                .fetch_one(&pool)
                .await
                .unwrap();
            let rate = f64::from(u32::try_from(initial).unwrap()) / first_window;
            let mut retry_interval = None;
            if pending && workers == 2 {
                let available = u32::try_from(channel.finished.available_permits()).unwrap();
                channel
                    .finished
                    .acquire_many(available)
                    .await
                    .unwrap()
                    .forget();
                let retried = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    channel.finished.acquire_many(2),
                )
                .await;
                if let Ok(Ok(permits)) = retried {
                    permits.forget();
                    let times = channel.attempts.lock().unwrap();
                    retry_interval =
                        Some(times[times.len() - 1].duration_since(times[times.len() - 2]));
                }
            }
            println!(
                "ACK_RATE workers={workers} pending={pending} initial_ack_commits={initial} after_external_event={after} approx_initial_commits_per_second={rate:.3} notifications={notifications}"
            );
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            let final_writes: i64 = sqlx::query_scalar("SELECT count(*) FROM ack_writes")
                .fetch_one(&pool)
                .await
                .unwrap();
            pool.close().await;
            std::fs::remove_dir_all(directory).unwrap();
            if pending && workers == 2 {
                if retry_interval.is_none_or(|interval| interval < UNKNOWN_SUPPORT_RETRY) {
                    violations.push(format!(
                        "cleanup lost its five-second retry: {retry_interval:?}"
                    ));
                }
                println!(
                    "ACK_FINISH_RETRY interval={retry_interval:?} unchanged_ack_writes={}",
                    final_writes - initial
                );
            }
            if initial > i64::from(workers) * i64::from(pending)
                || after != initial
                || final_writes != initial
                || notifications > u64::from(workers) * u64::from(pending)
            {
                violations.push(format!("workers={workers} pending={pending} initial={initial} after={after} final={final_writes} notifications={notifications}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "unchanged acknowledgment loop: {violations:?}"
    );
}

/// Durable receipts never regress, and fresh instances must persist their own acknowledgment once.
#[tokio::test]
async fn identical_stale_concurrent_and_new_instance_receipts() {
    let (directory, service) = file_service().await;
    let pool = service.pool_for_tests();
    let store = service.dataplane();
    let node = store.node_for_host("server").await.unwrap();
    sqlx::query("UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id='00000000-0000-4000-8000-000000000537',sequence=1")
        .execute(&pool).await.unwrap();
    count_receipt_writes(&pool).await;
    assert!(store.acknowledge_applied(node, 10).await.unwrap());
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .unwrap();
    for revision in [10, 9, 0, 10] {
        assert!(!store.acknowledge_applied(node, revision).await.unwrap());
    }
    assert_eq!(
        std::fs::metadata(directory.join("mesh.sqlite-wal"))
            .unwrap()
            .len(),
        0,
        "no-op receipts added WAL frames"
    );
    let (a, b) = tokio::join!(
        store.acknowledge_applied(node, 11),
        store.acknowledge_applied(node, 11)
    );
    assert_eq!(u32::from(a.unwrap()) + u32::from(b.unwrap()), 1);
    let current: i64 = sqlx::query_scalar("SELECT revision FROM mesh_node_applied")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(current, 11);
    let restarted = Store::new(pool.clone());
    assert!(restarted.acknowledge_applied(node, 11).await.unwrap());
    assert!(!restarted.acknowledge_applied(node, 11).await.unwrap());
    assert!(
        restarted
            .rotation_acks_ready(11, &[node].into_iter().collect())
            .await
            .unwrap()
    );
    assert!(
        !store
            .rotation_acks_ready(11, &[node].into_iter().collect())
            .await
            .unwrap()
    );
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM ack_writes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(writes, 3);
    let mut publisher = service.subscribe_rotation_progress();
    let mut observer = service.subscribe_rotation_progress();
    service.rotation_applied(&mut publisher);
    assert!(!publisher.has_changed().unwrap(), "publisher woke itself");
    assert!(
        observer.has_changed().unwrap(),
        "other driver was not woken"
    );
    assert_eq!(*observer.borrow_and_update(), 1);
    println!(
        "ACK_STORAGE mutations=3 duplicate_stale_mutations=0 concurrent_advances=1 fresh_instance_advances=1 self_wake=false"
    );
    pool.close().await;
    std::fs::remove_dir_all(directory).unwrap();
}

/// Deliver different revisions concurrently and then replay the older one after both complete.
#[tokio::test]
async fn reordered_receipts_keep_the_highest_revision() {
    let (directory, service) = file_service().await;
    let store = service.dataplane();
    let pool = service.pool_for_tests();
    let node = store.node_for_host("server").await.unwrap();
    sqlx::query("UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id='00000000-0000-4000-8000-000000000537',sequence=1")
        .execute(&pool).await.unwrap();
    for round in 1..=32 {
        let high = round * 2;
        let (old, new) = tokio::join!(
            store.acknowledge_applied(node, high - 1),
            store.acknowledge_applied(node, high)
        );
        old.unwrap();
        assert!(new.unwrap());
        assert!(!store.acknowledge_applied(node, high - 1).await.unwrap());
        let actual: i64 =
            sqlx::query_scalar("SELECT revision FROM mesh_node_applied WHERE node_id=?")
                .bind(i64::try_from(node.0).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(actual, i64::try_from(high).unwrap());
    }
    println!("ACK_REORDER concurrent_pairs=32 delayed_stale_replays=32 highest_revision=64");
    pool.close().await;
    std::fs::remove_dir_all(directory).unwrap();
}

/// A sleeping retirement driver consumes a peer's real receipt and acknowledges the new cleanup revision.
#[tokio::test]
async fn peer_progress_wakes_retirement_and_the_next_revision() {
    let (directory, service) = file_service().await;
    let store = service.dataplane();
    let pool = service.pool_for_tests();
    let (node, _, operation) = rotating_node(
        &service,
        "00000000-0000-4000-8000-000000000001",
        PublicKey([2; 32]),
    )
    .await;
    store
        .start_rotation_overlap(
            node,
            &operation.operation_id,
            PublicKey([3; 32]),
            100,
            "test-boot",
            1,
        )
        .await
        .unwrap();
    let revision = store
        .commit_rotation(node, &operation.operation_id)
        .await
        .unwrap();
    let server = store.node_for_host("server").await.unwrap();
    service.set_presence([(node, None), (server, None)].into_iter().collect());
    let channel = Arc::new(StuckFinish {
        inner: Channel::candidate(),
        attempts: Mutex::default(),
        finished: tokio::sync::Semaphore::new(0),
    });
    let mut progress = service.subscribe_rotation_progress();
    let task = tokio::spawn(run(
        store.clone(),
        service.clone(),
        channel.clone(),
        Arc::new(tokio::sync::Semaphore::new(1)),
    ));
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        // The worker has committed its receipt, but the reachable server has not.
        progress.changed().await.unwrap();
        assert_eq!(rotation_row(&service, i64::try_from(node.0).unwrap()).await.2.as_deref(), Some("retiring"));
        assert!(store.acknowledge_applied(server, revision).await.unwrap());
        service.rotation_applied(&mut progress);
        // This event has to wake the blocked driver; there is no rotation retry timer here.
        progress.changed().await.unwrap();
        let cleanup = store.config(node).await.unwrap().version;
        assert!(cleanup > revision);
        assert!(store.rotation_acks_ready(cleanup, &[node].into_iter().collect()).await.unwrap());
        assert!(store.acknowledge_applied(server, cleanup).await.unwrap());
        service.rotation_applied(&mut progress);
        channel.finished.acquire().await.unwrap().forget();
        assert_eq!(rotation_row(&service, i64::try_from(node.0).unwrap()).await.2.as_deref(), Some("cleanup"));
        println!("ACK_LIVENESS peer_woke_retiring=true new_revision_acknowledged=true cleanup_finish_attempted=true");
    }).await;
    task.abort();
    let _ = task.await;
    pool.close().await;
    std::fs::remove_dir_all(directory).unwrap();
    result.expect("peer progress must not be lost by self-notification suppression");
}
