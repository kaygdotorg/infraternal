//! Ensures Mesh snapshots isolate malformed hosts and explain storage failures without stored values (#229).
use super::*;
use std::io::Write;

#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Capture {
    /// Install a thread-local JSON subscriber for these current-thread fixtures.
    fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
    fn errors(&self) -> Vec<Value> {
        self.events("mesh_storage_error")
    }
    fn events(&self, name: &str) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == name)
            .collect()
    }
}

#[tokio::test]
async fn repeated_storage_failure_has_bounded_diagnostics() {
    let fixture = Fixture::new().await;
    sqlx::query("ALTER TABLE mesh_grants RENAME TO mesh_grants_unavailable")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let (capture, _guard) = Capture::start();
    for index in 0..50 {
        let answer = if index % 2 == 0 {
            fixture
                .service
                .list(OWNER, MeshFilter::default(), NOW)
                .await
                .map(|_| ())
        } else {
            fixture
                .service
                .execute(OWNER, "mesh.list", b"{}", NOW)
                .await
                .map(|_| ())
        };
        assert_eq!(answer, Err(MeshApiError::Storage));
    }
    assert_eq!(
        capture.errors().len(),
        1,
        "viewers and adapters share one failure"
    );
    sqlx::query("ALTER TABLE mesh_grants_unavailable RENAME TO mesh_grants")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let recovered = capture.events("mesh_storage_recovered");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0]["fields"]["count"], 50);
    assert_eq!(recovered[0]["fields"]["operation"], "mesh.list");
    sqlx::query("ALTER TABLE mesh_grants RENAME TO mesh_grants_unavailable")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    assert_eq!(
        capture.errors().len(),
        2,
        "recurrence starts a new counted failure"
    );
    assert!(!capture.text().contains("mesh_grants_unavailable"));
    fixture.cleanup().await;
    println!(
        "MESH_STORAGE_REPEAT requests=50 first_events=1 recovered_count=50 recurrence_events=1"
    );
}

#[tokio::test]
async fn changed_storage_failure_reports_the_previous_count() {
    let fixture = Fixture::new().await;
    sqlx::query("ALTER TABLE mesh_grants RENAME TO mesh_grants_unavailable")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let (capture, _guard) = Capture::start();
    for _ in 0..3 {
        assert_eq!(
            fixture
                .service
                .list(OWNER, MeshFilter::default(), NOW)
                .await,
            Err(MeshApiError::Storage)
        );
    }
    fixture.pool.close().await;
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    let errors = capture.errors();
    fixture.cleanup().await;
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0]["fields"]["reason"], "database table missing");
    assert_eq!(errors[1]["fields"]["reason"], "database pool closed");
    assert_eq!(errors[1]["fields"]["previous_count"], 3);
}

#[tokio::test]
async fn unrelated_success_does_not_reset_a_persistent_write_failure() {
    let fixture = Fixture::new().await;
    let readonly = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&fixture.path)
                .read_only(true),
        )
        .await
        .unwrap();
    let service = MeshService::new(readonly.clone());
    let (capture, _guard) = Capture::start();
    for _ in 0..5 {
        assert_eq!(
            call(
                &service,
                OWNER,
                "mesh.tag.create",
                json!({"name":"bounded-write"}),
                NOW
            )
            .await,
            Err(MeshApiError::Storage)
        );
        assert!(
            service
                .execute(OWNER, "mesh.default.get", b"{}", NOW)
                .await
                .is_ok()
        );
    }
    let errors = capture.errors();
    let recoveries = capture.events("mesh_storage_recovered");
    readonly.close().await;
    fixture.cleanup().await;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["fields"]["operation"], "mesh.tag.create");
    assert!(
        recoveries.is_empty(),
        "a different successful action proves no repair"
    );
    assert!(!capture.text().contains("bounded-write"));
}

#[tokio::test]
async fn malformed_unrelated_host_preserves_scoped_inventory() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let visible = enroll(service, "visible-host", 51).await;
    let unrelated = enroll(service, "unrelated-host", 52).await;
    for (action, input) in [
        ("mesh.tag.create", json!({"name":"visible"})),
        (
            "mesh.tag.member.add",
            json!({"tag":"visible","node_id":visible}),
        ),
        (
            "mesh.role.define",
            json!({"name":"visible-role","actions":["mesh.manage_nodes"],"scopes":["visible"]}),
        ),
        (
            "mesh.role.assign",
            json!({"user_id":MEMBER,"role":"visible-role"}),
        ),
    ] {
        call(service, OWNER, action, input, NOW).await.unwrap();
    }
    let before = service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert_eq!(before.nodes.len(), 1);
    assert_eq!(before.nodes[0].node.id.0, visible);
    sqlx::query("UPDATE mesh_nodes SET name='' WHERE id=?")
        .bind(i64::try_from(unrelated).unwrap())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let (capture, _guard) = Capture::start();
    let after = service.list(MEMBER, MeshFilter::default(), NOW).await;
    assert!(
        capture.text().is_empty(),
        "out-of-scope rows produce no diagnostics"
    );
    assert_eq!(
        after,
        Ok(before),
        "invalid out-of-scope host must not hide valid inventory"
    );
    // The same damaged row becomes visible without withdrawing the healthy
    // member. Its references disappear and clones still report its ID once.
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"visible","node_id":unrelated}),
        NOW,
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let snapshot = (*service)
            .clone()
            .list(MEMBER, MeshFilter::default(), NOW)
            .await
            .unwrap();
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(snapshot.nodes[0].node.id.0, visible);
        assert!(
            snapshot
                .tags
                .iter()
                .all(|tag| tag.members.iter().all(|id| id.0 == visible))
        );
    }
    let logs = capture.text();
    let events: Vec<Value> = logs
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["node_id"], unrelated);
    fixture.cleanup().await;
}

#[tokio::test]
async fn malformed_host_keeps_healthy_inventory_readable() {
    let fixture = Fixture::new().await;
    let healthy = enroll(&fixture.service, "readable-host", 53).await;
    let invalid = enroll(&fixture.service, "legacy-host", 54).await;
    call(
        &fixture.service,
        OWNER,
        "mesh.tag.create",
        json!({"name":"mixed"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        &fixture.service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"mixed","node_id":invalid}),
        NOW,
    )
    .await
    .unwrap();
    call(
        &fixture.service,
        OWNER,
        "mesh.grant.create",
        json!({"name":"affected","from":{"Node":healthy},"to":{"Node":invalid},"both_ways":false}),
        NOW,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mesh_nodes SET name='' WHERE id=?")
        .bind(i64::try_from(invalid).unwrap())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let answer = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await;
    fixture.cleanup().await;
    let snapshot = answer.expect("one invalid host must not hide healthy inventory");
    assert!(snapshot.nodes.iter().any(|node| node.node.id.0 == healthy));
    assert!(
        snapshot
            .tags
            .iter()
            .all(|tag| !tag.members.iter().any(|id| id.0 == invalid))
    );
    assert!(
        snapshot.grants.is_empty(),
        "skip references to the omitted host too"
    );
    // A successful response must also be readable by the existing strict
    // clients. Returning the malformed name alongside healthy rows is no recovery.
    for node in snapshot.nodes {
        assert!(
            parse_action(
                "mesh.node.rename",
                &serde_json::to_vec(&json!({"node_id":node.node.id.0,"name":node.node.host}))
                    .unwrap(),
            )
            .is_ok()
        );
    }
}

/// Storage failures report safe reasons and recover once storage is repaired.
#[tokio::test]
async fn storage_failures_have_safe_reasons_and_recover_after_repair() {
    let fixture = Fixture::new().await;
    let (capture, _guard) = Capture::start();
    sqlx::query("ALTER TABLE mesh_grants RENAME TO mesh_grants_unavailable")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    sqlx::query("ALTER TABLE mesh_grants_unavailable RENAME TO mesh_grants")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let id = i64::try_from(enroll(&fixture.service, "public-row-marker", 17).await).unwrap();
    sqlx::query("UPDATE mesh_nodes SET name='' WHERE id=?")
        .bind(id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let snapshot = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.nodes.len(), 0);
    sqlx::query("UPDATE mesh_nodes SET name='public-row-marker' WHERE id=?")
        .bind(id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .is_ok()
    );
    sqlx::query("INSERT INTO mesh_grants(name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) VALUES('public-rule-marker','node','1','node','2',0,'public-json-marker')")
        .execute(&fixture.pool).await.unwrap();
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    sqlx::query("DELETE FROM mesh_grants")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES(?,?)")
        .bind("public-tag-marker".repeat(5000))
        .bind(NOW)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    sqlx::query("DELETE FROM mesh_tags")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .is_ok()
    );
    let logs = capture.text();
    let errors = capture.errors();
    assert_eq!(
        errors.len(),
        3,
        "every distinct Storage result needs a diagnostic"
    );
    let reasons: Vec<_> = errors
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "database table missing",
            "stored access ports JSON invalid",
            "stored item exceeds frame budget",
        ]
    );
    for event in &errors {
        assert_eq!(event["level"], "ERROR");
        assert!(
            event["fields"]["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
        assert!(
            event["fields"]["file"]
                .as_str()
                .is_some_and(|file| file.contains("plugins/mesh/src/"))
        );
        assert!(
            event["fields"]["line"]
                .as_u64()
                .is_some_and(|line| line > 0)
        );
    }
    for value in [
        "public-row-marker",
        "public-rule-marker",
        "public-json-marker",
        "public-tag-marker",
    ] {
        assert!(!logs.contains(value));
    }
    assert!(!logs.contains("mesh_grants_unavailable"));
    println!(
        "MESH_STORAGE_DIAGNOSTICS errors=3 reasons={reasons:?} stored_values_excluded=true repaired_list=ok"
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn invalid_stored_column_is_skipped_without_panicking() {
    use futures_util::FutureExt;
    let fixture = Fixture::new().await;
    enroll(&fixture.service, "public-column-marker", 18).await;
    let (capture, _guard) = Capture::start();
    sqlx::query("UPDATE mesh_nodes SET name=zeroblob(1)")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let answer =
        std::panic::AssertUnwindSafe(fixture.service.list(OWNER, MeshFilter::default(), NOW))
            .catch_unwind()
            .await;
    assert!(
        matches!(answer, Ok(Ok(ref snapshot)) if snapshot.nodes.is_empty()),
        "invalid stored columns must be skipped without panicking"
    );
    assert_eq!(capture.errors().len(), 0);
    assert!(capture.text().contains("mesh_invalid_host"));
    assert!(!capture.text().contains("public-column-marker"));
    fixture.cleanup().await;
}

#[tokio::test]
async fn invalid_stored_host_is_reported_once_by_id() {
    let fixture = Fixture::new().await;
    let id = enroll(&fixture.service, "public-name-marker", 19).await;
    let (capture, _guard) = Capture::start();
    sqlx::query("UPDATE mesh_nodes SET name=''")
        .execute(&fixture.pool)
        .await
        .unwrap();
    for _ in 0..3 {
        let snapshot = fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .unwrap();
        assert_eq!(snapshot.nodes.len(), 0);
    }
    assert_eq!(capture.errors().len(), 0);
    let logs = capture.text();
    let events: Vec<Value> = logs
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    let fields = events[0]["fields"].as_object().unwrap();
    assert_eq!(fields["event"], "mesh_invalid_host");
    assert_eq!(fields["node_id"], id);
    assert_eq!(fields.len(), 3, "only static event/message and row id");
    assert!(!logs.contains("public-name-marker"));
    fixture.cleanup().await;
}

#[tokio::test]
async fn coordinator_clones_share_failure_counts_and_report_recovery() {
    let fixture = Fixture::new().await;
    let store = fixture.service.dataplane();
    let (capture, _guard) = Capture::start();
    for _ in 0..10 {
        assert_eq!(
            store
                .clone()
                .config(infraternal_mesh::model::NodeId(1))
                .await,
            Err(MeshApiError::Storage)
        );
    }
    let first_count = capture.errors().len();
    let (id, _) = store
        .attach(
            "server",
            infraternal_mesh::model::PublicKey([37; 32]),
            None,
            true,
        )
        .await
        .unwrap();
    store.config(id).await.unwrap();
    let recovered = capture.events("mesh_storage_recovered");
    fixture.cleanup().await;
    assert_eq!(first_count, 1);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0]["fields"]["count"], 10);
    assert_eq!(recovered[0]["fields"]["operation"], "mesh.coordinator.load");
}

#[tokio::test]
async fn coordinator_loading_preserves_missing_server_and_sql_reasons() {
    let fixture = Fixture::new().await;
    let store = fixture.service.dataplane();
    let (capture, _guard) = Capture::start();
    assert_eq!(
        store.config(infraternal_mesh::model::NodeId(1)).await,
        Err(MeshApiError::Storage)
    );
    let errors = capture.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0]["fields"]["reason"],
        "Mesh server node is not connected."
    );
    fixture.pool.close().await;
    assert_eq!(
        store.config(infraternal_mesh::model::NodeId(1)).await,
        Err(MeshApiError::Storage)
    );
    let errors = capture.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[1]["fields"]["reason"], "database pool closed");
    assert!(
        errors[1]["fields"]["file"]
            .as_str()
            .unwrap()
            .ends_with("store.rs")
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn coordinator_stored_column_refuses_without_panic_and_recovers_after_repair() {
    use futures_util::FutureExt;
    let fixture = Fixture::new().await;
    let store = fixture.service.dataplane();
    let (id, _) = store
        .attach(
            "server",
            infraternal_mesh::model::PublicKey([31; 32]),
            None,
            true,
        )
        .await
        .unwrap();
    let (capture, _guard) = Capture::start();
    sqlx::query("UPDATE mesh_nodes SET name=zeroblob(1)")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let answer = std::panic::AssertUnwindSafe(store.config(id))
        .catch_unwind()
        .await;
    assert!(
        matches!(answer, Ok(Err(MeshApiError::Storage))),
        "coordinator columns must refuse without panicking"
    );
    let errors = capture.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["fields"]["reason"], "stored column invalid");
    sqlx::query("UPDATE mesh_nodes SET name='server'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(store.config(id).await.is_ok());
    fixture.cleanup().await;
}

#[tokio::test]
async fn settings_storage_failure_has_a_safe_original_reason() {
    let fixture = Fixture::new().await;
    let (capture, _guard) = Capture::start();
    fixture.pool.close().await;
    assert_eq!(
        fixture
            .service
            .execute(OWNER, "mesh.default.get", b"{}", NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    let errors = capture.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["fields"]["reason"], "database pool closed");
    assert!(
        errors[0]["fields"]["file"]
            .as_str()
            .unwrap()
            .ends_with("settings.rs")
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_admission_failures_have_distinct_safe_reasons() {
    let fixture = Fixture::new().await;
    // Separate single-connection pools make the failure boundary deterministic
    // without changing host limits or another fixture's database settings.
    let options = SqliteConnectOptions::new()
        .filename(&fixture.path)
        .busy_timeout(Duration::ZERO);
    let busy = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let readonly = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().read_only(true))
        .await
        .unwrap();
    let saturated = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(1))
        .connect_with(options)
        .await
        .unwrap();
    let (capture, _guard) = Capture::start();
    let writer = fixture.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    assert_eq!(
        call(
            &MeshService::new(busy.clone()),
            OWNER,
            "mesh.tag.create",
            json!({"name":"bounded-write"}),
            NOW
        )
        .await,
        Err(MeshApiError::Storage)
    );
    writer.rollback().await.unwrap();
    assert_eq!(
        call(
            &MeshService::new(readonly.clone()),
            OWNER,
            "mesh.tag.create",
            json!({"name":"bounded-write"}),
            NOW
        )
        .await,
        Err(MeshApiError::Storage)
    );
    let held = saturated.acquire().await.unwrap();
    assert_eq!(
        MeshService::new(saturated.clone())
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    drop(held);
    let errors = capture.errors();
    let reasons: Vec<_> = errors
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "database locked or busy",
            "database is read-only",
            "database pool acquisition timed out"
        ]
    );
    println!("MESH_STORAGE_ADMISSION reasons={reasons:?}");
    busy.close().await;
    readonly.close().await;
    saturated.close().await;
    assert!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .is_ok()
    );
    fixture.cleanup().await;
}
