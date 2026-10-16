//! Ensures unavailable Mesh snapshots explain storage failures without exposing stored values (#229).
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
        self.text()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == "mesh_storage_error")
            .collect()
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep ordered failure/repair assertions under one real pool and capture.
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
    sqlx::query("UPDATE mesh_nodes SET id=-1 WHERE id=?")
        .bind(id)
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
    sqlx::query("UPDATE mesh_nodes SET id=? WHERE id=-1")
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
    assert_eq!(errors.len(), 4, "every Storage result needs a diagnostic");
    let reasons: Vec<_> = errors
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "database table missing",
            "stored node id invalid",
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
        "MESH_STORAGE_DIAGNOSTICS errors=4 reasons={reasons:?} stored_values_excluded=true repaired_list=ok"
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn invalid_stored_column_is_a_logged_storage_error() {
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
        matches!(answer, Ok(Err(MeshApiError::Storage))),
        "invalid stored columns must refuse without panicking"
    );
    let errors = capture.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["fields"]["reason"], "stored column invalid");
    assert!(!capture.text().contains("public-column-marker"));
    fixture.cleanup().await;
}

#[tokio::test]
async fn invalid_stored_host_name_is_a_logged_storage_error() {
    let fixture = Fixture::new().await;
    enroll(&fixture.service, "public-name-marker", 19).await;
    let (capture, _guard) = Capture::start();
    sqlx::query("UPDATE mesh_nodes SET name=''")
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
    let errors = capture.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["fields"]["reason"], "stored host name invalid");
    assert!(!capture.text().contains("public-name-marker"));
    fixture.cleanup().await;
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
