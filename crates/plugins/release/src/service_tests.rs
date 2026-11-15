//! Real SQLite tests ensure stable defaults, explicit edge opt-in and commit-time authority [226].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Lookup(AtomicUsize);
impl ReleaseLookup for Lookup {
    fn latest<'a>(&'a self, channel: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(json!({"channel":channel})) })
    }
}
async fn fixture() -> (ReleaseService, Arc<Lookup>) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin)); CREATE TABLE users(id TEXT,owner INTEGER); CREATE TABLE sessions(token_hash TEXT,user_id TEXT,unlocked INTEGER,expires INTEGER,fresh INTEGER);").execute(&pool).await.unwrap();
    let lookup = Arc::new(Lookup(AtomicUsize::new(0)));
    (ReleaseService::new(pool, lookup.clone()), lookup)
}
#[tokio::test]
async fn default_stable_refuses_silent_edge_and_persists_explicit_opt_in() {
    let (service, lookup) = fixture().await;
    assert_eq!(
        service.call(CHANNEL_GET.id, b"{}", None).await.unwrap()["channel"],
        "stable"
    );
    for input in [
        br#"{"channel":"edge"}"#.as_slice(),
        br#"{"channel":"edge","confirmed":false}"#,
    ] {
        assert_eq!(
            service.call(CHANNEL_SET.id, input, None).await,
            Err(EDGE_WARNING)
        );
        assert_eq!(
            service.call(CHANNEL_GET.id, b"{}", None).await.unwrap()["channel"],
            "stable"
        );
    }
    assert_eq!(
        service
            .call(
                CHANNEL_SET.id,
                br#"{"channel":"edge","confirmed":true}"#,
                None
            )
            .await
            .unwrap()["channel"],
        "edge"
    );
    let restarted = ReleaseService::new(service.pool.clone(), lookup.clone());
    assert_eq!(
        restarted.call(LATEST.id, b"{}", None).await.unwrap()["channel"],
        "edge"
    );
    assert_eq!(
        service
            .call(CHANNEL_SET.id, br#"{"channel":"stable"}"#, None)
            .await
            .unwrap()["channel"],
        "stable"
    );
    assert_eq!(lookup.0.load(Ordering::Relaxed), 1);
}
#[tokio::test]
async fn disabled_feature_starts_no_lookup_and_rejects_settings() {
    let (service, lookup) = fixture().await;
    sqlx::query(
        "INSERT INTO plugin_settings VALUES('server','release',0,'{\"channel\":\"stable\"}')",
    )
    .execute(&service.pool)
    .await
    .unwrap();
    for (action, input) in [
        (LATEST.id, b"{}".as_slice()),
        (CHANNEL_GET.id, b"{}"),
        (CHANNEL_SET.id, br#"{"channel":"edge","confirmed":true}"#),
    ] {
        assert_eq!(
            service.call(action, input, None).await,
            Err("release unavailable")
        );
    }
    assert_eq!(lookup.0.load(Ordering::Relaxed), 0);
}
struct Host;
impl SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "fixture-session-hash"
    }
    fn authorized<'a>(
        &'a self,
        op: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        op
    }
    fn fresh(&self, _now: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}
#[tokio::test]
async fn api_setting_requires_owner_and_current_fresh_session() {
    let (service, _lookup) = fixture().await;
    let input = br#"{"channel":"edge","confirmed":true}"#;
    assert_eq!(
        service.call(CHANNEL_SET.id, input, Some(&Host)).await,
        Err("not permitted")
    );
    sqlx::query("INSERT INTO users VALUES('owner',1)")
        .execute(&service.pool)
        .await
        .unwrap();
    assert_eq!(
        service.call(CHANNEL_SET.id, input, Some(&Host)).await,
        Err("not permitted")
    );
    sqlx::query(
        "INSERT INTO sessions VALUES('fixture-session-hash','owner',1,unixepoch()+600,unixepoch())",
    )
    .execute(&service.pool)
    .await
    .unwrap();
    assert!(
        service
            .call(CHANNEL_SET.id, input, Some(&Host))
            .await
            .is_ok()
    );
    sqlx::query("UPDATE users SET owner=0")
        .execute(&service.pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .call(CHANNEL_SET.id, br#"{"channel":"stable"}"#, Some(&Host))
            .await,
        Err("not permitted")
    );
    assert_eq!(
        service.call(CHANNEL_GET.id, b"{}", None).await.unwrap()["channel"],
        "edge"
    );
}
#[tokio::test]
async fn object_input_rejects_duplicates_unknown_fields_and_alternate_representations() {
    let (service, _) = fixture().await;
    for input in [
        br#"{"channel":"stable","channel":"edge","confirmed":true}"#.as_slice(),
        br#"{"channel":"edge","confirmed":false,"confirmed":true}"#,
        br#"["edge",true]"#,
        br#"{"channel":"edge","confirmed":true,"extra":0}"#,
        br#"{"channel":"invalid","confirmed":true}"#,
    ] {
        assert_eq!(
            service.call(CHANNEL_SET.id, input, None).await,
            Err("invalid input")
        );
    }
    assert_eq!(
        service.call(CHANNEL_GET.id, b"[]", None).await,
        Err("invalid input")
    );
    crate::descriptor::DESCRIPTOR.validate().unwrap();
}

#[tokio::test]
#[ignore = "run alone under CPUWeight=10000; measures SQLite action overhead, not terminal or full authenticated socket latency"]
async fn channel_reads_at_fifty_concurrent_callers() {
    let (service, _) = fixture().await;
    let mut times = Vec::with_capacity(50);
    for _ in 0..50 {
        let started = std::time::Instant::now();
        let result = service.call(CHANNEL_GET.id, b"{}", None).await.unwrap();
        assert_eq!(result["channel"], "stable");
        times.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(f64::total_cmp);
    let started = std::time::Instant::now();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let service = service.clone();
        calls.spawn(async move { service.call(CHANNEL_GET.id, b"{}", None).await.unwrap() });
    }
    while let Some(result) = calls.join_next().await {
        assert_eq!(result.unwrap()["channel"], "stable");
    }
    println!(
        "METRIC channel_get samples=50 p50_ms={:.3} concurrent_callers=50 batch_ms={:.3} service_bytes={} machine={} arch={} cores={} load={}",
        times[25],
        started.elapsed().as_secs_f64() * 1000.0,
        std::mem::size_of::<ReleaseService>(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::env::consts::ARCH,
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[tokio::test]
async fn authority_is_rechecked_after_the_setting_write_before_commit() {
    let (service, _) = fixture().await;
    sqlx::raw_sql("INSERT INTO users VALUES('owner',1); INSERT INTO sessions VALUES('fixture-session-hash','owner',1,unixepoch()+600,unixepoch()); CREATE TRIGGER release_write_retires_freshness AFTER INSERT ON plugin_settings BEGIN UPDATE sessions SET fresh=0; END;")
        .execute(&service.pool).await.unwrap();
    assert_eq!(
        service
            .call(
                CHANNEL_SET.id,
                br#"{"channel":"edge","confirmed":true}"#,
                Some(&Host)
            )
            .await,
        Err("not permitted")
    );
    assert_eq!(
        service.call(CHANNEL_GET.id, b"{}", None).await.unwrap()["channel"],
        "stable"
    );
}

/// A lookup whose server runs the updater, for the status-reason tests.
struct Updating;
impl ReleaseLookup for Updating {
    fn latest<'a>(&'a self, _: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        Box::pin(async { Err("unused") })
    }
    fn update_status(&self) -> Result<Value, &'static str> {
        Ok(json!({"current":"0.1.0","channel":"edge","mode":"auto","reason":null}))
    }
}

/// `release.update.status` says plainly when updates are off and why (J725 P3-4): the
/// plugin switched off or an unusable channel turns an updating host off, while a
/// host-level reason from the server is kept as it is.
#[tokio::test]
async fn update_status_names_why_updates_are_off() {
    let (base, _) = fixture().await;
    let service = ReleaseService::new(base.pool.clone(), Arc::new(Updating));
    let shown = service.call(UPDATE_STATUS.id, b"{}", None).await.unwrap();
    assert_eq!(
        (&shown["mode"], &shown["channel"]),
        (&json!("auto"), &json!("stable"))
    );
    assert!(shown["reason"].is_null());
    sqlx::query(
        "INSERT INTO plugin_settings VALUES('server','release',1,'{\"channel\":\"beta\"}')",
    )
    .execute(&base.pool)
    .await
    .unwrap();
    let shown = service.call(UPDATE_STATUS.id, b"{}", None).await.unwrap();
    assert_eq!(shown["mode"], "off");
    assert_eq!(shown["reason"], NO_CHANNEL);
    sqlx::query("UPDATE plugin_settings SET enabled=0")
        .execute(&base.pool)
        .await
        .unwrap();
    let shown = service.call(UPDATE_STATUS.id, b"{}", None).await.unwrap();
    assert_eq!(shown["mode"], "off");
    assert_eq!(shown["reason"], crate::update::UPDATES_OFF);
    // A lookup without server state still answers with its own fixed refusal.
    assert_eq!(
        base.call(UPDATE_STATUS.id, b"{}", None).await,
        Err("updates unavailable")
    );
    // A host-level reason wins over the switch: turning the plugin on would not help.
    let lookup = crate::latest::VerifiedLookup::new(
        std::env::temp_dir().join(format!("absent-{}", uuid::Uuid::new_v4())),
        "https://builds.invalid".into(),
        Arc::new(NoEngine),
    )
    .with_updates(Err(crate::update::OFF_NOT_ROOT));
    let host_off = ReleaseService::new(base.pool.clone(), Arc::new(lookup));
    let shown = host_off.call(UPDATE_STATUS.id, b"{}", None).await.unwrap();
    assert_eq!(shown["mode"], "off");
    assert_eq!(shown["reason"], crate::update::OFF_NOT_ROOT);
}

/// An engine that is never used: the status test only reads state.
struct NoEngine;
impl crate::latest::ReleaseEngine for NoEngine {
    fn download<'a>(
        &'a self,
        _: &'a str,
        _: &'a std::path::Path,
        _: u64,
    ) -> Operation<'a, Result<(), crate::latest::DownloadError>> {
        Box::pin(async { Err(crate::latest::DownloadError::Missing) })
    }
    fn verify_version(&self, _: &std::fs::File, _: &[u8], _: &[u8]) -> Result<(), &'static str> {
        Err("unused")
    }
}
