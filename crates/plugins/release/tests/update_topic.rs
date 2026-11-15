//! The `release.update` topic streams the update state to owners when it changes and
//! refuses everyone else (#211 S3, for S5's Updates row).
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use bytes::Bytes;
use infraternal_plugin_api::{Operation, Plugin, ReplySender, SocketHost};
use infraternal_plugin_release::{
    ReleasePlugin,
    latest::{DownloadError, ReleaseEngine},
    service::{ReleaseLookup, ReleaseService, settings_reader},
    update::{Admission, Outcome, Updater, status},
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;

/// Reports the update state of one data folder, as the server's lookup does.
struct Lookup(PathBuf);
impl ReleaseLookup for Lookup {
    fn latest<'a>(&'a self, _: &'a str) -> Operation<'a, Result<serde_json::Value, &'static str>> {
        Box::pin(async { Err("not used") })
    }
    fn update_status(&self) -> Result<serde_json::Value, &'static str> {
        Ok(serde_json::to_value(status(&self.0, "edge-20261101T000000Z")).unwrap())
    }
}
/// A channel that has published nothing yet.
struct Empty;
impl ReleaseEngine for Empty {
    fn download<'a>(
        &'a self,
        _: &'a str,
        _: &'a Path,
        _: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async { Err(DownloadError::Missing) })
    }
    fn verify_version(&self, _: &std::fs::File, _: &[u8], _: &[u8]) -> Result<(), &'static str> {
        Err("not used")
    }
}
/// A socket host that is always live and authorized, signed in as the user it names.
struct Host(&'static str);
impl SocketHost for Host {
    fn user_id(&self) -> &str {
        self.0
    }
    fn token_hash(&self) -> &'static str {
        "fixture"
    }
    fn authorized<'a>(
        &'a self,
        op: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        op
    }
    fn fresh(&self, _: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}

/// The wire frame subscribing `sub_id` 9 to `release.update`.
fn subscribe() -> Bytes {
    let mut wire = vec![];
    encode_muxed_frame_into(
        4,
        &Frame::Subscribe {
            sub_id: 9,
            filter_json: br#"{"topic":"release.update"}"#,
        },
        &mut wire,
    )
    .unwrap();
    Bytes::from(wire)
}

/// The next event the worker sends, decoded as JSON.
async fn event(
    answers: &mut mpsc::Receiver<infraternal_plugin_api::PluginReply>,
) -> serde_json::Value {
    let reply = answers.recv().await.unwrap();
    let decoded = decode_muxed_frame(&reply.wire).unwrap();
    assert_eq!(decoded.stream_id, 4);
    let Frame::Event { sub_id, event_json } = decoded.frame else {
        panic!("expected an event")
    };
    assert_eq!(sub_id, 9);
    serde_json::from_slice(event_json).unwrap()
}

/// An owner gets the update state on subscribe and again after a check writes it; a non-owner gets `not permitted`.
#[tokio::test]
async fn owners_get_the_state_now_and_after_each_check_others_are_refused() {
    let data = std::env::temp_dir().join(format!("topic-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin)); CREATE TABLE users(id TEXT,owner INTEGER); INSERT INTO users VALUES('owner',1),('member',0); INSERT INTO plugin_settings VALUES('server','release',1,'{\"channel\":\"edge\"}');")
        .execute(&pool)
        .await
        .unwrap();
    let service = ReleaseService::new(pool.clone(), Arc::new(Lookup(data.clone())));
    for (user, owner) in [("owner", true), ("member", false)] {
        let (requests, receiver) = mpsc::channel(4);
        let (outbound, mut answers) = mpsc::channel(4);
        let registry = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
        registry[0].store((2_u64 << 32) | 9, Ordering::Release);
        let worker = tokio::spawn(ReleasePlugin(service.clone()).run(
            Arc::new(Host(user)),
            receiver,
            ReplySender::new(outbound, "release", 1),
            registry,
        ));
        requests.send(subscribe()).await.unwrap();
        let first = event(&mut answers).await;
        if !owner {
            assert_eq!(
                first,
                serde_json::json!({"type":"error","error":"not permitted"})
            );
            drop(requests);
            worker.await.unwrap();
            continue;
        }
        assert_eq!(first["type"], "update");
        assert_eq!(first["update"]["current"], "edge-20261101T000000Z");
        assert_eq!(first["update"]["channel"], "edge");
        assert!(first["update"]["last_check"].is_null());
        // A check writes the state; the subscriber hears about it without asking.
        let updater = Updater::new(
            &data,
            "http://127.0.0.1:9".into(),
            "edge-20261101T000000Z".into(),
            "infraternal-x86_64-musl".into(),
            Arc::new(Empty),
            settings_reader(pool.clone()),
        );
        assert_eq!(
            updater.check(None, Admission::Forward).await,
            Ok(Outcome::Empty)
        );
        let next = event(&mut answers).await;
        assert_eq!(next["type"], "update");
        assert!(next["update"]["last_check"].is_i64());
        assert!(next["update"]["available"].is_null());
        drop(requests);
        worker.await.unwrap();
    }
    std::fs::remove_dir_all(&data).unwrap();
}
