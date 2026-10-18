//! Checks authenticated mux delivery, subscription generations and cancellation at outbound backpressure [28,183,198].
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use bytes::Bytes;
use infraternal_plugin_api::{Operation, Plugin, ReplySender, SocketHost};
use infraternal_plugin_canvas::socket::CanvasPlugin;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{mpsc, watch};
struct Host {
    account: &'static str,
    live: watch::Receiver<bool>,
}
impl SocketHost for Host {
    fn user_id(&self) -> &str {
        self.account
    }
    fn token_hash(&self) -> &'static str {
        "fixture"
    }
    fn authorized<'a>(
        &'a self,
        work: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        let mut live = self.live.clone();
        Box::pin(async move {
            if !*live.borrow_and_update() {
                return Err(());
            }
            tokio::select! {result=work=>result,_=live.changed()=>Err(())}
        })
    }
    fn fresh(&self, _: i64) -> Operation<'_, bool> {
        Box::pin(async { false })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { *self.live.borrow() })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { false })
    }
}
fn wire(stream: u32, frame: &Frame<'_>) -> Bytes {
    let mut bytes = vec![];
    encode_muxed_frame_into(stream, frame, &mut bytes).unwrap();
    Bytes::from(bytes)
}
#[tokio::test]
async fn snapshot_then_ordered_commit_events_and_revocation_cancel_output() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0026_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = Store::new(pool);
    let plugin = CanvasPlugin(Arc::new(store.clone()));
    let (live, authority) = watch::channel(true);
    let (requests, receiver) = mpsc::channel(4);
    let (outbound, mut answers) = mpsc::channel(1);
    let registry = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
    registry[0].store((2_u64 << 32) | 9, Ordering::Release);
    let worker = tokio::spawn(plugin.run(
        Arc::new(Host {
            account: "a",
            live: authority,
        }),
        receiver,
        ReplySender::new(outbound, "canvas", 1),
        registry.clone(),
    ));
    requests
        .send(wire(
            4,
            &Frame::Subscribe {
                sub_id: 9,
                filter_json: br#"{"topic":"canvas.layout"}"#,
            },
        ))
        .await
        .unwrap();
    let first = answers.recv().await.unwrap();
    let first = decode_muxed_frame(&first.wire).unwrap();
    assert_eq!(first.stream_id, 4);
    let Frame::Event { sub_id, event_json } = first.frame else {
        panic!("expected snapshot")
    };
    assert_eq!(sub_id, 9);
    let json: serde_json::Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(json["revision"], 0);
    assert_eq!(json["initialized"], false);
    for expected in 1..=2 {
        let input=serde_json::to_vec(&serde_json::json!({"op_id":format!("event{expected}"),"base_revision":0,"intent":{"type":"close","window_id":format!("w{expected}")}})).unwrap();
        store.apply("a", &input).await.unwrap();
        let notice = answers.recv().await.unwrap();
        let notice = decode_muxed_frame(&notice.wire).unwrap();
        assert_eq!(notice.stream_id, 4);
        let Frame::Event { event_json, .. } = notice.frame else {
            panic!("expected committed operation")
        };
        let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
        assert_eq!(event["type"], "canvas.layout.operation");
        assert_eq!(event["revision"], expected);
    }
    // Fill one outbound slot with a result; the worker blocks on the next result.
    for id in 0..2 {
        requests.send(wire(0,&Frame::Call{call_id:id,action_id:"canvas.layout.apply",input_json:br#"{"op_id":"close","base_revision":0,"intent":{"type":"close","window_id":"w"}}"#})).await.unwrap();
    }
    // Observe the durable commit before ending socket authority.
    for _ in 0..1000 {
        if store.events("a", None).await.unwrap()[0]["revision"] == 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(store.events("a", None).await.unwrap()[0]["revision"], 3);
    live.send_replace(false);
    worker.await.unwrap();
    let mut outputs = vec![];
    while let Some(answer) = answers.recv().await {
        outputs.push(answer);
    }
    assert_eq!(
        outputs.len(),
        1,
        "revoked authority must cancel blocked replies"
    );
    let foreign = store.events("b", None).await.unwrap();
    assert_eq!(foreign[0]["revision"], 0);
    registry[0].store(0, Ordering::Release);
    drop(requests);
}

use infraternal_server::canvas_store::Store;
