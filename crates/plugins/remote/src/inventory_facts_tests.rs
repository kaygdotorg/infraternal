//! Regressions for independent selected-host reads and bounded socket admission.
use super::*;
/// A live person socket for the scheduling regression.
struct Host(Option<watch::Receiver<bool>>);
impl SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "fixture"
    }
    fn authorized<'a>(
        &'a self,
        work: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        let Some(mut live) = self.0.clone() else {
            return work;
        };
        Box::pin(async move {
            if !*live.borrow_and_update() {
                return Err(());
            }
            tokio::select! { result = work => result, _ = live.changed() => Err(()) }
        })
    }
    fn fresh(&self, _: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { false })
    }
}
/// One deadline-bound host and one immediately ready host.
struct SlowSource {
    entered: tokio::sync::Notify,
    changes: Changes,
}
impl Inventory for SlowSource {
    fn list<'a>(&'a self, _: &'a str, _: Option<&'a str>) -> Operation<'a, Result<Value, ()>> {
        Box::pin(async { Ok(json!({"hosts":[]})) })
    }
    fn facts<'a>(&'a self, _: &'a str, id: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        Box::pin(async move {
            if id.ends_with("0001") {
                self.entered.notify_one();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    std::future::pending::<()>(),
                )
                .await;
                Err(HOST_OFFLINE)
            } else {
                Ok(json!({"hostname":"fast-host"}))
            }
        })
    }
    fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }
    fn observe(
        &self,
        _: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Operation<'_, ()> {
        Box::pin(async {})
    }
}
/// Encode a selected-host call on the shared socket.
fn call(id: u32, host: &str) -> Bytes {
    let input = serde_json::to_vec(&json!({"host_id":host})).unwrap();
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Call {
            call_id: id,
            action_id: FACTS.id,
            input_json: &input,
        },
        &mut wire,
    )
    .unwrap();
    Bytes::from(wire)
}
/// A five-second deadline on one host must not withhold another host's ready reply.
#[tokio::test(start_paused = true)]
async fn slow_host_must_not_block_fast_host_on_same_socket() {
    let source = Arc::new(SlowSource {
        entered: tokio::sync::Notify::new(),
        changes: Changes::default(),
    });
    let (tx, rx) = mpsc::channel(4);
    let (out, mut answers) = mpsc::channel(4);
    let registry = Arc::new(std::array::from_fn(|_| {
        std::sync::atomic::AtomicU64::new(0)
    }));
    let worker = tokio::spawn(InventoryPlugin(source.clone()).run(
        Arc::new(Host(None)),
        rx,
        ReplySender::new(out, DESCRIPTOR.id, 1),
        registry,
    ));
    let start = tokio::time::Instant::now();
    tx.send(call(1, "00000000-0000-0000-0000-000000000001"))
        .await
        .unwrap();
    source.entered.notified().await;
    tx.send(call(2, "00000000-0000-0000-0000-000000000002"))
        .await
        .unwrap();
    let early = tokio::time::timeout(std::time::Duration::from_secs(1), answers.recv()).await;
    println!(
        "fast reply available before slow deadline: {}",
        early.is_ok()
    );
    let fast = early
        .expect("fast host's ready reply was blocked behind the slow host")
        .unwrap();
    assert!(matches!(
        decode_muxed_frame(&fast.wire).unwrap().frame,
        Frame::Result {
            call_id: 2,
            ok: true,
            ..
        }
    ));
    println!("fast reply at virtual elapsed {:?}", start.elapsed());
    let slow = answers.recv().await.unwrap();
    assert!(matches!(
        decode_muxed_frame(&slow.wire).unwrap().frame,
        Frame::Result {
            call_id: 1,
            ok: false,
            ..
        }
    ));
    println!("slow reply at virtual elapsed {:?}", start.elapsed());
    drop(tx);
    worker.await.unwrap();
}

/// Reports each admitted read, then either replies or stays pending to exercise cancellation.
struct HeldSource {
    entered: mpsc::Sender<String>,
    ready: bool,
    changes: Changes,
}
impl Inventory for HeldSource {
    fn list<'a>(&'a self, _: &'a str, _: Option<&'a str>) -> Operation<'a, Result<Value, ()>> {
        Box::pin(async { Ok(json!({"hosts":[]})) })
    }
    fn facts<'a>(&'a self, _: &'a str, id: &'a str) -> Operation<'a, Result<Value, &'static str>> {
        Box::pin(async move {
            self.entered.send(id.to_owned()).await.unwrap();
            if self.ready {
                Ok(json!({"hostname":"ready"}))
            } else {
                std::future::pending().await
            }
        })
    }
    fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }
    fn observe(
        &self,
        _: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Operation<'_, ()> {
        Box::pin(async {})
    }
}

/// One host cannot consume every slot, and a full socket refuses more work without a queue.
#[tokio::test(start_paused = true)]
async fn facts_admission_is_bounded_per_host_and_per_socket() {
    let (entered, mut starts) = mpsc::channel(8);
    let source = Arc::new(HeldSource {
        entered,
        ready: false,
        changes: Changes::default(),
    });
    let (tx, rx) = mpsc::channel(16);
    let (out, mut answers) = mpsc::channel(16);
    let registry = Arc::new(std::array::from_fn(|_| {
        std::sync::atomic::AtomicU64::new(0)
    }));
    let worker = tokio::spawn(InventoryPlugin(source).run(
        Arc::new(Host(None)),
        rx,
        ReplySender::new(out, DESCRIPTOR.id, 1),
        registry,
    ));
    tx.send(call(1, "00000000-0000-0000-0000-000000000001"))
        .await
        .unwrap();
    assert_eq!(
        starts.recv().await.unwrap(),
        "00000000-0000-0000-0000-000000000001"
    );
    tx.send(call(2, "00000000-0000-0000-0000-000000000001"))
        .await
        .unwrap();
    let duplicate = tokio::time::timeout(std::time::Duration::from_secs(1), answers.recv()).await;
    assert!(
        duplicate.is_ok(),
        "duplicate host must be refused without waiting for the first read"
    );
    let duplicate = duplicate.unwrap().unwrap();
    assert!(matches!(
        decode_muxed_frame(&duplicate.wire).unwrap().frame,
        Frame::Result {
            call_id: 2,
            ok: false,
            ..
        }
    ));
    for id in 2..=8 {
        tx.send(call(id + 1, &format!("00000000-0000-0000-0000-{id:012}")))
            .await
            .unwrap();
        assert!(starts.recv().await.is_some());
    }
    tx.send(call(10, "00000000-0000-0000-0000-000000000009"))
        .await
        .unwrap();
    let full = answers.recv().await.unwrap();
    assert!(
        matches!(decode_muxed_frame(&full.wire).unwrap().frame, Frame::Result {call_id:10,ok:false,json} if serde_json::from_slice::<Value>(json).unwrap() == json!({"error":"host busy"}))
    );
    assert!(
        starts.try_recv().is_err(),
        "the refused ninth host must not reach the source"
    );
    // Inventory must remain usable even when all host-facts slots are occupied.
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Call {
            call_id: 11,
            action_id: LIST.id,
            input_json: b"{}",
        },
        &mut wire,
    )
    .unwrap();
    tx.send(Bytes::from(wire)).await.unwrap();
    let list = answers.recv().await.unwrap();
    assert!(matches!(
        decode_muxed_frame(&list.wire).unwrap().frame,
        Frame::Result {
            call_id: 11,
            ok: true,
            ..
        }
    ));
    drop(tx);
    worker.await.unwrap();
    assert!(
        starts.recv().await.is_none(),
        "socket closure must drop pending read futures"
    );
}

/// Revocation cancels both an outstanding read and a completed result waiting for socket credit.
#[tokio::test(start_paused = true)]
async fn revocation_cancels_concurrent_facts_and_queued_replies() {
    for ready in [false, true] {
        let (live, authority) = watch::channel(true);
        let (entered, mut starts) = mpsc::channel(1);
        let source = Arc::new(HeldSource {
            entered,
            ready,
            changes: Changes::default(),
        });
        let (tx, rx) = mpsc::channel(2);
        let (out, mut answers) = mpsc::channel(1);
        out.send(infraternal_plugin_api::PluginReply::new(
            DESCRIPTOR.id,
            1,
            Bytes::new(),
        ))
        .await
        .unwrap();
        let registry = Arc::new(std::array::from_fn(|_| {
            std::sync::atomic::AtomicU64::new(0)
        }));
        let worker = tokio::spawn(InventoryPlugin(source).run(
            Arc::new(Host(Some(authority))),
            rx,
            ReplySender::new(out, DESCRIPTOR.id, 1),
            registry,
        ));
        tx.send(call(1, "00000000-0000-0000-0000-000000000001"))
            .await
            .unwrap();
        starts.recv().await.unwrap();
        live.send_replace(false);
        tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(answers.recv().await.unwrap().wire.is_empty());
        assert!(
            answers.recv().await.is_none(),
            "revocation must discard a facts reply before socket credit returns"
        );
        assert!(starts.recv().await.is_none());
    }
}
