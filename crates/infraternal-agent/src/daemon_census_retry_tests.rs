//! A directory-retirement census must survive full control capacity and retry without inbound traffic [D81], #168.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, Semaphore, watch};

#[derive(Clone)]
struct QueueState {
    available: usize,
    census_pending: bool,
    replies: usize,
}
static OBSERVERS: std::sync::LazyLock<Mutex<HashMap<PathBuf, watch::Sender<Option<QueueState>>>>> =
    std::sync::LazyLock::new(Mutex::default);

/// Test-only observation retains no control sender or transport owner.
pub(super) struct Observer {
    updates: watch::Sender<Option<QueueState>>,
    replies: AtomicUsize,
}
pub(super) fn observer(state: &std::path::Path) -> Option<Observer> {
    OBSERVERS
        .lock()
        .unwrap()
        .get(state)
        .cloned()
        .map(|updates| Observer {
            updates,
            replies: AtomicUsize::new(0),
        })
}
impl Observer {
    pub(super) fn replied(&self) {
        self.replies.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn publish(&self, control: &mpsc::Sender<Message>, census_pending: bool) {
        self.updates.send_replace(Some(QueueState {
            available: control.capacity(),
            census_pending,
            replies: self.replies.load(Ordering::Relaxed),
        }));
    }
}

struct HeldReply {
    input: Mutex<(Vec<u8>, usize)>,
    greeting_len: usize,
    census_held: Notify,
    reply_held: Notify,
    written: mpsc::UnboundedSender<Vec<u8>>,
    writes: AtomicUsize,
    release: Semaphore,
}
impl Channel for HeldReply {
    async fn read(&self, destination: &mut [u8]) -> io::Result<usize> {
        let greeted = self.input.lock().unwrap().1 >= self.greeting_len;
        if greeted && self.writes.load(Ordering::Relaxed) < 2 {
            self.census_held.notified().await;
        }
        let copied = {
            let mut input = self.input.lock().unwrap();
            // Hold the initial census outside the FIFO so queue pressure
            // belongs to replies rather than fixture startup.
            let end = if input.1 < self.greeting_len {
                self.greeting_len
            } else {
                input.0.len()
            };
            let count = destination.len().min(end - input.1);
            destination[..count].copy_from_slice(&input.0[input.1..input.1 + count]);
            input.1 += count;
            count
        };
        if copied != 0 {
            return Ok(copied);
        }
        std::future::pending().await
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let index = self.writes.fetch_add(1, Ordering::Relaxed);
        if index == 1 {
            self.census_held.notify_one();
        }
        if index == 2 {
            self.reply_held.notify_one();
            self.release
                .acquire()
                .await
                .map_err(io::Error::other)?
                .forget();
        }
        self.written
            .send(bytes.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
struct State(PathBuf);
impl Drop for State {
    fn drop(&mut self) {
        OBSERVERS.lock().unwrap().remove(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Keep the full ordered fixture visible: no request is sent after retirement.
#[tokio::test]
async fn full_control_lane_retries_retirement_census_on_capacity_without_requests() {
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "q{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let root = sessions::state(Some(root)).unwrap();
    let _state = State(root.clone());
    let (updates, mut observed) = watch::channel(None);
    OBSERVERS.lock().unwrap().insert(root.clone(), updates);
    let mut ids = Vec::new();
    let mut paths = Vec::new();
    let mut shims = Vec::new();
    for _ in 0..2 {
        let id = *uuid::Uuid::new_v4().as_bytes();
        let path = sessions::rendezvous(&root, id);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let shim = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            sessions::send(
                &mut peer,
                &Shim::Hello {
                    version: 1,
                    cols: 80,
                    rows: 24,
                    created: 0,
                    session: id,
                    head: 0,
                    start: 0,
                    pid: std::process::id(),
                    caps: 0,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                Reader::default().read(&mut peer).await.unwrap(),
                Shim::Attach(0)
            ));
        });
        ids.push(id);
        paths.push(path);
        shims.push(shim);
    }
    let mut input = Vec::new();
    let mut frame = Vec::new();
    let mut greeting_len = 0;
    for request in std::iter::once(Frame::Hello {
        version: 1,
        caps: 0,
        client_info: "test",
    })
    .chain((0..8).map(|nonce| Frame::Ping { nonce, sent_us: 0 }))
    {
        infraternal_protocol::encode_muxed_frame_into(0, &request, &mut frame).unwrap();
        input.extend_from_slice(&frame);
        if greeting_len == 0 {
            greeting_len = input.len();
        }
    }
    let (written, mut frames) = mpsc::unbounded_channel();
    let channel = Arc::new(HeldReply {
        input: Mutex::new((input, 0)),
        greeting_len,
        census_held: Notify::new(),
        reply_held: Notify::new(),
        written,
        writes: AtomicUsize::new(0),
        release: Semaphore::new(0),
    });
    let daemon_channel = channel.clone();
    let daemon = tokio::spawn(async move {
        let service = crate::plugin_control::Service::start(
            &root,
            crate::plugins::ExecutionMode::Embedded,
            None,
        )
        .await
        .unwrap();
        run_channel::<false>(
            daemon_channel.as_ref(),
            root,
            None,
            None,
            Some(service.registry.clone()),
            None,
        )
        .await
    });
    // Hold the first Pong in the writer and admit the remaining seven. This
    // preserves all eight real replies without depending on an EOF read while
    // the dispatcher has reserved room for its next two-message turn.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.reply_held.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if observed
                .borrow_and_update()
                .as_ref()
                .is_some_and(|state| state.replies == 8 && state.available == 1)
            {
                break;
            }
            observed.changed().await.unwrap();
        }
    })
    .await
    .expect("all eight Pong replies must be admitted before retirement");
    for shim in shims {
        shim.await.unwrap();
    }
    // The first retirement consumes the final slot; the next retirement must
    // remain pending at actual full FIFO capacity until the writer is released.
    std::fs::remove_file(&paths[0]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if observed
                .borrow_and_update()
                .as_ref()
                .is_some_and(|state| !state.census_pending && state.available == 0)
            {
                break;
            }
            observed.changed().await.unwrap();
        }
    })
    .await
    .expect("first retirement census must fill the final queue slot");
    std::fs::remove_file(&paths[1]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if observed
                .borrow_and_update()
                .as_ref()
                .is_some_and(|state| state.census_pending && state.available == 0)
            {
                break;
            }
            observed.changed().await.unwrap();
        }
    })
    .await
    .expect("retirement census was not retained at full capacity");
    channel.release.add_permits(1);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut pongs = 0;
        let mut saw_live = false;
        let mut saw_first_retirement = false;
        loop {
            let bytes = frames.recv().await.unwrap();
            match infraternal_protocol::decode_muxed_frame(&bytes)
                .unwrap()
                .frame
            {
                Frame::Hello { .. } => {}
                Frame::Pong { .. } => pongs += 1,
                Frame::Event { event_json, .. } => {
                    let value: serde_json::Value = serde_json::from_slice(event_json).unwrap();
                    let live = value["session_ids"].as_array().unwrap();
                    match live.len() {
                        2 => {
                            for id in &ids {
                                assert!(live.contains(&serde_json::Value::String(
                                    uuid::Uuid::from_bytes(*id).to_string()
                                )));
                            }
                            saw_live = true;
                        }
                        1 => {
                            assert!(saw_live);
                            assert_eq!(pongs, 8);
                            assert_eq!(live[0], uuid::Uuid::from_bytes(ids[1]).to_string());
                            saw_first_retirement = true;
                        }
                        0 => {
                            assert!(saw_live && saw_first_retirement);
                            assert_eq!(pongs, 8);
                            return;
                        }
                        _ => panic!("unexpected live session set"),
                    }
                }
                other => panic!("unexpected control reply: {other:?}"),
            }
        }
    })
    .await;
    daemon.abort();
    let _ = daemon.await;
    result.expect("pending census was lost until another request or timer");
}
