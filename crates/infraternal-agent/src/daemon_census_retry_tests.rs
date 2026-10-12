//! A directory-retirement census must survive full control capacity and retry without inbound traffic [D81], #168.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::AtomicUsize},
};
use tokio::sync::{Notify, Semaphore};

struct HeldCensus {
    input: Mutex<(Vec<u8>, usize)>,
    greeting_len: usize,
    census_held: Notify,
    written: mpsc::UnboundedSender<Vec<u8>>,
    writes: AtomicUsize,
    release: Semaphore,
    drained: Notify,
}
impl Channel for HeldCensus {
    async fn read(&self, destination: &mut [u8]) -> io::Result<usize> {
        let greeted = self.input.lock().unwrap().1 >= self.greeting_len;
        if greeted && self.writes.load(Ordering::Relaxed) < 2 {
            self.census_held.notified().await;
        }
        let copied = {
            let mut input = self.input.lock().unwrap();
            // The census must leave its control slot before all eight Pongs arrive.
            // Otherwise setup itself correctly exercises overflow, not retirement retry.
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
        self.drained.notify_one();
        std::future::pending().await
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if self.writes.fetch_add(1, Ordering::Relaxed) == 1 {
            self.census_held.notify_one();
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Keep the full ordered fixture visible: no request is sent after retirement.
#[tokio::test]
#[allow(clippy::too_many_lines)]
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
    let channel = Arc::new(HeldCensus {
        input: Mutex::new((input, 0)),
        greeting_len,
        census_held: Notify::new(),
        written,
        writes: AtomicUsize::new(0),
        release: Semaphore::new(0),
        drained: Notify::new(),
    });
    let daemon_channel = channel.clone();
    let daemon = tokio::spawn(async move {
        run_channel(daemon_channel.as_ref(), Some(root), None, None, None).await
    });
    // The writer holds the first census; all eight Pongs occupy control slots.
    let setup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.drained.notified(),
    )
    .await;
    if setup.is_err() {
        let outcome = if daemon.is_finished() {
            format!("{:?}", daemon.await)
        } else {
            "still running".to_owned()
        };
        panic!("census setup never drained; daemon outcome: {outcome}");
    }
    shim.await.unwrap();
    std::fs::remove_file(&path).unwrap();
    // Directory readiness gives the dispatcher another turn with the lane full.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.drained.notified(),
    )
    .await
    .unwrap();
    channel.release.add_permits(1);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut pongs = 0;
        let mut saw_live = false;
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
                    let ids = value["session_ids"].as_array().unwrap();
                    if ids.is_empty() {
                        assert!(saw_live);
                        assert_eq!(pongs, 8);
                        return;
                    }
                    assert_eq!(
                        ids,
                        &[serde_json::Value::String(
                            uuid::Uuid::from_bytes(id).to_string()
                        )]
                    );
                    saw_live = true;
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
