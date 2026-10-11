//! Runtime cancellation must finish bounded verification before staging cleanup [198].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::{
    latest::{DownloadError, ReleaseEngine, VerifiedLookup},
    service::ReleaseLookup,
};
use infraternal_plugin_api::Operation;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
struct Engine {
    running: Arc<AtomicBool>,
    started: Arc<tokio::sync::Notify>,
}
impl ReleaseEngine for Engine {
    fn download<'a>(
        &'a self,
        address: &'a str,
        destination: &'a Path,
        _max: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async move {
            let bytes = if address.ends_with("stable.json") {
                br#"{"version":"0.1.0"}"#.as_slice()
            } else if address.ends_with("VERSION") {
                b"0.1.0\n".as_slice()
            } else {
                b"fixture".as_slice()
            };
            std::fs::write(destination, bytes).unwrap();
            Ok(())
        })
    }
    fn verify_version(
        &self,
        _file: &std::fs::File,
        _sums: &[u8],
        _signature: &[u8],
    ) -> Result<(), &'static str> {
        self.running.store(true, Ordering::SeqCst);
        self.started.notify_one();
        std::thread::sleep(std::time::Duration::from_millis(250));
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_joins_verification() {
    let state = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("release-cancel-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&state).unwrap();
    let running = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let lookup = VerifiedLookup::new(
        state.clone(),
        "http://127.0.0.1".into(),
        Arc::new(Engine {
            running: running.clone(),
            started: started.clone(),
        }),
    );
    let task = tokio::spawn(async move { lookup.latest("stable").await });
    started.notified().await;
    task.abort();
    let _ = task.await;
    let detached = running.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    std::fs::remove_dir(&state).unwrap();
    assert!(!detached, "verification outlived cancelled plugin task");
}
