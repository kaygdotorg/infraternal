//! Functional proof that a held file writer cannot prevent a runtime request from completing.
use super::runtime_probe::during_slow_write;
use std::{io, path::PathBuf};

/// A current-thread runtime must answer before the injected write is released.
#[tokio::test(flavor = "current_thread")]
async fn runtime_probe_answers_while_write_is_held() {
    let path = crate::test_state_root().join(format!("lag-{}", uuid::Uuid::new_v4()));
    let marker = path.clone();
    let (answer, _elapsed) = during_slow_write(path.clone(), async move {
        // The writer has created the file, but has not been allowed to finish it.
        assert_eq!(std::fs::read(&marker)?, b"pending");
        tokio::task::yield_now().await;
        Ok(73)
    })
    .await
    .unwrap();
    assert_eq!(answer, 73);
    assert_eq!(std::fs::read(&path).unwrap(), b"pending-complete");
    std::fs::remove_file(path).unwrap();
}

/// A failed request still releases and joins the writer before returning.
#[tokio::test]
async fn runtime_probe_releases_writer_on_request_error() {
    let path = crate::test_state_root().join(format!("lag-{}", uuid::Uuid::new_v4()));
    let result = during_slow_write(path.clone(), async {
        Err::<(), _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test request",
        ))
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read(&path).unwrap(), b"pending-complete");
    std::fs::remove_file(path).unwrap();
}

/// Refuse an existing path instead of truncating a caller's file.
#[tokio::test]
async fn runtime_probe_preserves_existing_file() {
    let path: PathBuf = crate::test_state_root().join(format!("lag-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"keep").unwrap();
    let result = during_slow_write(path.clone(), async { Ok(()) }).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    std::fs::remove_file(path).unwrap();
}

/// Cancelling the request disconnects the hold channel so shutdown can join the writer.
#[test]
fn runtime_probe_releases_writer_on_cancellation() {
    let path = crate::test_state_root().join(format!("lag-{}", uuid::Uuid::new_v4()));
    let marker = path.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(during_slow_write(marker, async move {
            started.send(()).unwrap();
            std::future::pending::<io::Result<()>>().await
        }));
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    });
    // Runtime shutdown joins blocking workers, proving cancellation released it.
    drop(runtime);
    assert_eq!(std::fs::read(&path).unwrap(), b"pending-complete");
    std::fs::remove_file(path).unwrap();
}

/// Exercise the ordinary protocol dispatcher while the probe's file writer is held.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn runtime_probe_uses_real_agent_ping() {
    let state = crate::test_state_root().join(format!(
        "p{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        super::runtime_probe::agent_ping_under_slow_write(state.clone()),
    )
    .await;
    assert!(result.unwrap().is_ok());
    assert_eq!(
        std::fs::read(state.join("lag-probe.write")).unwrap(),
        b"pending-complete"
    );
    std::fs::remove_dir_all(state).unwrap();
}
