//! Own database completion and notification together, independently of the requesting waiter [28].

use super::Result;
use infraternal_plugin_api::Operation;

/// Once polled, the write runs to completion even if its caller stops waiting.
/// The owned operation must publish only after a successful commit. Reuse the
/// unit-returning task already used by node work rather than spawning each
/// database future as a separate task type (D243).
pub(super) async fn run(write: Operation<'static, Result<()>>) -> Result<()> {
    let (finished, waiting) = tokio::sync::oneshot::channel();
    let completion: Operation<'static, ()> = Box::pin(async move {
        let _ = finished.send(write.await);
    });
    tokio::spawn(completion);
    waiting.await.map_err(|_| sqlx::Error::WorkerCrashed)?
}
