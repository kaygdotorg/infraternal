//! Own database completion and notification together, independently of the requesting waiter [28].

use super::Result;
use infraternal_plugin_api::Operation;

/// Once polled, the write runs to completion even if its caller stops waiting.
/// The owned operation must publish only after a successful commit. Reuse the
/// authority-query retention: ordinary completion runs inline, and cancellation
/// moves the pinned operation into the existing unit-output task (D243).
pub(super) async fn run(write: Operation<'static, Result<()>>) -> Result<()> {
    // Cancellation may happen on a thread with no runtime entered.
    crate::completion::DetachOnDrop::new(write)
        .on_runtime(tokio::runtime::Handle::current())
        .await
}
