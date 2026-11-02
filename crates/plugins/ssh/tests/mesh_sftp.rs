//! Check that the file protocol worker belongs to its SSH attachment.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use russh_sftp::{
    client::SftpSession,
    protocol::{Attrs, StatusCode},
    server::{self, Handler},
};
use std::time::Duration;
use tokio::{sync::oneshot, time::timeout};
struct PendingFiles {
    started: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}
impl Drop for PendingFiles {
    fn drop(&mut self) {
        if let Some(sender) = self.dropped.take() {
            let _ = sender.send(());
        }
    }
}
impl Handler for PendingFiles {
    type Error = StatusCode;
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }
    async fn stat(&mut self, _: u32, _: String) -> Result<Attrs, Self::Error> {
        self.started.take().unwrap().send(()).unwrap();
        std::future::pending().await
    }
}
#[tokio::test]
async fn attachment_teardown_cancels_a_pending_file_operation() {
    timeout(Duration::from_secs(10), async {
        let (service, client) = tokio::io::duplex(1024);
        let (started, begin) = oneshot::channel();
        let (dropped, ended) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let handler = PendingFiles {
                started: Some(started),
                dropped: Some(dropped),
            };
            if std::env::var_os("MESH_TEST_DETACHED_SFTP").is_some() {
                server::run_with_config(service, handler, server::Config::default()).await;
            } else {
                let _ =
                    server::serve_with_config(service, handler, server::Config::default()).await;
            }
        });
        let client = SftpSession::new(client).await.unwrap();
        let request = tokio::spawn(async move { client.metadata("/pending").await });
        begin.await.unwrap();
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        ended.await.unwrap();
        request.abort();
        let _ = request.await;
    })
    .await
    .unwrap();
}
