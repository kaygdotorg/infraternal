//! Separates installed ledger admission from the actor's active route before private readiness (#189).

use super::*;
use crate::remote_runtime::tests::{identities, revocation, ssh_bridge};
use futures_util::FutureExt;
use infraternal_agent::{
    remote_tls,
    transport::{Receive, Transmit},
};
use infraternal_protocol::Frame;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn installed_admission_waits_for_the_active_route() {
    let scratch = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/addhost-instant")
                .into_os_string()
        }),
    );
    let directory = Directory(scratch.join(format!("route-{}", Uuid::new_v4())));
    std::fs::create_dir_all(&directory.0).unwrap();
    let (server, identity, root, _) = identities();
    let (store, _pool, host, fingerprint) = revocation::admitted_store(&identity, &root).await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store, fingerprint)
        .await
        .unwrap();
    let hosts = RemoteHosts::default();
    // Reproduce the observable admission window directly: installed metadata
    // is visible while the same actor still owns its old SSH route. No session
    // may be opened merely because that metadata has become visible.
    hosts
        .admit_observed(
            guard.clone(),
            ssh_bridge::pipe_link(&directory.0.join("pid")).await,
            None,
        )
        .await
        .unwrap();
    assert!(hosts.installed(host).await);
    let ssh_actor = hosts.actor(host).await.unwrap();
    assert!(!ssh_actor.installed_route().await.unwrap());
    let mut waiting = Box::pin(wait_installed_actor(&hosts, host));
    assert!(
        waiting.as_mut().now_or_never().is_none(),
        "ledger admission released the old SSH route"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_config = remote_tls::client_config(&identity, std::slice::from_ref(&root)).unwrap();
    let server_config = remote_tls::server_config(&server, &[root]).unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(address, "localhost", &client_config)
            .await
            .unwrap();
        Transmit::default()
            .send(
                &connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: 0,
                    client_info: "admission fixture",
                },
            )
            .await
            .unwrap();
        let mut receive = Receive::default();
        while let Ok(frame) = receive.next(&connection.channel).await {
            assert!(
                !matches!(frame.frame, Frame::Call { .. }),
                "route query created remote work"
            );
        }
    });
    let (stream, peer_address) = listener.accept().await.unwrap();
    let connection = remote_tls::accept(stream, &server_config).await.unwrap();
    let link = crate::remote_link::RemoteLink::tcp(connection.channel)
        .await
        .unwrap();
    hosts
        .admit_observed(guard, link, Some(peer_address.ip()))
        .await
        .unwrap();
    let actor = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap();
    assert!(actor.installed_route().await.unwrap());
    drop((actor, ssh_actor, hosts));
    peer.abort();
    if let Err(error) = peer.await {
        assert!(error.is_cancelled(), "admission peer panicked: {error}");
    }
}
