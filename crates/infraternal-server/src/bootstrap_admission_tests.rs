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

/// Link observations include remote execution stalls. Arithmetic must remain
/// monotonic without overflow even when the observation is an extreme outlier.
#[test]
fn review_commit_budget_is_monotonic_for_zero_and_outlier_samples() {
    let mut previous = Duration::ZERO;
    for sample in [
        Duration::ZERO,
        Duration::from_secs(3),
        Duration::from_secs(6),
        Duration::from_secs(7),
        Duration::MAX,
    ] {
        let budget = setup_commit_budget(sample);
        assert!(
            budget >= previous,
            "larger observations shortened the commit allowance"
        );
        assert!(budget >= installed_actor_budget(sample).min(Duration::from_secs(180)));
        previous = budget;
    }
    assert_eq!(installed_actor_budget(Duration::MAX), Duration::MAX);
}

/// Readiness includes final facts and terminal work after both route phases.
/// The zero/absent observation must preserve that healthy final proof.
#[tokio::test(start_paused = true)]
async fn review_commit_budget_allows_final_proof_after_both_route_phases() {
    final_proof_fits_commit_budget(Duration::ZERO, 29, 3).await;
}

/// A real slow-link observation also needs the final proof allowance; two SSH
/// round trips alone do not cover facts and terminal work after route admission.
#[tokio::test(start_paused = true)]
async fn review_commit_budget_allows_final_proof_at_600_ms() {
    final_proof_fits_commit_budget(Duration::from_millis(600), 34, 4).await;
}

async fn final_proof_fits_commit_budget(sample: Duration, route_seconds: u64, proof_seconds: u64) {
    let operation = async {
        // Each phase remains strictly inside installed_actor_budget(sample).
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_secs(route_seconds)).await;
        }
        // Both final proofs run concurrently after route admission and
        // each permits ten seconds; this healthy result uses less than half.
        tokio::time::sleep(Duration::from_secs(proof_seconds)).await;
    };
    tokio::time::timeout(setup_commit_budget(sample), operation)
        .await
        .expect("SSH commit cancelled healthy final proof inside the readiness allowances");
}

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
    let mut waiting = Box::pin(wait_installed_actor(&hosts, host, Duration::from_secs(30)));
    assert!(waiting.as_mut().now_or_never().is_none());
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
        .unwrap()
        .unwrap();
    assert!(actor.installed_route().await.unwrap());
    drop((actor, ssh_actor, hosts));
    peer.abort();
    if let Err(error) = peer.await {
        assert!(error.is_cancelled(), "admission peer panicked: {error}");
    }
}

/// A failed route must keep the old startup allowance even on a fast SSH link.
#[tokio::test(start_paused = true)]
async fn missing_route_uses_link_scaled_bound_without_inventory_extensions() {
    let hosts = RemoteHosts::default();
    let budget = installed_actor_budget(Duration::from_millis(600));
    assert_eq!(budget, Duration::from_millis(34800));
    assert_eq!(
        setup_commit_budget(Duration::from_millis(600)),
        Duration::from_millis(90800),
        "commit includes both route waits, facts, terminal proof and two SSH exchanges"
    );
    assert_eq!(
        setup_commit_budget(Duration::ZERO),
        Duration::from_secs(80),
        "the command deadline covers both route waits and final proof allowances"
    );
    assert_eq!(
        installed_actor_budget(Duration::ZERO),
        Duration::from_secs(30)
    );
    let waiting = wait_installed_actor(&hosts, Uuid::new_v4(), budget);
    tokio::pin!(waiting);
    assert!(waiting.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_secs(29)).await;
    hosts.5.publish();
    assert!(waiting.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_secs(5)).await;
    hosts.5.publish();
    assert!(waiting.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(801)).await;
    assert!(waiting.await.is_err());
}
