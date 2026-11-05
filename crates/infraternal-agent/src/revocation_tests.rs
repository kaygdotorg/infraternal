//! Revocation must deny before a saturated ordinary queue or stalled disk can proceed.
use super::*;
use std::{future::Future as _, task::Context};

/// Bound a broken test, not disk latency. Parallel publication tests can hold
/// the VM's real journal beyond thirty seconds; causal assertions below still
/// require denial before disk progress and completion before ordinary release.
const DEADLOCK_GUARD: Duration = Duration::from_secs(300);

/// Interleave the review's eighteen ordinary waiters with three revocations.
/// Held blocking workers make denial observable before any marker can be saved.
#[test]
fn ordinary_flood_cannot_refuse_or_delay_denial() {
    const CHILD: &str = "INFRATERNAL_REVOCATION_FLOOD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logins::revocation_tests::ordinary_flood_cannot_refuse_or_delay_denial",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        eprint!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    ordinary_flood_child();
}

/// Keep ordinary admission occupied until all three security saves are durable.
fn ordinary_flood_child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .unwrap();
    let root = crate::durable_tests::directory();
    runtime.block_on(async {
        let ordinary = uuid::Uuid::new_v4();
        let fence = acquire(&root, &format!("{}.person", ordinary.simple()))
            .await
            .unwrap();
        let mut releases = Vec::new();
        let mut blockers = Vec::new();
        for _ in 0..2 {
            let (release, wait) = std::sync::mpsc::channel();
            let (entered, ready) = tokio::sync::oneshot::channel();
            blockers.push(tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = wait.recv();
            }));
            ready.await.unwrap();
            releases.push(release);
        }
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut saves: Vec<_> = (0..18)
            .map(|_| Box::pin(restore_at(&root, ordinary)))
            .collect();
        for save in &mut saves {
            assert!(save.as_mut().poll(&mut context).is_pending());
        }
        let people: Vec<_> = (0..3).map(|_| uuid::Uuid::new_v4()).collect();
        let mut revokes: Vec<_> = people
            .iter()
            .map(|person| Box::pin(revoke_at(&root, Manager::Detached, *person, false)))
            .collect();
        let pending: Vec<_> = revokes
            .iter_mut()
            .map(|call| call.as_mut().poll(&mut context).is_pending())
            .collect();
        let denied: Vec<_> = people
            .iter()
            .map(|person| permitted(&root, *person).is_err())
            .collect();
        let unrelated_allowed = permitted(&root, uuid::Uuid::new_v4()).is_ok();
        // Release disk workers, but keep every ordinary admission and its fence.
        for release in releases {
            release.send(()).unwrap();
        }
        for blocker in blockers {
            blocker.await.unwrap();
        }
        let completed = if pending.iter().all(|value| *value) {
            tokio::time::timeout(DEADLOCK_GUARD, async {
                for revoke in revokes { revoke.await?; }
                Ok::<_, io::Error>(())
            }).await.is_ok_and(|result| result.is_ok())
        } else { drop(revokes); false };
        // Even a broken security lane releases all fixture ownership before asserting.
        drop(saves);
        drop(fence);
        eprintln!("ordinary_waiters=18 security_pending={pending:?} denied_before_disk={denied:?} durable_before_ordinary_release={completed}");
        assert!(
            pending.iter().all(|value| *value),
            "revocation was refused by ordinary admission"
        );
        assert!(
            denied.iter().all(|value| *value),
            "access stayed permitted until disk progress"
        );
        assert!(
            unrelated_allowed,
            "ordinary saturation must not deny unrelated people"
        );
        assert!(completed, "ordinary admission prevented durable security progress");
        for person in people {
            assert!(permitted(&root, person).is_err());
        }
    });
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
}

/// A refused marker stays denied after the finite caller has left, then retries.
#[tokio::test]
async fn failed_marker_stays_denied_and_retries_after_caller_leaves() {
    let root = crate::durable_tests::directory();
    let person = uuid::Uuid::new_v4();
    drop(
        acquire(&root, &format!("{}.person", person.simple()))
            .await
            .unwrap(),
    );
    let marker = root
        .join("infraternal-login-locks")
        .join(format!("{}.revoked", person.simple()));
    let target = root.join("untouched");
    std::fs::write(&target, b"fixture").unwrap();
    std::os::unix::fs::symlink(&target, &marker).unwrap();
    for _ in 0..3 {
        assert!(
            revoke_at(&root, Manager::Detached, person, false)
                .await
                .is_err()
        );
    }
    assert!(permitted(&root, person).is_err());
    assert_eq!(
        revocations::retained(&root),
        1,
        "finite retries must share one owner"
    );
    std::fs::remove_file(&marker).unwrap();
    // Absence of the refused on-disk object must not restore access in memory.
    let denied = permitted(&root, person).is_err();
    let restore_refused = restore_at(&root, person).await.is_err();
    assert!(
        denied && restore_refused,
        "failed persistence lost the retained denial"
    );
    // The condition is completion of the real retry, not elapsed wall-clock time.
    // The deadline only terminates a broken test whose retained worker never runs.
    tokio::time::timeout(DEADLOCK_GUARD, async {
        loop {
            if marker.is_file() && restore_at(&root, person).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained revocation never became durable");
    assert_eq!(std::fs::read(&target).unwrap(), b"fixture");
    permitted(&root, person).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

/// Distinct security requests remain bounded even when every caller disconnects.
/// Overflow is a durable host refusal, never an eviction of an older revocation.
#[tokio::test]
async fn security_flood_coalesces_without_forgetting_cancelled_intent() {
    let root = crate::durable_tests::directory();
    drop(acquire(&root, "fixture").await.unwrap());
    let host_marker = root.join("infraternal-login-locks/host.revoked");
    let target = root.join("untouched");
    std::fs::write(&target, b"fixture").unwrap();
    std::os::unix::fs::symlink(&target, &host_marker).unwrap();
    let people: Vec<_> = (0..1024).map(|_| uuid::Uuid::new_v4()).collect();
    let mut calls: Vec<_> = people
        .iter()
        .map(|person| Box::pin(revoke_at(&root, Manager::Detached, *person, false)))
        .collect();
    let mut context = Context::from_waker(std::task::Waker::noop());
    for call in &mut calls {
        assert!(call.as_mut().poll(&mut context).is_pending());
    }
    let retained = revocations::retained(&root);
    assert_eq!(retained, revocations::CAPACITY + 1);
    assert!(
        people
            .iter()
            .all(|person| permitted(&root, *person).is_err())
    );
    assert!(
        permitted(&root, uuid::Uuid::new_v4()).is_err(),
        "overflow must fail closed for the host"
    );
    drop(calls);
    // A refused host marker must not starve the eighteen known people either.
    tokio::time::timeout(DEADLOCK_GUARD, async {
        while revocations::retained(&root) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed host marker starved individual security saves");
    std::fs::remove_file(&host_marker).unwrap();
    assert!(permitted(&root, uuid::Uuid::new_v4()).is_err());
    tokio::time::timeout(DEADLOCK_GUARD, async {
        while revocations::retained(&root) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled security intent never completed");
    assert!(host_marker.is_file());
    assert_eq!(std::fs::read(&target).unwrap(), b"fixture");
    assert!(restore_at(&root, people[0]).await.is_err());
    assert!(permitted(&root, uuid::Uuid::new_v4()).is_err());
    eprintln!(
        "security_flood=1024 retained_intents_peak={retained} retained_after_durability=0 host_denied=true"
    );
    std::fs::remove_dir_all(root).unwrap();
}
