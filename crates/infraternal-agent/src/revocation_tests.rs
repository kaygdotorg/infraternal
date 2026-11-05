//! Revocation must deny before a saturated ordinary queue or stalled disk can proceed.
use super::*;
use std::{future::Future as _, task::Context};

/// Bound a broken test, not disk latency. Parallel publication tests can hold
/// the VM's real journal beyond thirty seconds; causal assertions below still
/// require denial before disk progress and completion before ordinary release.
const DEADLOCK_GUARD: Duration = Duration::from_secs(300);

/// A full reserved lane retains only accepted people and backpressures later
/// requests without denying an unrelated authorized person or retaining fences.
#[tokio::test]
async fn saturated_security_lane_never_locks_out_unrelated_people() {
    let root = crate::durable_tests::directory();
    drop(acquire(&root, "fixture").await.unwrap());
    let unrelated = uuid::Uuid::new_v4();
    synchronize_at(&root, unrelated).unwrap();
    let reserved = crate::durable_io::security().await.unwrap();
    let people: Vec<_> = (0..1024).map(|_| uuid::Uuid::new_v4()).collect();
    let mut calls: Vec<_> = people
        .iter()
        .map(|person| Box::pin(revoke_at(&root, Manager::Detached, *person, false)))
        .collect();
    let mut context = Context::from_waker(std::task::Waker::noop());
    let mut accepted = 0;
    let mut busy = 0;
    for call in &mut calls {
        match call.as_mut().poll(&mut context) {
            std::task::Poll::Pending => accepted += 1,
            std::task::Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                busy += 1;
            }
            other @ std::task::Poll::Ready(_) => {
                panic!("unexpected security admission: {other:?}");
            }
        }
    }
    let retained = revocations::retained(&root);
    let unaffected = permitted(&root, unrelated).is_ok();
    drop(calls);
    drop(reserved);
    tokio::time::timeout(DEADLOCK_GUARD, async {
        while revocations::retained(&root) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let host_marker = root.join("infraternal-login-locks/host.revoked").exists();
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        unaffected,
        "security saturation denied an unrelated authorized person"
    );
    assert_eq!(accepted, revocations::CAPACITY);
    assert_eq!(busy, 1024 - revocations::CAPACITY);
    assert_eq!(retained, revocations::CAPACITY);
    assert!(!host_marker, "overflow created a host-wide refusal");
}

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

/// A pending in-memory refusal must still be present after the daemon restarts.
/// The child holds the reserved lane until denial is visible but no marker exists,
/// then exits abruptly; the parent checks only the shared on-disk state.
#[test]
fn denied_intent_survives_restart_before_marker_write() {
    const CHILD: &str = "INFRATERNAL_REVOCATION_RESTART_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let root = std::path::PathBuf::from(
            std::env::var_os("INFRATERNAL_REVOCATION_RESTART_ROOT").unwrap(),
        );
        let person =
            uuid::Uuid::parse_str(&std::env::var("INFRATERNAL_REVOCATION_RESTART_PERSON").unwrap())
                .unwrap();
        let marker = root
            .join("infraternal-login-locks")
            .join(format!("{}.revoked", person.simple()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let _reserved = runtime.block_on(crate::durable_io::security()).unwrap();
        runtime.block_on(async {
            let state = root.clone();
            tokio::spawn(async move {
                let _ = revoke_at(&state, Manager::Detached, person, false).await;
            });
            while !revocations::denied(&root, person) {
                tokio::task::yield_now().await;
            }
            assert!(permitted(&root, person).is_err());
            assert!(
                !marker.exists(),
                "the held lane must precede marker creation"
            );
        });
        std::process::exit(0);
    }

    let root = crate::durable_tests::directory();
    let person = uuid::Uuid::new_v4();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "logins::revocation_tests::denied_intent_survives_restart_before_marker_write",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("INFRATERNAL_REVOCATION_RESTART_ROOT", &root)
        .env("INFRATERNAL_REVOCATION_RESTART_PERSON", person.to_string())
        .output()
        .unwrap();
    let child_succeeded = result.status.success();
    let child_output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let access_allowed_after_restart = permitted(&root, person).is_ok();
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        child_succeeded,
        "abrupt-stop fixture failed: {child_output}"
    );
    assert!(
        !access_allowed_after_restart,
        "restart lost the accepted in-memory denial before it became durable"
    );
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
        for person in &people { synchronize_at(&root, *person).unwrap(); }
        let unrelated = uuid::Uuid::new_v4();
        synchronize_at(&root, unrelated).unwrap();
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
        let unrelated_allowed = permitted(&root, unrelated).is_ok();
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
    synchronize_at(&root, person).unwrap();
    permitted(&root, person).unwrap();
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

/// Fresh processes need an affirmative server snapshot; neither missing markers
/// nor a snapshot for a different person can grant access.
#[test]
fn fresh_login_access_requires_explicit_server_authority() {
    let root = crate::durable_tests::directory();
    let person = uuid::Uuid::new_v4();
    assert!(permitted(&root, person).is_err());
    synchronize_at(&root, person).unwrap();
    permitted(&root, person).unwrap();
    assert!(permitted(&root, uuid::Uuid::new_v4()).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
