//! Keeps an authorized transaction runnable while its periodic authority read waits for the same pool (#189).

use super::*;
use crate::auth::tests::socket_clock::FrozenSocketTime;
use futures_util::FutureExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_keeps_its_connection_owner_runnable() {
    assert_eq!(held_authority_operation(Completion::Live).await, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_rejects_revocation_committed_by_its_operation() {
    assert_eq!(held_authority_operation(Completion::Revoked).await, Err(()));
}

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_rejects_expiry_committed_by_its_operation() {
    assert_eq!(held_authority_operation(Completion::Expired).await, Err(()));
}

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_keeps_its_existing_timeout() {
    assert_eq!(held_authority_operation(Completion::Held).await, Err(()));
}

#[derive(Clone, Copy)]
enum Completion {
    Live,
    Revoked,
    Expired,
    Held,
}

async fn held_authority_operation(completion: Completion) -> Result<(), ()> {
    let _clock = FrozenSocketTime::new().await;
    let (pool, user, _) = database().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = "authority-watchdog-fixture";
    let now = unix_seconds().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'watchdog',?,?,1)")
        .bind(crate::auth::hash(token))
        .bind(&user)
        .bind(now + 3600)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
    let state = WebSocketState::new(auth, pool.clone(), EmbeddedAgent::from_test_socket(socket))
        .await
        .unwrap();
    let (held, mut acquired) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let owner_polled = Arc::new(AtomicBool::new(false));
    let observed = owner_polled.clone();
    let operation = async move {
        let mut transaction = pool.begin().await.map_err(|_| ())?;
        held.send(()).unwrap();
        released.await.map_err(|_| ())?;
        // This signal is reached only if the watchdog keeps polling the exact
        // future that can release the pool's sole checked-out connection.
        observed.store(true, Ordering::SeqCst);
        if matches!(completion, Completion::Revoked | Completion::Expired) {
            // A completed operation cannot bypass the already-started read:
            // it must observe the lost authority after this transaction commits.
            let query = match completion {
                Completion::Revoked => "DELETE FROM sessions WHERE token_hash=?",
                Completion::Expired => {
                    "UPDATE sessions SET expires=unixepoch()-1 WHERE token_hash=?"
                }
                Completion::Live | Completion::Held => unreachable!(),
            };
            sqlx::query(query)
                .bind(crate::auth::hash(token))
                .execute(&mut *transaction)
                .await
                .map_err(|_| ())?;
            transaction.commit().await.map_err(|_| ())?;
        } else {
            transaction.rollback().await.map_err(|_| ())?;
        }
        Ok(())
    };
    let guarded = while_authorized_operation(&state, &user, token, false, operation.boxed());
    tokio::pin!(guarded);
    tokio::select! {
        result = &mut acquired => result.unwrap(),
        result = &mut guarded => panic!("authorized transaction ended before release: {result:?}"),
    }

    // The operation is waiting on our explicit release while owning the only
    // connection. Poll exactly at the production check interval so the read
    // starts and waits on that connection; no physical latency is asserted.
    tokio::time::advance(BUSY_AUTHORITY_INTERVAL).await;
    assert!(guarded.as_mut().now_or_never().is_none());
    if matches!(completion, Completion::Held) {
        // Progress support is not an extension: a still-held connection must
        // fail at the unchanged production authority-read deadline.
        tokio::time::advance(AUTHORITY_READ_TIMEOUT).await;
        let result = guarded.await;
        assert!(!owner_polled.load(Ordering::SeqCst));
        return result;
    }
    release.send(()).unwrap();
    let completed = guarded.as_mut().now_or_never();
    assert!(
        owner_polled.load(Ordering::SeqCst),
        "periodic authority read stopped polling the operation that owns its only database connection"
    );
    match completed {
        Some(result) => result,
        None => guarded.await,
    }
}

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_stops_side_effects_on_revocation() {
    interrupted_authority_operation(Interruption::Revocation).await;
}

#[tokio::test(start_paused = true)]
async fn periodic_authority_read_stops_side_effects_at_expiry() {
    interrupted_authority_operation(Interruption::Expiry).await;
}

#[derive(Clone, Copy)]
enum Interruption {
    Revocation,
    Expiry,
}

#[allow(clippy::too_many_lines)] // Keep the held connection and exact interruption fence together.
async fn interrupted_authority_operation(interruption: Interruption) {
    let _clock = FrozenSocketTime::new().await;
    for _ in 0..3 {
        let (pool, user, _) = database().await;
        let auth = Auth::new(
            pool.clone(),
            "auth.example.test",
            "https://auth.example.test",
        )
        .await
        .unwrap();
        let token = "authority-interruption-fixture";
        let now = unix_seconds().unwrap();
        let lifetime = match interruption {
            Interruption::Revocation => 3600,
            Interruption::Expiry => 1,
        };
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'interruption',?,?,1)")
            .bind(crate::auth::hash(token))
            .bind(&user)
            .bind(now + lifetime)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
        let state =
            WebSocketState::new(auth, pool.clone(), EmbeddedAgent::from_test_socket(socket))
                .await
                .unwrap();
        // Avoid beginning a one-second lease across a wall-second boundary.
        // This retries fixture alignment only, before the guarded operation.
        if matches!(interruption, Interruption::Expiry) && unix_seconds().unwrap() != now {
            continue;
        }
        let (held, mut acquired) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let side_effect = Arc::new(AtomicBool::new(false));
        let observed = side_effect.clone();
        let operation = async move {
            let transaction = pool.begin().await.map_err(|_| ())?;
            held.send(()).unwrap();
            released.await.map_err(|_| ())?;
            // A socket write cannot be undone by rejecting its result later.
            observed.store(true, Ordering::SeqCst);
            transaction.rollback().await.map_err(|_| ())?;
            Ok(())
        };
        let guarded = while_authorized_operation(&state, &user, token, false, operation.boxed());
        tokio::pin!(guarded);
        let entered = tokio::select! {
            result = &mut acquired => { result.unwrap(); true },
            result = &mut guarded => {
                if matches!(interruption, Interruption::Expiry) && unix_seconds().unwrap() != now {
                    false
                } else {
                    panic!("operation ended before interruption: {result:?}");
                }
            },
        };
        if !entered {
            continue;
        }
        // Initial authority is now established. A straddle during its real
        // database read is still alignment, never a behavioral retry.
        if matches!(interruption, Interruption::Expiry) && unix_seconds().unwrap() != now {
            continue;
        }
        let before_read = match interruption {
            Interruption::Revocation => BUSY_AUTHORITY_INTERVAL,
            Interruption::Expiry => Duration::from_millis(990),
        };
        tokio::time::advance(before_read).await;
        assert!(guarded.as_mut().now_or_never().is_none());
        let read_started = tokio::time::Instant::now();
        match interruption {
            Interruption::Revocation => crate::auth::tests::publish_revocation(&state.auth),
            Interruption::Expiry => tokio::time::advance(Duration::from_millis(10)).await,
        }
        release.send(()).unwrap();
        let completed = guarded.as_mut().now_or_never();
        assert!(
            !side_effect.load(Ordering::SeqCst),
            "periodic authority read polled a send-like side effect after authority interruption"
        );
        let result = if let Some(result) = completed {
            result
        } else {
            tokio::time::advance(
                (read_started + AUTHORITY_READ_TIMEOUT)
                    .saturating_duration_since(tokio::time::Instant::now()),
            )
            .await;
            guarded.await
        };
        assert_eq!(result, Err(()));
        return;
    }
    panic!("could not align the initial one-second authority lease");
}
