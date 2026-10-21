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
async fn periodic_authority_read_fails_closed_at_the_bounded_wait() {
    assert_eq!(held_authority_operation(Completion::Held).await, Err(()));
}

#[derive(Clone, Copy)]
enum Completion {
    Live,
    Revoked,
    Expired,
    Held,
}

// Handshakes return owned identities: denial must dispose of the value even
// when its operation completed before the outstanding authority check.
#[derive(Debug)]
struct CompletionValue {
    marker: [u8; 16],
    dropped: Arc<AtomicBool>,
}

impl Drop for CompletionValue {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
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
    let dropped = Arc::new(AtomicBool::new(false));
    let value = CompletionValue {
        marker: [7; 16],
        dropped: dropped.clone(),
    };
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
        Ok(value)
    };
    let guarded = while_authorized_value(&state, &user, token, false, operation);
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
        // Progress support is not an extension: a still-held connection is a
        // busy store, retried at the unchanged per-read deadline and failed
        // closed at the bounded authority wait (#240), never later.
        let result = advance_through_authority_wait(guarded.as_mut()).await;
        assert!(!owner_polled.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        return result.map(|_| ());
    }
    release.send(()).unwrap();
    let completed = guarded.as_mut().now_or_never();
    assert!(
        owner_polled.load(Ordering::SeqCst),
        "periodic authority read stopped polling the operation that owns its only database connection"
    );
    let result = match completed {
        Some(result) => result,
        None => guarded.await,
    };
    let result = result.map(|value| {
        assert_eq!(value.marker, [7; 16]);
        assert!(!dropped.load(Ordering::SeqCst));
        drop(value);
    });
    assert!(dropped.load(Ordering::SeqCst));
    result
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
        // The frozen operation keeps the only connection, so the pending read
        // can never finish: it fails closed at the bounded wait (#240). The
        // bound is measured from the interruption: the read in flight when it
        // came is dropped, and one fresh read decides (review P3-4).
        let result = if let Some(result) = completed {
            result
        } else {
            advance_through_authority_wait(guarded.as_mut()).await
        };
        assert_eq!(result, Err(()));
        return;
    }
    panic!("could not align the initial one-second authority lease");
}

/// Step paused time through one bounded authority wait. The future must stay
/// pending for most of it (a busy store is retried, not refused) and must end
/// by its bound plus one read deadline (a busy store never extends it).
async fn advance_through_authority_wait<T>(
    mut guarded: std::pin::Pin<&mut impl std::future::Future<Output = T>>,
) -> T {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(result) = guarded.as_mut().now_or_never() {
            assert!(
                started.elapsed() >= AUTHORITY_WAIT / 2,
                "a busy store was refused before the bounded authority wait"
            );
            return result;
        }
        assert!(
            started.elapsed() <= AUTHORITY_WAIT + AUTHORITY_READ_TIMEOUT,
            "a busy store extended the bounded authority wait"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
    }
}

/// Exercise the shared places directly so socket transport scheduling cannot
/// hide a retained query or a duplicated place (#240, delta review r3).
mod cap_review_r3 {
    use super::*;

    async fn fixture() -> (WebSocketState, String) {
        let (pool, user, _) = database().await;
        let auth = Auth::new(
            pool.clone(),
            "auth.example.test",
            "https://auth.example.test",
        )
        .await
        .unwrap();
        let now = unix_seconds().unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'cap review',?,?,1)")
            .bind(crate::auth::hash("cap-review-r3"))
            .bind(&user)
            .bind(now + 3600)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
        let state = WebSocketState::new(auth, pool, EmbeddedAgent::from_test_socket(socket))
            .await
            .unwrap();
        (state, user)
    }

    /// Thirty-two simultaneous callers exhaust all four places, but only four
    /// queries may outlive their attempts. Waiting callers own no place.
    #[tokio::test(start_paused = true)]
    async fn deadline_storm_retains_exactly_four_places_then_recovers() {
        let clock = FrozenSocketTime::new().await;
        let (state, user) = fixture().await;
        let held = state.pool.acquire().await.unwrap();
        let mut storm: Vec<_> = (0..32)
            .map(|_| {
                Some(Box::pin(read_expiry(
                    &state,
                    &user,
                    "cap-review-r3",
                    false,
                    AUTHORITY_WAIT,
                )))
            })
            .collect();
        for read in &mut storm {
            assert!(read.as_mut().unwrap().as_mut().now_or_never().is_none());
        }
        assert_eq!(state.authority.reads.available_permits(), 0);
        let mut ended = 0;
        // Advance the entire retry budget while the sole pooled connection
        // stays held. A repeated attempt cannot create a fifth detached query.
        for _ in 0..22 {
            tokio::time::advance(Duration::from_millis(50)).await;
            for slot in &mut storm {
                if let Some(read) = slot
                    && let Some(result) = read.as_mut().now_or_never()
                {
                    assert!(matches!(result, Err(AuthorityMiss::Unavailable)));
                    *slot = None;
                    ended += 1;
                }
            }
            assert_eq!(state.authority.reads.available_permits(), 0);
        }
        assert_eq!(ended, 32, "not every waiting access check failed closed");
        assert_eq!(Arc::strong_count(&state.authority), AUTHORITY_READS + 1);
        drop(storm);
        assert_eq!(state.authority.reads.available_permits(), 0);
        drop(held);
        // Restore physical scheduling only for SQLite's worker and the pool's
        // asynchronous return; this is a completion guard, not a latency claim.
        drop(clock);
        let all = tokio::time::timeout(
            Duration::from_secs(10),
            state
                .authority
                .reads
                .acquire_many(u32::try_from(AUTHORITY_READS).unwrap()),
        )
        .await
        .expect("detached access checks did not return their places")
        .unwrap();
        assert_eq!(state.authority.reads.available_permits(), 0);
        drop(all);
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
        assert_eq!(Arc::strong_count(&state.authority), 1);
        assert!(
            read_expiry(&state, &user, "cap-review-r3", false, AUTHORITY_WAIT)
                .await
                .is_ok()
        );
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
    }
    /// Disconnect and shutdown both drop the enclosing read future. Cancelling
    /// while queued must release nothing; cancelling a query must detach it.
    #[tokio::test(start_paused = true)]
    async fn cancelled_storm_returns_every_place_without_duplication() {
        let clock = FrozenSocketTime::new().await;
        let (state, user) = fixture().await;
        let held = state.pool.acquire().await.unwrap();
        let mut storm: Vec<_> = (0..32)
            .map(|_| {
                Box::pin(read_expiry(
                    &state,
                    &user,
                    "cap-review-r3",
                    false,
                    AUTHORITY_WAIT,
                ))
            })
            .collect();
        for read in &mut storm {
            assert!(read.as_mut().now_or_never().is_none());
        }
        assert_eq!(state.authority.reads.available_permits(), 0);
        drop(storm);
        assert_eq!(state.authority.reads.available_permits(), 0);
        drop(held);
        drop(clock);
        let all = tokio::time::timeout(
            Duration::from_secs(10),
            state
                .authority
                .reads
                .acquire_many(u32::try_from(AUTHORITY_READS).unwrap()),
        )
        .await
        .expect("cancelled access checks retained their places")
        .unwrap();
        assert_eq!(state.authority.reads.available_permits(), 0);
        drop(all);
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
        assert!(matches!(
            read_expiry(&state, &user, "absent-session", false, AUTHORITY_WAIT).await,
            Err(AuthorityMiss::Refused)
        ));
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
        state.pool.close().await;
        assert!(matches!(
            read_expiry(&state, &user, "cap-review-r3", false, AUTHORITY_WAIT).await,
            Err(AuthorityMiss::Unavailable)
        ));
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
    }
}
