//! Checks typed authority outcomes and retained read places at retry boundaries (#240).

use super::*;
use crate::auth::tests::socket_clock::FrozenSocketTime;
use futures_util::FutureExt;

pub(in crate::websocket) const TOKEN: &str = "busy-edge-review";

/// Share a live, non-renewing authority fixture with the closed-source check.
pub(in crate::websocket) async fn fixture() -> (WebSocketState, String) {
    let (pool, user, _) = database().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let now = unix_seconds().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'review',?,?,1)")
        .bind(crate::auth::hash(TOKEN)).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
    let state = WebSocketState::new(auth, pool, EmbeddedAgent::from_test_socket(socket))
        .await
        .unwrap();
    (state, user)
}

/// Deleted authority is refused when SQL can answer, unavailable when it cannot;
/// neither outcome may poll the guarded write or retain a place after recovery.
#[tokio::test(start_paused = true)]
async fn revoked_probe_across_attempt_backoff_and_total_wait_edges() {
    let _clock = FrozenSocketTime::new().await;
    for stall_ms in [0, 24, 25, 26, 100, 300, 800, 925, 975, 1000, 1025, 1200] {
        let (state, user) = fixture().await;
        let mut lease = probe_authority::Lease::new(&state, &user, TOKEN)
            .await
            .unwrap();
        state.auth.logout(TOKEN).await.unwrap();
        let mut held = Some(state.pool.acquire().await.unwrap());
        let wrote = std::sync::atomic::AtomicBool::new(false);
        let guarded = async {
            tokio::join!(
                authority_deadline(&state, &user, TOKEN, false),
                lease.run(&state, &user, TOKEN, async {
                    wrote.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<(), ()>(())
                })
            )
        };
        tokio::pin!(guarded);
        let started = tokio::time::Instant::now();
        let (main_result, result) = loop {
            if started.elapsed() >= Duration::from_millis(stall_ms) {
                drop(held.take());
            }
            if let Some(result) = guarded.as_mut().now_or_never() {
                break result;
            }
            assert!(started.elapsed() <= AUTHORITY_WAIT + AUTHORITY_READ_TIMEOUT);
            assert!(state.authority.reads.available_permits() <= AUTHORITY_READS);
            // After release, preserve a real worker's current attempt. Only a
            // gap between attempts needs the controlled clock to move again.
            if held.is_some() || state.authority.reads.available_permits() == AUTHORITY_READS {
                tokio::time::advance(Duration::from_millis(1)).await;
            }
            tokio::task::yield_now().await;
        };
        assert!(!wrote.load(std::sync::atomic::Ordering::SeqCst));
        if stall_ms <= 800 {
            assert_eq!(result, Err(AuthorityMiss::Refused), "stall={stall_ms}");
            assert_eq!(main_result, Err(AuthorityMiss::Refused), "stall={stall_ms}");
        } else {
            assert!(matches!(
                result,
                Err(AuthorityMiss::Refused | AuthorityMiss::Unavailable)
            ));
            assert!(matches!(
                main_result,
                Err(AuthorityMiss::Refused | AuthorityMiss::Unavailable)
            ));
        }
        drop(held);
        let places = state
            .authority
            .reads
            .acquire_many(u32::try_from(AUTHORITY_READS).unwrap())
            .await
            .unwrap();
        drop(places);
        assert_eq!(state.authority.reads.available_permits(), AUTHORITY_READS);
        // A full pool acquisition fences sqlx's asynchronous connection return.
        drop(state.pool.acquire().await.unwrap());
        assert_eq!(std::sync::Arc::strong_count(&state.authority), 1);
    }
}
