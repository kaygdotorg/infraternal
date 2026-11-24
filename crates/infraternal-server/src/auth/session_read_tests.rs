//! `Auth::session` reads first and slides only when the slide is due (#559, J1151).
//!
//! These tests pin the rules from the `sessions` module docs ("Read first,
//! slide only when due"): a read that needs no slide takes no write, a due
//! slide still moves the deadline, an unknown cookie and a live pending login
//! write nothing, an expired pending login is still deleted, a revoked
//! session is refused on the very next read, and a deadline left ahead of
//! `now + SESSION` by a clock step back is pulled in. Each runs on both
//! drivers: the D379 pool (an on-disk database) and sqlx (in memory).

use super::*;
use crate::auth::sessions::{NextStep, next_step};

/// An owner fixture on the D379 pool (on disk) or on sqlx (in memory), plus
/// the on-disk path to remove afterwards.
async fn driver_fixture(on_pool: bool) -> (Fixture, Option<PathBuf>) {
    if on_pool {
        let (pool, path) = disk_pool("session-read").await;
        let (auth, token) = empty_with_pool(pool).await;
        assert!(auth.sessions_on_pool(), "an on-disk Auth must use the pool");
        (fixture_with_bootstrap(auth, token).await, Some(path))
    } else {
        let f = fixture().await;
        assert!(!f.auth.sessions_on_pool());
        (f, None)
    }
}

/// Close the pool and remove an on-disk fixture's directory.
async fn finish(f: Fixture, path: Option<PathBuf>) {
    f.auth.close_database().await;
    if let Some(dir) = path.as_deref().and_then(std::path::Path::parent) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The committed deadline of `token`'s row, read through sqlx.
async fn deadline(auth: &Auth, token: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=?")
        .bind(hash(token))
        .fetch_optional(&auth.pool)
        .await
        .unwrap()
}

/// Insert a session row for `user` created at `now`, pending when `pending`.
async fn plant(auth: &Auth, user: &str, now: i64, pending: bool) -> String {
    let token = random();
    let mut tx = auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &token, user, "planted", now, None)
        .await
        .unwrap();
    if pending {
        sqlx::query("UPDATE sessions SET unlocked=0 WHERE token_hash=?")
            .bind(hash(&token))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    token
}

/// The decision table: liveness and cleanup match the slide's own SQL, and
/// only a live unlocked row with a due deadline asks for the writer.
#[test]
fn the_first_read_decides_exactly_what_the_slide_would_have() {
    let now = NOW;
    let full = now + SESSION;
    // Live and unlocked: slide only when due (a minute behind, or ahead).
    assert_eq!(next_step(full, true, now, false), NextStep::Answer);
    assert_eq!(next_step(full - 60, true, now, false), NextStep::Answer);
    assert_eq!(next_step(full - 61, true, now, false), NextStep::Slide);
    assert_eq!(next_step(now + 1, true, now, false), NextStep::Slide);
    assert_eq!(next_step(full + 1, true, now, false), NextStep::Slide);
    // The pending flag does not change how an unlocked row slides.
    assert_eq!(next_step(full - 61, true, now, true), NextStep::Slide);
    assert_eq!(next_step(full, true, now, true), NextStep::Answer);
    // Expired unlocked rows are refused and left alone, as before.
    assert_eq!(next_step(now, true, now, false), NextStep::Refuse);
    assert_eq!(next_step(now - 1, true, now, true), NextStep::Refuse);
    // A live pending login: answered on unlock routes, never extended,
    // refused on full-session routes; no write either way.
    assert_eq!(next_step(now + 1, false, now, true), NextStep::Answer);
    assert_eq!(next_step(now + 300, false, now, false), NextStep::Refuse);
    // An expired pending login is deleted on any route.
    assert_eq!(
        next_step(now, false, now, true),
        NextStep::DropExpiredPending
    );
    assert_eq!(
        next_step(now - 5, false, now, false),
        NextStep::DropExpiredPending
    );
}

/// A busy session writes about once a minute instead of on every request,
/// and the deadline still slides when the slide is due.
#[tokio::test]
async fn a_session_read_writes_only_when_the_slide_is_due() {
    let _guard = SERIAL.lock().await;
    for on_pool in [true, false] {
        let (f, path) = driver_fixture(on_pool).await;
        let created = deadline(&f.auth, &f.session).await.unwrap();
        assert_eq!(created, NOW + SESSION);
        let writes = f.auth.session_writes();
        for second in 0..=60 {
            let session = f.auth.session(&f.session, NOW + second).await.unwrap();
            assert_eq!(session.user_id, f.user);
        }
        assert_eq!(
            f.auth.session_writes(),
            writes,
            "a read inside the minute wrote (pool: {on_pool})"
        );
        assert_eq!(deadline(&f.auth, &f.session).await, Some(created));

        // The 61st second is due: one write, a full session from then.
        f.auth.session(&f.session, NOW + 61).await.unwrap();
        assert_eq!(f.auth.session_writes(), writes + 1);
        assert_eq!(
            deadline(&f.auth, &f.session).await,
            Some(NOW + 61 + SESSION)
        );
        // ...and the next minute is quiet again.
        f.auth.session(&f.session, NOW + 100).await.unwrap();
        assert_eq!(f.auth.session_writes(), writes + 1);
        finish(f, path).await;
    }
}

/// A revocation takes effect on the very next request, also when that
/// request needs no slide (so no writer step would have noticed it).
#[tokio::test]
async fn a_revoked_session_is_refused_at_once_without_a_due_slide() {
    let _guard = SERIAL.lock().await;
    for on_pool in [true, false] {
        let (f, path) = driver_fixture(on_pool).await;
        f.auth.session(&f.session, NOW + 1).await.unwrap();
        let writes = f.auth.session_writes();
        f.auth.logout(&f.session).await.unwrap();
        assert!(matches!(
            f.auth.session(&f.session, NOW + 2).await,
            Err(Error::Denied)
        ));
        assert!(matches!(
            f.auth.unlock_session(&f.session, NOW + 2).await,
            Err(Error::Denied)
        ));
        assert_eq!(f.auth.session_writes(), writes, "a refusal wrote");
        assert_eq!(deadline(&f.auth, &f.session).await, None);

        // The same for a session whose slide would be due: the writer's
        // `UPDATE` cannot bring a deleted row back.
        let second = plant(&f.auth, &f.user, NOW, false).await;
        f.auth.logout(&second).await.unwrap();
        assert!(matches!(
            f.auth.session(&second, NOW + 3_600).await,
            Err(Error::Denied)
        ));
        assert_eq!(deadline(&f.auth, &second).await, None);
        finish(f, path).await;
    }
}

/// Unknown cookies and live pending logins cost no write; an expired
/// pending login is still deleted by the refused read.
#[tokio::test]
async fn unknown_and_pending_cookies_write_only_to_clean_up() {
    let _guard = SERIAL.lock().await;
    for on_pool in [true, false] {
        let (f, path) = driver_fixture(on_pool).await;
        let writes = f.auth.session_writes();
        for _ in 0..50 {
            assert!(matches!(
                f.auth.session(&random(), NOW).await,
                Err(Error::Denied)
            ));
        }
        assert_eq!(f.auth.session_writes(), writes, "an unknown cookie wrote");

        let pending = plant(&f.auth, &f.user, NOW, true).await;
        let pending_deadline = deadline(&f.auth, &pending).await;
        assert!(f.auth.unlock_session(&pending, NOW + 120).await.is_ok());
        assert!(matches!(
            f.auth.session(&pending, NOW + 120).await,
            Err(Error::Denied)
        ));
        assert_eq!(f.auth.session_writes(), writes, "a live pending read wrote");
        assert_eq!(
            deadline(&f.auth, &pending).await,
            pending_deadline,
            "a pending login was extended"
        );

        assert!(matches!(
            f.auth.unlock_session(&pending, NOW + SESSION).await,
            Err(Error::Denied)
        ));
        assert_eq!(f.auth.session_writes(), writes + 1);
        assert_eq!(
            deadline(&f.auth, &pending).await,
            None,
            "the expired pending login was not deleted"
        );
        finish(f, path).await;
    }
}

/// A deadline ahead of `now + SESSION` (the clock stepped back) is pulled
/// in by the next read, as the write on every request did, so a session
/// never outlives a full session from its latest use.
#[tokio::test]
async fn a_deadline_ahead_of_a_full_session_is_pulled_back() {
    let _guard = SERIAL.lock().await;
    for on_pool in [true, false] {
        let (f, path) = driver_fixture(on_pool).await;
        sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
            .bind(NOW + 2 * SESSION)
            .bind(hash(&f.session))
            .execute(&f.auth.pool)
            .await
            .unwrap();
        f.auth.session(&f.session, NOW + 10).await.unwrap();
        assert_eq!(
            deadline(&f.auth, &f.session).await,
            Some(NOW + 10 + SESSION)
        );
        finish(f, path).await;
    }
}

/// Many due slides racing a revocation on the other driver: whatever order
/// SQLite picks, the session ends revoked and every later read refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn due_slides_racing_a_revocation_never_revive_the_session() {
    let _guard = SERIAL.lock().await;
    let (f, path) = driver_fixture(true).await;
    let token = plant(&f.auth, &f.user, NOW, false).await;
    // Each read is a minute and more after the last, so every one is due.
    let slides: Vec<_> = (1..=32)
        .map(|n| {
            let auth = f.auth.clone();
            let token = token.clone();
            tokio::spawn(async move { auth.session(&token, NOW + 61 * n).await.is_ok() })
        })
        .collect();
    f.auth.logout(&token).await.unwrap();
    for slide in slides {
        let _ = slide.await.unwrap();
    }
    assert!(matches!(
        f.auth.session(&token, NOW + 61 * 33).await,
        Err(Error::Denied)
    ));
    assert_eq!(deadline(&f.auth, &token).await, None);
    finish(f, path).await;
}
