//! The host activity log and the root upgrade's "2 tries, then wait" rule (D274, D376, #399).
//!
//! Every privileged action on a host is a row in `host_activity`: who asked,
//! when, which way in, and what came of it. The host's activity view and the
//! Inbox read it. Rows hold fixed words and ids only, never a secret and
//! never text from the host.
//!
//! D376 allows two wrong passwords, then a wait. That keeps a person under
//! the common three-failure account lockout (pam_faillock's default `deny=3`).
//! The wait is [`WAIT`], pam_faillock's default `fail_interval`, so the
//! host's own counter has forgotten both failures before the next try.
//! [`retry_after`] computes the wait from the log, so a restart doesn't reset
//! it.
use sqlx::SqlitePool;

/// How long a host refuses tries after two wrong passwords, in seconds.
pub const WAIT: i64 = 15 * 60;
/// Wrong passwords allowed before the wait.
pub const TRIES: usize = 2;

/// What happened, as stored. The words are part of the schema's CHECK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An upgrade try started (after consent, with or without a password).
    Attempt,
    /// The password was refused.
    Wrong,
    /// A try was refused because of the wait.
    Locked,
    /// This account may not become root this way.
    Denied,
    /// The root infraternal agent took over.
    Upgraded,
    /// The upgrade failed and the host was put back as it was.
    RolledBack,
    /// The upgrade failed in a way that needs attention.
    Failed,
}

impl Kind {
    /// The stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Attempt => "privilege.attempt",
            Self::Wrong => "privilege.wrong",
            Self::Locked => "privilege.locked",
            Self::Denied => "privilege.denied",
            Self::Upgraded => "privilege.upgraded",
            Self::RolledBack => "privilege.rolled_back",
            Self::Failed => "privilege.failed",
        }
    }

    /// The kind for a stored word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        [
            Self::Attempt,
            Self::Wrong,
            Self::Locked,
            Self::Denied,
            Self::Upgraded,
            Self::RolledBack,
            Self::Failed,
        ]
        .into_iter()
        .find(|kind| kind.word() == word)
    }
}

/// One row to write.
pub struct Entry<'a> {
    /// The host it happened on.
    pub host: uuid::Uuid,
    /// The person who asked (their user id).
    pub person: &'a str,
    /// What happened.
    pub kind: Kind,
    /// The way in: `sudo`, `doas` or `su`.
    pub method: Option<&'static str>,
    /// The upgrade attempt, if any.
    pub attempt: Option<uuid::Uuid>,
    /// A fixed lowercase reason word for failures.
    pub reason: Option<&'static str>,
}

/// Write `entry` at `now` (Unix seconds).
///
/// # Errors
/// The database refused the row (including the schema's checks).
pub async fn record(pool: &SqlitePool, entry: &Entry<'_>, now: i64) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO host_activity(host_id, at, person, kind, method, attempt, reason) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(entry.host.as_bytes().as_slice())
        .bind(now)
        .bind(entry.person)
        .bind(entry.kind.word())
        .bind(entry.method)
        .bind(entry.attempt.as_ref().map(|attempt| attempt.as_bytes().to_vec()))
        .bind(entry.reason)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Seconds until `host` accepts another `method` try, or `None` when it does now.
///
/// # Errors
/// The database could not be read; callers refuse the try.
pub async fn retry_after(
    pool: &SqlitePool,
    host: uuid::Uuid,
    method: &str,
    now: i64,
) -> sqlx::Result<Option<i64>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT at, kind FROM host_activity WHERE host_id=? AND method=? AND at>? AND kind IN ('privilege.wrong','privilege.upgraded') ORDER BY id",
    )
    .bind(host.as_bytes().as_slice())
    .bind(method)
    .bind(now - WAIT)
    .fetch_all(pool)
    .await?;
    let events: Vec<(i64, Kind)> = rows
        .into_iter()
        .filter_map(|(at, word)| Kind::from_word(&word).map(|kind| (at, kind)))
        .collect();
    Ok(wait(&events, now))
}

/// The rule itself, over one host's and one method's recent wrong and
/// upgraded rows, oldest first: after [`TRIES`] wrong passwords in a row
/// (with no successful upgrade after them) the host waits [`WAIT`] seconds
/// from the last of them.
#[must_use]
pub fn wait(events: &[(i64, Kind)], now: i64) -> Option<i64> {
    let streak: Vec<i64> = events
        .iter()
        .rev()
        .take_while(|(_, kind)| *kind == Kind::Wrong)
        .map(|(at, _)| *at)
        .collect();
    let last = *streak.first()?;
    (streak.len() >= TRIES && now < last + WAIT).then_some(last + WAIT - now)
}

#[cfg(test)]
mod tests {
    //! Two wrong tries wait 15 minutes; a success or the passing time clears it.
    use super::*;

    /// One wrong try never waits; the second does, counted from itself.
    #[test]
    fn the_second_wrong_try_starts_the_wait() {
        assert_eq!(wait(&[(100, Kind::Wrong)], 110), None);
        assert_eq!(
            wait(&[(100, Kind::Wrong), (130, Kind::Wrong)], 140),
            Some(130 + WAIT - 140)
        );
    }

    /// The wait ends after 15 minutes.
    #[test]
    fn the_wait_ends() {
        assert_eq!(
            wait(&[(100, Kind::Wrong), (130, Kind::Wrong)], 130 + WAIT),
            None
        );
    }

    /// A successful upgrade between wrong tries resets the count.
    #[test]
    fn a_success_resets_the_count() {
        assert_eq!(
            wait(
                &[
                    (100, Kind::Wrong),
                    (110, Kind::Upgraded),
                    (130, Kind::Wrong)
                ],
                140
            ),
            None
        );
    }

    /// Stored words map back to their kinds, and nothing else does.
    #[test]
    fn words_round_trip() {
        for kind in [
            Kind::Attempt,
            Kind::Wrong,
            Kind::Locked,
            Kind::Denied,
            Kind::Upgraded,
            Kind::RolledBack,
            Kind::Failed,
        ] {
            assert_eq!(Kind::from_word(kind.word()), Some(kind));
        }
        assert_eq!(Kind::from_word("privilege.other"), None);
    }

    /// A migrated in-memory database.
    async fn pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    /// Rows go in, the rule reads them back per host and method, and the
    /// schema refuses anything that isn't a fixed word (no free text, so no
    /// secret can be stored by mistake).
    #[tokio::test]
    async fn the_log_holds_fixed_words_and_drives_the_wait() {
        let pool = pool().await;
        let host = uuid::Uuid::from_u128(7);
        let wrong = |at| {
            let pool = pool.clone();
            async move {
                record(
                    &pool,
                    &Entry {
                        host,
                        person: "p1",
                        kind: Kind::Wrong,
                        method: Some("sudo"),
                        attempt: None,
                        reason: None,
                    },
                    at,
                )
                .await
            }
        };
        wrong(1_000).await.unwrap();
        assert_eq!(retry_after(&pool, host, "sudo", 1_010).await.unwrap(), None);
        wrong(1_020).await.unwrap();
        assert_eq!(
            retry_after(&pool, host, "sudo", 1_030).await.unwrap(),
            Some(1_020 + WAIT - 1_030)
        );
        // Another way in, or another host, is not affected.
        assert_eq!(retry_after(&pool, host, "su", 1_030).await.unwrap(), None);
        assert_eq!(
            retry_after(&pool, uuid::Uuid::from_u128(8), "sudo", 1_030)
                .await
                .unwrap(),
            None
        );
        let free_text = sqlx::query("INSERT INTO host_activity(host_id, at, person, kind, reason) VALUES (?, 1, 'p1', 'privilege.failed', 'Password: hunter2')")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await;
        assert!(free_text.is_err());
        let other_kind = sqlx::query(
            "INSERT INTO host_activity(host_id, at, person, kind) VALUES (?, 1, 'p1', 'hunter2')",
        )
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await;
        assert!(other_kind.is_err());
    }
}
