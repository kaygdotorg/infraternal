//! The host activity log of privileged actions (D274, D376, #399).
//!
//! Every privileged action on a host is a row in `host_activity`: who asked,
//! when, which way in, and what came of it. The host's activity view and the
//! Inbox read it. Rows hold fixed words and ids only, never a secret and
//! never text from the host.
//!
//! The upgrade's "2 tries, then wait" rule (D376) is not computed here: it
//! lives with the promotion's own row, where the check and the try are one
//! write (`crate::enrollment::promotion`, J415 B2). This log only records it.
use sqlx::SqlitePool;

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

#[cfg(test)]
mod tests {
    //! Two wrong tries wait 15 minutes; a success or the passing time clears it.
    use super::*;

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

    /// Rows go in, and the schema refuses anything that isn't a fixed word
    /// (no free text, so no secret can be stored by mistake).
    #[tokio::test]
    async fn the_log_holds_fixed_words_only() {
        let pool = pool().await;
        let host = uuid::Uuid::from_u128(7);
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
            1_000,
        )
        .await
        .unwrap();
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
