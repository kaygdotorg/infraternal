//! One-time owner setup capability and initial enrollment [24,26,53].
use super::{Auth, Authority, DAY, Error, Result, Uuid, Value, hash, random};

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Rotate the single-use capability at startup until an owner exists [26].
    /// The transaction invalidates older enrollment authority without retaining plaintext.
    pub async fn bootstrap(&self, now: i64, announce: impl FnOnce(&str)) -> Result<()> {
        let token = random();
        let inserted = sqlx::query("INSERT INTO setup(singleton,token_hash,expires) SELECT 1,?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE owner=1) ON CONFLICT(singleton) DO UPDATE SET token_hash=excluded.token_hash, expires=excluded.expires")
            .bind(hash(&token)).bind(now + DAY).execute(&self.pool).await?.rows_affected();
        if inserted == 1 {
            announce(&format!(
                "=== INFRATERNAL ONE-TIME OWNER SETUP (expires in 24 hours) ===\n{token}\n=== END OWNER SETUP TOKEN ==="
            ));
        }
        Ok(())
    }

    /// Preserve the original setup request by treating its name as both account labels.
    pub async fn setup_start(&self, token: &str, name: &str, now: i64) -> Result<Value> {
        self.setup_start_with_identity(token, name, Some(name), now)
            .await
    }

    /// Start owner enrollment with separate public and display labels.
    pub async fn setup_start_with_identity(
        &self,
        token: &str,
        username: &str,
        display_name: Option<&str>,
        now: i64,
    ) -> Result<Value> {
        if sqlx::query("SELECT singleton FROM setup WHERE token_hash=? AND expires>?")
            .bind(hash(token))
            .bind(now)
            .fetch_optional(&self.pool)
            .await?
            .is_none()
        {
            return Err(Error::Denied);
        }
        if !valid_username(username) {
            return Err(Error::Invalid);
        }
        let display_name = display_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(username);
        if display_name.chars().count() > 64 {
            return Err(Error::Invalid);
        }
        let username_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)")
                .bind(username)
                .fetch_one(&self.pool)
                .await?;
        if username_exists {
            return Err(Error::Conflict);
        }
        self.registration(
            Uuid::new_v4().to_string(),
            username,
            display_name,
            Authority::Setup(hash(token)),
            true,
            now,
        )
        .await
    }
}

pub(super) fn valid_username(username: &str) -> bool {
    (2..=32).contains(&username.len())
        && username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}
