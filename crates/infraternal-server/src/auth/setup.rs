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

    /// Start owner enrollment. Recovery words are returned once; pending state contains only their hash.
    pub async fn setup_start(&self, token: &str, name: &str, now: i64) -> Result<Value> {
        if sqlx::query("SELECT singleton FROM setup WHERE token_hash=? AND expires>?")
            .bind(hash(token))
            .bind(now)
            .fetch_optional(&self.pool)
            .await?
            .is_none()
        {
            return Err(Error::Denied);
        }
        self.registration(
            Uuid::new_v4().to_string(),
            name,
            Authority::Setup(hash(token)),
            true,
            now,
        )
        .await
    }
}
