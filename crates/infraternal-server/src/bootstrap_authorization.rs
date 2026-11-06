//! Rechecks owner authority on bootstrap admission, retry and revocation; only unlocked sessions qualify.

use super::{Auth, Error, Result};

impl Auth {
    /// Root consent is a request choice, never a substitute for authenticated owner authority.
    /// # Errors
    /// Refuses expired, revoked, locked or non-owner sessions and storage failure.
    pub async fn bootstrap_owner(&self, token: &str, now: i64) -> Result<String> {
        let session = self.session(token, now).await?;
        let owner: bool = sqlx::query_scalar("SELECT owner FROM users WHERE id=?")
            .bind(&session.user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::Denied)?;
        if !owner {
            return Err(Error::Denied);
        }
        Ok(session.user_id)
    }
    /// Current host ownership for retained setup delivery, independent of a wizard.
    #[cfg(feature = "remote")]
    pub(crate) async fn bootstrap_host(&self, owner: &str, host: uuid::Uuid) -> bool {
        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.confirmed=0))")
            .bind(host.as_bytes().as_slice()).bind(owner).fetch_one(&self.pool).await.unwrap_or(false)
    }
}
