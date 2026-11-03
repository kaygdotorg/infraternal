//! Single-use device approval and exact-scope API key authorization [27,28].
use super::{Auth, B64, Engine, Error, Result, Row, Value, hash, json, random, require_session_tx};

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Start device-code approval. Only the high-entropy polling token can redeem approval.
    pub async fn device_start(&self, device: &str, scopes: Vec<String>, now: i64) -> Result<Value> {
        if device.is_empty()
            || device.len() > 128
            || scopes.is_empty()
            || scopes.len() > 32
            || scopes.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "hosts:read"
                        | "hosts:write"
                        | "sessions:read"
                        | "sessions:write"
                        | "status:read"
                        | "terminal:connect"
                        | "actions:dry-run"
                )
            })
        {
            return Err(Error::Invalid);
        }
        sqlx::query("DELETE FROM approvals WHERE expires<=?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        let token = random();
        let code = B64.encode(rand::random::<[u8; 12]>());
        sqlx::query(
            "INSERT INTO approvals(token_hash,code_hash,scopes,device,expires) VALUES (?,?,?,?,?)",
        )
        .bind(hash(&token))
        .bind(hash(&code))
        .bind(serde_json::to_string(&scopes)?)
        .bind(device)
        .bind(now + 600)
        .execute(&self.pool)
        .await?;
        Ok(json!({"poll_token":token,"user_code":code,"expires_in":600}))
    }

    /// Signed-in browser approval requires a fresh passkey tap and binds exact requested scopes.
    pub async fn device_approve(&self, session_token: &str, code: &str, now: i64) -> Result<()> {
        let session = self.session(session_token, now).await?;
        session.require_fresh(now)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET name=name WHERE id=?")
            .bind(&session.user_id)
            .execute(&mut *tx)
            .await?;
        require_session_tx(&mut tx, &hash(session_token), &session.user_id, now).await?;
        if sqlx::query(
            "UPDATE approvals SET user_id=? WHERE code_hash=? AND expires>? AND user_id IS NULL",
        )
        .bind(session.user_id)
        .bind(hash(code))
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 1
        {
            return Err(Error::Denied);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Inspect requested device and scopes before approval (a code alone never grants access).
    pub async fn device_inspect(&self, token: &str, code: &str, now: i64) -> Result<Value> {
        self.session(token, now).await?;
        let row =
            sqlx::query("SELECT device,scopes FROM approvals WHERE code_hash=? AND expires>?")
                .bind(hash(code))
                .bind(now)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::Denied)?;
        Ok(
            json!({"device":row.get::<String,_>("device"),"scopes":serde_json::from_str::<Value>(row.get("scopes"))?}),
        )
    }

    /// Redeem approval once. The API key is returned only here and stored as a hash.
    pub async fn device_redeem(&self, token: &str, now: i64) -> Result<String> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("DELETE FROM approvals WHERE token_hash=? AND expires>? AND user_id IS NOT NULL RETURNING user_id,device,scopes")
            .bind(hash(token)).bind(now).fetch_optional(&mut *tx).await?.ok_or(Error::Denied)?;
        let now = api_key_time(&mut tx, now).await?;
        let key = random();
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at) VALUES (?,?,?,?,?,?+(SELECT api_key_lifetime_days*86400 FROM server_settings WHERE id=1))")
            .bind(hash(&key))
            .bind(row.get::<String, _>("user_id"))
            .bind(row.get::<String, _>("device"))
            .bind(row.get::<String, _>("scopes"))
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(key)
    }

    /// Validate a CLI/MCP key for one explicit scope; no browser session or fresh-tap privilege.
    pub async fn api_authorize(&self, token: &str, scope: &str) -> Result<String> {
        let token_hash = hash(token);
        self.api_authorize_key_hash(&token_hash, scope).await
    }

    /// Validate a previously hashed key for one action without recovering its bearer value.
    /// Sliding expiry, policy clamping and dead-key tombstones still go through the J90 transaction.
    pub(crate) async fn api_authorize_key_hash(
        &self,
        token_hash: &str,
        scope: &str,
    ) -> Result<String> {
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
        let user = self
            .api_authorize_key_hash_tx(&mut tx, token_hash, scope, None)
            .await?;
        // Expiry tombstones and the persisted clock commit on a denied call too.
        tx.commit().await?;
        user.ok_or(Error::Denied)
    }

    /// Return nonsecret owner and device context for one authenticated action.
    pub(crate) async fn api_authorize_context(
        &self,
        token: &str,
        scope: &str,
    ) -> Result<(String, String)> {
        // Keep API adapters on the public authorizer so J90 sliding expiry,
        // policy clamping and revocation stay one implementation.
        let user = self.api_authorize(token, scope).await?;
        let token_hash = hash(token);
        let device: Option<String> = sqlx::query_scalar(
            "SELECT device FROM api_keys WHERE token_hash=? AND user_id=? AND dead=0",
        )
        .bind(&token_hash)
        .bind(&user)
        .fetch_optional(&self.pool)
        .await?;
        Ok((user, device.ok_or(Error::Denied)?))
    }

    /// Recheck a key by its one-way id inside an existing writer transaction.
    /// The caller commits even when this returns `None`, preserving expiry tombstones.
    pub(crate) async fn api_authorize_key_hash_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        token_hash: &str,
        scope: &str,
        wall_time: Option<i64>,
    ) -> Result<Option<String>> {
        // Serialize expiry, policy clamping, renewal and revocation. A dead row
        // remains dead even if the owner subsequently lengthens the policy.
        let row = sqlx::query("SELECT user_id,scopes,renewed_at,expires_at,dead,api_key_lifetime_days FROM api_keys CROSS JOIN server_settings WHERE server_settings.id=1 AND token_hash=?")
            .bind(token_hash).fetch_optional(&mut **tx).await?;
        // Sample only after the caller acquired the writer and the key was read.
        let wall_time = match wall_time {
            Some(time) => time,
            None => super::http::current_time(self)?,
        };
        let now = api_key_time(tx, wall_time).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let renewed_at: i64 = row.get("renewed_at");
        let stored_expiry: i64 = row.get("expires_at");
        let lifetime = row.get::<i64, _>("api_key_lifetime_days") * 86400;
        let deadline = stored_expiry.min(renewed_at + lifetime);
        if row.get::<bool, _>("dead") || deadline <= now {
            sqlx::query("UPDATE api_keys SET dead=1,expires_at=? WHERE token_hash=? AND dead=0")
                .bind(deadline)
                .bind(token_hash)
                .execute(&mut **tx)
                .await?;
            return Ok(None);
        }
        let scopes: Vec<String> = serde_json::from_str(row.get("scopes"))?;
        let allowed = scopes.iter().any(|s| s == scope);
        if allowed && now.saturating_sub(renewed_at) >= 3600 {
            sqlx::query(
                "UPDATE api_keys SET renewed_at=?,expires_at=? WHERE token_hash=? AND dead=0",
            )
            .bind(now)
            .bind(now + lifetime)
            .bind(token_hash)
            .execute(&mut **tx)
            .await?;
        } else if deadline < stored_expiry {
            // A shorter policy is permanent for this key until a valid renewal.
            sqlx::query("UPDATE api_keys SET expires_at=? WHERE token_hash=? AND dead=0")
                .bind(deadline)
                .bind(token_hash)
                .execute(&mut **tx)
                .await?;
        }
        Ok(allowed.then(|| row.get("user_id")))
    }

    /// Revoke an API key belonging to this user after a fresh tap.
    /// Retaining its one-way id lets denied actions keep accurate audit attribution.
    pub async fn api_revoke(&self, session_token: &str, key_hash: &str, now: i64) -> Result<()> {
        let session = self.session(session_token, now).await?;
        session.require_fresh(now)?;
        sqlx::query("UPDATE api_keys SET dead=1 WHERE token_hash=? AND user_id=?")
            .bind(key_hash)
            .bind(session.user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List revocable API key identifiers without returning any bearer secret.
    pub async fn api_list(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        let rows =
            sqlx::query("SELECT token_hash,device,scopes FROM api_keys WHERE user_id=? AND dead=0")
                .bind(session.user_id)
                .fetch_all(&self.pool)
                .await?;
        let keys: Vec<Value> = rows.iter().map(|r| Ok(json!({"id":r.get::<String,_>("token_hash"),"device":r.get::<String,_>("device"),"scopes":serde_json::from_str::<Value>(r.get("scopes"))?}))).collect::<Result<_>>()?;
        Ok(json!(keys))
    }
}

/// The writer transaction serializes the persisted high-water mark with expiry.
/// Only a new maximum writes; rollback and restart cannot make expiry time regress.
pub(super) async fn api_key_time(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    wall: i64,
) -> Result<i64> {
    let recorded: i64 =
        sqlx::query_scalar("SELECT api_key_time_high_water FROM server_settings WHERE id=1")
            .fetch_one(&mut **tx)
            .await?;
    if wall > recorded {
        sqlx::query("UPDATE server_settings SET api_key_time_high_water=? WHERE id=1")
            .bind(wall)
            .execute(&mut **tx)
            .await?;
    }
    Ok(wall.max(recorded))
}
