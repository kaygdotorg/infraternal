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
                    "hosts:read" | "terminal:connect" | "actions:dry-run"
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
        let key = random();
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires) VALUES (?,?,?,?,?,?+(SELECT api_key_lifetime_days*86400 FROM server_settings WHERE id=1))")
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
        let now = super::http::current_time(self)?;
        let token_hash = hash(token);
        // The policy is read with the key, not cached at issuance. `expires` records
        // the deadline at the last renewal; a policy edit changes the effective
        // deadline immediately without rewriting every key or resetting inactivity.
        let row = sqlx::query("SELECT user_id,scopes,renewed_at FROM api_keys CROSS JOIN server_settings WHERE server_settings.id=1 AND token_hash=? AND renewed_at+api_key_lifetime_days*86400>?")
            .bind(&token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::Denied)?;
        let scopes: Vec<String> = serde_json::from_str(row.get("scopes"))?;
        if !scopes.iter().any(|s| s == scope) {
            return Err(Error::Denied);
        }
        if now.saturating_sub(row.get::<i64, _>("renewed_at")) >= 3600 {
            // Recheck the live deadline and hourly cutoff under SQLite's writer lock.
            // Concurrent uses cannot double-renew, and deletion is never an upsert.
            let changed = sqlx::query("UPDATE api_keys SET renewed_at=?,expires=?+(SELECT api_key_lifetime_days*86400 FROM server_settings WHERE id=1) WHERE token_hash=? AND renewed_at<=? AND renewed_at+(SELECT api_key_lifetime_days*86400 FROM server_settings WHERE id=1)>?")
                .bind(now).bind(now).bind(&token_hash).bind(now - 3600).bind(now)
                .execute(&self.pool).await?.rows_affected();
            if changed == 0 {
                // Another use may have renewed first, or revocation/policy change
                // may have won. Only an existing, currently valid key can proceed.
                let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM api_keys CROSS JOIN server_settings WHERE server_settings.id=1 AND token_hash=? AND renewed_at+api_key_lifetime_days*86400>?)")
                    .bind(&token_hash).bind(now).fetch_one(&self.pool).await?;
                if !live {
                    return Err(Error::Denied);
                }
            }
        }
        Ok(row.get("user_id"))
    }

    /// Revoke an API key belonging to this user after a fresh tap.
    pub async fn api_revoke(&self, session_token: &str, key_hash: &str, now: i64) -> Result<()> {
        let session = self.session(session_token, now).await?;
        session.require_fresh(now)?;
        sqlx::query("DELETE FROM api_keys WHERE token_hash=? AND user_id=?")
            .bind(key_hash)
            .bind(session.user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List revocable API key identifiers without returning any bearer secret.
    pub async fn api_list(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        let rows = sqlx::query("SELECT token_hash,device,scopes FROM api_keys WHERE user_id=?")
            .bind(session.user_id)
            .fetch_all(&self.pool)
            .await?;
        let keys: Vec<Value> = rows.iter().map(|r| Ok(json!({"id":r.get::<String,_>("token_hash"),"device":r.get::<String,_>("device"),"scopes":serde_json::from_str::<Value>(r.get("scopes"))?}))).collect::<Result<_>>()?;
        Ok(json!(keys))
    }
}
