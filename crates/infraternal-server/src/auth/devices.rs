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
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes) VALUES (?,?,?,?)")
            .bind(hash(&key))
            .bind(row.get::<String, _>("user_id"))
            .bind(row.get::<String, _>("device"))
            .bind(row.get::<String, _>("scopes"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(key)
    }

    /// Validate a CLI/MCP key for one explicit scope; no browser session or fresh-tap privilege.
    pub async fn api_authorize(&self, token: &str, scope: &str) -> Result<String> {
        let row = sqlx::query("SELECT user_id,scopes FROM api_keys WHERE token_hash=?")
            .bind(hash(token))
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::Denied)?;
        let scopes: Vec<String> = serde_json::from_str(row.get("scopes"))?;
        if !scopes.iter().any(|s| s == scope) {
            return Err(Error::Denied);
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
