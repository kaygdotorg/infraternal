//! Ciphertext envelope shape validation and user-bound persistence [23].
use super::{Auth, B64, Deserialize, Engine, Error, Result, Row, Serialize, Value, json};

/// Opaque browser-created ciphertext envelope; decoding validates dimensions, not plaintext.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrap {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
impl Wrap {
    pub(super) fn validate(&self) -> Result<()> {
        for (value, length) in [(&self.salt, 32), (&self.nonce, 12), (&self.ciphertext, 48)] {
            let decoded = B64.decode(value).map_err(|_| Error::Invalid)?;
            if decoded.len() != length || B64.encode(&decoded) != *value {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Return only authenticated user's envelopes. No PRF output or DEK is accepted.
    pub async fn wraps(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        let rows = sqlx::query("SELECT kind,key_id,blob FROM wraps WHERE user_id=?")
            .bind(session.user_id)
            .fetch_all(&self.pool)
            .await?;
        let wraps: Vec<Value> = rows.into_iter().map(|r| Ok(json!({"kind":r.get::<String,_>("kind"),"key_id":r.get::<String,_>("key_id"),"wrap":serde_json::from_str::<Value>(r.get("blob"))?}))).collect::<Result<_>>()?;
        Ok(json!(wraps))
    }
}

pub(super) async fn put_wrap(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    kind: &str,
    key: &str,
    wrap: &Wrap,
) -> Result<()> {
    sqlx::query("INSERT INTO wraps(user_id,kind,key_id,blob) VALUES (?,?,?,?)")
        .bind(user)
        .bind(kind)
        .bind(key)
        .bind(serde_json::to_string(wrap)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
