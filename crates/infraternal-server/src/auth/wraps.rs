//! Ciphertext envelope shape validation and user-bound persistence [23].
use super::{B64, Deserialize, Engine, Error, Result, Serialize};

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
