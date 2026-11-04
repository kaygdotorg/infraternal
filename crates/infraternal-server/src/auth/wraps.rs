//! Ciphertext envelope shape validation and user-bound persistence [23].
use super::{Auth, B64, Deserialize, Engine, Error, Result, Row, Serialize, Value, json, prf_salt};

/// Opaque browser-created ciphertext envelope; decoding validates dimensions, not plaintext.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrap {
    /// Key-derivation salt; decodes to exactly 32 bytes.
    pub salt: String,
    /// AES-GCM nonce; decodes to exactly 12 bytes.
    pub nonce: String,
    /// Sealed 32-byte key followed by its 16-byte tag; decodes to exactly 48 bytes.
    pub ciphertext: String,
}
impl Wrap {
    /// Checks that each field decodes to its exact length and that re-encoding gives
    /// back the same text, so one envelope has exactly one accepted spelling.
    ///
    /// # Errors
    /// Returns `Error::Invalid` for bad base64, a wrong length, or non-canonical text.
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
        let session = self.unlock_session(token, now).await?;
        let rows = sqlx::query("SELECT wraps.kind,wraps.key_id,wraps.blob,passkeys.prf_input,users.recovery_wrap_version FROM wraps JOIN users ON users.id=wraps.user_id LEFT JOIN passkeys ON passkeys.id=wraps.key_id AND passkeys.user_id=wraps.user_id WHERE wraps.user_id=?")
            .bind(session.user_id)
            .fetch_all(&self.pool)
            .await?;
        let wraps: Vec<Value> = rows
            .into_iter()
            .map(|row| {
                let kind: String = row.get("kind");
                // Only authenticated envelopes reveal credential IDs/inputs. Legacy NULL
                // must retain the v1 input, or existing ciphertext becomes inaccessible.
                let input = if kind == "passkey" {
                    Some(
                        row.get::<Option<String>, _>("prf_input")
                            .unwrap_or_else(|| prf_salt(None)),
                    )
                } else {
                    None
                };
                Ok(json!({"kind":kind,"key_id":row.get::<String,_>("key_id"),
                "wrap":serde_json::from_str::<Value>(row.get("blob"))?,"prf_input":input,"recovery_wrap_version":row.get::<i64,_>("recovery_wrap_version")}))
            })
            .collect::<Result<_>>()?;
        Ok(json!(wraps))
    }
}

/// Stores one envelope for `user` inside the caller's transaction, so it commits or
/// rolls back together with the credential it belongs to. `kind` names the
/// envelope type (for example a passkey or the recovery code) and `key` the
/// credential id. The caller must have called [`Wrap::validate`] first.
///
/// # Errors
/// Fails on a storage error, including a duplicate `(user, kind, key)` row.
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
