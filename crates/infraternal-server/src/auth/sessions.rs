//! Initial session issuance after successful owner enrollment [28].
use super::{Result, SESSION, hash};
pub(super) async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &str,
    user: &str,
    device: &str,
    now: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh) VALUES (?,?,?,?,?)")
        .bind(hash(token))
        .bind(user)
        .bind(device)
        .bind(now + SESSION)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
