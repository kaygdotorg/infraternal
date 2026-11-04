//! Reads explicit current CA-administrator generations under live passkey-session authority; the owner flag is bootstrap-only [168], #78.

use crate::ca::CaError;
use sqlx::{Row, Sqlite, Transaction};

/// A copy's membership binding is public metadata, never a signing key.
pub struct Membership {
    /// User id of the administrator.
    pub(crate) user: String,
    /// Role generation; it goes up every time the administrator role is granted or revoked.
    pub(crate) generation: i64,
}

impl Membership {
    /// Return the exact current administrator identity.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
    /// Return the generation that binds the ceremony and encrypted copy.
    #[must_use]
    pub fn generation(&self) -> i64 {
        self.generation
    }
}

/// The caller holds the SQLite writer lock while installing or replacing CA
/// material. Fresh session authority also requires its exact credential still
/// belongs to this user, so credential deletion cannot leave a stale unlock.
/// # Errors
/// Refuses absent/revoked roles, stale/pending sessions, deleted credentials or storage failure.
pub async fn require_current(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
    now: i64,
) -> Result<Membership, CaError> {
    require_session(tx, token_hash, now, true).await
}

/// Read a live administrator session to start a new proof or deliver lock status.
/// This grants no signing unlock: installation separately requires a fresh passkey.
/// # Errors
/// Refuses absent/revoked roles, expired/pending sessions or deleted credentials.
pub async fn require_live(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
    now: i64,
) -> Result<Membership, CaError> {
    require_session(tx, token_hash, now, false).await
}

/// Shared check behind [`require_current`] and [`require_live`]. It first writes to
/// the administrator row so the transaction holds SQLite's writer lock, then
/// reads the membership in the same transaction. The row is returned only when
/// the role is active, the session is unlocked and unexpired, its passkey still
/// belongs to the user, and (when `fresh` is true) the passkey was used in the
/// last 300 seconds. Every failure collapses into the same opaque `CaError`.
async fn require_session(
    tx: &mut Transaction<'_, Sqlite>,
    token_hash: &str,
    now: i64,
    fresh: bool,
) -> Result<Membership, CaError> {
    // A write before the security-sensitive read serializes role, credential
    // and session revocation with the caller's eventual in-memory installation.
    sqlx::query("UPDATE ca_administrators SET generation=generation WHERE user_id=(SELECT user_id FROM sessions WHERE token_hash=?)")
        .bind(token_hash).execute(&mut **tx).await.map_err(|_|CaError)?;
    let row=sqlx::query("SELECT a.user_id,a.generation FROM ca_administrators a JOIN sessions s ON s.user_id=a.user_id JOIN passkeys p ON p.id=s.passkey_id AND p.user_id=s.user_id WHERE s.token_hash=? AND a.active=1 AND s.unlocked=1 AND s.expires>MAX(?,unixepoch()) AND (?=0 OR s.fresh>MAX(?,unixepoch())-300) AND s.fresh<=MAX(?,unixepoch())")
        .bind(token_hash).bind(now).bind(fresh).bind(now).bind(now)
        .fetch_optional(&mut **tx).await.map_err(|_|CaError)?.ok_or(CaError)?;
    Ok(Membership {
        user: row.get("user_id"),
        generation: row.get("generation"),
    })
}

/// A consumed ceremony is bound to the same member generation at both ends.
/// Nothing can upgrade an old proof by silently substituting a current role.
/// # Errors
/// Refuses a different user or membership generation.
pub fn require_binding(current: &Membership, expected: &Membership) -> Result<(), CaError> {
    if current.user != expected.user || current.generation != expected.generation {
        return Err(CaError);
    }
    Ok(())
}
