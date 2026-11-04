//! Per-action passkey taps bound to the one action shown on screen (D333, D336).
//!
//! D333 asks a tap for each of these changes, even inside the browser's admin window: key
//! approval, passkey add, recovery-key rotation and the security settings. D336 binds each such
//! tap to the one action on screen ("agreed"), not to whichever change comes first after a
//! sign-in.
//!
//! The browser names the action when it starts the passkey ceremony (`login-start` with
//! `action`). The server keeps only a digest of it on the pending ceremony, and a successful
//! finish writes that digest on the new session row (`sessions.tap_action`). The change spends it
//! inside its own writer transaction (`require_tap_tx`), and only when:
//! - the digest is this exact action with these exact parameters;
//! - the tap is younger than `ACTION_TAP_SECONDS`;
//! - it was not spent before (`tap_spent`).
//!
//! A rollback leaves the tap unspent. A plain sign-in has no `tap_action`, so it authorizes none
//! of these changes, though it still starts the 15-minute admin window for everyday admin
//! actions.
//!
//! CA setup and CA role changes are per-action taps too. They already run their own ceremonies,
//! bound to one operation in `ca_administration` (for a role change, the exact recipient and
//! role), and they do not use this module.
use super::{Error, Result, hash};
use serde::Deserialize;

/// How long a per-action tap stays usable. The browser runs the change right after the tap
/// (local key unwrap included), so two minutes is ample and keeps a stolen session's window short.
pub(crate) const ACTION_TAP_SECONDS: i64 = 120;

/// The action a tap is for, with the parameters the screen shows. Closed list: a new per-action
/// change adds a variant here and calls `require_tap_tx` with it.
#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum TapAction {
    /// Approve the one key request whose user code is on the approval page.
    #[serde(rename = "device.approve")]
    ApproveKey { code: String },
    /// Start enrolling one more passkey on this account.
    #[serde(rename = "passkey.add")]
    AddPasskey,
    /// Replace this account's recovery key. The new key is made on the device after the tap,
    /// so the tap binds the action and the account (the session's user), not the key material.
    #[serde(rename = "recovery.rotate")]
    RotateRecovery,
    /// Set the server-wide API key inactivity lifetime to this many days.
    #[serde(rename = "security.settings")]
    SecuritySettings { api_key_lifetime_days: i64 },
}

impl TapAction {
    /// Refuse parameters no change could accept, before a ceremony is spent on them.
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            // Server codes are 16 base64url characters; never store an unbounded string.
            Self::ApproveKey { code } if code.is_empty() || code.len() > 64 => Err(Error::Invalid),
            Self::SecuritySettings {
                api_key_lifetime_days,
            } if !(1..=365).contains(api_key_lifetime_days) => Err(Error::Invalid),
            _ => Ok(()),
        }
    }
}

/// Domain-separated digest of one action and its parameters, as stored on the session row.
/// The session row already binds the user, so the digest does not repeat it.
pub(crate) fn digest(action: &TapAction) -> String {
    hash(&match action {
        TapAction::ApproveKey { code } => format!("infraternal/tap/v1|device.approve|{code}"),
        TapAction::AddPasskey => "infraternal/tap/v1|passkey.add".to_owned(),
        TapAction::RotateRecovery => "infraternal/tap/v1|recovery.rotate".to_owned(),
        TapAction::SecuritySettings {
            api_key_lifetime_days,
        } => format!("infraternal/tap/v1|security.settings|{api_key_lifetime_days}"),
    })
}

/// Spend this session's tap on `action`, inside the change's writer transaction.
///
/// One statement checks and spends: the session is live and unlocked, its tap was made for this
/// exact action, is younger than `ACTION_TAP_SECONDS` by both the caller's and SQLite's clock,
/// and is unspent. Any other session, action, age or a second use is `Denied`.
pub(crate) async fn require_tap_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    action: &TapAction,
    now: i64,
) -> Result<()> {
    let spent = sqlx::query(
        "UPDATE sessions SET tap_spent=1 WHERE token_hash=? AND user_id=? AND unlocked=1 \
         AND expires>MAX(?,unixepoch()) AND tap_spent=0 AND tap_action=? \
         AND fresh>MAX(?,unixepoch())-? AND fresh<=MAX(?,unixepoch())",
    )
    .bind(token_hash)
    .bind(user)
    .bind(now)
    .bind(digest(action))
    .bind(now)
    .bind(ACTION_TAP_SECONDS)
    .bind(now)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if spent != 1 {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Read-only form of `require_tap_tx`, for refusing a caller before costly work (the recovery
/// verifier's KDF). It grants nothing: the change still spends the tap in its transaction.
pub(super) async fn tap_ready(
    pool: &sqlx::SqlitePool,
    token_hash: &str,
    user: &str,
    action: &TapAction,
    now: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 \
         AND expires>? AND tap_spent=0 AND tap_action=? AND fresh>?-? AND fresh<=?)",
    )
    .bind(token_hash)
    .bind(user)
    .bind(now)
    .bind(digest(action))
    .bind(now)
    .bind(ACTION_TAP_SECONDS)
    .bind(now)
    .fetch_one(pool)
    .await?)
}

/// The session spent a tap on `action`. Passkey add spends its tap when the registration
/// starts; the finish, which may follow a slow new authenticator, checks it was this session.
pub(super) async fn tap_spent_on_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    action: &TapAction,
    now: i64,
) -> Result<()> {
    let spent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 \
         AND expires>MAX(?,unixepoch()) AND tap_spent=1 AND tap_action=?)",
    )
    .bind(token_hash)
    .bind(user)
    .bind(now)
    .bind(digest(action))
    .fetch_one(&mut **tx)
    .await?;
    if !spent {
        return Err(Error::Denied);
    }
    Ok(())
}
