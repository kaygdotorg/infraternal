//! Server-wide API key inactivity policy; an owner change spends a passkey tap made for that
//! exact value (#269, D333, D336).
use super::{Auth, Error, Result, TapAction, hash, require_tap_tx};
use serde::{Deserialize, Serialize};

/// Current API key policy, applied at check time even to keys issued before a policy change.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecuritySettings {
    api_key_lifetime_days: i64,
}

impl Auth {
    pub(super) async fn security_settings(
        &self,
        token: &str,
        now: i64,
    ) -> Result<serde_json::Value> {
        if !self.session(token, now).await?.owner {
            return Err(Error::Denied);
        }
        let days =
            sqlx::query_scalar("SELECT api_key_lifetime_days FROM server_settings WHERE id=1")
                .fetch_one(&self.pool)
                .await?;
        Ok(serde_json::to_value(SecuritySettings {
            api_key_lifetime_days: days,
        })?)
    }

    pub(super) async fn update_security_settings(
        &self,
        token: &str,
        settings: SecuritySettings,
        now: i64,
    ) -> Result<serde_json::Value> {
        if !(1..=365).contains(&settings.api_key_lifetime_days) {
            return Err(Error::Invalid);
        }
        let session = self.session(token, now).await?;
        if !session.owner {
            return Err(Error::Denied);
        }
        // Take the writer before rechecking authority, so concurrent logout/recovery wins
        // if it committed before this mutation; never trust a pre-lock owner snapshot.
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
        require_tap_tx(
            &mut tx,
            &hash(token),
            &session.user_id,
            &TapAction::SecuritySettings {
                api_key_lifetime_days: settings.api_key_lifetime_days,
            },
            now,
        )
        .await?;
        let owner: bool = sqlx::query_scalar("SELECT owner FROM users WHERE id=?")
            .bind(&session.user_id)
            .fetch_one(&mut *tx)
            .await?;
        if !owner {
            return Err(Error::Denied);
        }
        sqlx::query("UPDATE server_settings SET api_key_lifetime_days=? WHERE id=1")
            .bind(settings.api_key_lifetime_days)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(serde_json::to_value(settings)?)
    }
}
