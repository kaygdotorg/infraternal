//! Persists release opt-in atomically and delegates bounded verified lookups without polling [198,226].
use crate::descriptor::{CHANNEL_GET, CHANNEL_SET, EDGE_WARNING, LATEST};
use infraternal_plugin_api::{Operation, SocketHost};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// The server supplies its existing download/signature engines; a disabled plugin owns no work.
pub trait ReleaseLookup: Send + Sync {
    fn latest<'a>(&'a self, channel: &'a str) -> Operation<'a, Result<Value, &'static str>>;
}
/// One stateless service serves local operator and authenticated socket adapters.
#[derive(Clone)]
pub struct ReleaseService {
    pool: SqlitePool,
    lookup: Arc<dyn ReleaseLookup>,
    writer_admission: Arc<Semaphore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelSet {
    channel: String,
    #[serde(default)]
    confirmed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
// Keep LTO from cloning these identical schema parsers into the local and socket call futures.
#[inline(never)]
fn parse_channel_set(input: &[u8]) -> Result<ChannelSet, serde_json::Error> {
    serde_json::from_slice(input)
}
#[inline(never)]
fn parse_empty(input: &[u8]) -> Result<Empty, serde_json::Error> {
    serde_json::from_slice(input)
}
impl ReleaseService {
    #[must_use]
    pub fn new(pool: SqlitePool, lookup: Arc<dyn ReleaseLookup>) -> Self {
        Self {
            pool,
            lookup,
            writer_admission: Arc::new(Semaphore::new(1)),
        }
    }
    /// Local operator authority uses the existing private database; socket authority is rechecked at commit.
    /// # Errors
    /// Refuses disabled features, invalid input, unconfirmed edge, revoked authority and unverified releases.
    pub async fn call(
        &self,
        action: &str,
        input: &[u8],
        host: Option<&dyn SocketHost>,
    ) -> Result<Value, &'static str> {
        if input.len() > 1024 || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err("invalid input");
        }
        if let Some(host) = host {
            let owner: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
                    .bind(host.user_id())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|_| "release unavailable")?;
            if !owner {
                return Err("not permitted");
            }
        }
        if action == CHANNEL_SET.id {
            let setting = parse_channel_set(input).map_err(|_| "invalid input")?;
            if !matches!(setting.channel.as_str(), "stable" | "edge") {
                return Err("invalid input");
            }
            if setting.channel == "edge" && !setting.confirmed {
                return Err(EDGE_WARNING);
            }
            // BEGIN IMMEDIATE may wait on another writer for SQLite's busy timeout.
            // Admit one release writer so waiters do not occupy shared authority slots.
            let _writer = self
                .writer_admission
                .acquire()
                .await
                .map_err(|_| "release unavailable")?;
            let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
                .await
                .map_err(|_| "release unavailable")?;
            let enabled: bool = sqlx::query_scalar("SELECT COALESCE((SELECT enabled FROM plugin_settings WHERE role='server' AND plugin='release'),1)")
                .fetch_one(&mut *tx).await.map_err(|_| "release unavailable")?;
            if !enabled {
                return Err("release unavailable");
            }
            sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled,settings) VALUES('server','release',1,json_object('channel',?)) ON CONFLICT(role,plugin) DO UPDATE SET settings=json_set(plugin_settings.settings,'$.channel',?)")
                .bind(&setting.channel).bind(&setting.channel).execute(&mut *tx).await.map_err(|_| "release unavailable")?;
            // Writes may trigger authority changes. Recheck owner/freshness after the write, where rollback still protects the setting.
            if let Some(host) = host {
                let owner: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
                        .bind(host.user_id())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|_| "release unavailable")?;
                let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| "release unavailable")?;
                if !owner
                    || !infraternal_plugin_api::fresh_session_tx(
                        &mut tx,
                        host.token_hash(),
                        host.user_id(),
                        now,
                        infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
                    )
                    .await
                    .map_err(|_| "release unavailable")?
                {
                    return Err("not permitted");
                }
            }
            tx.commit().await.map_err(|_| "release unavailable")?;
            return Ok(json!({"channel":setting.channel}));
        }
        parse_empty(input).map_err(|_| "invalid input")?;
        let (enabled, channel): (bool,String) = sqlx::query_as("SELECT enabled,COALESCE(json_extract(settings,'$.channel'),'stable') FROM plugin_settings WHERE role='server' AND plugin='release'")
            .fetch_optional(&self.pool).await.map_err(|_| "release unavailable")?.unwrap_or((true,"stable".into()));
        if !enabled {
            return Err("release unavailable");
        }
        if !matches!(channel.as_str(), "stable" | "edge") {
            return Err("invalid release channel setting");
        }
        if action == CHANNEL_GET.id {
            Ok(json!({"channel":channel}))
        } else if action == LATEST.id {
            self.lookup.latest(&channel).await
        } else {
            Err("invalid input")
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
