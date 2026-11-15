//! Persists release opt-in atomically and delegates bounded verified lookups without polling [198,226].
use crate::descriptor::{CHANNEL_GET, CHANNEL_SET, EDGE_WARNING, LATEST, UPDATE_STATUS};
use infraternal_plugin_api::{Operation, SocketHost};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// The server supplies its existing download/signature engines; a disabled plugin owns no work.
pub trait ReleaseLookup: Send + Sync {
    fn latest<'a>(&'a self, channel: &'a str) -> Operation<'a, Result<Value, &'static str>>;
    /// The persisted update state (#211 S3) as JSON; see [`crate::update::UpdateState`].
    /// Lookups without server state report that updates are unavailable.
    /// # Errors
    /// A fixed public reason when this lookup has no update state.
    fn update_status(&self) -> Result<Value, &'static str> {
        Err("updates unavailable")
    }
}

/// Read the release plugin's switch and channel from the server database, with the
/// plugin's defaults (on, stable) when nothing is saved.
///
/// A disabled plugin reports `(false, _)` before its channel is validated, so a
/// switched-off feature never reports a configuration error.
/// # Errors
/// A fixed public reason when the database cannot be read or an enabled plugin's
/// saved channel is neither stable nor edge.
pub async fn settings(pool: &SqlitePool) -> Result<(bool, String), &'static str> {
    let (enabled, channel): (bool, String) = sqlx::query_as("SELECT enabled,COALESCE(json_extract(settings,'$.channel'),'stable') FROM plugin_settings WHERE role='server' AND plugin='release'")
        .fetch_optional(pool).await.map_err(|_| "release unavailable")?.unwrap_or((true,"stable".into()));
    if enabled && !matches!(channel.as_str(), "stable" | "edge") {
        return Err("invalid release channel setting");
    }
    Ok((enabled, channel))
}

/// [`settings`] as the reader the updater takes.
#[must_use]
pub fn settings_reader(pool: SqlitePool) -> crate::update::Settings {
    Arc::new(move || {
        let pool = pool.clone();
        Box::pin(async move { settings(&pool).await })
    })
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
        if action == UPDATE_STATUS.id {
            return self.update_status().await;
        }
        let (enabled, channel) = settings(&self.pool).await?;
        if !enabled {
            return Err("release unavailable");
        }
        if action == CHANNEL_GET.id {
            Ok(json!({"channel":channel}))
        } else if action == LATEST.id {
            self.lookup.latest(&channel).await
        } else {
            Err("invalid input")
        }
    }

    /// `release.update.status`: the update state with `mode` and `reason` (J725 P3-4).
    ///
    /// It answers even when the release plugin is off, because "updates are off, and
    /// why" is exactly what the owner needs then. A host-level reason (not Linux, a
    /// development build, not root) comes first, since switching the plugin on would
    /// not help; otherwise a switched-off plugin or an unusable channel setting is the
    /// reason. The channel shown is the saved setting, not the last check's.
    async fn update_status(&self) -> Result<Value, &'static str> {
        let mut state = self.lookup.update_status()?;
        let off = match settings(&self.pool).await {
            Ok((true, channel)) => {
                state["channel"] = Value::String(channel);
                None
            }
            Ok((false, _)) => Some(crate::update::UPDATES_OFF),
            Err("invalid release channel setting") => Some(NO_CHANNEL),
            Err(reason) => return Err(reason),
        };
        if let Some(reason) = off
            && state["mode"] != "off"
        {
            state["mode"] = Value::String("off".to_owned());
            state["reason"] = Value::String(reason.to_owned());
        }
        Ok(state)
    }
}

/// The status reason when the saved channel is neither stable nor edge.
const NO_CHANNEL: &str = "no valid release channel is set; choose stable or edge";

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
