//! Persists release opt-in atomically and delegates bounded verified lookups without polling [198,226].
use crate::applier::{Unavailable, UpdateApplier};
use crate::descriptor::{
    CHANNEL_GET, CHANNEL_SET, EDGE_WARNING, LATEST, UPDATE_APPLY, UPDATE_CANCEL, UPDATE_CHECK,
    UPDATE_HISTORY, UPDATE_ROLLBACK, UPDATE_SETTINGS, UPDATE_STATUS,
};
use crate::update::{Admission, Outcome, Updater};
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
    /// The server's updater, when this host runs one (#211 S5): the check, apply and
    /// cancel actions work through it. A lookup without one answers those actions with
    /// its own reason (why updates are off here).
    /// # Errors
    /// A fixed public reason when this host has no updater.
    fn updater(&self) -> Result<Arc<Updater>, &'static str> {
        Err("updates unavailable")
    }
    /// The update history, oldest first (#211 S5).
    fn update_history(&self) -> Vec<crate::history::Entry> {
        Vec::new()
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
    /// Applies a staged release and undoes the last update (S4); refuses until S4 is built in.
    applier: Arc<dyn UpdateApplier>,
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
/// The input of `release.update.check` and `release.update.apply`: an optional exact version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned {
    version: Option<String>,
}
/// The input of `release.update.settings`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuietSet {
    quiet_minutes: u32,
}
/// Parse an optional exact version (kept out of line, like the other parsers).
#[inline(never)]
fn parse_versioned(input: &[u8]) -> Result<Versioned, serde_json::Error> {
    serde_json::from_slice(input)
}
/// Parse the quiet-window setting (kept out of line, like the other parsers).
#[inline(never)]
fn parse_quiet(input: &[u8]) -> Result<QuietSet, serde_json::Error> {
    serde_json::from_slice(input)
}
/// The quiet window when nobody set one: no typing or attaching for 5 minutes.
pub const DEFAULT_QUIET_MINUTES: u32 = 5;
/// Longest quiet window the owner may set (one day).
pub const MAX_QUIET_MINUTES: u32 = 1440;
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
    /// Bind the service to the server database and its release lookup. Apply and rollback
    /// refuse until an applier is added with [`ReleaseService::with_applier`].
    #[must_use]
    pub fn new(pool: SqlitePool, lookup: Arc<dyn ReleaseLookup>) -> Self {
        Self {
            pool,
            lookup,
            writer_admission: Arc::new(Semaphore::new(1)),
            applier: Arc::new(Unavailable),
        }
    }
    /// Plug in the apply step (S4). Without it apply and rollback refuse with a plain reason.
    #[must_use]
    pub fn with_applier(mut self, applier: Arc<dyn UpdateApplier>) -> Self {
        self.applier = applier;
        self
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
        if action == UPDATE_CHECK.id {
            return self.update_check(input, host).await;
        }
        if action == UPDATE_APPLY.id {
            return self.update_apply(input, host).await;
        }
        if action == UPDATE_SETTINGS.id {
            return self.update_settings(input, host).await;
        }
        parse_empty(input).map_err(|_| "invalid input")?;
        if action == UPDATE_ROLLBACK.id {
            self.require_fresh(host).await?;
            return self.applier.rollback().await.and_then(to_json);
        }
        if action == UPDATE_CANCEL.id {
            self.require_fresh(host).await?;
            self.lookup.updater()?.cancel_hold().await?;
            return self.update_status().await;
        }
        if action == UPDATE_HISTORY.id {
            let mut entries = self.lookup.update_history();
            entries.reverse();
            return Ok(json!({"entries":entries}));
        }
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

    /// Refuse unless the caller is an owner whose passkey tap is recent (the admin window).
    ///
    /// Update, rollback, cancel and an explicit stage change what the server runs, so they
    /// need the same proof as `release.channel.set`. The local operator (`host` is `None`)
    /// is the machine's own authority and needs none. Callers check this immediately before
    /// they act; the action itself is not a database write, so there is no commit to recheck at.
    async fn require_fresh(&self, host: Option<&dyn SocketHost>) -> Result<(), &'static str> {
        let Some(host) = host else { return Ok(()) };
        let mut tx = self.pool.begin().await.map_err(|_| "release unavailable")?;
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
        let fresh = infraternal_plugin_api::fresh_session_tx(
            &mut tx,
            host.token_hash(),
            host.user_id(),
            now,
            infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
        )
        .await
        .map_err(|_| "release unavailable")?;
        if owner && fresh {
            Ok(())
        } else {
            Err("not permitted")
        }
    }

    /// `release.update.check`: a periodic check now (owner), or with `version` an explicit
    /// stage of exactly that release (owner with a fresh session). The release plugin must be
    /// on, as for every update action.
    async fn update_check(
        &self,
        input: &[u8],
        host: Option<&dyn SocketHost>,
    ) -> Result<Value, &'static str> {
        let Versioned { version } = parse_versioned(input).map_err(|_| "invalid input")?;
        let admission = if version.is_some() {
            self.require_fresh(host).await?;
            Admission::Explicit
        } else {
            Admission::Forward
        };
        let updater = self.lookup.updater()?;
        let outcome = updater.check(version.as_deref(), admission).await?;
        let (name, version, reason) = match outcome {
            Outcome::Empty => ("empty", None, None),
            Outcome::Current(v) => ("current", Some(v), None),
            Outcome::Staged(v) => ("staged", Some(v), None),
            Outcome::Held(v) => ("held", Some(v), None),
            Outcome::Refused(r) => ("refused", None, Some(r)),
        };
        Ok(
            json!({"outcome":name,"version":version,"reason":reason,"state":self.update_status().await?}),
        )
    }

    /// `release.update.apply`: re-verify the staged release and hand it to the apply step.
    /// Needs the owner with a fresh session. `version`, when given, must be the staged release,
    /// so the owner never applies something other than what they saw.
    async fn update_apply(
        &self,
        input: &[u8],
        host: Option<&dyn SocketHost>,
    ) -> Result<Value, &'static str> {
        let Versioned { version } = parse_versioned(input).map_err(|_| "invalid input")?;
        self.require_fresh(host).await?;
        let updater = self.lookup.updater()?;
        let confirmed = updater.confirm_staged().await?;
        if version.as_deref().is_some_and(|v| v != confirmed.version()) {
            return Err("a different release is staged");
        }
        // Authority is checked again right before the switch, after the slow re-verification.
        self.require_fresh(host).await?;
        self.applier.apply(confirmed).await.and_then(to_json)
    }

    /// `release.update.settings`: save the quiet window next to the channel, in the same
    /// plugin settings row, as one atomic statement. Needs the owner with a fresh session.
    async fn update_settings(
        &self,
        input: &[u8],
        host: Option<&dyn SocketHost>,
    ) -> Result<Value, &'static str> {
        let QuietSet {
            quiet_minutes: minutes,
        } = parse_quiet(input).map_err(|_| "invalid input")?;
        if !(1..=MAX_QUIET_MINUTES).contains(&minutes) {
            return Err("invalid input");
        }
        self.require_fresh(host).await?;
        let _writer = self
            .writer_admission
            .acquire()
            .await
            .map_err(|_| "release unavailable")?;
        sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled,settings) VALUES('server','release',1,json_object('quiet_minutes',?)) ON CONFLICT(role,plugin) DO UPDATE SET settings=json_set(plugin_settings.settings,'$.quiet_minutes',?)")
            .bind(minutes).bind(minutes).execute(&self.pool).await.map_err(|_| "release unavailable")?;
        self.update_status().await
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
        state["quiet_minutes"] = json!(quiet_minutes(&self.pool).await);
        state["rollback"] =
            serde_json::to_value(self.applier.rollback_plan()).unwrap_or(Value::Null);
        if let Some(reason) = off
            && state["mode"] != "off"
        {
            state["mode"] = Value::String("off".to_owned());
            state["reason"] = Value::String(reason.to_owned());
        }
        Ok(state)
    }
}

/// Turn an applier's answer into the wire JSON.
fn to_json(started: crate::applier::Started) -> Result<Value, &'static str> {
    serde_json::to_value(started).map_err(|_| "release unavailable")
}

/// The saved quiet window in minutes: the default when none is saved or the saved one is out of range.
async fn quiet_minutes(pool: &SqlitePool) -> u32 {
    let saved: Option<i64> = sqlx::query_scalar("SELECT json_extract(settings,'$.quiet_minutes') FROM plugin_settings WHERE role='server' AND plugin='release'")
        .fetch_optional(pool).await.ok().flatten().flatten();
    saved
        .and_then(|m| u32::try_from(m).ok())
        .filter(|m| (1..=MAX_QUIET_MINUTES).contains(m))
        .unwrap_or(DEFAULT_QUIET_MINUTES)
}

/// The status reason when the saved channel is neither stable nor edge.
const NO_CHANNEL: &str = "no valid release channel is set; choose stable or edge";

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
