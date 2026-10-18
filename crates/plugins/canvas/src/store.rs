//! Serializes account-scoped SQLite commits and checkpoints without expiring retry receipts [183,248].
use crate::{
    model::{CHECKPOINT, Document, Layout, MAX_DOCUMENT, MAX_INPUT, MAX_RECEIPTS, Target, text},
    reducer::{Apply, Initialize, Intent, reduce},
};
use serde_json::{Value, json};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;

/// Opaque public refusal avoids revealing foreign account or session existence.
#[derive(Debug)]
pub struct Error;
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self
    }
}
impl From<()> for Error {
    fn from((): ()) -> Self {
        Self
    }
}
/// Shares one post-commit invalidation source across every socket worker.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    changes: watch::Sender<()>,
}
impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            changes: watch::channel(()).0,
        }
    }
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }
    /// Read a consistent canonical head plus ordered log tail in one transaction.
    /// # Errors
    /// Refuses unavailable storage or invalid persisted state.
    pub async fn events(&self, account: &str, after: Option<i64>) -> Result<Vec<Value>, Error> {
        let mut tx = self.pool.begin().await?;
        let row =
            sqlx::query("SELECT revision, document, initialized FROM canvas_heads WHERE account=?")
                .bind(account)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(vec![snapshot(&Document::default(), false)]);
        };
        let revision: i64 = row.get("revision");
        if let Some(after) = after
            && after <= revision
        {
            let rows = sqlx::query("SELECT revision,event FROM canvas_operations WHERE account=? AND revision>? ORDER BY revision").bind(account).bind(after).fetch_all(&mut *tx).await?;
            if i64::try_from(rows.len()).ok() == Some(revision - after) {
                let events = rows
                    .iter()
                    .map(|r| serde_json::from_str::<Value>(r.get("event")))
                    .collect::<Result<Vec<_>, _>>()?;
                tx.commit().await?;
                return Ok(events);
            }
        }
        let document: Document = serde_json::from_str(row.get("document"))?;
        tx.commit().await?;
        Ok(vec![snapshot(&document, row.get::<bool, _>("initialized"))])
    }
    /// Apply exactly one bounded semantic intent, allowing stale but never future revisions.
    /// # Errors
    /// Refuses invalid references, bounds, ownership or reused IDs with different input.
    pub async fn apply(&self, account: &str, input: &[u8]) -> Result<i64, Error> {
        let request: Apply = decode(input, MAX_INPUT)?;
        if !text(&request.op_id) {
            return Err(Error);
        }
        let encoded = serde_json::to_string(&json!({"action":"apply","input":request}))?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
        let mut document = head(&mut tx, account).await?;
        if let Some(revision) = receipt(&mut tx, account, &request.op_id, &encoded).await? {
            return Ok(revision);
        }
        if request.base_revision < 0 || request.base_revision > document.revision {
            return Err(Error);
        }
        let closed: HashSet<String> =
            sqlx::query_scalar("SELECT window_id FROM canvas_closed WHERE account=?")
                .bind(account)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect();
        reduce(&mut document, &request.intent, &closed)?;
        ownership(&mut tx, account, &document).await?;
        if let Intent::Close { window_id } = &request.intent {
            if closed.len() >= usize::try_from(MAX_RECEIPTS).map_err(|_| Error)?
                && !closed.contains(window_id)
            {
                return Err(Error);
            }
            sqlx::query("INSERT OR IGNORE INTO canvas_closed(account,window_id) VALUES(?,?)")
                .bind(account)
                .bind(window_id)
                .execute(&mut *tx)
                .await?;
        }
        document.revision += 1;
        if !document.valid() {
            return Err(Error);
        }
        let event = json!({"type":"canvas.layout.operation","revision":document.revision,"op_id":request.op_id,"intent":request.intent});
        save(
            &mut tx,
            account,
            &document,
            &request.op_id,
            &encoded,
            &event,
            false,
        )
        .await?;
        tx.commit().await?;
        self.changes.send_replace(());
        Ok(document.revision)
    }
    /// Compare-and-set bootstrap, preserving a differing loser as recoverable views.
    /// # Errors
    /// Refuses invalid ownership, bounds, or inconsistent idempotency input.
    pub async fn initialize(&self, account: &str, input: &[u8]) -> Result<i64, Error> {
        let request: Initialize = decode(input, MAX_DOCUMENT + 1024)?;
        if !text(&request.op_id) || !request.document.valid() {
            return Err(Error);
        }
        let encoded = serde_json::to_string(&json!({"action":"initialize","input":request}))?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
        let mut document = head(&mut tx, account).await?;
        if let Some(revision) = receipt(&mut tx, account, &request.op_id, &encoded).await? {
            return Ok(revision);
        }
        ownership(&mut tx, account, &request.document).await?;
        let initialized: bool =
            sqlx::query_scalar("SELECT initialized FROM canvas_heads WHERE account=?")
                .bind(account)
                .fetch_one(&mut *tx)
                .await?;
        let mut incoming = request.document;
        incoming.revision = document.revision;
        if !initialized {
            document = incoming;
        } else if incoming != document {
            let mut ids = HashMap::<String, String>::new();
            for mut view in incoming.views {
                view.id = uuid::Uuid::new_v4().to_string();
                view.name = format!(
                    "Recovered: {}",
                    view.name.chars().take(189).collect::<String>()
                );
                if let Layout::Tiled { columns } = &mut view.layout {
                    for column in columns {
                        column.id = uuid::Uuid::new_v4().to_string();
                        for window in &mut column.windows {
                            let mapped = ids
                                .entry(window.id.clone())
                                .or_insert_with(|| uuid::Uuid::new_v4().to_string());
                            window.id.clone_from(mapped);
                        }
                    }
                }
                document.views.push(view);
            }
        }
        document.revision += 1;
        if !document.valid() {
            return Err(Error);
        }
        let event = snapshot(&document, true);
        save(
            &mut tx,
            account,
            &document,
            &request.op_id,
            &encoded,
            &event,
            true,
        )
        .await?;
        tx.commit().await?;
        self.changes.send_replace(());
        Ok(document.revision)
    }
}
#[allow(clippy::items_after_statements)]
fn decode<T: serde::de::DeserializeOwned>(input: &[u8], max: usize) -> Result<T, Error> {
    if input.len() > max || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(Error);
    }
    // Bound every identifier, including those used only by a no-op, before SQL.
    fn bounded(value: &Value) -> bool {
        match value {
            Value::String(s) => text(s),
            Value::Array(a) => a.iter().all(bounded),
            Value::Object(o) => o.iter().all(|(key, v)| text(key) && bounded(v)),
            _ => true,
        }
    }
    let value: Value = serde_json::from_slice(input)?;
    if !bounded(&value) {
        return Err(Error);
    }
    Ok(serde_json::from_value(value)?)
}
fn snapshot(document: &Document, initialized: bool) -> Value {
    json!({"type":"canvas.layout.snapshot","revision":document.revision,"initialized":initialized,"document":document})
}
async fn head(tx: &mut Transaction<'_, Sqlite>, account: &str) -> Result<Document, Error> {
    let empty = serde_json::to_string(&Document::default())?;
    sqlx::query(
        "INSERT OR IGNORE INTO canvas_heads(account,revision,document,initialized) VALUES(?,0,?,0)",
    )
    .bind(account)
    .bind(empty)
    .execute(&mut **tx)
    .await?;
    let json: String = sqlx::query_scalar("SELECT document FROM canvas_heads WHERE account=?")
        .bind(account)
        .fetch_one(&mut **tx)
        .await?;
    Ok(serde_json::from_str(&json)?)
}
async fn receipt(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    id: &str,
    request: &str,
) -> Result<Option<i64>, Error> {
    if let Some(row) =
        sqlx::query("SELECT request,revision FROM canvas_receipts WHERE account=? AND op_id=?")
            .bind(account)
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
    {
        if row.get::<String, _>("request") != request {
            return Err(Error);
        }
        return Ok(Some(row.get("revision")));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canvas_receipts WHERE account=?")
        .bind(account)
        .fetch_one(&mut **tx)
        .await?;
    if count >= MAX_RECEIPTS {
        return Err(Error);
    }
    Ok(None)
}
async fn ownership(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    document: &Document,
) -> Result<(), Error> {
    let mut seen = HashSet::new();
    for window in document.windows() {
        if let Target::Session { id, .. } = &window.target
            && seen.insert(id)
        {
            let uuid = uuid::Uuid::parse_str(id).map_err(|_| Error)?;
            let owned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=? AND user_id=?)",
            )
            .bind(uuid.as_bytes().as_slice())
            .bind(account)
            .fetch_one(&mut **tx)
            .await?;
            if !owned {
                return Err(Error);
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn save(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    document: &Document,
    id: &str,
    request: &str,
    event: &Value,
    force_snapshot: bool,
) -> Result<(), Error> {
    let json = serde_json::to_string(document)?;
    sqlx::query("UPDATE canvas_heads SET revision=?,document=?,initialized=1 WHERE account=?")
        .bind(document.revision)
        .bind(&json)
        .bind(account)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO canvas_receipts(account,op_id,request,revision) VALUES(?,?,?,?)")
        .bind(account)
        .bind(id)
        .bind(request)
        .bind(document.revision)
        .execute(&mut **tx)
        .await?;
    if force_snapshot || document.revision % CHECKPOINT == 0 {
        sqlx::query("INSERT INTO canvas_snapshots(account,revision,document) VALUES(?,?,?) ON CONFLICT(account) DO UPDATE SET revision=excluded.revision,document=excluded.document").bind(account).bind(document.revision).bind(json).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM canvas_operations WHERE account=?")
            .bind(account)
            .execute(&mut **tx)
            .await?;
    } else {
        sqlx::query("INSERT INTO canvas_operations(account,revision,event) VALUES(?,?,?)")
            .bind(account)
            .bind(document.revision)
            .bind(serde_json::to_string(event)?)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture() -> Store {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);").execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../../infraternal-server/migrations/0026_canvas_layout.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        Store::new(pool)
    }
    #[tokio::test]
    async fn cas_retry_and_foreign_account_isolation() {
        let store = fixture().await;
        let init =
            serde_json::to_vec(&json!({"op_id":"init","document":Document::default()})).unwrap();
        assert_eq!(store.initialize("a", &init).await.unwrap(), 1);
        assert_eq!(store.initialize("a", &init).await.unwrap(), 1);
        assert_eq!(store.events("a", None).await.unwrap()[0]["revision"], 1);
        assert_eq!(store.events("b", None).await.unwrap()[0]["revision"], 0);
        let bad=br#"{"op_id":"x","base_revision":0,"intent":{"type":"close","window_id":"one"},"account":"a"}"#;
        assert!(store.apply("b", bad).await.is_err());
        let close =
            br#"{"op_id":"x","base_revision":0,"intent":{"type":"close","window_id":"one"}}"#;
        assert_eq!(store.apply("a", close).await.unwrap(), 2);
        assert_eq!(store.apply("a", close).await.unwrap(), 2);
        assert_eq!(store.events("a", Some(1)).await.unwrap()[0]["revision"], 2);
    }
}
