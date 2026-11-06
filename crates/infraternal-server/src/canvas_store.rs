//! Supplies the canvas plugin with the host's existing SQLite and terminal-ownership context [183,198,243].
mod recovery;

use infraternal_plugin_canvas::{
    model::{self, CHECKPOINT, Document, MAX_DOCUMENT, MAX_INPUT, MAX_RECEIPTS, text},
    reducer::reduce,
};
use serde_json::{Value, json};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

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
    writes: Arc<Mutex<()>>,
}
/// Internal read repair uses the same bounded transaction machinery as caller intents.
#[derive(Clone, Copy)]
enum Mode {
    Apply,
    Initialize,
    Repair,
}
impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            changes: watch::channel(()).0,
            writes: Arc::new(Mutex::new(())),
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
        let mut cursor = after;
        loop {
            // One statement gives head and tail the same SQLite read snapshot without
            // retaining a read transaction or repeating the document for every log row.
            let rows=sqlx::query("SELECT 0 AS kind,revision,document,initialized,NULL AS event FROM canvas_heads WHERE account=? UNION ALL SELECT 1,revision,NULL,NULL,event FROM canvas_operations WHERE account=? AND revision>? ORDER BY kind,revision").bind(account).bind(account).bind(cursor.unwrap_or(i64::MAX)).fetch_all(&self.pool).await?;
            let Some(head) = rows.first() else {
                return Ok(vec![snapshot(&Document::default(), false)]);
            };
            if head.get::<i64, _>("kind") != 0 {
                return Err(Error);
            }
            let revision: i64 = head.get("revision");
            let tail = cursor.is_some_and(|after| {
                after <= revision && i64::try_from(rows.len() - 1).ok() == Some(revision - after)
            });
            let raw: &str = head.get("document");
            // Every persisted document is written by serde_json, which leaves this
            // literal prefix unescaped. A missing marker rules out historical recovery
            // views; incidental matches only take the fully validated slow path.
            let document = if !tail || raw.contains("Recovered: ") {
                let document = Document(serde_json::from_slice(raw.as_bytes())?);
                if !document.valid() {
                    return Err(Error);
                }
                Some(document)
            } else {
                None
            };
            // A bounded repair can leave recovery views intact. Only reload
            // if maintenance (or a competing writer) advanced the head.
            if document.as_ref().is_some_and(recovery::needed)
                && self.transact(Mode::Repair, account, &[]).await? != revision
            {
                cursor = None;
                continue;
            }
            if tail {
                let mut events = Vec::with_capacity(rows.len() - 1);
                for row in &rows[1..] {
                    events.push(serde_json::from_slice(
                        row.get::<&str, _>("event").as_bytes(),
                    )?);
                }
                return Ok(events);
            }
            return Ok(vec![snapshot(
                &document.ok_or(Error)?,
                head.get::<bool, _>("initialized"),
            )]);
        }
    }
    /// Apply exactly one bounded semantic intent, allowing stale but never future revisions.
    /// # Errors
    /// Refuses invalid references, bounds, ownership or reused IDs with different input.
    pub async fn apply(&self, account: &str, input: &[u8]) -> Result<i64, Error> {
        self.call(false, account, input).await
    }
    /// Initialize once, then merge only targets absent from the account canvas.
    /// # Errors
    /// Refuses invalid references, bounds, ownership or inconsistent retry input.
    pub async fn initialize(&self, account: &str, input: &[u8]) -> Result<i64, Error> {
        self.call(true, account, input).await
    }
    /// One transaction path keeps the existing storage futures shared by both actions.
    /// # Errors
    /// Returns the same opaque refusal as the two declared action wrappers.
    pub async fn call(&self, initialize: bool, account: &str, input: &[u8]) -> Result<i64, Error> {
        self.transact(
            if initialize {
                Mode::Initialize
            } else {
                Mode::Apply
            },
            account,
            input,
        )
        .await
    }
    // Keep one storage state machine for edits and read repair. The caller holds
    // only this operation handle rather than another copy of the write futures.
    #[inline(never)]
    fn transact<'a>(
        &'a self,
        mode: Mode,
        account: &'a str,
        input: &'a [u8],
    ) -> infraternal_plugin_api::Operation<'a, Result<i64, Error>> {
        Box::pin(async move {
            let initialize = matches!(mode, Mode::Initialize);
            let maintenance = matches!(mode, Mode::Repair);
            let request = if maintenance {
                Value::Null
            } else {
                decode(
                    input,
                    if initialize {
                        MAX_DOCUMENT + 2048
                    } else {
                        MAX_INPUT
                    },
                )?
            };
            let fields = if initialize {
                &["op_id", "document", "session_incarnation"][..]
            } else {
                &["op_id", "base_revision", "intent", "session_incarnation"][..]
            };
            if !maintenance && !model::shape(&request, fields) {
                return Err(Error);
            }
            let op_id = if maintenance {
                ""
            } else {
                model::string(&request, "op_id").ok_or(Error)?
            };
            // Permanent retry receipts retain the existing SHA-256 digest, never a
            // second copy of a bootstrap document. Canonical JSON ignores key order.
            let request_hash = if maintenance {
                String::new()
            } else {
                // The original envelope sorts action before input. Only the fixed
                // header is literal; serde_json still encodes every input value.
                let mut envelope = serde_json::to_string(&request)?;
                envelope.insert_str(
                    0,
                    if initialize {
                        r#"{"action":"initialize","input":"#
                    } else {
                        r#"{"action":"apply","input":"#
                    },
                );
                envelope.push('}');
                crate::auth::hash(&envelope)
            };
            let _writer = self.writes.lock().await;
            let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
            let mut document = head_document(&mut tx, account).await?;
            let repaired = recovery::repair(&mut document)?;
            let retry = if maintenance {
                None
            } else {
                receipt(&mut tx, account, op_id, &request_hash, document.revision()).await?
            };
            let mut noop = false;
            let mut import_noop = false;
            let accepted = !maintenance && retry.is_none();
            if accepted {
                if initialize {
                    let mut incoming = Document(request.get("document").cloned().ok_or(Error)?);
                    if !incoming.valid() || serde_json::to_string(&incoming.0)?.len() > MAX_DOCUMENT
                    {
                        return Err(Error);
                    }
                    incoming.normalize();
                    ownership(&mut tx, account, OwnershipWindows::Document(&incoming)).await?;
                    let initialized: bool =
                        sqlx::query("SELECT initialized FROM canvas_heads WHERE account=?")
                            .bind(account)
                            .fetch_one(&mut *tx)
                            .await?
                            .get(0);
                    incoming.0["revision"] = json!(document.revision());
                    if initialized {
                        let before = document.clone();
                        let views = incoming.0["views"].as_array_mut().ok_or(Error)?;
                        recovery::merge(&mut document, std::mem::take(views), true)?;
                        import_noop = document == before;
                    } else {
                        document = incoming;
                    }
                } else {
                    let base = request
                        .get("base_revision")
                        .and_then(Value::as_i64)
                        .ok_or(Error)?;
                    if base < 0 || base > document.revision() {
                        return Err(Error);
                    }
                    let intent = request.get("intent").ok_or(Error)?;
                    // Each intent can inspect only its own ID and a split anchor. Probe
                    // the account index instead of loading its lifetime close history.
                    let id = intent
                        .get("window")
                        .and_then(|w| model::string(w, "id"))
                        .or_else(|| model::string(intent, "window_id"))
                        .unwrap_or("");
                    let anchor = model::string(intent, "anchor_id").unwrap_or("");
                    let closed: Vec<String> = sqlx::query(
                "SELECT window_id FROM canvas_closed WHERE account=? AND window_id IN (?,?)",
            )
            .bind(account)
            .bind(id)
            .bind(anchor)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect();
                    let before = document.clone();
                    reduce(&mut document, intent, &closed)?;
                    document.normalize();
                    noop = document == before;
                    // Admit new references only: retirement must not freeze unrelated edits.
                    if matches!(model::string(intent, "type"), Some("open" | "split")) {
                        ownership(
                            &mut tx,
                            account,
                            OwnershipWindows::One(intent.get("window").ok_or(Error)?),
                        )
                        .await?;
                    }
                    if model::string(intent, "type") == Some("target") {
                        // Retargeting introduces a reference just as opening does; close must never bypass admission.
                        let window = json!({"target": intent.get("target").ok_or(Error)?});
                        ownership(&mut tx, account, OwnershipWindows::One(&window)).await?;
                    }
                    if model::string(intent, "type") == Some("close") {
                        let id = model::string(intent, "window_id").ok_or(Error)?;
                        // At most one tombstone is added per accepted revision; the
                        // permanent receipt quota also bounds this table.
                        sqlx::query(
                            "INSERT OR IGNORE INTO canvas_closed(account,window_id) VALUES(?,?)",
                        )
                        .bind(account)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    }
                }
            }
            if accepted && !import_noop {
                document.normalize();
                document.0["revision"] = json!(document.revision() + 1);
                if !document.valid() {
                    return Err(Error);
                }
            }
            let changed = repaired || (accepted && !import_noop);
            if changed {
                // A repairing edit keeps both normal revision steps but publishes the
                // final snapshot: no operation tail may replay against the replaced IDs.
                let checkpoint = initialize || repaired;
                let event = if checkpoint {
                    snapshot(&document, true)
                } else {
                    model::object(vec![
                        ("type", Value::from("canvas.layout.operation")),
                        ("revision", Value::from(document.revision())),
                        ("op_id", Value::from(op_id)),
                        ("intent", request["intent"].clone()),
                        ("noop", Value::from(noop)),
                    ])
                };
                save(&mut tx, account, &document, &event, checkpoint).await?;
            }
            // Imports with no new targets still retain a durable retry receipt. Keep
            // both paths in one commit, notifying only when the layout actually changed.
            if accepted {
                save_receipt(&mut tx, account, op_id, &request_hash, document.revision()).await?;
            }
            if changed || accepted {
                commit(tx, self.changes.clone(), changed).await?;
            }
            Ok(retry.unwrap_or(document.revision()))
        })
    }
}
async fn commit(
    tx: Transaction<'static, Sqlite>,
    changes: watch::Sender<()>,
    notify: bool,
) -> Result<(), Error> {
    // COMMIT can become durable before its caller receives the acknowledgement.
    // Keep its invalidation in the same finite task so socket cancellation cannot
    // strand connected devices on an older revision. No timer or worker is retained.
    tokio::spawn(async move {
        tx.commit().await?;
        if notify {
            changes.send_replace(());
        }
        Ok::<(), Error>(())
    })
    .await
    .map_err(|_| Error)?
}
#[allow(clippy::items_after_statements)]
fn decode(input: &[u8], max: usize) -> Result<Value, Error> {
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
    Ok(value)
}
fn snapshot(document: &Document, initialized: bool) -> Value {
    model::object(vec![
        ("type", Value::from("canvas.layout.snapshot")),
        ("revision", Value::from(document.revision())),
        ("initialized", Value::from(initialized)),
        ("document", document.0.clone()),
    ])
}
async fn head_document(tx: &mut Transaction<'_, Sqlite>, account: &str) -> Result<Document, Error> {
    let empty = serde_json::to_string(&Document::default().0)?;
    sqlx::query(
        "INSERT OR IGNORE INTO canvas_heads(account,revision,document,initialized) VALUES(?,0,?,0)",
    )
    .bind(account)
    .bind(empty)
    .execute(&mut **tx)
    .await?;
    let json: String = sqlx::query("SELECT document FROM canvas_heads WHERE account=?")
        .bind(account)
        .fetch_one(&mut **tx)
        .await?
        .get(0);
    Ok(Document(serde_json::from_slice(json.as_bytes())?))
}
async fn receipt(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    id: &str,
    request_hash: &str,
    revision: i64,
) -> Result<Option<i64>, Error> {
    // A matching retry is the first row; otherwise the union yields the account's
    // transactional receipt counter. LIMIT preserves retry admission at the quota and shares one
    // row-query future across both paths. No-op imports count without a revision.
    let row = sqlx::query("SELECT request,revision FROM canvas_receipts WHERE account=? AND op_id=? UNION ALL SELECT NULL,receipt_count FROM canvas_heads WHERE account=? LIMIT 1")
        .bind(account).bind(id).bind(account).fetch_one(&mut **tx).await?;
    let value: i64 = row.get("revision");
    if let Some(request) = row.get::<Option<&str>, _>("request") {
        if request != request_hash {
            return Err(Error);
        }
        return Ok(Some(value));
    }
    if value >= MAX_RECEIPTS || revision >= 9_007_199_254_740_991 {
        return Err(Error);
    }
    Ok(None)
}
/// Chooses between bootstrap traversal and one operation window without generic iterator copies.
enum OwnershipWindows<'a> {
    Document(&'a Document),
    One(&'a Value),
}
async fn ownership(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    windows: OwnershipWindows<'_>,
) -> Result<(), Error> {
    let mut seen = Vec::new();
    match windows {
        OwnershipWindows::Document(document) => {
            for window in document.windows() {
                ownership_window(tx, account, window, &mut seen).await?;
            }
        }
        OwnershipWindows::One(window) => ownership_window(tx, account, window, &mut seen).await?,
    }
    Ok(())
}
/// Checks a session target once per input ID and keeps the account predicate in the SQL query.
async fn ownership_window<'a>(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    window: &'a Value,
    seen: &mut Vec<&'a str>,
) -> Result<(), Error> {
    let target = window.get("target").ok_or(Error)?;
    if model::string(target, "type") == Some("session") {
        let id = model::string(target, "id").ok_or(Error)?;
        if seen.contains(&id) {
            return Ok(());
        }
        seen.push(id);
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| Error)?;
        let owned: bool =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=? AND user_id=?)")
                .bind(uuid.as_bytes().as_slice())
                .bind(account)
                .fetch_one(&mut **tx)
                .await?
                .get(0);
        if !owned {
            return Err(Error);
        }
    }
    Ok(())
}
async fn save_receipt(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    id: &str,
    request_hash: &str,
    revision: i64,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO canvas_receipts(account,op_id,request,revision) VALUES(?,?,?,?)")
        .bind(account)
        .bind(id)
        .bind(request_hash)
        .bind(revision)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn save(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
    document: &Document,
    event: &Value,
    force_snapshot: bool,
) -> Result<(), Error> {
    let json = serde_json::to_string(&document.0)?;
    if json.len() > MAX_DOCUMENT {
        return Err(Error);
    }
    sqlx::query("UPDATE canvas_heads SET revision=?,document=?,initialized=1 WHERE account=?")
        .bind(document.revision())
        .bind(&json)
        .bind(account)
        .execute(&mut **tx)
        .await?;
    if force_snapshot || document.revision() % CHECKPOINT == 0 {
        sqlx::query("INSERT INTO canvas_snapshots(account,revision,document) VALUES(?,?,?) ON CONFLICT(account) DO UPDATE SET revision=excluded.revision,document=excluded.document").bind(account).bind(document.revision()).bind(json).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM canvas_operations WHERE account=?")
            .bind(account)
            .execute(&mut **tx)
            .await?;
    } else {
        sqlx::query("INSERT INTO canvas_operations(account,revision,event) VALUES(?,?,?)")
            .bind(account)
            .bind(document.revision())
            .bind(serde_json::to_string(event)?)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

impl infraternal_plugin_canvas::store::LayoutStore for Store {
    fn changes(&self) -> watch::Receiver<()> {
        self.changes()
    }
    fn call<'a>(
        &'a self,
        initialize: bool,
        account: &'a str,
        input: &'a [u8],
    ) -> infraternal_plugin_api::Operation<'a, Result<i64, ()>> {
        Box::pin(async move {
            Store::call(self, initialize, account, input)
                .await
                .map_err(|_| ())
        })
    }
    fn events<'a>(
        &'a self,
        account: &'a str,
        after: Option<i64>,
    ) -> infraternal_plugin_api::Operation<'a, Result<Vec<Value>, ()>> {
        Box::pin(async move { Store::events(self, account, after).await.map_err(|_| ()) })
    }
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
        sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0030_canvas_receipt_count.sql"))
            .execute(&pool)
            .await
            .unwrap();
        Store::new(pool)
    }
    #[tokio::test]
    async fn permanent_receipts_keep_the_original_json_digest_recipe() {
        let store = fixture().await;
        let request = json!({"op_id":"initial","document":Document::default()});
        let input = serde_json::to_vec(&request).unwrap();
        store.initialize("a", &input).await.unwrap();
        for (initialize, legacy) in [
            (
                true,
                json!({"op_id":"legacy-λ-\"","document":Document::default()}),
            ),
            (
                false,
                json!({"op_id":"legacy-apply","base_revision":1,"intent":{"type":"close","window_id":"gone"}}),
            ),
        ] {
            let action = if initialize { "initialize" } else { "apply" };
            let digest = crate::auth::hash(
                &serde_json::to_string(&model::object(vec![
                    ("action", Value::from(action)),
                    ("input", legacy.clone()),
                ]))
                .unwrap(),
            );
            sqlx::query("INSERT INTO canvas_receipts VALUES('a',?,?,1)")
                .bind(legacy["op_id"].as_str().unwrap())
                .bind(digest)
                .execute(&store.pool)
                .await
                .unwrap();
            assert_eq!(
                store
                    .call(initialize, "a", &serde_json::to_vec(&legacy).unwrap())
                    .await
                    .unwrap(),
                1
            );
        }
    }
    #[tokio::test]
    async fn cancelled_commit_still_invalidates_a_durable_change() {
        use std::{future::Future, task::Poll};
        let store = fixture().await;
        let mut notice = store.changes();
        notice.borrow_and_update();
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&store.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO canvas_heads(account,revision,document,initialized) VALUES('a',0,'{}',0)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let mut pending = Box::pin(commit(tx, store.changes.clone(), true));
        let ready =
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_ready())).await;
        assert!(!ready, "commit needs the database worker acknowledgement");
        drop(pending);
        // This single-connection read fences completion of COMMIT and connection return.
        let committed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM canvas_heads WHERE account='a')")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(committed);
        assert!(
            notice.has_changed().unwrap(),
            "durable commit lost its subscriber invalidation when its caller was cancelled"
        );
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

    /// A real look edit survives reload in its account's canvas and is absent from another account.
    #[tokio::test]
    async fn appearance_edits_are_persisted_for_only_the_authorized_account() {
        let store = fixture().await;
        let init = serde_json::to_vec(&json!({"op_id":"init-a","document":Document::default()}))
            .unwrap();
        assert_eq!(store.initialize("a", &init).await.unwrap(), 1);

        let look = json!({
            "v": 1,
            "selected": "solid",
            "basics": {"colors": "ink", "font": "geist-mono", "uiSize": 110},
            "uiFont": "sans",
            "windowSizes": {"phone": "full", "desktop": "wide"},
            "extendedInfo": true,
            "themes": [{
                "id": "solid", "name": "Solid", "tint": 100, "blur": 0, "grain": 0,
                "font": "geist-mono", "colors": "ink", "uiSize": 110,
                "background": "solid", "customSolid": "#3b4252",
                "custom": {"stops": ["#7a9cff", "#cba6f7"], "angle": 135}
            }]
        });
        let edit = serde_json::to_vec(&json!({
            "op_id": "look-a",
            "base_revision": 1,
            "intent": {"type": "look.set", "look": look}
        }))
        .unwrap();
        assert_eq!(store.apply("a", &edit).await.unwrap(), 2);

        let mut later_look = look.clone();
        later_look["themes"][0]["font"] = json!("fira-code");
        later_look["basics"]["font"] = json!("fira-code");
        let stale_edit = serde_json::to_vec(&json!({
            "op_id": "look-b",
            "base_revision": 1,
            "intent": {"type": "look.set", "look": later_look}
        }))
        .unwrap();
        assert_eq!(store.apply("a", &stale_edit).await.unwrap(), 3);

        let reloaded_a = store.events("a", None).await.unwrap();
        assert_eq!(reloaded_a[0]["revision"], 3);
        assert_eq!(reloaded_a[0]["document"]["look"], later_look);
        let account_b = store.events("b", None).await.unwrap();
        assert_eq!(account_b[0]["revision"], 0);
        assert!(account_b[0]["document"].get("look").is_none());
    }
}
