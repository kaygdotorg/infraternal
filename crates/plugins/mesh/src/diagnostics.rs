//! Logs why Mesh storage operations fail, without leaking data (#229).
//!
//! Callers still get the plain public [`MeshApiError::Storage`]. Behind it,
//! this module logs one short reason (for example "database locked or busy")
//! and the source location, and nothing else: database messages can contain
//! bound values and stored JSON errors can contain administrator input, so
//! neither is ever logged.
//!
//! Repeats are folded. A failing operation logs once, counts identical
//! repeats silently, and logs a recovery line with the count when the
//! operation next succeeds. That keeps a broken database from flooding the log.
use crate::api::MeshApiError;
use futures_util::TryFutureExt;

/// Logs a storage failure and returns the public error to hand back.
///
/// `reason` must be a fixed description. Only it and the caller's source
/// location (this function is `#[track_caller]`) are recorded. Inside
/// [`StorageDiagnostics::run`] repeats are counted; outside, each failure is
/// logged immediately under the operation name `mesh.storage`.
#[cold]
#[inline(never)]
#[track_caller]
pub(crate) fn storage_error(reason: &'static str) -> MeshApiError {
    let caller = std::panic::Location::caller();
    if CURRENT
        .try_with(|active| active.failed(reason, caller))
        .is_err()
    {
        log_storage_failure(reason, caller, "mesh.storage", 0);
    }
    MeshApiError::Storage
}

/// Turns a database driver error into a logged, fixed reason, and returns the
/// public storage error.
///
/// The reason is chosen from the error's kind or database result code (busy,
/// read-only, I/O, corrupt, full, constraint, missing table or column, pool
/// problems, decode problems). SQL text, values, connection strings and
/// free-form driver messages are never logged. A missing table or column is
/// reported separately from load problems so schema mistakes stand out.
#[cold]
#[inline(never)]
#[track_caller]
pub(crate) fn storage_sql_error(error: sqlx::Error) -> MeshApiError {
    let reason = match error {
        sqlx::Error::Database(database) => {
            let message = database.message();
            if message.starts_with("no such table:") {
                "database table missing"
            } else if message.starts_with("no such column:") {
                "database column missing"
            } else {
                // Extended SQLite codes retain their primary category in the low byte.
                match database
                    .code()
                    .and_then(|code| code.parse::<u32>().ok())
                    .map(|code| code & 0xff)
                {
                    Some(5 | 6) => "database locked or busy",
                    Some(8) => "database is read-only",
                    Some(10) => "database I/O failed",
                    Some(11 | 26) => "database format invalid",
                    Some(13) => "database storage full",
                    Some(19) => "database constraint failed",
                    _ => "database statement failed",
                }
            }
        }
        sqlx::Error::PoolTimedOut => "database pool acquisition timed out",
        sqlx::Error::PoolClosed => "database pool closed",
        sqlx::Error::RowNotFound => "required database row missing",
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "stored column invalid",
        sqlx::Error::ColumnNotFound(_) => "database column missing",
        sqlx::Error::Io(_) => "database I/O failed",
        _ => "database operation failed",
    };
    storage_error(reason)
}

/// Remembers which malformed host rows were already reported, so each is
/// logged once however often reads are retried.
///
/// Clones share one set. Only row IDs are kept, never row contents.
#[derive(Clone, Default)]
pub(crate) struct InvalidHosts(std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<i64>>>);

impl InvalidHosts {
    /// Logs that host row `id` was skipped as malformed, unless it was
    /// reported before.
    #[cold]
    #[inline(never)]
    pub(crate) fn report(&self, id: i64) {
        let first = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id);
        if first {
            tracing::error!(
                event = "mesh_invalid_host",
                node_id = id,
                "Mesh host row skipped"
            );
        }
    }
}

/// The failure counter of the operation running on this task, set by
/// [`StorageDiagnostics::run`].
///
/// A counter belongs to one logical operation and is shared by all service
/// clones. Task-local scoping carries it through free storage helpers without
/// exposing stored values or installing request authority in shared state.
tokio::task_local! {
    static CURRENT: StorageDiagnostics;
}

/// The most recent failure of an operation: what went wrong, where it was
/// raised, and how many times in a row it happened.
#[derive(Clone, Copy)]
struct Failure {
    reason: &'static str,
    caller: &'static std::panic::Location<'static>,
    count: u64,
}

/// The failure counter of one named operation, shared by its clones.
///
/// It holds at most one [`Failure`], so its size is fixed. It has no timers and
/// no per-viewer state.
#[derive(Clone)]
pub(crate) struct StorageDiagnostics(std::sync::Arc<DiagnosticState>);

/// Shared state behind a [`StorageDiagnostics`].
struct DiagnosticState {
    /// The operation's name, used in log lines.
    operation: Box<str>,
    /// `true` while a failure is recorded. Lets healthy calls skip the mutex.
    active: std::sync::atomic::AtomicBool,
    failure: std::sync::Mutex<Option<Failure>>,
}

impl StorageDiagnostics {
    /// Creates a counter for the operation called `operation`, with no failure
    /// recorded.
    pub(crate) fn new(operation: &str) -> Self {
        Self(std::sync::Arc::new(DiagnosticState {
            operation: operation.into(),
            active: std::sync::atomic::AtomicBool::new(false),
            failure: std::sync::Mutex::new(None),
        }))
    }

    /// Runs `work` with this counter active, so every [`storage_error`] raised
    /// inside it is counted here. When `work` succeeds after earlier failures,
    /// logs the recovery and the repeat count.
    ///
    /// Returns the future directly rather than being an `async fn`, so the
    /// wrapper never stores a second copy of a large operation future in the
    /// caller's argument frame.
    pub(crate) fn run<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, MeshApiError>>,
    ) -> impl std::future::Future<Output = Result<T, MeshApiError>> {
        CURRENT.scope(self.clone(), work).inspect_ok(move |_| {
            // Healthy reads never take a diagnostic mutex.
            if self.0.active.load(std::sync::atomic::Ordering::Acquire) {
                self.recovered();
            }
        })
    }

    /// Notes a failure. If it repeats the previous one (same reason and
    /// location) only the count grows. Otherwise it replaces the record and
    /// logs, reporting how many times the previous failure had repeated.
    #[cold]
    #[inline(never)]
    fn failed(&self, reason: &'static str, caller: &'static std::panic::Location<'static>) {
        let previous_count = {
            let mut state = self
                .0
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(failure) = state.as_mut()
                && failure.reason == reason
                && failure.caller == caller
            {
                failure.count = failure.count.saturating_add(1);
                return;
            }
            let previous = state.map_or(0, |failure| failure.count);
            *state = Some(Failure {
                reason,
                caller,
                count: 1,
            });
            self.0
                .active
                .store(true, std::sync::atomic::Ordering::Release);
            previous
        };
        log_storage_failure(reason, caller, &self.0.operation, previous_count);
    }

    /// Clears the recorded failure and logs that storage works again, with
    /// the final repeat count.
    #[cold]
    #[inline(never)]
    fn recovered(&self) {
        let previous = {
            let mut state = self
                .0
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = state.take();
            self.0
                .active
                .store(false, std::sync::atomic::Ordering::Release);
            previous
        };
        if let Some(failure) = previous {
            tracing::info!(
                event = "mesh_storage_recovered",
                operation = self.0.operation.as_ref(),
                reason = failure.reason,
                file = failure.caller.file(),
                line = failure.caller.line(),
                count = failure.count,
                "Mesh storage recovered"
            );
        }
    }
}

/// Writes the error log line for a storage failure: operation, fixed reason,
/// source location and the repeat count of the failure before it.
#[cold]
#[inline(never)]
fn log_storage_failure(
    reason: &'static str,
    caller: &'static std::panic::Location<'static>,
    operation: &str,
    previous_count: u64,
) {
    tracing::error!(
        event = "mesh_storage_error",
        operation,
        reason,
        file = caller.file(),
        line = caller.line(),
        count = 1_u64,
        previous_count,
        "Mesh storage unavailable"
    );
}

/// One [`StorageDiagnostics`] counter per API action, created on first use.
///
/// Counters are only added after action parsing has accepted the action name.
/// The parser's fixed set of actions bounds how many there can be, no matter
/// how many viewers there are.
#[derive(Clone, Default)]
pub(crate) struct ActionDiagnostics(std::sync::Arc<std::sync::Mutex<Vec<StorageDiagnostics>>>);

impl ActionDiagnostics {
    /// The counter for `action`, created if this is its first use. Calls with
    /// the same name share one counter.
    pub(crate) fn for_action(&self, action: &str) -> StorageDiagnostics {
        let mut counters = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(counter) = counters
            .iter()
            .find(|counter| counter.0.operation.as_ref() == action)
        {
            return counter.clone();
        }
        let counter = StorageDiagnostics::new(action);
        counters.push(counter.clone());
        counter
    }
}
