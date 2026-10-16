//! Records bounded, content-free reasons for Mesh storage failures while preserving public errors (#229).
use crate::api::MeshApiError;
use futures_util::TryFutureExt;

/// Record only static descriptions and source locations: database messages can
/// contain bound values, and stored JSON errors can contain administrator input.
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

/// Classify driver errors without printing SQL, values, connection strings or
/// free-form driver messages. Schema errors remain distinguishable from load.
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

/// Clones share the IDs already reported; retries never repeat a row diagnostic.
/// Only IDs of malformed rows visible to a caller are retained, never row values.
#[derive(Clone, Default)]
pub(crate) struct InvalidHosts(std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<i64>>>);

impl InvalidHosts {
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

// A counter belongs to one logical operation and is shared by all service
// clones. Task-local scoping carries it through free storage helpers without
// exposing stored values or installing request authority in shared state.
tokio::task_local! {
    static CURRENT: StorageDiagnostics;
}

#[derive(Clone, Copy)]
struct Failure {
    reason: &'static str,
    caller: &'static std::panic::Location<'static>,
    count: u64,
}

/// One bounded failure counter, with no timers or per-viewer state.
#[derive(Clone)]
pub(crate) struct StorageDiagnostics(std::sync::Arc<DiagnosticState>);

struct DiagnosticState {
    operation: Box<str>,
    active: std::sync::atomic::AtomicBool,
    failure: std::sync::Mutex<Option<Failure>>,
}

impl StorageDiagnostics {
    pub(crate) fn new(operation: &str) -> Self {
        Self(std::sync::Arc::new(DiagnosticState {
            operation: operation.into(),
            active: std::sync::atomic::AtomicBool::new(false),
            failure: std::sync::Mutex::new(None),
        }))
    }

    /// Scope helpers to one operation and flush its repeat count on success.
    /// Construct the scope directly so the wrapper never stores a second copy
    /// of a large operation future in an async function's argument frame.
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

/// Cache counters only after action parsing has admitted the action name. The
/// parser's fixed action set bounds this collection, independent of viewers.
#[derive(Clone, Default)]
pub(crate) struct ActionDiagnostics(std::sync::Arc<std::sync::Mutex<Vec<StorageDiagnostics>>>);

impl ActionDiagnostics {
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
