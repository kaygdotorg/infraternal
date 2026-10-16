//! Records bounded, content-free reasons for Mesh storage failures while preserving public errors (#229).
use crate::api::MeshApiError;

/// Record only static descriptions and source locations: database messages can
/// contain bound values, and stored JSON errors can contain administrator input.
#[cold]
#[inline(never)]
#[track_caller]
pub(crate) fn storage_error(reason: &'static str) -> MeshApiError {
    let caller = std::panic::Location::caller();
    tracing::error!(
        event = "mesh_storage_error",
        reason,
        file = caller.file(),
        line = caller.line(),
        "Mesh storage unavailable"
    );
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
