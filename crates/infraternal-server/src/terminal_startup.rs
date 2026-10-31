//! Account and host startup hints; a notice is claimed only after real detection [D315].
use serde::Deserialize;
use sqlx::{Row, SqlitePool};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Get {
        host_id: Option<uuid::Uuid>,
    },
    Set {
        host_id: Option<uuid::Uuid>,
        #[serde(default)]
        global: bool,
        enabled: Option<bool>,
    },
    Inspect {
        session: uuid::Uuid,
    },
    Apply {
        session: uuid::Uuid,
        proposal: serde_json::Value,
        confirmed: bool,
    },
    Undo {
        session: uuid::Uuid,
        proposal: serde_json::Value,
        confirmed: bool,
    },
}

pub(crate) async fn preferences(
    pool: &SqlitePool,
    user: &str,
    host: &str,
) -> Result<(bool, Option<bool>), ()> {
    let row = sqlx::query("SELECT COALESCE((SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host='*'),1),(SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host=?)")
        .bind(user).bind(user).bind(host).fetch_one(pool).await.map_err(|_| ())?;
    Ok((
        row.try_get(0).map_err(|_| ())?,
        row.try_get(1).map_err(|_| ())?,
    ))
}

pub(crate) async fn save(
    pool: &SqlitePool,
    user: &str,
    host: &str,
    value: Option<bool>,
) -> Result<(), ()> {
    sqlx::query("INSERT INTO terminal_startup_hints(user_id,host,enabled) VALUES(?,?,?) ON CONFLICT(user_id,host) DO UPDATE SET enabled=excluded.enabled")
        .bind(user).bind(host).bind(value).execute(pool).await.map_err(|_| ())?;
    Ok(())
}

/// Once shown, future sessions do no process inspection at all.
pub(crate) async fn pending(pool: &SqlitePool, user: &str, host: &str) -> Result<bool, ()> {
    sqlx::query_scalar("SELECT NOT COALESCE((SELECT shown FROM terminal_startup_hints WHERE user_id=? AND host=?),0) AND COALESCE((SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host=?),(SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host='*'),1)")
        .bind(user).bind(host).bind(user).bind(host).bind(user).fetch_one(pool).await.map_err(|_| ())
}

pub(crate) async fn claim(pool: &SqlitePool, user: &str, host: &str) -> Result<bool, ()> {
    let changed = sqlx::query("INSERT INTO terminal_startup_hints(user_id,host,enabled,shown) SELECT ?,?,NULL,1 WHERE COALESCE((SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host=?),(SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host='*'),1) ON CONFLICT(user_id,host) DO UPDATE SET shown=1 WHERE NOT shown AND COALESCE(terminal_startup_hints.enabled,(SELECT enabled FROM terminal_startup_hints WHERE user_id=? AND host='*'),1)")
        .bind(user).bind(host).bind(user).bind(host).bind(user).bind(user).execute(pool).await.map_err(|_| ())?;
    Ok(changed.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    //! Scoped switches and atomic first-use claims must survive independent concurrent callers.
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE terminal_startup_hints(user_id TEXT, host TEXT, enabled INTEGER, shown INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,host))").execute(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn switches_preserve_account_and_host_scope_across_concurrent_updates() {
        let pool = pool().await;
        assert_eq!(
            preferences(&pool, "a", "local").await.unwrap(),
            (true, None)
        );
        let (global, host) = tokio::join!(
            save(&pool, "a", "*", Some(false)),
            save(&pool, "a", "local", Some(true))
        );
        global.unwrap();
        host.unwrap();
        assert_eq!(
            preferences(&pool, "a", "local").await.unwrap(),
            (false, Some(true))
        );
        assert_eq!(
            preferences(&pool, "a", "other").await.unwrap(),
            (false, None)
        );
        assert_eq!(
            preferences(&pool, "b", "local").await.unwrap(),
            (true, None)
        );
        save(&pool, "a", "local", None).await.unwrap();
        assert_eq!(
            preferences(&pool, "a", "local").await.unwrap(),
            (false, None)
        );
    }

    #[tokio::test]
    async fn only_one_caller_claims_and_disabled_hints_do_not_consume_notice() {
        let pool = pool().await;
        save(&pool, "a", "*", Some(false)).await.unwrap();
        assert!(!pending(&pool, "a", "local").await.unwrap());
        assert!(!claim(&pool, "a", "local").await.unwrap());
        save(&pool, "a", "*", Some(true)).await.unwrap();
        assert!(pending(&pool, "a", "local").await.unwrap());
        let (one, two) = tokio::join!(claim(&pool, "a", "local"), claim(&pool, "a", "local"));
        assert_ne!(one.unwrap(), two.unwrap());
        assert!(!pending(&pool, "a", "local").await.unwrap());
        assert!(!claim(&pool, "a", "local").await.unwrap());
        assert!(claim(&pool, "b", "local").await.unwrap());
        assert!(claim(&pool, "a", "other").await.unwrap());
    }
}
