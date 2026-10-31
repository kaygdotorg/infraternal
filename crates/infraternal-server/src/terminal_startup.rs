//! Account and host startup hints; a notice is claimed only after real detection [D315].
use serde::Deserialize;
use sqlx::{Row, SqlitePool};

pub(crate) enum Request {
    Get {
        host_id: Option<uuid::Uuid>,
    },
    Set {
        host_id: Option<uuid::Uuid>,
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

/// A flat wire shape avoids serde's tagged-enum content buffering. Validate
/// operation-specific keys separately, retaining duplicate-field rejection in
/// the typed pass. This cold, bounded action does not run on terminal traffic.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    op: String,
    host_id: Option<uuid::Uuid>,
    #[serde(default)]
    global: bool,
    enabled: Option<bool>,
    session: Option<uuid::Uuid>,
    #[serde(default)]
    proposal: serde_json::Value,
    confirmed: Option<bool>,
}

impl Request {
    pub(crate) fn parse(input: &[u8]) -> serde_json::Result<Self> {
        use serde::de::Error as _;
        let wire: WireRequest = serde_json::from_slice(input)?;
        let value: serde_json::Value = serde_json::from_slice(input)?;
        let invalid = || serde_json::Error::custom("invalid startup request");
        let object = value.as_object().ok_or_else(invalid)?;
        let allowed: &[&str] = match wire.op.as_str() {
            "get" => &["op", "host_id"],
            "set" => &["op", "host_id", "global", "enabled"],
            "inspect" => &["op", "session"],
            "apply" | "undo" => &["op", "session", "proposal", "confirmed"],
            _ => return Err(invalid()),
        };
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(invalid());
        }
        Ok(match wire.op.as_str() {
            "get" => Self::Get {
                host_id: wire.host_id,
            },
            "set" => Self::Set {
                host_id: wire.host_id,
                global: wire.global,
                enabled: wire.enabled,
            },
            "inspect" => Self::Inspect {
                session: wire.session.ok_or_else(invalid)?,
            },
            op => {
                if !object.contains_key("proposal") {
                    return Err(invalid());
                }
                let session = wire.session.ok_or_else(invalid)?;
                let confirmed = wire.confirmed.ok_or_else(invalid)?;
                if op == "apply" {
                    Self::Apply {
                        session,
                        proposal: wire.proposal,
                        confirmed,
                    }
                } else {
                    Self::Undo {
                        session,
                        proposal: wire.proposal,
                        confirmed,
                    }
                }
            }
        })
    }
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

    #[test]
    fn request_decoder_keeps_operation_fields_strict() {
        for input in [
            r#"{"op":"get"}"#,
            r#"{"op":"get","host_id":null}"#,
            r#"{"op":"set","global":true,"enabled":false}"#,
            r#"{"op":"set","enabled":null}"#,
            r#"{"op":"inspect","session":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"op":"apply","session":"00000000-0000-0000-0000-000000000001","proposal":null,"confirmed":true}"#,
        ] {
            assert!(Request::parse(input.as_bytes()).is_ok(), "{input}");
        }
        for input in [
            r#"{"op":"get","session":null}"#,
            r#"{"op":"get","uid":0}"#,
            r#"{"op":"get","host_id":false}"#,
            r#"{"op":"get","op":"get"}"#,
            r#"{"op":"set","global":null}"#,
            r#"{"op":"set","enabled":1}"#,
            r#"{"op":"inspect","session":null}"#,
            r#"{"op":"inspect","session":"invalid"}"#,
            r#"{"op":"apply","session":"00000000-0000-0000-0000-000000000001","proposal":{},"confirmed":null}"#,
            r#"{"op":"undo","session":"00000000-0000-0000-0000-000000000001","confirmed":true}"#,
            r#"{"op":"unknown"}"#,
            r#"[]"#,
        ] {
            assert!(Request::parse(input.as_bytes()).is_err(), "{input}");
        }
    }

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
