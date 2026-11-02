//! Owner-only Mesh default preview and revision-checked fresh-passkey updates [28,211,216].
use crate::{
    api::MeshApiError,
    dataplane::DefaultPolicy,
    diagnostics::{storage_error, storage_sql_error},
    store::Store,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    default_policy: DefaultPolicy,
    #[serde(default)]
    cursor: Option<crate::api::MeshCursor>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    default_policy: DefaultPolicy,
    expected_revision: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationIntervalSet {
    rotation_period_secs: u64,
    expected_revision: i64,
}
fn parse<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, MeshApiError> {
    if input.len() > crate::api::MAX_MESH_FRAME_LEN
        || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(MeshApiError::InvalidInput);
    }
    serde_json::from_slice(input).map_err(|_| MeshApiError::InvalidInput)
}
/// Pure public setting request, shared with parser fuzzing and the action adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Get,
    Preview {
        default_policy: DefaultPolicy,
        cursor: Option<crate::api::MeshCursor>,
    },
    Set {
        default_policy: DefaultPolicy,
        expected_revision: i64,
    },
    RotationGet,
    RotationIntervalSet {
        rotation_period_secs: u64,
        expected_revision: i64,
    },
}
/// Parse a bounded object and reject unknown/duplicate fields before storage work.
/// # Errors
/// Returns invalid input for unknown actions, non-objects or invalid revision fields.
pub fn parse_action(action: &str, input: &[u8]) -> Result<Request, MeshApiError> {
    match action {
        "mesh.default.get" => {
            let _: Empty = parse(input)?;
            Ok(Request::Get)
        }
        "mesh.default.preview" => {
            let input: Preview = parse(input)?;
            Ok(Request::Preview {
                default_policy: input.default_policy,
                cursor: input.cursor,
            })
        }
        "mesh.default.set" => {
            let input: Set = parse(input)?;
            if input.expected_revision < 0 {
                return Err(MeshApiError::InvalidInput);
            }
            Ok(Request::Set {
                default_policy: input.default_policy,
                expected_revision: input.expected_revision,
            })
        }
        "mesh.rotation.get" => {
            let _: Empty = parse(input)?;
            Ok(Request::RotationGet)
        }
        "mesh.rotation.interval.set" => {
            let input: RotationIntervalSet = parse(input)?;
            if input.rotation_period_secs == 0
                || i64::try_from(input.rotation_period_secs).is_err()
                || input.expected_revision < 0
            {
                return Err(MeshApiError::InvalidInput);
            }
            Ok(Request::RotationIntervalSet {
                rotation_period_secs: input.rotation_period_secs,
                expected_revision: input.expected_revision,
            })
        }
        _ => Err(MeshApiError::InvalidInput),
    }
}
/// Read/preview/apply from the same action adapter. Setter refuses a changed preview revision.
/// # Errors
/// Returns denied/fresh/conflict/storage failures without leaking database details.
pub async fn execute(
    pool: &SqlitePool,
    store: &Store,
    actor: &str,
    action: &str,
    input: &[u8],
    now: i64,
    fresh: Option<&str>,
) -> Result<Value, MeshApiError> {
    let request = parse_action(action, input)?;
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(pool)
            .await
            .map_err(|error| storage_sql_error(error))?;
    if !owner {
        return Err(MeshApiError::Denied);
    }
    match request {
        Request::Get => {
            let default: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                "SELECT default_policy FROM mesh_dataplane WHERE singleton=1",
            )
            .fetch_optional(pool)
            .await
            .map_err(|error| storage_sql_error(error))?
            .flatten();
            let default = match default.as_deref() {
                Some("allow") => DefaultPolicy::Allow,
                Some("deny") => DefaultPolicy::Deny,
                None => DefaultPolicy::default(),
                _ => return Err(storage_error("stored default invalid")),
            };
            Ok(json!({"default_policy":default}))
        }
        Request::Preview {
            default_policy,
            cursor,
        } => store.preview_page(default_policy, cursor).await,
        Request::Set {
            default_policy,
            expected_revision,
        } => set_default(pool, actor, default_policy, expected_revision, now, fresh).await,
        Request::RotationGet => get_rotation(pool, actor).await,
        Request::RotationIntervalSet {
            rotation_period_secs,
            expected_revision,
        } => {
            set_rotation_interval(
                pool,
                actor,
                rotation_period_secs,
                expected_revision,
                now,
                fresh,
            )
            .await
        }
    }
}

async fn get_rotation(pool: &SqlitePool, actor: &str) -> Result<Value, MeshApiError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage_sql_error(error))?;
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
    if !owner {
        return Err(MeshApiError::Denied);
    }
    let period: i64 =
        sqlx::query_scalar("SELECT rotation_period_secs FROM mesh_dataplane WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    if period <= 0 {
        return Err(storage_error("rotation period invalid"));
    }
    let rows = sqlx::query(
        "SELECT n.id,n.name,n.key_rotation_supported,r.last_rotation,r.rotation_phase FROM mesh_nodes AS n JOIN mesh_node_key_rotation AS r ON r.node_id=n.id ORDER BY n.id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let unsupported_peers: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE key_rotation_supported=0)",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let mut hosts = Vec::with_capacity(rows.len());
    for row in rows {
        let last: i64 = row
            .try_get("last_rotation")
            .map_err(|error| storage_sql_error(error))?;
        let next = (i128::from(last) + i128::from(period)).to_string();
        let supported: bool = row
            .try_get("key_rotation_supported")
            .map_err(|error| storage_sql_error(error))?;
        let deferred_reason = if !supported {
            Some("local_unsupported")
        } else if unsupported_peers {
            Some("peer_unsupported")
        } else {
            None
        };
        hosts.push(json!({
            "node_id": row.try_get::<i64, _>("id").map_err(|error| storage_sql_error(error))?,
            "name": row.try_get::<String, _>("name").map_err(|error| storage_sql_error(error))?,
            "last_rotation": last.to_string(),
            "next_rotation": next,
            "pending": row.try_get::<Option<String>, _>("rotation_phase").map_err(|error| storage_sql_error(error))?.is_some(),
            "deferred_reason": deferred_reason,
        }));
    }
    tx.commit()
        .await
        .map_err(|error| storage_sql_error(error))?;
    Ok(json!({
        "revision": revision,
        "rotation_period_secs": period,
        "hosts": hosts,
    }))
}

async fn set_rotation_interval(
    pool: &SqlitePool,
    actor: &str,
    rotation_period_secs: u64,
    expected_revision: i64,
    now: i64,
    fresh: Option<&str>,
) -> Result<Value, MeshApiError> {
    let period = i64::try_from(rotation_period_secs).map_err(|_| MeshApiError::InvalidInput)?;
    if period <= 0 {
        return Err(MeshApiError::InvalidInput);
    }
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool)
        .await
        .map_err(|error| storage_sql_error(error))?;
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
    if !owner {
        return Err(MeshApiError::Denied);
    }
    if let Some(hash) = fresh
        && !infraternal_plugin_api::fresh_session_tx(
            &mut tx,
            hash,
            actor,
            now,
            infraternal_plugin_api::FRESH_SECONDS,
        )
        .await
        .map_err(|error| storage_sql_error(error))?
    {
        return Err(MeshApiError::FreshRequired);
    }
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    if revision != expected_revision {
        return Err(MeshApiError::Conflict);
    }
    let next = revision
        .checked_add(1)
        .ok_or_else(|| storage_error("revision exhausted"))?;
    sqlx::query("UPDATE mesh_dataplane SET rotation_period_secs=? WHERE singleton=1")
        .bind(period)
        .execute(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    sqlx::query("UPDATE mesh_state SET revision=? WHERE singleton=1")
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES(?,'mesh.rotation.interval.set','mesh',?,?,?)")
        .bind(actor)
        .bind(next)
        .bind(now)
        .bind(serde_json::to_string(&rotation_period_secs).map_err(|_| storage_error("rotation period serialization failed"))?)
        .execute(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    if let Some(hash) = fresh
        && !infraternal_plugin_api::fresh_session_tx(
            &mut tx,
            hash,
            actor,
            now,
            infraternal_plugin_api::FRESH_SECONDS,
        )
        .await
        .map_err(|error| storage_sql_error(error))?
    {
        return Err(MeshApiError::FreshRequired);
    }
    tx.commit()
        .await
        .map_err(|error| storage_sql_error(error))?;
    Ok(json!({
        "rotation_period_secs": rotation_period_secs,
        "revision": next,
    }))
}

// Keep the writer transaction and its two authority checks together. Preview
// pins the same revision; a concurrent membership/policy edit forces a new preview.
async fn set_default(
    pool: &SqlitePool,
    actor: &str,
    default_policy: DefaultPolicy,
    expected_revision: i64,
    now: i64,
    fresh: Option<&str>,
) -> Result<Value, MeshApiError> {
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool)
        .await
        .map_err(|error| storage_sql_error(error))?;
    // Recheck after the writer wait, where rollback still fences authority.
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
    if !owner {
        return Err(MeshApiError::Denied);
    }
    if let Some(hash) = fresh
        && !infraternal_plugin_api::fresh_session_tx(
            &mut tx,
            hash,
            actor,
            now,
            infraternal_plugin_api::FRESH_SECONDS,
        )
        .await
        .map_err(|error| storage_sql_error(error))?
    {
        return Err(MeshApiError::FreshRequired);
    }

    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    if revision != expected_revision {
        return Err(MeshApiError::Conflict);
    }
    let next = revision
        .checked_add(1)
        .ok_or_else(|| storage_error("revision exhausted"))?;
    let value = if default_policy == DefaultPolicy::Allow {
        "allow"
    } else {
        "deny"
    };
    sqlx::query("INSERT INTO mesh_dataplane(singleton,default_policy) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET default_policy=excluded.default_policy").bind(value).execute(&mut *tx).await.map_err(|error| storage_sql_error(error))?;
    sqlx::query("UPDATE mesh_state SET revision=? WHERE singleton=1")
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES(?,'mesh.default.set','mesh',?,?,?)").bind(actor).bind(next).bind(now).bind(serde_json::to_string(&default_policy).map_err(|_| storage_error("default serialization failed"))?).execute(&mut *tx).await.map_err(|error| storage_sql_error(error))?;
    if let Some(hash) = fresh
        && !infraternal_plugin_api::fresh_session_tx(
            &mut tx,
            hash,
            actor,
            now,
            infraternal_plugin_api::FRESH_SECONDS,
        )
        .await
        .map_err(|error| storage_sql_error(error))?
    {
        return Err(MeshApiError::FreshRequired);
    }
    tx.commit()
        .await
        .map_err(|error| storage_sql_error(error))?;
    Ok(json!({"default_policy":default_policy,"revision":next}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_objects_are_bounded_and_strict_before_storage() {
        for action in [
            "mesh.default.get",
            "mesh.default.preview",
            "mesh.default.set",
            "mesh.rotation.get",
            "mesh.rotation.interval.set",
        ] {
            assert_eq!(parse_action(action, b"[]"), Err(MeshApiError::InvalidInput));
            assert_eq!(
                parse_action(action, b"null"),
                Err(MeshApiError::InvalidInput)
            );
            assert_eq!(
                parse_action(action, &vec![b' '; crate::api::MAX_MESH_FRAME_LEN + 1]),
                Err(MeshApiError::InvalidInput)
            );
        }
        for input in [
            br#"{"default_policy":"Deny","expected_revision":-1}"#.as_slice(),
            br#"{"default_policy":"Deny","expected_revision":0,"expected_revision":0}"#,
            br#"{"default_policy":"Deny","expected_revision":0,"unknown":true}"#,
        ] {
            assert_eq!(
                parse_action("mesh.default.set", input),
                Err(MeshApiError::InvalidInput)
            );
        }
        assert_eq!(
            parse_action(
                "mesh.default.set",
                br#"{"default_policy":"Deny","expected_revision":0}"#
            ),
            Ok(Request::Set {
                default_policy: DefaultPolicy::Deny,
                expected_revision: 0
            })
        );
        for input in [
            br#"{"rotation_period_secs":0,"expected_revision":0}"#.as_slice(),
            br#"{"rotation_period_secs":9223372036854775808,"expected_revision":0}"#,
            br#"{"rotation_period_secs":604800,"expected_revision":-1}"#,
            br#"{"rotation_period_secs":604800,"expected_revision":0,"unexpected":true}"#,
            br#"{"rotation_period_secs":604800,"rotation_period_secs":604800,"expected_revision":0}"#,
        ] {
            assert_eq!(
                parse_action("mesh.rotation.interval.set", input),
                Err(MeshApiError::InvalidInput)
            );
        }
        assert_eq!(
            parse_action(
                "mesh.rotation.interval.set",
                br#"{"rotation_period_secs":604800,"expected_revision":0}"#
            ),
            Ok(Request::RotationIntervalSet {
                rotation_period_secs: 604_800,
                expected_revision: 0,
            })
        );
    }
}
