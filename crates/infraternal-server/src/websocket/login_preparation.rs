//! Preopens preferred accounts on authorized connected hosts once per authenticated socket [D229,D231,D240].
//!
//! Four concurrent requests bound transient work; each has its own deadline.
//! There is no refresh timer, and dropping the socket cancels pending work.
use super::{WebSocketState, terminal_agent};
use futures_util::{StreamExt, stream};
use std::{sync::Arc, time::Duration};

#[cfg(feature = "remote")]
async fn remote_targets(
    pool: &sqlx::SqlitePool,
    user: &str,
    token: &str,
) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    // A live session and host ownership must hold in the same read snapshot.
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT h.id FROM remote_hosts h WHERE h.owner_id=? AND h.revoked_at IS NULL AND EXISTS(SELECT 1 FROM sessions s WHERE s.token_hash=? AND s.user_id=h.owner_id AND s.unlocked=1 AND s.expires>unixepoch())")
        .bind(user).bind(token).fetch_all(pool).await?;
    rows.into_iter()
        .map(|id| uuid::Uuid::from_slice(&id).map_err(|error| sqlx::Error::Decode(Box::new(error))))
        .collect()
}

pub(super) async fn prepare(state: Arc<WebSocketState>, user: &str, token: &str) {
    let Ok(person) = uuid::Uuid::parse_str(user) else {
        return;
    };
    let digest = crate::auth::hash(token);
    #[cfg(feature = "remote")]
    let targets = {
        let mut targets = vec![None];
        if let Ok(hosts) = remote_targets(&state.pool, user, &digest).await {
            targets.extend(hosts.into_iter().map(Some));
        }
        targets
    };
    #[cfg(not(feature = "remote"))]
    let targets = vec![None];
    let digest = digest.as_str();
    stream::iter(targets)
        .for_each_concurrent(4, |host| {
            let state = state.clone();
            async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    let Ok(account) =
                        crate::preferred_accounts::resolve(&state.pool, user, digest, host).await
                    else {
                        return;
                    };
                    // Recheck durable host authority immediately before actor lookup;
                    // offline hosts are skipped and are opened by a later terminal.
                    let Ok(actor) = terminal_agent(&state, user, host).await else {
                        return;
                    };
                    let Ok(grant) = crate::login_access::grant(&state.pool, user, host).await
                    else {
                        return;
                    };
                    let _ = actor.prepare_login(person, Some(account), grant).await;
                })
                .await;
            }
        })
        .await;
}

#[cfg(all(test, feature = "remote"))]
mod tests {
    //! A single persisted authority snapshot excludes foreign, revoked and expired targets.
    use super::*;

    #[tokio::test]
    async fn preparation_targets_require_live_session_and_owned_unrevoked_host() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE sessions(token_hash BLOB,user_id TEXT,unlocked INTEGER,expires INTEGER)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TABLE remote_hosts(id BLOB,owner_id TEXT,revoked_at INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        let ids = [
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ];
        for (id, owner, revoked) in [
            (ids[0], "alice", None),
            (ids[1], "bob", None),
            (ids[2], "alice", Some(1_i64)),
        ] {
            sqlx::query("INSERT INTO remote_hosts VALUES(?,?,?)")
                .bind(id.as_bytes().as_slice())
                .bind(owner)
                .bind(revoked)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO sessions VALUES(?,'alice',1,unixepoch()+60)")
            .bind("public-fixture")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            remote_targets(&pool, "alice", "public-fixture")
                .await
                .unwrap(),
            vec![ids[0]]
        );
        assert_eq!(
            remote_targets(&pool, "bob", "public-fixture")
                .await
                .unwrap(),
            Vec::<uuid::Uuid>::new()
        );
        assert_eq!(
            remote_targets(&pool, "alice", "missing").await.unwrap(),
            Vec::<uuid::Uuid>::new()
        );
        sqlx::query("UPDATE sessions SET expires=unixepoch()-1")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            remote_targets(&pool, "alice", "public-fixture")
                .await
                .unwrap(),
            Vec::<uuid::Uuid>::new()
        );
        sqlx::query("UPDATE sessions SET expires=unixepoch()+60,unlocked=0")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            remote_targets(&pool, "alice", "public-fixture")
                .await
                .unwrap(),
            Vec::<uuid::Uuid>::new()
        );
    }
}
