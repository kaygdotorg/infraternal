//! Persists SSH-domain login preferences under exact session and host authority [198][229][231].
use infraternal_plugin_api::{
    Operation, Plugin, PluginDescriptor, ReplySender, SocketHost, SubscriptionRegistry,
};
use infraternal_plugin_ssh::accounts::{self, Backend, Change, Preference, Scope, Selection};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::sync::Arc;

const REFUSED: &str = "preferences unavailable or unauthorized";
#[derive(Clone)]
pub struct AccountsPlugin {
    pool: SqlitePool,
}
impl AccountsPlugin {
    /// Bind initialized server state; construction starts no background work.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
async fn authorize(
    tx: &mut Transaction<'_, Sqlite>,
    person: &str,
    hash: &str,
    host: Option<uuid::Uuid>,
) -> Result<(), &'static str> {
    let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=? AND token_hash=? AND unlocked=1 AND expires>unixepoch())")
        .bind(person).bind(hash).fetch_one(&mut **tx).await.map_err(|_| REFUSED)?;
    if !live {
        return Err(REFUSED);
    }
    authorize_host(tx, person, host).await
}
async fn authorize_host(
    tx: &mut Transaction<'_, Sqlite>,
    person: &str,
    host: Option<uuid::Uuid>,
) -> Result<(), &'static str> {
    if let Some(host) = host {
        let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL)")
            .bind(host.as_bytes().as_slice()).bind(person).fetch_one(&mut **tx).await.map_err(|_| REFUSED)?;
        if !owned {
            return Err(REFUSED);
        }
    }
    Ok(())
}
fn host_key(host: Option<uuid::Uuid>) -> Vec<u8> {
    host.map_or_else(Vec::new, |host| host.as_bytes().to_vec())
}
async fn read(
    tx: &mut Transaction<'_, Sqlite>,
    person: &str,
    host: Option<uuid::Uuid>,
) -> Result<Preference, &'static str> {
    let global_account: String = sqlx::query_scalar("SELECT COALESCE(p.account,u.username) FROM users u LEFT JOIN preferred_accounts p ON p.user_id=u.id WHERE u.id=?")
        .bind(person).fetch_one(&mut **tx).await.map_err(|_| REFUSED)?;
    let host_account: Option<String> = sqlx::query_scalar(
        "SELECT account FROM preferred_host_accounts WHERE user_id=? AND host_id=?",
    )
    .bind(person)
    .bind(host_key(host))
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| REFUSED)?;
    Ok(Preference {
        account: host_account
            .clone()
            .unwrap_or_else(|| global_account.clone()),
        global_account,
        host_account,
    })
}
/// Resolve a preferred account for a real terminal open using the same durable state and authority.
/// # Errors
/// Refuses expired sessions, foreign/revoked hosts and unavailable storage.
pub async fn resolve(
    pool: &SqlitePool,
    person: &str,
    hash: &str,
    host: Option<uuid::Uuid>,
) -> Result<String, &'static str> {
    AccountsPlugin::new(pool.clone())
        .get(person, hash, Selection { host_id: host })
        .await
        .map(|preference| preference.account)
}
/// Resolve the same preference for an API-key add-host. The caller rechecks the key's
/// `hosts:write` liveness around this read; host ownership is checked here as above.
/// # Errors
/// Refuses foreign/revoked hosts and unavailable storage.
#[cfg(feature = "remote")]
pub(crate) async fn resolve_for_key(
    pool: &SqlitePool,
    person: &str,
    host: uuid::Uuid,
) -> Result<String, &'static str> {
    let mut tx = pool.begin().await.map_err(|_| REFUSED)?;
    authorize_host(&mut tx, person, Some(host)).await?;
    let preference = read(&mut tx, person, Some(host)).await?;
    tx.commit().await.map_err(|_| REFUSED)?;
    Ok(preference.account)
}
impl Backend for AccountsPlugin {
    fn get<'a>(
        &'a self,
        person: &'a str,
        hash: &'a str,
        selection: Selection,
    ) -> Operation<'a, Result<Preference, &'static str>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(|_| REFUSED)?;
            authorize(&mut tx, person, hash, selection.host_id).await?;
            let preference = read(&mut tx, person, selection.host_id).await?;
            authorize(&mut tx, person, hash, selection.host_id).await?;
            tx.commit().await.map_err(|_| REFUSED)?;
            Ok(preference)
        })
    }
    fn set<'a>(
        &'a self,
        person: &'a str,
        hash: &'a str,
        change: Change,
    ) -> Operation<'a, Result<Preference, &'static str>> {
        Box::pin(async move {
            if (change.scope == Scope::Global && change.host_id.is_some())
                || change
                    .account
                    .as_deref()
                    .is_some_and(|account| !accounts::valid_account(account))
            {
                return Err("invalid input");
            }
            // Writer admission precedes authority checks, so a logout or host
            // revocation that won the lock cannot be bypassed by a queued setter.
            let mut tx = self
                .pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(|_| REFUSED)?;
            authorize(&mut tx, person, hash, change.host_id).await?;
            match (change.scope, change.account) {
                (Scope::Global, Some(account)) => {
                    sqlx::query("INSERT INTO preferred_accounts(user_id,account) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET account=excluded.account").bind(person).bind(account).execute(&mut *tx).await.map_err(|_| REFUSED)?;
                }
                (Scope::Global, None) => {
                    sqlx::query("DELETE FROM preferred_accounts WHERE user_id=?")
                        .bind(person)
                        .execute(&mut *tx)
                        .await
                        .map_err(|_| REFUSED)?;
                }
                (Scope::Host, Some(account)) => {
                    sqlx::query("INSERT INTO preferred_host_accounts(user_id,host_id,account) VALUES (?,?,?) ON CONFLICT(user_id,host_id) DO UPDATE SET account=excluded.account").bind(person).bind(host_key(change.host_id)).bind(account).execute(&mut *tx).await.map_err(|_| REFUSED)?;
                }
                (Scope::Host, None) => {
                    sqlx::query(
                        "DELETE FROM preferred_host_accounts WHERE user_id=? AND host_id=?",
                    )
                    .bind(person)
                    .bind(host_key(change.host_id))
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| REFUSED)?;
                }
            }
            let preference = read(&mut tx, person, change.host_id).await?;
            authorize(&mut tx, person, hash, change.host_id).await?;
            tx.commit().await.map_err(|_| REFUSED)?;
            Ok(preference)
        })
    }
}
impl Plugin for AccountsPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &accounts::DESCRIPTOR
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        replies: ReplySender,
        _registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let service = self.clone();
        Box::pin(async move {
            while let Some(wire) = requests.recv().await {
                if host
                    .authorized(Box::pin(async {
                        let decoded =
                            infraternal_protocol::decode_muxed_frame(&wire).map_err(|_| ())?;
                        let infraternal_protocol::Frame::Call {
                            call_id,
                            action_id,
                            input_json,
                        } = decoded.frame
                        else {
                            return Err(());
                        };
                        let (ok, value) = match accounts::call(
                            &service,
                            host.user_id(),
                            host.token_hash(),
                            action_id,
                            input_json,
                        )
                        .await
                        {
                            Ok(value) => (true, value),
                            Err(error) => (false, serde_json::json!({"error":error})),
                        };
                        let json = serde_json::to_vec(&value).map_err(|_| ())?;
                        let mut encoded = Vec::new();
                        infraternal_protocol::encode_muxed_frame_into(
                            0,
                            &infraternal_protocol::Frame::Result {
                                call_id,
                                ok,
                                json: &json,
                            },
                            &mut encoded,
                        )
                        .map_err(|_| ())?;
                        replies
                            .send(bytes::Bytes::from(encoded))
                            .await
                            .map_err(|_| ())
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    }
}
#[cfg(test)]
#[path = "preferred_accounts_tests.rs"]
mod tests;
