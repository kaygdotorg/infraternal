//! Reads login access rules and machine provenance into one grant per (person, host) [D235, D252, D319], #221.
//!
//! The decision itself is the pure reduction in
//! `infraternal_plugin_api::login_access`; this module only loads its inputs,
//! all inside one read transaction so the rules, the person and the machine
//! provenance are one consistent view. Every failure, unknown person, unknown
//! or revoked host and malformed row gives the empty grant, which refuses
//! everything: there is no fallback that widens access.

use infraternal_plugin_api::login_access::{
    self, Account, HostFacts, HostRef, Hosts, LoginGrant, Rule, Subject,
};
use sqlx::{SqliteConnection, SqlitePool};

fn host_key(host: Option<uuid::Uuid>) -> Vec<u8> {
    host.map_or_else(Vec::new, |host| host.as_bytes().to_vec())
}

fn host_ref(key: &[u8]) -> Option<HostRef> {
    if key.is_empty() {
        return Some(HostRef::Embedded);
    }
    key.try_into().ok().map(HostRef::Remote)
}

type RuleRow = (Option<String>, String, Option<String>, Option<Vec<u8>>);

fn rule(row: RuleRow) -> Option<Rule> {
    let (subject, kind, account, host) = row;
    Some(Rule {
        subject: subject.map_or(Subject::Everyone, Subject::Person),
        account: match (kind.as_str(), account) {
            ("own", None) => Account::OwnUsername,
            ("any", None) => Account::Any,
            ("named", Some(account)) => Account::Named(account),
            _ => return None,
        },
        hosts: match host {
            None => Hosts::All,
            Some(key) => Hosts::Host(host_ref(&key)?),
        },
    })
}

/// The login grant for `person` on `host` (`None` is the server's own host).
///
/// # Errors
/// Returns storage errors; callers refuse the login on any error.
pub async fn grant(
    pool: &SqlitePool,
    person: &str,
    host: Option<uuid::Uuid>,
) -> Result<LoginGrant, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let grant = grant_in(&mut tx, person, host).await?;
    tx.commit().await?;
    Ok(grant)
}

/// [`grant`] inside a caller's transaction, so a caller can bind the check
/// to the same view as its own write.
///
/// # Errors
/// Returns storage errors; callers refuse the login on any error.
pub async fn grant_in(
    connection: &mut SqliteConnection,
    person: &str,
    host: Option<uuid::Uuid>,
) -> Result<LoginGrant, sqlx::Error> {
    let Some((username, owner)): Option<(String, bool)> =
        sqlx::query_as("SELECT username, owner = 1 FROM users WHERE id = ?")
            .bind(person)
            .fetch_optional(&mut *connection)
            .await?
    else {
        return Ok(LoginGrant::default());
    };
    let key = host_key(host);
    let added_by_person = if host.is_some() {
        let current: Option<String> = sqlx::query_scalar(
            "SELECT owner_id FROM remote_hosts WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(&key)
        .fetch_optional(&mut *connection)
        .await?;
        let Some(adder) = current else {
            // A removed or unknown machine has no logins at all.
            return Ok(LoginGrant::default());
        };
        adder == person
    } else {
        // The owner set up the server, so the server's own host is theirs.
        owner
    };
    let names_match_people: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM login_names_match WHERE host_id = ?)")
            .bind(&key)
            .fetch_one(&mut *connection)
            .await?;
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT subject, account_kind, account, host_id FROM login_rules \
         WHERE (subject IS NULL OR subject = ?) AND (host_id IS NULL OR host_id = ?)",
    )
    .bind(person)
    .bind(&key)
    .fetch_all(&mut *connection)
    .await?;
    // A row the schema should have refused is skipped, never read as wider.
    let rules: Vec<Rule> = rows.into_iter().filter_map(rule).collect();
    Ok(login_access::grant(
        &rules,
        person,
        &username,
        &HostFacts {
            host: host_ref(&key).unwrap_or(HostRef::Embedded),
            added_by_person,
            names_match_people,
        },
    ))
}

/// Give a newly created owner the D235 starter rule, inside the transaction
/// that creates them. Runs once: the owner row is unique and never recreated,
/// so a deleted starter rule stays deleted.
///
/// # Errors
/// Returns storage errors, which abort owner creation.
pub async fn add_owner_defaults(
    connection: &mut SqliteConnection,
    owner: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO login_rules (subject, account_kind, account, host_id, created_at) \
         VALUES (?, 'any', NULL, NULL, unixepoch())",
    )
    .bind(owner)
    .execute(connection)
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "login_access_tests.rs"]
mod tests;
