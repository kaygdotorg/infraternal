//! D355: when Start fresh proves it emptied an account's install base on a host,
//! the same person's stale entries for that address and account are dropped at
//! once; nothing else changes (#305).
use super::*;

/// The rootless account on `user@fixture` the tests' Start fresh cleaned.
fn cleaned() -> (Target, Check) {
    (
        Target {
            id: "one".into(),
            address: TargetAddress::Manual("user@fixture".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        },
        Check::parse(b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n")
            .unwrap(),
    )
}

/// A person account, as production owners are.
async fn person(f: &Fixture) -> String {
    let person = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,0,'test')")
        .bind(&person)
        .bind(&person)
        .bind(&person)
        .execute(&f.pool)
        .await
        .unwrap();
    person
}

/// One host row of `owner` at `address`, with a certificate (so Console lists
/// it). `stale` gives it an open setup intent; `pending` a denial awaiting its
/// agent's cleanup receipt (what an add that found it abandoned leaves).
async fn row(
    f: &Fixture,
    owner: &str,
    address: &str,
    mode: &str,
    uid: i64,
    stale: bool,
    pending: bool,
) -> Uuid {
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,?,?,100)")
        .bind(host.as_bytes().as_slice()).bind(owner).bind(mode).bind(uid).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,?,NULL)")
        .bind(host.as_bytes().as_slice())
        .bind(address)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(randomblob(32),?,randomblob(32),randomblob(32),unixepoch(),unixepoch()+604800)")
        .bind(host.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    if stale {
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(host.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
    }
    if pending {
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,?,0)")
            .bind(host.as_bytes().as_slice())
            .bind(owner)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    host
}

/// (revoked, cleanup confirmed or absent, listed by Console's query).
async fn state(f: &Fixture, host: Uuid) -> (bool, Option<i64>, bool) {
    let (revoked, confirmed): (bool, Option<i64>) = sqlx::query_as("SELECT h.revoked_at IS NOT NULL, (SELECT confirmed FROM remote_login_cleanup q WHERE q.host_id=h.id) FROM remote_hosts h WHERE h.id=?")
        .bind(host.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
    // The predicate Console's host list uses (remote_inventory::list).
    let listed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=? AND h.revoked_at IS NULL AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id))")
        .bind(host.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
    (revoked, confirmed, listed)
}

/// After Start fresh cleaned the account's base, the person's stale rows for that
/// address and account are finished and leave Console: the pending one already
/// denied by an earlier add, and one whose setup never finished.
#[tokio::test]
async fn start_fresh_drops_the_persons_stale_entries_for_that_account() {
    let f = fixture(true).await;
    let owner = person(&f).await;
    let pending = row(&f, &owner, "user@fixture", "rootless", 1002, true, true).await;
    let unfinished = row(&f, &owner, "user@fixture", "rootless", 1002, true, false).await;
    let (target, check) = cleaned();
    f.backend
        .drop_cleaned_stale_entries(&owner, &target, &check, None)
        .await
        .unwrap();
    for host in [pending, unfinished] {
        assert_eq!(state(&f, host).await, (true, Some(1), false), "{host}");
    }
}

/// A pending entry Start fresh did not prove clean stays pending: no Start fresh
/// ran for its address, or it belongs to another account on the machine.
#[tokio::test]
async fn an_entry_whose_cleanup_was_not_proven_stays_pending() {
    let f = fixture(true).await;
    let owner = person(&f).await;
    let elsewhere = row(&f, &owner, "user@other", "rootless", 1002, true, true).await;
    let other_account = row(&f, &owner, "user@fixture", "rootless", 2002, true, true).await;
    let rootful = row(&f, &owner, "user@fixture", "rootful", 0, true, true).await;
    let (target, check) = cleaned();
    f.backend
        .drop_cleaned_stale_entries(&owner, &target, &check, None)
        .await
        .unwrap();
    for host in [elsewhere, other_account, rootful] {
        assert_eq!(state(&f, host).await, (false, Some(0), true), "{host}");
    }
}

/// Only the same person's own stale row is dropped: another person's row at the
/// same address, a finished host and one still being installed are untouched.
#[tokio::test]
async fn only_the_persons_own_stale_row_is_dropped() {
    let f = fixture(true).await;
    let owner = person(&f).await;
    let someone = person(&f).await;
    let theirs = row(&f, &someone, "user@fixture", "rootless", 1002, true, true).await;
    let finished = row(&f, &owner, "user@fixture", "rootless", 1002, false, false).await;
    let running = row(&f, &owner, "user@fixture", "rootless", 1002, true, false).await;
    f.backend.attempts.lock().unwrap().insert(
        running,
        Attempt {
            owner: owner.clone(),
            batch: Uuid::new_v4(),
            uid: 1002,
            link_round_trip: Duration::ZERO,
            destination: Some(("user@fixture".into(), None)),
            canary: None,
            retirement: None,
            replacement: false,
        },
    );
    let (target, check) = cleaned();
    f.backend
        .drop_cleaned_stale_entries(&owner, &target, &check, None)
        .await
        .unwrap();
    assert_eq!(state(&f, theirs).await, (false, Some(0), true));
    assert_eq!(state(&f, finished).await, (false, None, true));
    assert_eq!(state(&f, running).await, (false, None, true));
}
