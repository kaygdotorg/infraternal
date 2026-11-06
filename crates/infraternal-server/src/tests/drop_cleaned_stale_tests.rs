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
    sqlx::query(
        "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,?,?,100)",
    )
    .bind(host.as_bytes().as_slice())
    .bind(owner)
    .bind(mode)
    .bind(uid)
    .execute(&f.pool)
    .await
    .unwrap();
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

/// The check on a machine with no infraternal install at all: the fixture's own
/// session, whose "clear" report becomes the proven "absent" (D355). When the new
/// invitation reaches the host it records how many of the person's unrevoked
/// entries the address has (the new one included).
struct NoInstall {
    opens: Arc<AtomicUsize>,
    pool: sqlx::SqlitePool,
    owner: String,
    at_invitation: Arc<std::sync::Mutex<Vec<i64>>>,
}
struct NoInstallSession {
    sniff: Sniff,
    pool: sqlx::SqlitePool,
    owner: String,
    at_invitation: Arc<std::sync::Mutex<Vec<i64>>>,
}
impl SshTransport for NoInstall {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            self.opens.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(NoInstallSession {
                sniff: Sniff {
                    opens: self.opens.clone(),
                    refuse_key_payload_upload: false,
                },
                pool: self.pool.clone(),
                owner: self.owner.clone(),
                at_invitation: self.at_invitation.clone(),
            }) as Arc<dyn SshSession>)
        })
    }
}
impl SshSession for NoInstallSession {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            if matches!(input, Input::Bytes(_)) {
                let entries: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts h JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.owner_id=? AND h.revoked_at IS NULL AND b.address='user@fixture'")
                    .bind(&self.owner).fetch_one(&self.pool).await.unwrap();
                self.at_invitation.lock().unwrap().push(entries);
            }
            let mut output = self.sniff.run(script, input).await?;
            if output.stdout.ends_with(b"INFRATERNAL_SETUP_CLEAR\n") {
                let keep = output.stdout.len() - b"INFRATERNAL_SETUP_CLEAR\n".len();
                output.stdout.truncate(keep);
                output
                    .stdout
                    .extend_from_slice(b"INFRATERNAL_SETUP_ABSENT\n");
            }
            Ok(output)
        })
    }
}

/// The owner's `code` (#305): the machine is clean (no install at all), and the
/// server still holds the Nov 2 unfinished entry for `kayg@code`, kept across
/// restarts by its never-used first shell. Re-adding proves the absence, drops
/// that entry at once, and leaves exactly one entry for the address: the new one.
#[tokio::test]
async fn re_adding_a_clean_machine_leaves_exactly_one_entry_for_it() {
    let f = fixture(true).await;
    let owner = person(&f).await;
    // As on production: the person is the server's owner (one owner per server).
    sqlx::query("UPDATE users SET owner=0 WHERE owner=1")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let cookie = "C".repeat(43);
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'fixture',unixepoch()+3600,unixepoch(),1)")
        .bind(crate::auth::hash(&cookie)).bind(&owner).execute(&f.pool).await.unwrap();
    let nov2 = row(&f, &owner, "user@fixture", "rootless", 1002, true, false).await;
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) VALUES(?,?,100,100,?)")
        .bind(Uuid::new_v4().as_bytes().as_slice()).bind(&owner).bind(nov2.as_bytes().as_slice())
        .execute(&f.pool).await.unwrap();
    let at_invitation = Arc::new(std::sync::Mutex::new(Vec::new()));
    let fixture_payload = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let runner = Bootstrap::new(
        Arc::new(NoInstall {
            opens: f.opens.clone(),
            pool: f.pool.clone(),
            owner: owner.clone(),
            at_invitation: at_invitation.clone(),
        }),
        f.backend.clone(),
        BinaryPaths {
            x86_64: fixture_payload.clone(),
            aarch64: fixture_payload,
        },
    );
    let batch = runner
        .start_authenticated(
            owner.clone(),
            Secret::new(cookie.as_bytes().to_vec()),
            vec![cleaned().0],
            None,
        )
        .unwrap();
    let event = finished(&batch).await;
    assert!(
        !event
            .failure
            .as_ref()
            .is_some_and(|failure| failure.already_added),
        "{event:?}"
    );
    assert_eq!(
        *at_invitation.lock().unwrap(),
        vec![1],
        "the new invitation must be the address's only entry ({event:?})"
    );
    assert_eq!(state(&f, nov2).await, (true, Some(1), false));
}
