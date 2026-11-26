//! Many-host fixture, #562: one disposable server and N enrolled infraternal agents on this machine.
//!
//! The server runs inside this test process with the memory-only CA fixture
//! (`ca_memory::MemoryCaSource` unlocked by the test's own `Administrator`),
//! so no passkey, prod, test or QA server is involved. Each agent is a real
//! `infraternal agent join` process with its own data and state directories,
//! enrolled through a real `POST /remote/invitations`.
//!
//! The test enrols the hosts, writes a JSON manifest (address, cookie, root CA,
//! host ids, per-host enrol times, server PID) and then idles until a stop
//! file appears. An external driver, `scripts/measure-many-hosts.py`, opens
//! browser sockets against the manifest and samples the server's `/proc`
//! entries. Keeping the browsers outside this process means the server's CPU
//! and memory are not mixed with the load generator's.
//!
//! Environment: `INFRATERNAL_REMOTE_TEST_BINARY` (the agent binary),
//! `INFRATERNAL_MANY_HOSTS` (N), `INFRATERNAL_MANY_PORT` (default 4702),
//! `INFRATERNAL_MANY_MANIFEST` and `INFRATERNAL_MANY_STOP` (file paths),
//! and `INFRATERNAL_MANY_RUNTIME` (see [`fixture_runtime`]).
//!
//! The server runs on the same kind of tokio runtime the shipped binary
//! builds (`tokio::runtime::Runtime::new()` in `crates/infraternal/src/main.rs`).
//! A plain `#[tokio::test]` would put it on a current-thread runtime instead,
//! and then every host link, quinn driver and socket shares the test thread:
//! J1220's profile read that thread (`runtime::remote`, the test path cut to
//! 15 bytes) as the server being single-threaded (#562, J1246).

use super::*;

/// Read a required environment variable as a path.
fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
}

/// Build the runtime the fixture's server runs on.
///
/// By default this is the runtime the shipped server uses: tokio's
/// multi-thread runtime with one worker per CPU this process may run on, built
/// by the same `Runtime::new()` call as `main.rs`. `INFRATERNAL_MANY_RUNTIME=current`
/// selects a current-thread runtime, the shape of a plain `#[tokio::test]`,
/// so earlier many-host numbers (J1220) can be reproduced side by side.
fn fixture_runtime() -> tokio::runtime::Runtime {
    match std::env::var("INFRATERNAL_MANY_RUNTIME").as_deref() {
        Ok("current") => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        Ok("production") | Err(_) => tokio::runtime::Runtime::new().unwrap(),
        Ok(other) => panic!("INFRATERNAL_MANY_RUNTIME must be production or current, not {other}"),
    }
}

/// Start N agents against one disposable server and hold them until the stop file appears.
#[test]
#[ignore = "fixture for scripts/measure-many-hosts.py; needs INFRATERNAL_REMOTE_TEST_BINARY and INFRATERNAL_MANY_*"]
fn many_host_server_fixture() {
    fixture_runtime().block_on(run_many_host_fixture());
}

/// The fixture itself: enrol the hosts, publish the manifest, idle until told to stop.
async fn run_many_host_fixture() {
    let binary = env_path("INFRATERNAL_REMOTE_TEST_BINARY");
    let manifest = env_path("INFRATERNAL_MANY_MANIFEST");
    let stop = env_path("INFRATERNAL_MANY_STOP");
    let hosts: usize = std::env::var("INFRATERNAL_MANY_HOSTS")
        .expect("INFRATERNAL_MANY_HOSTS is required")
        .parse()
        .unwrap();
    let port: u16 = std::env::var("INFRATERNAL_MANY_PORT")
        .ok()
        .map_or(4702, |value| value.parse().unwrap());
    assert!(binary.is_file());

    // The server's data lives in the first host's directory; every host gets
    // its own `data` and `s` (state) directory, as separate machines would.
    let directories: Vec<Directory> = (0..hosts.max(1)).map(|_| Directory::new()).collect();
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut fixture = fixture_at(&directories[0], address, "127.0.0.1:0".parse().unwrap()).await;

    // The terminal path resolves the account UUID and preferred OS user, so
    // the owner is shaped like a real passkey user (as the two-process proof).
    let owner = uuid::Uuid::new_v4().to_string();
    let account = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap()
        .name;
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused',?,'Owner')")
        .bind(&owner)
        .bind(&account)
        .execute(&fixture.pool)
        .await
        .unwrap();
    // This fixture inserts its owner directly instead of going through signup,
    // so seed only the account it will open under D235's explicit login policy.
    sqlx::query("INSERT INTO login_rules(subject,account_kind,account,host_id,created_at) VALUES (?,'named',?,NULL,unixepoch())")
        .bind(&owner)
        .bind(&account)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET user_id=? WHERE token_hash=?")
        .bind(owner)
        .bind(crate::auth::hash(&fixture.cookie))
        .execute(&fixture.pool)
        .await
        .unwrap();

    let origin = format!("https://localhost:{port}");
    let started = Instant::now();
    let mut children = Vec::new();
    let mut records = Vec::new();
    // Enrol hosts one after another: each join is a real invitation plus a
    // real agent process. Enrolment time is spawn until the agent publishes
    // its identity, which is its last step before it dials the server.
    for (index, directory) in directories.iter().take(hosts).enumerate() {
        let host = uuid::Uuid::new_v4();
        let marker = directory.0.join(".bootstrap-owner");
        std::fs::write(&marker, format!("{}\n", host.simple())).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        let data = directory.0.join("data");
        let digest = prepare_pending_join_key(&data);
        // The invitation helper asserts a 200. Under load a few attempts get 503
        // (SQLite write-lock refusal in the issue transaction, J1220); run each attempt
        // in its own task so a refusal is counted and retried instead of ending the run.
        let mut retries = 0u32;
        let invitation = loop {
            let (address, root, origin, cookie) = (
                fixture.address,
                fixture.root.clone(),
                origin.clone(),
                fixture.cookie.clone(),
            );
            let attempt = tokio::spawn(async move {
                invitation(address, &root, &origin, &cookie, host, digest).await
            })
            .await;
            if let Ok(bytes) = attempt {
                break bytes;
            }
            retries += 1;
            assert!(retries < 500, "host {index}: invitation kept failing");
            // sleep: a short back-off before asking again; the refusal clears once the other writer commits.
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let spawned = Instant::now();
        let mut child = cli(&binary, directory, true, &origin);
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(&invitation)
            .unwrap();
        let identity = data.join("identity.json");
        while !identity.is_file() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "host {index} exited before enrolling"
            );
            assert!(
                spawned.elapsed() < Duration::from_secs(60),
                "host {index} enrol timeout"
            );
            // sleep: poll for the agent's identity file; it has no event the fixture can wait on.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        records.push(serde_json::json!({
            "host_id": host,
            "pid": child.0.id(),
            "enrol_ms": spawned.elapsed().as_secs_f64() * 1000.0,
            "invitation_retries": retries,
            "state": directory.0.join("s"),
        }));
        children.push(child);
    }

    let root_pem = String::from_utf8(fixture.root.to_pem().unwrap()).unwrap();
    let body = serde_json::json!({
        "port": port,
        "origin": origin,
        "cookie": fixture.cookie,
        "root_pem": root_pem,
        "server_pid": std::process::id(),
        "enrol_total_ms": started.elapsed().as_secs_f64() * 1000.0,
        "hosts": records,
    });
    // Write then rename so a polling driver never reads a half-written file.
    let partial = manifest.with_extension("partial");
    std::fs::write(&partial, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    std::fs::rename(&partial, &manifest).unwrap();

    while !stop.exists() {
        // sleep: poll for the driver's stop file; the driver is another process.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(children);
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    fixture.listeners.take();
    fixture.pool.close().await;
    // Directory::drop retires every host's shims through the authenticated cleanup.
    drop(directories);
}
