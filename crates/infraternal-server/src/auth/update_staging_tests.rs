//! Proves the auto-update apply and its D295 undo on a real root server (#211 S4).
//!
//! The server under test is the shipping static binary built with the non-default
//! `staging-trust` feature, so it trusts a throwaway signing key and can read its
//! release channel from a loopback bucket (`INFRATERNAL_STAGING_BUILDS_ORIGIN`). It
//! runs as a transient systemd unit started from the boot pointer
//! `updates/current/<image>`, the way S6 will start production. The CA is unlocked
//! once with a real passkey. With `INFRATERNAL_UPDATE_TEST_SESSIONS=1`, live PTY
//! sessions are kept open throughout; since D354 they need the host's system manager,
//! which the unit's private `/run` hides, so isolated hosts run without them. The
//! cases, in order:
//!
//! 1. **Bad release:** the channel offers C, which is set to fail its health check.
//!    C is applied in a quiet window and fails, and the server undoes it warm: A runs
//!    again in the same process, the CA is still unlocked, C is paused and the boot
//!    pointer never moved.
//! 2. **Updates off:** with the release plugin switched off, a newer B is announced.
//!    Several check periods pass and nothing is staged or applied.
//! 3. **Withdrawn:** updates on, B is staged while a browser keeps attaching (so the
//!    quiet window never closes), then the channel withdraws B. B is removed and
//!    never applied.
//! 4. **Good release:** the channel offers B again and the attaching stops. B is applied
//!    warm, passes its health check and becomes the boot pointer.
//!
//! For every switch the test measures how long `/healthz` stopped answering (the
//! handoff downtime), and checks that the same service PID and the unlocked CA
//! survive (and, with sessions, the same shims, which still echo input).
//!
//! Inputs (prepared by the run script, never by this test): signed release folders in
//! `$INFRATERNAL_DEPLOY_TEST_ROOT/releases/<version>/`, and the three versions, in
//! order A B C, in `INFRATERNAL_UPDATE_TEST_VERSIONS`. No signing key is present.
use super::*;
use crate::release_payload::tests::Bucket;
use std::{collections::HashMap, path::Path, sync::Arc};

/// The image name for this machine.
const IMAGE: &str = "infraternal-x86_64-musl";
/// The staging check period and quiet window, in seconds.
const STEP: u64 = 10;

/// Every file of every release folder under `releases`, keyed by bucket path.
fn release_files(releases: &std::path::Path) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    for release in std::fs::read_dir(releases).unwrap() {
        let release = release.unwrap();
        let version = release.file_name().into_string().unwrap();
        for file in std::fs::read_dir(release.path()).unwrap() {
            let file = file.unwrap();
            let name = file.file_name().into_string().unwrap();
            files.insert(
                format!("/releases/{version}/{name}"),
                std::fs::read(file.path()).unwrap(),
            );
        }
    }
    files
}

/// Point the bucket's edge channel at `version`, or at nothing.
fn announce(bucket: &Bucket, version: Option<&str>) {
    let mut files = bucket.files.lock().unwrap();
    match version {
        Some(version) => {
            files.insert(
                "/releases/channels/edge.json".into(),
                format!("{{\"version\":\"{version}\"}}").into_bytes(),
            );
        }
        None => {
            files.remove("/releases/channels/edge.json");
        }
    }
}

/// Switch the release plugin on or off, on the edge channel, through a short-lived
/// connection (the server may have replaced the database file since the last one).
async fn release_setting(database: &std::path::Path, enabled: bool) {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(database),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled,settings) VALUES('server','release',?,'{\"channel\":\"edge\"}') ON CONFLICT(role,plugin) DO UPDATE SET enabled=excluded.enabled, settings=excluded.settings")
        .bind(enabled)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

/// The saved update state of the server under test.
fn update_state(data: &std::path::Path) -> infraternal_plugin_release::update::UpdateState {
    infraternal_plugin_release::update::status(data, "")
}

/// SHA-256 (hex) of the image the service process runs now.
fn running_digest(pid: u32) -> String {
    let file = std::fs::File::open(format!("/proc/{pid}/exe")).unwrap();
    infraternal_plugin_release::apply::digest(&file).unwrap()
}

/// SHA-256 (hex) of `path`.
fn file_digest(path: &std::path::Path) -> String {
    infraternal_plugin_release::apply::digest(&std::fs::File::open(path).unwrap()).unwrap()
}

/// Probes `/healthz` every 5 ms in the background and keeps the longest time without a
/// 200 answer since the last [`Downtime::take`]: the switch downtime as a client sees it.
struct Downtime {
    longest: Arc<std::sync::Mutex<Duration>>,
    task: tokio::task::JoinHandle<()>,
}
impl Downtime {
    /// Start probing `address`.
    fn start(address: SocketAddr) -> Self {
        let longest = Arc::new(std::sync::Mutex::new(Duration::ZERO));
        let shared = Arc::clone(&longest);
        let task = tokio::spawn(async move {
            let mut last_ok = std::time::Instant::now();
            loop {
                let ok = tokio::time::timeout(Duration::from_secs(1), async {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut socket = tokio::net::TcpStream::connect(address).await.ok()?;
                    socket
                        .write_all(
                            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .ok()?;
                    let mut head = [0; 12];
                    socket.read_exact(&mut head).await.ok()?;
                    head.ends_with(b" 200").then_some(())
                })
                .await
                .ok()
                .flatten()
                .is_some();
                let now = std::time::Instant::now();
                if ok {
                    last_ok = now;
                } else {
                    let mut longest = shared.lock().unwrap();
                    *longest = (*longest).max(now - last_ok);
                }
                // sleep: the probe interval sets the downtime resolution (5 ms).
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        Self { longest, task }
    }
    /// The longest outage since the last call, and reset it.
    fn take(&self) -> Duration {
        std::mem::take(&mut *self.longest.lock().unwrap())
    }
}
impl Drop for Downtime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Wait up to `limit` until the saved update state satisfies `done`.
async fn wait_state(
    data: &std::path::Path,
    limit: Duration,
    what: &str,
    done: impl Fn(&infraternal_plugin_release::update::UpdateState) -> bool,
) -> infraternal_plugin_release::update::UpdateState {
    let deadline = std::time::Instant::now() + limit;
    loop {
        let state = update_state(data);
        if done(&state) {
            return state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "update state never reached: {what}; last {state:?}"
        );
        // sleep: the server writes state.json from another process; poll it at 4 Hz.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Wait until the server answers `/healthz` with 200 again. The update state flips as
/// soon as a starting release writes it, which is before its listener is up.
async fn serving(address: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if crate::update_apply::healthz_for_tests(address).await {
                return;
            }
            // sleep: the restarted listener is still coming up; poll it at 20 Hz.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the server answers /healthz again after the switch");
}

/// Whether the CA is unlocked, asked over the owner's HTTP session.
async fn ca_unlocked(address: SocketAddr, session: &str) -> bool {
    post(address, session, "/remote/ca/status", json!({})).await["locked"] == false
}

/// Type one command into the first session of every attached browser and wait for its
/// echo. `sent` counts the input bytes already sent per browser's first session, since
/// an input frame names its offset in the session's input stream.
async fn echo_all(
    attached: &mut [crate::ca_handoff::shipping_tests::Browser],
    sent: &mut HashMap<usize, u64>,
    marker: &str,
) -> usize {
    let mut echoed = 0;
    for (index, browser) in attached.iter_mut().enumerate() {
        // attach_all puts up to 25 sessions on one browser, on streams 1, 3, 5, ...
        let stream = 1;
        let command = format!("printf '%s%s\\n' '{marker}' '-echo'\n");
        let offset = sent.entry(index).or_default();
        wire_send(
            browser,
            stream,
            &infraternal_protocol::Frame::Input {
                in_seq: *offset,
                bytes: command.as_bytes(),
            },
        )
        .await;
        *offset += command.len() as u64;
        let wanted = format!("{marker}-echo");
        let mut seen = Vec::new();
        loop {
            let bytes = wire_read(browser).await;
            let frame = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
            if frame.stream_id == stream
                && let infraternal_protocol::Frame::Output { bytes, .. } = frame.frame
            {
                seen.extend_from_slice(bytes);
                if seen
                    .windows(wanted.len())
                    .any(|part| part == wanted.as_bytes())
                {
                    break;
                }
                assert!(seen.len() < 65536, "no echo of {wanted}");
            }
        }
        echoed += 1;
    }
    echoed
}

/// One attach attempt on a fresh browser connection, the way a reconnecting browser
/// starts: the server counts an attach in progress as activity, so the quiet window
/// stays open (D251), whether or not the session exists.
async fn attach_pulse(address: SocketAddr, session: &str) {
    use infraternal_protocol::{Frame, decode_muxed_frame};
    let mut socket = crate::ca_handoff::shipping_tests::Browser::new(
        crate::ca_handoff::shipping_tests::connect_browser(address, session, ORIGIN).await,
    );
    let hello = wire_read(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&hello).unwrap().frame,
        Frame::Hello { .. }
    ));
    wire_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "update-proof",
        },
    )
    .await;
    let _welcome = wire_read(&mut socket).await;
    wire_send(
        &mut socket,
        1,
        &Frame::AttachTerm {
            session_id: &[0; 16],
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
}

/// The S4 proof; see the module docs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "root staging proof; requires signed staging releases and systemd (#211 S4)"]
async fn auto_update_applies_warm_and_undoes_a_bad_release() {
    std::panic::set_hook(Box::new(|failure| {
        if let Some(location) = failure.location() {
            // A panic payload can contain credentials; report only source location.
            println!(
                "UPDATE failure_file={} failure_line={}",
                location.file(),
                location.line()
            );
        }
    }));
    assert!(nix::unistd::Uid::effective().is_root());
    let root = PathBuf::from(std::env::var_os("INFRATERNAL_DEPLOY_TEST_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    assert!(staging_root_is_allowed(&root));
    let versions = std::env::var("INFRATERNAL_UPDATE_TEST_VERSIONS").unwrap();
    let [old, good, bad]: [&str; 3] = versions
        .split_whitespace()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let releases = root.join("releases");
    let digest = |version: &str| file_digest(&releases.join(version).join(IMAGE));
    let (old_image, good_image, bad_image) = (digest(old), digest(good), digest(bad));
    let bucket = Bucket::new(release_files(&releases));
    announce(&bucket, Some(old));

    let mut f = shipping_auth_fixture().await;
    let data = f.root.join("db");
    let database = data.join("infraternal.sqlite");
    let runtime = root.join("r");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    let profile = f.root.join("profile");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&profile)
        .unwrap();
    std::fs::write(
        profile.join(".zshrc"),
        include_bytes!("../../../infraternal/tests/profile/.zshrc"),
    )
    .unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = reservation.local_addr().unwrap();
    drop(reservation);
    let ca = data.join("remote-ca");
    std::fs::DirBuilder::new().mode(0o700).create(&ca).unwrap();
    private_write(&ca.join("pending"), &[]);
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let bootstrap = crate::ca_bootstrap::BootstrapConfig {
        directory: ca.clone(),
        name: "auth.example.test".into(),
        address: remote,
        deferred: false,
    };
    drop(
        crate::ca_bootstrap::publish_first(&bootstrap, &f.auth.user, 1, &[3; 32], &[7; 32], now)
            .unwrap(),
    );
    // Prod shape after S6: A installed under updates/releases/, started via the pointer.
    let updates = data.join("updates");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(updates.join("releases"))
        .unwrap();
    let installed = updates.join("releases").join(old);
    let copied = Command::new("cp")
        .args(["-a"])
        .arg(releases.join(old))
        .arg(&installed)
        .status()
        .unwrap();
    assert!(copied.success());
    std::fs::set_permissions(
        installed.join(IMAGE),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::os::unix::fs::symlink(Path::new("releases").join(old), updates.join("current")).unwrap();
    // Updates start off; the bad release is announced before they are switched on.
    release_setting(&database, true).await;
    f.auth.auth.pool.close().await;

    let unit_name = format!("infraternal-update-{}", Uuid::new_v4().simple());
    let output = Command::new("systemd-run")
        .args(["--quiet", "--collect", "--unit"])
        .arg(&unit_name)
        .arg("--property=KillMode=control-group")
        .arg("--property=StandardOutput=journal")
        .arg("--property=StandardError=journal")
        .arg(format!("--property=BindPaths={}:/run", runtime.display()))
        .arg(format!("--setenv=ZDOTDIR={}", profile.display()))
        .arg(format!(
            "--setenv=INFRATERNAL_STAGING_BUILDS_ORIGIN={}",
            bucket.origin
        ))
        .arg(format!(
            "--setenv=INFRATERNAL_STAGING_UPDATE_SECONDS={STEP}"
        ))
        .arg(format!(
            "--setenv=INFRATERNAL_STAGING_UNHEALTHY_VERSION={bad}"
        ))
        .arg("--setenv=RUST_LOG=info")
        .arg(updates.join("current").join(IMAGE))
        .args([
            "server",
            "--listen",
            &address.to_string(),
            "--remote-listen",
            &remote.to_string(),
            "--public-origin",
            ORIGIN,
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1",
            "--remote-ca-dir",
        ])
        .arg(&ca)
        .arg("--data")
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "update staging unit failed to start"
    );
    let unit = Unit(unit_name);
    let pid = Command::new("systemctl")
        .args(["show", &unit.0, "--property=MainPID", "--value"])
        .output()
        .unwrap();
    let pid: u32 = std::str::from_utf8(&pid.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(pid, 0);
    println!("UPDATE unit={} pid={pid} port={}", unit.0, address.port());
    tokio::time::timeout(Duration::from_secs(30), async {
        while tokio::net::TcpStream::connect(address).await.is_err() {
            // sleep: waiting for the unit's listener; 10 ms keeps startup timing honest.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the update staging server became ready");
    // One real passkey unlock; every switch after this must keep it (D217).
    let start = post(
        address,
        &f.auth.session,
        "/remote/ca/unlock/start",
        json!({}),
    )
    .await;
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let status = post(
        address,
        &f.auth.session,
        "/remote/ca/unlock/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":vec![7u8;32]}),
    )
    .await;
    assert_eq!(status["locked"], false);
    // Live PTY sessions need the host's system manager since D354, which this unit's
    // private /run hides (sessions then run as their own systemd units, outside it).
    // Hosts that can run them set INFRATERNAL_UPDATE_TEST_SESSIONS=1.
    let with_sessions = std::env::var("INFRATERNAL_UPDATE_TEST_SESSIONS").as_deref() == Ok("1");
    let sessions = if with_sessions {
        terminals(address, &f.auth.session, ORIGIN).await
    } else {
        Vec::new()
    };
    let pids = staging_shim_pids(&unit.0, &sessions);
    let mut sent = HashMap::new();
    assert_eq!(running_digest(pid), old_image);
    println!(
        "UPDATE ready ca_unlocked=true real_pty_sessions={} running={old}",
        sessions.len()
    );
    let downtime = Downtime::start(address);

    // 1. Bad release: C is applied in a quiet window, fails, and is undone warm.
    announce(&bucket, Some(bad));
    let state = wait_state(&data, Duration::from_secs(240), "C undone", |state| {
        state
            .applied
            .as_ref()
            .is_some_and(|applied| applied.version == bad && applied.outcome == "undone")
    })
    .await;
    serving(address).await;
    let gap = downtime.take();
    assert_eq!(state.paused.as_deref(), Some(bad));
    assert_eq!(
        running_digest(pid),
        old_image,
        "A runs again after the undo"
    );
    assert!(
        ca_unlocked(address, &f.auth.session).await,
        "the CA stayed unlocked"
    );
    assert_eq!(staging_shim_pids(&unit.0, &sessions), pids);
    assert_eq!(
        std::fs::read_link(updates.join("current")).unwrap(),
        Path::new("releases").join(old),
        "the boot pointer never moved"
    );
    let mut attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
    let echoed = echo_all(&mut attached, &mut sent, "after-undo").await;
    attached.clear();
    println!(
        "UPDATE case=bad_release outcome=undone reason={:?} paused={bad} same_pid=true ca_unlocked=true shims_unchanged={} echoed_browsers={echoed} max_healthz_gap_ms={:.1} not_running_bad={}",
        state.applied.as_ref().unwrap().reason,
        pids.len(),
        gap.as_secs_f64() * 1000.0,
        running_digest(pid) != bad_image
    );

    // 2. Updates off: B is announced, nothing is staged or applied.
    release_setting(&database, false).await;
    announce(&bucket, Some(good));
    // sleep: three check periods must pass with nothing happening; there is no event.
    tokio::time::sleep(Duration::from_secs(STEP * 4)).await;
    let state = update_state(&data);
    assert_eq!(state.staged, None);
    assert_eq!(running_digest(pid), old_image);
    assert_eq!(state.applied.as_ref().unwrap().version, bad);
    println!(
        "UPDATE case=updates_off staged=None applied_unchanged=true refused={:?}",
        state.refused
    );

    // 3. Withdrawn: staged while someone keeps attaching (the window stays open), then
    // withdrawn by the channel; never applied.
    let attaching = {
        let session = f.auth.session.clone();
        tokio::spawn(async move {
            loop {
                attach_pulse(address, &session).await;
                // sleep: an attach once a second keeps the quiet window open (D251).
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    release_setting(&database, true).await;
    wait_state(&data, Duration::from_secs(120), "B staged", |state| {
        state.staged.as_deref() == Some(good)
    })
    .await;
    announce(&bucket, Some(old));
    let state = wait_state(&data, Duration::from_secs(120), "B withdrawn", |state| {
        state.staged.is_none()
            && state
                .removed
                .as_ref()
                .is_some_and(|removed| removed.version.as_deref() == Some(good))
    })
    .await;
    attaching.abort();
    // sleep: a full quiet window plus a check must pass without an apply.
    tokio::time::sleep(Duration::from_secs(STEP * 3)).await;
    assert_eq!(running_digest(pid), old_image);
    assert_eq!(update_state(&data).applied.unwrap().version, bad);
    println!(
        "UPDATE case=withdrawn removed={:?} applied=false activity_held_the_window=true",
        state.removed.unwrap().reason
    );

    // 4. Good release: B applies warm in the quiet window and becomes the boot pointer.
    downtime.take();
    announce(&bucket, Some(good));
    let state = wait_state(&data, Duration::from_secs(240), "B applied", |state| {
        state
            .applied
            .as_ref()
            .is_some_and(|applied| applied.version == good && applied.outcome == "applied")
    })
    .await;
    serving(address).await;
    let gap = downtime.take();
    assert_eq!(running_digest(pid), good_image, "B runs");
    assert!(
        ca_unlocked(address, &f.auth.session).await,
        "the CA stayed unlocked"
    );
    assert_eq!(staging_shim_pids(&unit.0, &sessions), pids);
    assert_eq!(
        std::fs::read_link(updates.join("current")).unwrap(),
        Path::new("releases").join(good)
    );
    assert!(updates.join("previous").join(IMAGE).exists());
    assert!(!updates.join("pending.json").exists());
    let mut attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
    let echoed = echo_all(&mut attached, &mut sent, "after-update").await;
    attached.clear();
    let main_pid = Command::new("systemctl")
        .args(["show", &unit.0, "--property=MainPID", "--value"])
        .output()
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&main_pid.stdout).unwrap().trim(),
        pid.to_string(),
        "one server process throughout"
    );
    println!(
        "UPDATE case=good_release outcome=applied pointer=releases/{good} same_pid=true ca_unlocked=true shims_unchanged={} echoed_browsers={echoed} max_healthz_gap_ms={:.1} paused={:?}",
        pids.len(),
        gap.as_secs_f64() * 1000.0,
        state.paused
    );
    println!(
        "METRIC name=auto_update_handoff real_pty_sessions={} unlock_ceremonies=1 ca_unlocked=true",
        sessions.len()
    );
    drop(downtime);
    drop(unit);
}
