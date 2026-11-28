//! Proves S6 on a real root server: an operator-installed server moves onto the boot pointer, and cold starts follow updates (#211 S6).
//!
//! This ignored test runs inside the throwaway NixOS microVM of `scripts/update-proof-vm`
//! (inputs built with `PROOF=adopt`), never on a shared host. It starts the server the way
//! production ran before S6, then walks the whole move:
//!
//! 1. **The production shape.** The `opt` build is copied to the fixed path
//!    `/opt/infraternal/<version>/infraternal` with its own `web/` beside it, and an
//!    operator-written unit `infraternal-server.service` (in `/run/systemd/system`, the
//!    VM's writable unit folder) starts that path with `--web-root` and the other
//!    production flags. The CA is unlocked with a real passkey ceremony and real PTY
//!    sessions are open.
//! 2. **`adopt`.** Root runs `infraternal server update adopt <release> --dry-run` (it
//!    must change nothing), then for real, with the `adopted` release's own binary. The
//!    move must be warm (same PID, CA unlocked, shims kept, the sessions still echo), the
//!    unit must start `<data>/updates/current/infraternal` without
//!    `--web-root` and keep every other line, a backup of the old unit must exist, and
//!    the server must serve the `adopted` release's own web build. A second run changes
//!    nothing.
//! 3. **`update apply`.** Root stages and applies the `newer` release with
//!    `infraternal server update check|apply`: warm, the boot pointer moves to it, and the
//!    page is now the `newer` web build. `previous/web/` keeps the `adopted` one.
//!    A fresh local PTY runs a command and exits while the server still runs from its memfd (#613).
//! 4. **Cold start.** `systemctl restart`: a new PID runs the `newer` image through the
//!    boot pointer (argv\[0\] is the pointer path) and serves the `newer` web build; one
//!    passkey unlock brings the CA back (D168).
//! 5. **Cold start after an undone update.** The `faulty` release fails its health check
//!    (`INFRATERNAL_STAGING_FAULTS`) and is undone warm; the pointer stays on `newer`; a
//!    cold restart then starts `newer` again with its web build.
//!
//! Every step prints one `UPDATE case=… ` line; the VM script collects them.
use super::*;

/// The operator's unit, as production names it.
const SERVER_UNIT: &str = "infraternal-server.service";
/// Where the VM keeps writable system units (its `/etc/systemd/system` is read-only).
const UNIT_FOLDER: &str = "/run/systemd/system";
/// The fixed install folder the operator used before S6.
const OPT: &str = "/opt/infraternal";
/// This proof's HTTP listener.
const ADOPT_LISTEN: &str = "127.0.0.1:4821";
/// This proof's remote (infraternal agent) listener.
const ADOPT_REMOTE: &str = "127.0.0.1:4822";
/// This proof's loopback release bucket.
const ADOPT_BUCKET: &str = "127.0.0.1:4823";

/// The four builds of this proof, oldest first, from `INFRATERNAL_UPDATE_TEST_VERSIONS`.
struct Builds {
    /// Runs from the fixed `/opt` path at the start, like production before S6.
    opt: String,
    /// The signed release `adopt` moves the server onto.
    adopted: String,
    /// A newer release that `server update apply` switches to.
    newer: String,
    /// Fails its health check, so its update is undone.
    faulty: String,
}
impl Builds {
    /// Read the builds from the environment.
    fn from_environment() -> Self {
        let versions = std::env::var("INFRATERNAL_UPDATE_TEST_VERSIONS").unwrap();
        let [opt, adopted, newer, faulty]: [String; 4] = versions
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self {
            opt,
            adopted,
            newer,
            faulty,
        }
    }
}

/// The main PID of `unit` now (0 while it is not running).
fn unit_pid(unit: &str) -> u32 {
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=MainPID", "--value"])
        .output()
        .unwrap();
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// argv\[0\] of process `pid`.
fn argv0(pid: u32) -> PathBuf {
    let line = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    PathBuf::from(
        String::from_utf8_lossy(line.split(|byte| *byte == 0).next().unwrap()).into_owned(),
    )
}

/// The body of `GET /` (the web app's page) as the browser would load it first.
async fn page(address: SocketAddr) -> String {
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method("GET")
        .uri("/")
        .header(header::HOST, "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    task.abort();
    assert_eq!(status, StatusCode::OK, "GET / answered");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The web marker each build's page carries (`scripts/update-proof-vm/build-inputs`).
fn marker(build: &str) -> String {
    format!("proof-web {build}")
}

/// Wait until the server listens on `address` again.
async fn listening(address: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while tokio::net::TcpStream::connect(address).await.is_err() {
            // sleep: waiting for the unit's listener; 10 ms keeps startup timing honest.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server listens");
}

/// The one `ExecStart=` value of the unit file.
fn exec_start(unit: &Path) -> String {
    std::fs::read_to_string(unit)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .unwrap()
        .to_owned()
}

/// `systemctl <arguments>`, which must succeed.
fn systemctl(arguments: &[&str]) {
    let status = Command::new("systemctl").args(arguments).status().unwrap();
    assert!(status.success(), "systemctl {arguments:?}");
}

/// The S6 proof; see the module docs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "root staging proof; runs inside scripts/update-proof-vm with PROOF=adopt (#211 S6)"]
async fn boot_pointer_adoption() {
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
    let builds = Builds::from_environment();
    let releases = root.join("releases");
    let bucket = Bucket::at(ADOPT_BUCKET.parse().unwrap(), release_files(&releases));

    // The server's data, CA and profile, as the S4 proof sets them up.
    let mut f = shipping_auth_fixture().await;
    let data = f.root.join("db");
    let database = data.join("infraternal.sqlite");
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
    let address: SocketAddr = ADOPT_LISTEN.parse().unwrap();
    let remote: SocketAddr = ADOPT_REMOTE.parse().unwrap();
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
    release_setting(&database, true).await;
    f.auth.auth.pool.close().await;

    // 1. The production shape before S6: a fixed /opt path, its web folder beside it, and an
    //    operator-written unit.
    let opt = Path::new(OPT).join(&builds.opt);
    std::fs::create_dir_all(opt.join("web")).unwrap();
    std::fs::copy(
        releases.join(&builds.opt).join(IMAGE),
        opt.join("infraternal"),
    )
    .unwrap();
    std::fs::set_permissions(
        opt.join("infraternal"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(
        opt.join("web/index.html"),
        format!("<!doctype html><title>{}</title>", marker("opt")),
    )
    .unwrap();
    let unit = Path::new(UNIT_FOLDER).join(SERVER_UNIT);
    let operator_exec = format!(
        "{} server --listen {address} --data {} --public-origin {ORIGIN} --web-root {} --remote-listen {remote} --remote-ca-dir {} --behind-proxy --trusted-proxy 127.0.0.1",
        opt.join("infraternal").display(),
        data.display(),
        opt.join("web").display(),
        ca.display(),
    );
    let operator_unit = format!(
        "[Unit]\nDescription=infraternal server (operator unit, S6 proof)\nAfter=network.target\n\n[Service]\nEnvironment=ZDOTDIR={}\nEnvironment=INFRATERNAL_STAGING_BUILDS_ORIGIN=http://{ADOPT_BUCKET}\nEnvironment=INFRATERNAL_STAGING_FAULTS={}=unhealthy\nEnvironment=RUST_LOG=info\nExecStart={operator_exec}\nRestart=always\nRestartSec=1s\nLimitMEMLOCK=infinity\n\n[Install]\nWantedBy=multi-user.target\n",
        profile.display(),
        builds.faulty,
    );
    std::fs::write(&unit, &operator_unit).unwrap();
    systemctl(&["daemon-reload"]);
    systemctl(&["start", SERVER_UNIT]);
    listening(address).await;
    let pid = unit_pid(SERVER_UNIT);
    assert_ne!(pid, 0);
    let mut unlocks = 1;
    unlock(address, &f.auth.session, &mut f.auth.software).await;
    let session = f.auth.session.clone();
    let sessions = tokio::time::timeout(
        Duration::from_secs(300),
        terminals(address, &session, ORIGIN),
    )
    .await
    .expect("the sessions opened within 5 minutes");
    let shims = shim_pids(&sessions);
    let digest = |build: &str| file_digest(&releases.join(build).join(IMAGE));
    assert_eq!(running_digest(pid), digest(&builds.opt));
    assert!(page(address).await.contains(&marker("opt")));
    println!(
        "UPDATE case=opt_start unit={SERVER_UNIT} pid={pid} exec={} ca_unlocked=true real_pty_sessions={} web=opt",
        opt.join("infraternal").display(),
        sessions.len()
    );
    let echo = |label: &'static str| {
        let sessions = sessions.clone();
        let session = session.clone();
        async move {
            let mut attached = attach_all(address, &session, &sessions, ORIGIN).await;
            let mut sent = HashMap::new();
            tokio::time::timeout(
                Duration::from_secs(120),
                echo_all(&mut attached, &mut sent, label),
            )
            .await
            .unwrap_or_else(|_| panic!("no echo within 2 minutes ({label})"))
        }
    };

    // 2. adopt: the dry run changes nothing, the real run moves warm.
    let cli = PathBuf::from("/tmp/j1131-infraternal");
    std::fs::copy(releases.join(&builds.adopted).join(IMAGE), &cli).unwrap();
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
    let release = releases.join(&builds.adopted).display().to_string();
    let data_text = data.display().to_string();
    let adopt = [
        "server",
        "update",
        "adopt",
        release.as_str(),
        "--data",
        data_text.as_str(),
    ];
    let mut dry = adopt.to_vec();
    dry.push("--dry-run");
    let (code, planned) = run_cli(&cli, &dry, false);
    assert_eq!(code, 0, "dry run: {planned}");
    assert_eq!(planned["data"]["adopt"]["changed"], false);
    assert_eq!(
        std::fs::read_to_string(&unit).unwrap(),
        operator_unit,
        "the dry run wrote nothing"
    );
    assert!(
        !data.join("updates/current").exists(),
        "the dry run installed nothing"
    );
    let pointer = data.join("updates/current").join(IMAGE);
    let expected_exec = planned["data"]["adopt"]["plan"]["exec_start_after"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        expected_exec.starts_with(&format!("\"{}\"", pointer.display())),
        "{expected_exec}"
    );
    assert!(!expected_exec.contains("--web-root"), "{expected_exec}");
    let downtime = Downtime::start(address);
    let started = std::time::Instant::now();
    let (code, adopted) = run_cli(&cli, &adopt, false);
    let adopt_seconds = started.elapsed().as_secs_f64();
    assert_eq!(code, 0, "adopt: {adopted}");
    assert_eq!(adopted["data"]["adopt"]["warm"], true, "{adopted}");
    serving(address).await;
    let adopt_gap = downtime.take_ms();
    assert_eq!(unit_pid(SERVER_UNIT), pid, "one server process throughout");
    assert_eq!(
        running_digest(pid),
        digest(&builds.adopted),
        "the adopted release runs"
    );
    assert!(
        ca_unlocked(address, &session).await,
        "the CA stayed unlocked"
    );
    assert_eq!(shim_pids(&sessions), shims, "the sessions were kept");
    let echoed = echo("after-adopt").await;
    assert_eq!(exec_start(&unit), expected_exec);
    let changed: Vec<_> = operator_unit
        .lines()
        .zip(std::fs::read_to_string(&unit).unwrap().lines())
        .filter(|(old, new)| old != new)
        .map(|(old, _)| old.to_owned())
        .collect();
    assert_eq!(
        changed,
        [format!("ExecStart={operator_exec}")],
        "only ExecStart changed"
    );
    let backup = PathBuf::from(adopted["data"]["adopt"]["plan"]["backup"].as_str().unwrap());
    assert_eq!(
        std::fs::read_to_string(&backup).unwrap(),
        operator_unit,
        "the old unit is backed up"
    );
    assert_eq!(
        std::fs::read_link(data.join("updates/current")).unwrap(),
        Path::new("releases").join(&builds.adopted)
    );
    let web = page(address).await;
    assert!(
        web.contains(&marker(&builds.adopted)),
        "the release serves its own web build: {web}"
    );
    println!(
        "UPDATE case=adopt bucket=warm same_pid=true ca_unlocked=true unlocks=0 shims_unchanged={} echoed_browsers={echoed} exec={expected_exec} backup={} web=adopted cli_seconds={adopt_seconds:.1} max_healthz_gap_ms={adopt_gap:.1}",
        shims.len(),
        backup.display()
    );
    let (code, again) = run_cli(&cli, &adopt, false);
    assert_eq!(code, 0, "adopt again: {again}");
    assert_eq!(again["data"]["adopt"]["changed"], false, "{again}");
    assert_eq!(exec_start(&unit), expected_exec);
    println!("UPDATE case=adopt_again changed=false");

    // Keep the quiet window closed, so nothing applies by itself while root drives updates.
    let attaching = {
        let session = session.clone();
        tokio::spawn(async move {
            loop {
                let _ = tokio::time::timeout(
                    Duration::from_secs(20),
                    tokio::spawn({
                        let session = session.clone();
                        async move { attach_pulse(address, &session).await }
                    }),
                )
                .await;
                // sleep: an attach once a second keeps the quiet window open (D251).
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    let update =
        |command: &'static str| ["server", "update", command, "--data", data_text.as_str()];

    // 3. update apply to the newer release, warm.
    announce(&bucket, Some(&builds.newer));
    let (code, checked) = run_cli(&cli, &update("check"), false);
    assert_eq!(code, 0, "check: {checked}");
    let (code, applied) = run_cli(&cli, &update("apply"), false);
    assert_eq!(code, 0, "apply: {applied}");
    serving(address).await;
    let apply_gap = downtime.take_ms();
    assert_eq!(unit_pid(SERVER_UNIT), pid, "one server process throughout");
    assert!(
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .unwrap()
            .starts_with("/memfd:infraternal-replacement (deleted)"),
        "the server execs from the warm replacement memfd"
    );
    assert_eq!(
        running_digest(pid),
        digest(&builds.newer),
        "the newer release runs"
    );
    assert!(
        ca_unlocked(address, &session).await,
        "the CA stayed unlocked"
    );
    assert_eq!(
        std::fs::read_link(data.join("updates/current")).unwrap(),
        Path::new("releases").join(&builds.newer)
    );
    assert!(
        page(address).await.contains(&marker(&builds.newer)),
        "the newer web build is served"
    );
    let kept = std::fs::read_to_string(data.join("updates/previous/web/index.html")).unwrap();
    assert!(
        kept.contains(&marker(&builds.adopted)),
        "previous/ keeps its web build"
    );
    let started = std::time::Instant::now();
    let shell_ms = tokio::time::timeout(Duration::from_secs(30), async {
        let fresh =
            crate::ca_handoff::shipping_tests::open_terminals(address, &session, ORIGIN, 1).await;
        let mut browsers = attach_all(address, &session, &fresh, ORIGIN).await;
        let mut sent = HashMap::new();
        assert_eq!(
            echo_all(&mut browsers, &mut sent, "fresh-after-apply").await,
            1
        );
        let shell_ms = started.elapsed().as_secs_f64() * 1000.0;
        wire_send(
            &mut browsers[0],
            1,
            &infraternal_protocol::Frame::Input {
                in_seq: sent[&0],
                bytes: b"exit 0\n",
            },
        )
        .await;
        let session_id = Uuid::from_bytes(fresh[0]);
        // The shell can exit while the shim still retains its output for replay.
        loop {
            let wire = wire_read(&mut browsers[0]).await;
            let message = infraternal_protocol::decode_muxed_frame(&wire).unwrap();
            if message.stream_id == 1
                && let infraternal_protocol::Frame::Event { event_json, .. } = message.frame
            {
                let event: Value = serde_json::from_slice(event_json).unwrap();
                if event["type"] == "terminal.exited" {
                    assert_eq!(event["session_id"], session_id.to_string());
                    assert_eq!(event["status"], 0);
                    break;
                }
            }
        }
        shell_ms
    })
    .await
    .expect("a new local shell starts and exits after warm apply");
    println!(
        "UPDATE case=apply bucket=warm same_pid=true ca_unlocked=true pointer=releases/{} web=newer previous_web=adopted fresh_shell_echoed=true fresh_shell_exited=true fresh_shell_ms={shell_ms:.1} max_healthz_gap_ms={apply_gap:.1}",
        builds.newer
    );

    // 4. A cold start follows the update through the boot pointer.
    systemctl(&["restart", SERVER_UNIT]);
    listening(address).await;
    let cold = unit_pid(SERVER_UNIT);
    assert_ne!(cold, pid, "a cold start is a new process");
    assert_eq!(argv0(cold), pointer, "the unit starts the boot pointer");
    assert_eq!(
        running_digest(cold),
        digest(&builds.newer),
        "the cold start runs the update"
    );
    assert!(
        page(address).await.contains(&marker(&builds.newer)),
        "and serves its web build"
    );
    assert!(
        !ca_unlocked(address, &session).await,
        "a cold start locks the CA (D168)"
    );
    unlock(address, &session, &mut f.auth.software).await;
    unlocks += 1;
    println!(
        "UPDATE case=cold_after_apply bucket=cold pid={cold} argv0={} running={} web=newer unlocks={unlocks}",
        pointer.display(),
        builds.newer
    );

    // 5. An undone update leaves the pointer alone, so a cold start starts the previous one.
    announce(&bucket, Some(&builds.faulty));
    let (code, checked) = run_cli(&cli, &update("check"), false);
    assert_eq!(code, 0, "check: {checked}");
    let (code, undone) = run_cli(&cli, &update("apply"), false);
    assert_eq!(code, 1, "the faulty update is undone: {undone}");
    serving(address).await;
    assert_eq!(unit_pid(SERVER_UNIT), cold, "the undo was warm");
    assert_eq!(running_digest(cold), digest(&builds.newer));
    assert_eq!(
        update_state(&data).paused.as_deref(),
        Some(builds.faulty.as_str())
    );
    assert_eq!(
        std::fs::read_link(data.join("updates/current")).unwrap(),
        Path::new("releases").join(&builds.newer),
        "the pointer never moved"
    );
    assert!(page(address).await.contains(&marker(&builds.newer)));
    attaching.abort();
    systemctl(&["restart", SERVER_UNIT]);
    listening(address).await;
    let after_undo = unit_pid(SERVER_UNIT);
    assert_ne!(after_undo, cold);
    assert_eq!(argv0(after_undo), pointer);
    assert_eq!(
        running_digest(after_undo),
        digest(&builds.newer),
        "the previous release starts"
    );
    assert!(
        page(address).await.contains(&marker(&builds.newer)),
        "with its web build"
    );
    println!(
        "UPDATE case=cold_after_undo bucket=cold pid={after_undo} running={} paused={} web=newer",
        builds.newer, builds.faulty
    );
    drop(downtime);

    // Leave the VM as found: the unit, the /opt build and the CLI copy go.
    let _ = Command::new("systemctl")
        .args(["stop", SERVER_UNIT])
        .status();
    let _ = std::fs::remove_file(&unit);
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = std::fs::remove_dir_all(&opt);
    let _ = std::fs::remove_file(&cli);
    println!("UPDATE case=done unlocks={unlocks}");
}
