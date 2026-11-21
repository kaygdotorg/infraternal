//! Proves the auto-update apply and every D295 undo path on a real root server (#211 S4).
//!
//! These two ignored tests run inside the throwaway NixOS microVM that
//! `scripts/update-proof-vm` builds and boots, never on a shared host. The VM is the
//! idle root machine the proof needs: nothing else uses its `/run`, so the server
//! reaches the system manager and opens real PTY sessions (D354), and it can be
//! killed and hard-rebooted at will.
//!
//! The server under test is the shipping static binary built with the non-default
//! `staging-trust` feature, so it trusts a throwaway signing key, reads its release
//! channel from a loopback bucket (`INFRATERNAL_STAGING_BUILDS_ORIGIN`) and gives named
//! releases one fault each (`INFRATERNAL_STAGING_FAULTS`). It runs as the VM's
//! persistent `infraternal-proof.service`, which starts the boot pointer
//! `updates/current/<image>` the way S6 will start production, and restarts it if it
//! dies. The CA is unlocked with a real passkey ceremony.
//!
//! **Phase 1, [`auto_update_failure_matrix`]:** with live PTY sessions open, the channel
//! offers one faulty release after another. Each must be undone and paused, with the
//! boot pointer unchanged:
//!
//! | release | fault | expected bucket |
//! |---|---|---|
//! | unhealthy | the health check fails | warm: same PID, CA unlocked, shims kept |
//! | timeout | the health check never passes (the real 2 minutes) | warm |
//! | migration | startup fails like a broken migration | warm |
//! | exec | the exec of the new image is refused | warm (late-exec recovery) |
//! | kill | SIGKILL of the new release during its trial | cold: one passkey unlock |
//!
//! Then: updates off (nothing staged), and a staged release the channel withdraws
//! while a browser keeps attaching (never applied). Last, the channel offers the
//! `reboot` release; once it is on trial, the test saves what phase 2 needs and
//! returns, and the VM's runner hard-resets the VM (`sysrq b`, no clean shutdown).
//!
//! **Phase 2, [`auto_update_after_reboot`]:** the VM booted and the unit started the
//! boot pointer, the previous release, cold. It must have undone the `reboot`
//! release, so one passkey unlock brings the CA back. Then the good release applies
//! warm with live sessions, passes its trial and becomes the boot pointer.
//!
//! **No data loss.** Before every switch the test writes a marker into the database
//! (`server_settings.api_key_lifetime_days`). After every undo the marker must read
//! back, which proves the D295 copy is complete. During the `timeout` trial the test
//! also writes a different value into the new release's database, which must be gone
//! after the undo: the copy really replaced the database (D295 accepts losing the
//! trial's writes).
//!
//! Every case prints one `UPDATE case=… bucket=warm|cold …` line with the `/healthz`
//! outage the switch caused; the VM script collects them into the S4 matrix.
//!
//! Inputs (prepared by the VM script, never by this test): signed release folders in
//! `$INFRATERNAL_DEPLOY_TEST_ROOT/releases/<version>/`, and eight versions, oldest
//! first, in `INFRATERNAL_UPDATE_TEST_VERSIONS`: the running release, then the
//! `unhealthy`, `timeout`, `migration`, `exec`, `kill` and `reboot` releases, then the
//! good release. No signing key is present.
use super::*;
use crate::release_payload::tests::Bucket;
use std::{collections::HashMap, path::Path, sync::Arc};

/// The image name for this machine.
const IMAGE: &str = "infraternal-x86_64-musl";
/// The staging check period and quiet window, in seconds.
const STEP: u64 = 10;
/// The VM's server unit (defined by `scripts/update-proof-vm/vm.nix`).
const UNIT: &str = "infraternal-proof.service";
/// The unit's environment file; the unit starts only once it exists.
const ENVIRONMENT: &str = "/var/lib/infraternal-proof.env";
/// The unit starts `<POINTER>/current/<IMAGE>`; this symlink names the proof's
/// `updates/` folder.
const POINTER: &str = "/var/lib/infraternal-proof";
/// The server's HTTP listener, fixed so it is the same after the reboot.
const LISTEN: &str = "127.0.0.1:4811";
/// The server's remote (infraternal agent) listener.
const REMOTE: &str = "127.0.0.1:4812";
/// The loopback release bucket, fixed so the server finds it again after the reboot.
const BUCKET: &str = "127.0.0.1:4813";
/// What phase 1 leaves for phase 2, inside the test root.
const CARRY: &str = "carry.json";

/// The eight releases of the proof, from `INFRATERNAL_UPDATE_TEST_VERSIONS`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Versions {
    /// The release that runs first and must come back after every undo.
    old: String,
    /// Fails its health check.
    unhealthy: String,
    /// Never passes its health check, so the trial limit ends it.
    timeout: String,
    /// Fails at startup like a broken database migration.
    migration: String,
    /// Its exec is refused.
    exec: String,
    /// Killed during its trial.
    kill: String,
    /// On trial when the VM is hard-reset.
    reboot: String,
    /// The good release, applied last.
    good: String,
}
impl Versions {
    /// Read the versions from the environment.
    fn from_environment() -> Self {
        let versions = std::env::var("INFRATERNAL_UPDATE_TEST_VERSIONS").unwrap();
        let [old, unhealthy, timeout, migration, exec, kill, reboot, good]: [String; 8] = versions
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self {
            old,
            unhealthy,
            timeout,
            migration,
            exec,
            kill,
            reboot,
            good,
        }
    }
    /// The `INFRATERNAL_STAGING_FAULTS` value: the kill and reboot releases never pass
    /// their health check, so they stay on trial until the test stops them.
    fn faults(&self) -> String {
        format!(
            "{}=unhealthy {}=timeout {}=migration {}=exec {}=timeout {}=timeout",
            self.unhealthy, self.timeout, self.migration, self.exec, self.kill, self.reboot
        )
    }
}

/// What phase 1 saves for phase 2: the owner's session, the software passkey and
/// where everything is. All of it is throwaway VM state.
#[derive(serde::Serialize, serde::Deserialize)]
struct Carry {
    /// The fixture root (data folder, CA folder, profile).
    root: PathBuf,
    /// The owner's session cookie value.
    session: String,
    /// The software passkey's P-256 key as PKCS#8 PEM.
    key: String,
    /// The passkey's credential id (base64).
    id: String,
    /// The passkey's PRF secret (base64).
    prf: String,
    /// The passkey's signature counter.
    counter: u32,
    /// The proof's releases.
    versions: Versions,
    /// The kernel boot id before the reset, to prove the VM really rebooted.
    boot_id: String,
    /// The database marker written before the `reboot` switch.
    marker: i64,
    /// How many passkey unlocks phase 1 needed.
    unlocks: u32,
}

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

/// Run `statement` (with one integer bound, if given) on the server's database through
/// a short-lived connection: the server may have replaced the file since the last one.
async fn database_write(database: &Path, statement: &'static str, value: Option<i64>) {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(database),
    )
    .await
    .unwrap();
    let mut query = sqlx::query(statement);
    if let Some(value) = value {
        query = query.bind(value);
    }
    query.execute(&pool).await.unwrap();
    pool.close().await;
}

/// Switch the release plugin on or off, on the edge channel.
async fn release_setting(database: &Path, enabled: bool) {
    database_write(
        database,
        "INSERT INTO plugin_settings(role,plugin,enabled,settings) VALUES('server','release',?,'{\"channel\":\"edge\"}') ON CONFLICT(role,plugin) DO UPDATE SET enabled=excluded.enabled, settings=excluded.settings",
        Some(i64::from(enabled)),
    )
    .await;
}

/// Write the no-data-loss marker (an ordinary server setting, 1..=365).
async fn write_marker(database: &Path, marker: i64) {
    database_write(
        database,
        "UPDATE server_settings SET api_key_lifetime_days=? WHERE id=1",
        Some(marker),
    )
    .await;
}

/// Read the no-data-loss marker back.
async fn read_marker(database: &Path) -> i64 {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(database)
            .read_only(true),
    )
    .await
    .unwrap();
    let (marker,): (i64,) =
        sqlx::query_as("SELECT api_key_lifetime_days FROM server_settings WHERE id=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    marker
}

/// The saved update state of the server under test.
fn update_state(data: &std::path::Path) -> infraternal_plugin_release::update::UpdateState {
    infraternal_plugin_release::update::status(data, "")
}

/// The phase of the switch in flight (`switching`, `trial`, `rollback`), if any.
fn pending_phase(data: &Path) -> Option<String> {
    let text = std::fs::read(
        data.join("updates")
            .join(infraternal_plugin_release::apply::PENDING),
    )
    .ok()?;
    let marker: Value = serde_json::from_slice(&text).ok()?;
    marker["phase"].as_str().map(str::to_owned)
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

/// The unit's main PID now (0 while it is not running).
fn main_pid() -> u32 {
    let output = Command::new("systemctl")
        .args(["show", UNIT, "--property=MainPID", "--value"])
        .output()
        .unwrap();
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// The kernel's id for this boot.
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned()
}

/// The shim PID of each of `sessions`, found anywhere on the machine: since D354 a
/// root server starts each session in its own `infraternal-session-<id>` scope unit,
/// outside the server's cgroup. `None` for a session whose shim is gone; more than one
/// shim for a session fails the proof.
fn session_shims(sessions: &[[u8; 16]]) -> Vec<Option<i32>> {
    let wanted: Vec<String> = sessions
        .iter()
        .map(|id| Uuid::from_bytes(*id).simple().to_string())
        .collect();
    let mut found: Vec<Option<i32>> = vec![None; sessions.len()];
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(line) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<_> = line.split(|byte| *byte == 0).collect();
        if !args.iter().any(|arg| *arg == b"__shim") {
            continue;
        }
        let Some(session) = args
            .windows(2)
            .find(|pair| pair[0] == b"--session")
            .map(|pair| pair[1])
        else {
            continue;
        };
        if let Some(index) = wanted.iter().position(|id| id.as_bytes() == session) {
            assert!(found[index].is_none(), "one shim per session");
            found[index] = Some(pid);
        }
    }
    found
}

/// The shim PID of every one of `sessions`; each must be alive.
fn shim_pids(sessions: &[[u8; 16]]) -> Vec<i32> {
    session_shims(sessions)
        .into_iter()
        .map(|pid| pid.expect("every session still has its shim"))
        .collect()
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
    /// The longest outage since the last call, in milliseconds, and reset it.
    fn take_ms(&self) -> f64 {
        std::mem::take(&mut *self.longest.lock().unwrap()).as_secs_f64() * 1000.0
    }
}
impl Drop for Downtime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Wait up to `limit` until `done` holds, polling at 4 Hz.
async fn wait_for(limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + limit;
    while !done() {
        assert!(
            std::time::Instant::now() < deadline,
            "never reached: {what}"
        );
        // sleep: the server changes its files from another process; poll them at 4 Hz.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Wait until the saved update state records `version` with `outcome`, and return it.
async fn wait_outcome(
    data: &Path,
    limit: Duration,
    version: &str,
    outcome: &str,
) -> infraternal_plugin_release::update::UpdateState {
    wait_for(limit, &format!("{version} {outcome}"), || {
        update_state(data)
            .applied
            .as_ref()
            .is_some_and(|applied| applied.version == version && applied.outcome == outcome)
    })
    .await;
    update_state(data)
}

/// Wait until the server answers `/healthz` with 200 again. The update state flips as
/// soon as a starting release writes it, which is before its listener is up.
async fn serving(address: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(90), async {
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

/// Unlock the CA with one real passkey ceremony.
async fn unlock(address: SocketAddr, session: &str, software: &mut Software) {
    let start = post(address, session, "/remote/ca/unlock/start", json!({})).await;
    let proof = software.login(&start, ORIGIN, true);
    let status = post(
        address,
        session,
        "/remote/ca/unlock/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":vec![7u8;32]}),
    )
    .await;
    assert_eq!(status["locked"], false, "the passkey unlocked the CA");
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

/// The server under test, as both phases see it.
struct Server {
    /// The HTTP listener.
    address: SocketAddr,
    /// The data folder.
    data: PathBuf,
    /// The database file.
    database: PathBuf,
    /// The owner's session cookie value.
    session: String,
    /// The image digest of each release, by version.
    digests: HashMap<String, String>,
    /// The releases.
    versions: Versions,
    /// The service's main PID.
    pid: u32,
    /// Live PTY sessions.
    sessions: Vec<[u8; 16]>,
    /// Shim PIDs of `sessions`.
    shims: Vec<i32>,
    /// Input bytes sent per attached browser.
    sent: HashMap<usize, u64>,
}
impl Server {
    /// Open the full set of live PTY sessions and record their shims.
    async fn open_sessions(&mut self) {
        self.sessions = terminals(self.address, &self.session, ORIGIN).await;
        self.shims = shim_pids(&self.sessions);
        self.sent.clear();
    }
    /// Attach to every session and check each browser's first session still echoes.
    async fn echo(&mut self, marker: &str) -> usize {
        let mut attached = attach_all(self.address, &self.session, &self.sessions, ORIGIN).await;
        let echoed = echo_all(&mut attached, &mut self.sent, marker).await;
        attached.clear();
        echoed
    }
    /// The boot pointer's target, relative to `updates/`.
    fn pointer(&self) -> PathBuf {
        std::fs::read_link(self.data.join("updates").join("current")).unwrap()
    }
    /// Check what every undo leaves: `version` paused and not installed, the old
    /// release running from an unmoved pointer, the marker intact.
    async fn assert_undone(&self, version: &str, marker: i64) {
        let state = update_state(&self.data);
        assert_eq!(
            state.paused.as_deref(),
            Some(version),
            "{version} is paused"
        );
        assert_eq!(
            running_digest(main_pid()),
            self.digests[&self.versions.old],
            "the old release runs again"
        );
        assert_eq!(
            self.pointer(),
            Path::new("releases").join(&self.versions.old),
            "the boot pointer never moved"
        );
        assert!(
            !self.data.join("updates/releases").join(version).exists(),
            "the undone release is not installed"
        );
        assert!(!self.data.join("updates/pending.json").exists());
        assert_eq!(
            read_marker(&self.database).await,
            marker,
            "the pre-switch data is all there (D295 copy)"
        );
    }
    /// Offer a faulty release that must be undone warm, and print its matrix row.
    async fn warm_case(
        &mut self,
        case: &str,
        version: &str,
        downtime: &Downtime,
        bucket: &Bucket,
        marker: i64,
    ) {
        write_marker(&self.database, marker).await;
        downtime.take_ms();
        announce(bucket, Some(version));
        let limit = if case == "timeout" { 420 } else { 240 };
        if case == "timeout" {
            // While the new release is on trial, write into its database: the undo must
            // throw this away with the rest of the trial's writes (D295).
            wait_for(Duration::from_secs(240), "timeout release on trial", || {
                pending_phase(&self.data).as_deref() == Some("trial")
            })
            .await;
            serving(self.address).await;
            write_marker(&self.database, marker + 100).await;
        }
        let state = wait_outcome(&self.data, Duration::from_secs(limit), version, "undone").await;
        serving(self.address).await;
        let gap = downtime.take_ms();
        self.assert_undone(version, marker).await;
        assert_eq!(main_pid(), self.pid, "one server process throughout");
        assert!(
            ca_unlocked(self.address, &self.session).await,
            "the CA stayed unlocked"
        );
        assert_eq!(
            shim_pids(&self.sessions),
            self.shims,
            "the shims are unchanged"
        );
        let echoed = self.echo(&format!("after-{case}")).await;
        println!(
            "UPDATE case={case} bucket=warm outcome=undone reason={:?} same_pid=true ca_unlocked=true unlocks=0 shims_unchanged={} echoed_browsers={echoed} marker_kept=true trial_write_discarded={} max_healthz_gap_ms={gap:.1}",
            state.applied.as_ref().unwrap().reason,
            self.shims.len(),
            case == "timeout",
        );
    }
}

/// Phase 1 of the S4 proof: the warm undo of four faults, the cold undo of a kill,
/// updates off, a withdrawn release, and a `reboot` release left on trial for the hard
/// reset. See the module docs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "root staging proof; runs inside scripts/update-proof-vm (#211 S4)"]
async fn auto_update_failure_matrix() {
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
    let versions = Versions::from_environment();
    let releases = root.join("releases");
    let bucket = Bucket::at(BUCKET.parse().unwrap(), release_files(&releases));
    announce(&bucket, Some(&versions.old));

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
    let address: SocketAddr = LISTEN.parse().unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
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
    // Prod shape after S6: the old release installed under updates/releases/, started
    // through the boot pointer.
    let updates = data.join("updates");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(updates.join("releases"))
        .unwrap();
    let installed = updates.join("releases").join(&versions.old);
    let copied = Command::new("cp")
        .args(["-a"])
        .arg(releases.join(&versions.old))
        .arg(&installed)
        .status()
        .unwrap();
    assert!(copied.success());
    std::fs::set_permissions(
        installed.join(IMAGE),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        Path::new("releases").join(&versions.old),
        updates.join("current"),
    )
    .unwrap();
    release_setting(&database, true).await;
    f.auth.auth.pool.close().await;

    // The VM's unit starts <POINTER>/current/<IMAGE> with these arguments and variables.
    let _ = std::fs::remove_file(POINTER);
    std::os::unix::fs::symlink(&updates, POINTER).unwrap();
    let arguments = format!(
        "server --listen {address} --remote-listen {remote} --public-origin {ORIGIN} --behind-proxy --trusted-proxy 127.0.0.1 --remote-ca-dir {} --data {}",
        ca.display(),
        data.display()
    );
    private_write(
        Path::new(ENVIRONMENT),
        format!(
            "ZDOTDIR={}\nINFRATERNAL_STAGING_BUILDS_ORIGIN=http://{BUCKET}\nINFRATERNAL_STAGING_UPDATE_SECONDS={STEP}\nINFRATERNAL_STAGING_FAULTS=\"{}\"\nRUST_LOG=info\nINFRATERNAL_PROOF_ARGS=\"{arguments}\"\n",
            profile.display(),
            versions.faults()
        )
        .as_bytes(),
    );
    let started = Command::new("systemctl")
        .args(["start", UNIT])
        .status()
        .unwrap();
    assert!(started.success(), "the proof unit started");
    let pid = main_pid();
    assert_ne!(pid, 0);
    tokio::time::timeout(Duration::from_secs(30), async {
        while tokio::net::TcpStream::connect(address).await.is_err() {
            // sleep: waiting for the unit's listener; 10 ms keeps startup timing honest.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the proof server became ready");
    let mut unlocks = 1;
    unlock(address, &f.auth.session, &mut f.auth.software).await;
    let digests = [
        &versions.old,
        &versions.unhealthy,
        &versions.timeout,
        &versions.migration,
        &versions.exec,
        &versions.kill,
        &versions.reboot,
        &versions.good,
    ]
    .into_iter()
    .map(|version| {
        (
            version.clone(),
            file_digest(&releases.join(version).join(IMAGE)),
        )
    })
    .collect();
    let mut server = Server {
        address,
        data: data.clone(),
        database: database.clone(),
        session: f.auth.session.clone(),
        digests,
        versions: versions.clone(),
        pid,
        sessions: Vec::new(),
        shims: Vec::new(),
        sent: HashMap::new(),
    };
    server.open_sessions().await;
    assert_eq!(running_digest(pid), server.digests[&versions.old]);
    println!(
        "UPDATE ready unit={UNIT} pid={pid} ca_unlocked=true real_pty_sessions={} running={}",
        server.sessions.len(),
        versions.old
    );
    let downtime = Downtime::start(address);

    // The warm bucket: B is still running when it fails, so it hands the CA back.
    for (marker, case, version) in [
        (11, "unhealthy", versions.unhealthy.clone()),
        (12, "timeout", versions.timeout.clone()),
        (13, "migration", versions.migration.clone()),
        (14, "exec", versions.exec.clone()),
    ] {
        server
            .warm_case(case, &version, &downtime, &bucket, marker)
            .await;
    }

    // The cold bucket: B is killed during its trial; the unit restarts the pointer.
    write_marker(&database, 15).await;
    announce(&bucket, Some(&versions.kill));
    wait_for(Duration::from_secs(240), "kill release on trial", || {
        pending_phase(&data).as_deref() == Some("trial")
    })
    .await;
    serving(address).await;
    downtime.take_ms();
    let killed = std::time::Instant::now();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(main_pid()).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    let state = wait_outcome(&data, Duration::from_secs(120), &versions.kill, "undone").await;
    serving(address).await;
    let back = killed.elapsed();
    let gap = downtime.take_ms();
    server.assert_undone(&versions.kill, 15).await;
    let locked = !ca_unlocked(address, &server.session).await;
    assert!(locked, "a cold start leaves the CA locked (D168)");
    let shims = session_shims(&server.sessions);
    let shims_left = shims.iter().flatten().count();
    let shims_same = shims
        .iter()
        .zip(&server.shims)
        .filter(|(now, before)| now.as_ref() == Some(*before))
        .count();
    unlock(address, &server.session, &mut f.auth.software).await;
    unlocks += 1;
    server.pid = main_pid();
    // Sessions live in their own scope units, so they may outlive the server; whether
    // the cold-started release can still reach them is reported, not required.
    let echoed_after_cold = if shims_left == server.sessions.len() {
        tokio::time::timeout(Duration::from_secs(60), server.echo("after-kill"))
            .await
            .ok()
    } else {
        None
    };
    println!(
        "UPDATE case=kill bucket=cold outcome=undone reason={:?} new_pid={} ca_locked_after_restart={locked} unlocks=1 shims_survived={shims_left}/{} shims_same_pid={shims_same} echoed_after_cold={echoed_after_cold:?} marker_kept=true back_after_ms={} max_healthz_gap_ms={gap:.1}",
        state.applied.as_ref().unwrap().reason,
        server.pid,
        server.sessions.len(),
        back.as_millis()
    );
    if echoed_after_cold.is_none() {
        server.open_sessions().await;
    }

    // Updates off: the good release is announced, nothing is staged or applied.
    release_setting(&database, false).await;
    announce(&bucket, Some(&versions.good));
    // sleep: four check periods must pass with nothing happening; there is no event.
    tokio::time::sleep(Duration::from_secs(STEP * 4)).await;
    let state = update_state(&data);
    assert_eq!(state.staged, None);
    assert_eq!(running_digest(main_pid()), server.digests[&versions.old]);
    assert_eq!(state.applied.as_ref().unwrap().version, versions.kill);
    println!(
        "UPDATE case=updates_off staged=None applied_unchanged=true refused={:?}",
        state.refused
    );

    // Withdrawn: staged while someone keeps attaching (the window stays open), then
    // withdrawn by the channel; never applied.
    let attaching = {
        let session = server.session.clone();
        tokio::spawn(async move {
            loop {
                attach_pulse(address, &session).await;
                // sleep: an attach once a second keeps the quiet window open (D251).
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    release_setting(&database, true).await;
    wait_for(Duration::from_secs(120), "good release staged", || {
        update_state(&data).staged.as_deref() == Some(versions.good.as_str())
    })
    .await;
    announce(&bucket, Some(&versions.old));
    wait_for(Duration::from_secs(120), "good release withdrawn", || {
        let state = update_state(&data);
        state.staged.is_none()
            && state
                .removed
                .as_ref()
                .is_some_and(|removed| removed.version.as_deref() == Some(versions.good.as_str()))
    })
    .await;
    attaching.abort();
    // sleep: a full quiet window plus a check must pass without an apply.
    tokio::time::sleep(Duration::from_secs(STEP * 3)).await;
    assert_eq!(running_digest(main_pid()), server.digests[&versions.old]);
    println!(
        "UPDATE case=withdrawn removed={:?} applied=false activity_held_the_window=true",
        update_state(&data).removed.unwrap().reason
    );

    // The reboot case: leave the reboot release on trial, then the runner resets the VM.
    write_marker(&database, 16).await;
    announce(&bucket, Some(&versions.reboot));
    wait_for(Duration::from_secs(240), "reboot release on trial", || {
        pending_phase(&data).as_deref() == Some("trial")
    })
    .await;
    serving(address).await;
    assert_eq!(running_digest(main_pid()), server.digests[&versions.reboot]);
    let software = &f.auth.software;
    let carry = Carry {
        root: f.root.clone(),
        session: server.session.clone(),
        key: String::from_utf8(software.key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
        id: B64.encode(&software.id),
        prf: B64.encode(software.prf_key.raw_private_key().unwrap()),
        counter: software.counter,
        versions: versions.clone(),
        boot_id: boot_id(),
        marker: 16,
        unlocks,
    };
    let path = root.join(CARRY);
    private_write(&path, &serde_json::to_vec(&carry).unwrap());
    std::fs::File::open(&path).unwrap().sync_all().unwrap();
    std::fs::File::open(&root).unwrap().sync_all().unwrap();
    // Phase 2 finds a clean pre-reset state only if nothing else is left running here.
    drop(downtime);
    drop(bucket);
    println!(
        "UPDATE case=reboot_armed version={} phase=trial reset_next=true",
        versions.reboot
    );
}

/// Phase 2 of the S4 proof, after the hard reset: the cold undo of the `reboot`
/// release, one passkey unlock, then the good release applied warm with live sessions.
/// See the module docs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "root staging proof; runs inside scripts/update-proof-vm after its reset (#211 S4)"]
async fn auto_update_after_reboot() {
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
    let carry: Carry = serde_json::from_slice(&std::fs::read(root.join(CARRY)).unwrap()).unwrap();
    assert_ne!(carry.boot_id, boot_id(), "the VM really rebooted");
    let versions = carry.versions;
    let releases = root.join("releases");
    let bucket = Bucket::at(BUCKET.parse().unwrap(), release_files(&releases));
    // The channel still offers what it offered at the reset.
    announce(&bucket, Some(&versions.reboot));
    let mut software = Software {
        key: PKey::private_key_from_pem(carry.key.as_bytes()).unwrap(),
        id: B64.decode(&carry.id).unwrap(),
        prf_key: PKey::hmac(&B64.decode(&carry.prf).unwrap()).unwrap(),
        counter: carry.counter,
        aaguid: Uuid::nil(),
        rp_id: "auth.example.test",
    };
    let data = carry.root.join("db");
    let database = data.join("infraternal.sqlite");
    let address: SocketAddr = LISTEN.parse().unwrap();
    // The unit started at boot from the pointer; the old release undid the reboot release
    // before it opened the database.
    let state = wait_outcome(&data, Duration::from_secs(120), &versions.reboot, "undone").await;
    serving(address).await;
    let digests = [&versions.old, &versions.reboot, &versions.good]
        .into_iter()
        .map(|version| {
            (
                version.clone(),
                file_digest(&releases.join(version).join(IMAGE)),
            )
        })
        .collect();
    let mut server = Server {
        address,
        data: data.clone(),
        database: database.clone(),
        session: carry.session.clone(),
        digests,
        versions: versions.clone(),
        pid: main_pid(),
        sessions: Vec::new(),
        shims: Vec::new(),
        sent: HashMap::new(),
    };
    server.assert_undone(&versions.reboot, carry.marker).await;
    let locked = !ca_unlocked(address, &server.session).await;
    assert!(locked, "a cold start leaves the CA locked (D168)");
    unlock(address, &server.session, &mut software).await;
    println!(
        "UPDATE case=reboot bucket=cold outcome=undone reason={:?} rebooted=true ca_locked_after_boot={locked} unlocks=1 marker_kept=true",
        state.applied.as_ref().unwrap().reason
    );

    // The good release: applied warm in the quiet window, with live sessions.
    server.open_sessions().await;
    let downtime = Downtime::start(address);
    write_marker(&database, 17).await;
    announce(&bucket, Some(&versions.good));
    let state = wait_outcome(&data, Duration::from_secs(240), &versions.good, "applied").await;
    serving(address).await;
    let gap = downtime.take_ms();
    assert_eq!(
        running_digest(server.pid),
        server.digests[&versions.good],
        "the good release runs"
    );
    assert_eq!(main_pid(), server.pid, "one server process throughout");
    assert!(
        ca_unlocked(address, &server.session).await,
        "the CA stayed unlocked"
    );
    assert_eq!(shim_pids(&server.sessions), server.shims);
    assert_eq!(server.pointer(), Path::new("releases").join(&versions.good));
    assert!(data.join("updates/previous").join(IMAGE).exists());
    assert!(!data.join("updates/pending.json").exists());
    assert_eq!(read_marker(&database).await, 17);
    let echoed = server.echo("after-update").await;
    println!(
        "UPDATE case=good_release bucket=warm outcome=applied pointer=releases/{} same_pid=true ca_unlocked=true unlocks=0 shims_unchanged={} echoed_browsers={echoed} max_healthz_gap_ms={gap:.1} paused={:?}",
        versions.good,
        server.shims.len(),
        state.paused
    );
    println!(
        "METRIC name=auto_update_matrix real_pty_sessions={} unlock_ceremonies={} ca_unlocked=true",
        server.sessions.len(),
        carry.unlocks + 1
    );
    drop(downtime);
    let _ = Command::new("systemctl").args(["stop", UNIT]).status();
}
