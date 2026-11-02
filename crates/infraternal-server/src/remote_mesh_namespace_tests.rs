//! Exercises the production mesh coordinator, authenticated transport supervisor and surviving PTY in two disposable kernel namespaces [128,168,215,228].
use super::*;
use crate::embedded::{AttachmentHandle, TerminalOutput};
use bytes::Bytes;
use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind};
use std::{
    io::{Read as _, Write as _},
    os::fd::AsRawFd as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use zeroize::Zeroize as _;

#[path = "remote_mesh_timing.rs"]
mod timing;

const PROOF_SCRATCH: &str = "/home/kayg/.cache/codex-scratch/mesh-autoswitch/evidence";
// The longer evidence directory would make a session socket 108 bytes. This
// owned sibling keeps kernel sun_path below 107 bytes without changing sessions.
const STATE_SCRATCH: &str = "/home/kayg/.cache/codex-scratch/mat-r2-ns";
// The shim's audited exec isolation closes fd 3. Reuse this wrapper for both
// inherited channels so neither can remain open in the surviving shim.
const INHERITED_SOCKET_EXEC: &str = "leg_b_fd=$1; if [ \"$leg_b_fd\" != 3 ]; then exec 3<&\"$leg_b_fd\"; exec {leg_b_fd}<&-; fi; shift; exec \"$@\"";

/// All public reports share the caller-selected benchmark artifact directory.
fn proof_scratch() -> PathBuf {
    std::env::var_os("INFRATERNAL_MESH_PROOF_SCRATCH")
        .map_or_else(|| PathBuf::from(PROOF_SCRATCH), PathBuf::from)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ClientBundle {
    certificate: String,
    private_key: String,
    root: String,
    endpoint: SocketAddr,
    state: PathBuf,
    binary: PathBuf,
    session: Option<Uuid>,
    server_key: infraternal_plugin_mesh::policy::model::PublicKey,
}
impl Drop for ClientBundle {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// The private key crosses only an inherited pipe; the fixture never writes it or logs its bundle.
#[tokio::test]
#[ignore = "Child of the isolated mesh namespace proof; requires its private stdin bundle."]
async fn mesh_namespace_client() {
    if std::env::var("INFRATERNAL_MESH_CHILD").ok().as_deref() != Some("1") {
        return;
    }
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut encoded).unwrap();
    let mut bundle: ClientBundle = serde_json::from_slice(&encoded).unwrap();
    let key = PKey::private_key_from_pem(bundle.private_key.as_bytes()).unwrap();
    bundle.private_key.zeroize();
    let identity = infraternal_agent::remote_client::RemoteIdentity {
        identity: Identity {
            certificate: X509::from_pem(bundle.certificate.as_bytes()).unwrap(),
            key,
        },
        roots: vec![X509::from_pem(bundle.root.as_bytes()).unwrap()],
        endpoint: Some(bundle.endpoint),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: 0,
    };
    let state = infraternal_agent::sessions::state(Some(bundle.state.clone())).unwrap();
    let session = if let Some(session) = bundle.session {
        infraternal_agent::sessions::connect(
            state
                .join("sessions")
                .join(format!("{}.sock", session.simple())),
            session.into_bytes(),
        )
        .await
        .unwrap()
    } else {
        infraternal_agent::sessions::launch(
            &bundle.binary,
            &state,
            infraternal_agent::sessions::Manager::Detached,
            0,
            80,
            24,
        )
        .await
        .unwrap()
    };
    println!(
        "MESH_SESSION {} {}",
        Uuid::from_bytes(session.id),
        session.pid
    );
    let shim_pid = session.pid;
    drop(session);
    let fd = std::env::var("INFRATERNAL_MESH_TIMING_FD")
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let timing_socket = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    assert_ne!(
        std::fs::read_link(format!("/proc/{shim_pid}/fd/{fd}")).ok(),
        Some(timing_socket),
        "timing socket leaked into the surviving shim"
    );
    let running = infraternal_agent::remote_client::run(&identity, Some(state));
    tokio::pin!(running);
    tokio::select! {
        result = &mut running => result.unwrap(),
        result = timing::serve(fd, bundle.server_key) => {
            result.unwrap();
            running.await.unwrap();
        }
    }
}

fn command(program: &str, args: &[&str]) {
    let result = Command::new(program).args(args).output().unwrap();
    assert!(
        result.status.success(),
        "namespace operation refused: {program}"
    );
}
fn namespace(pid: u32, program: &str, args: &[&str]) {
    let result = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-n", program])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "node namespace operation refused: {program}"
    );
}

/// Every process belongs to this fixture; namespaces and their kernel keys retire with their last owner.
struct Processes {
    children: Vec<Child>,
    shim: Option<u32>,
    states: Vec<PathBuf>,
}
impl Drop for Processes {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(pid) = self.shim
            && let Ok(pid) = i32::try_from(pid)
            && pid > 0
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        for state in &self.states {
            let _ = std::fs::remove_dir_all(state);
        }
    }
}

async fn node_process(
    namespace_pid: u32,
    bundle: &ClientBundle,
) -> (tokio::process::Child, Uuid, u32, tokio::net::UnixStream) {
    let (timestamps, inherited) = std::os::unix::net::UnixStream::pair().unwrap();
    nix::fcntl::fcntl(
        &inherited,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let mut child = tokio::process::Command::new("nsenter")
        .args(["-t", &namespace_pid.to_string(), "-n", "bash", "-c"])
        .arg(INHERITED_SOCKET_EXEC)
        .arg("mesh-proof")
        .arg(inherited.as_raw_fd().to_string())
        .arg(std::env::current_exe().unwrap())
        .args([
            "mesh_namespace_client",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("INFRATERNAL_MESH_CHILD", "1")
        .env("INFRATERNAL_MESH_TIMING_FD", "3")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    drop(inherited);
    timestamps.set_nonblocking(true).unwrap();
    let timestamps = tokio::net::UnixStream::from_std(timestamps).unwrap();
    let mut input = child.stdin.take().unwrap();
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(bundle).unwrap());
    input.write_all(&encoded).await.unwrap();
    drop(input);
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let (id, pid) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).await.unwrap(),
                0,
                "node fixture stopped"
            );
            if let Some((_, value)) = line.split_once("MESH_SESSION ") {
                let mut fields = value.split_whitespace();
                return (
                    Uuid::parse_str(fields.next().unwrap()).unwrap(),
                    fields.next().unwrap().parse::<u32>().unwrap(),
                );
            }
        }
    })
    .await
    .unwrap();
    // The client has no further stdout records. Keeping this drain avoids a harness pipe retaining it.
    tokio::spawn(async move {
        let mut discard = String::new();
        while output.read_line(&mut discard).await.unwrap_or(0) != 0 {
            discard.clear();
        }
    });
    (child, id, pid, timestamps)
}

fn wire(frame: &Frame<'_>) -> Bytes {
    let mut encoded = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(1, frame, &mut encoded).unwrap();
    Bytes::from(encoded)
}

async fn link(actor: &EmbeddedAgent) -> Option<ServerLink> {
    let result = actor
        .call("mesh.status".into(), b"{}".to_vec())
        .await
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&result).ok()?;
    serde_json::from_value(value["server_link"].clone()).ok()
}
pub(crate) async fn wait_link(actor: &EmbeddedAgent, kind: ServerLinkKind) -> ServerLink {
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(link) = link(actor).await
                && link.kind == kind
            {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    let Ok(link) = result else {
        let status = actor.call("mesh.status".into(), b"{}".to_vec()).await.ok();
        let public =
            status.and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        std::fs::write(
            proof_scratch().join(format!("path-timeout-{kind:?}.json")),
            serde_json::to_vec_pretty(&public).unwrap(),
        )
        .unwrap();
        panic!("server path unavailable: {kind:?}");
    };
    link
}

/// Drain continuously so a path move cannot be disguised by receiver backpressure.
pub(crate) struct Echo {
    input: AttachmentHandle,
    bytes: Arc<Mutex<Vec<u8>>>,
    changed: Arc<tokio::sync::Notify>,
    fault: Arc<std::sync::atomic::AtomicBool>,
    ready: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    sequence: u64,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Echo {
    pub(crate) fn writer_id(&self) -> u32 {
        self.input.stream_id()
    }

    pub(crate) async fn start(actor: &EmbeddedAgent, session: Uuid) -> Self {
        let (input, mut output) = actor
            .attach(session.into_bytes(), 0, 0, 2)
            .await
            .unwrap()
            .split();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let changed = Arc::new(tokio::sync::Notify::new());
        let fault = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (received, notification, failed, running, credit) = (
            bytes.clone(),
            changed.clone(),
            fault.clone(),
            ready.clone(),
            input.clone(),
        );
        let task = tokio::spawn(async move {
            while let Some(frame) = output.recv().await {
                match frame {
                    TerminalOutput::Output { bytes, .. } => {
                        received.lock().await.extend_from_slice(&bytes);
                        credit
                            .send_frame(wire(&Frame::Credit {
                                bytes: bytes.len().try_into().unwrap(),
                            }))
                            .await
                            .unwrap();
                    }
                    TerminalOutput::Snapshot { bytes, .. } => {
                        if running.load(std::sync::atomic::Ordering::Acquire) && !bytes.is_empty() {
                            println!("FAULT repaint_snapshot");
                            failed.store(true, std::sync::atomic::Ordering::Release);
                        }
                        received.lock().await.extend_from_slice(&bytes);
                        credit
                            .send_frame(wire(&Frame::Credit {
                                bytes: bytes.len().try_into().unwrap(),
                            }))
                            .await
                            .unwrap();
                    }
                    TerminalOutput::Closed { .. } => {
                        println!("FAULT terminal_closed");
                        failed.store(true, std::sync::atomic::Ordering::Release);
                        break;
                    }
                    _ => {}
                }
                notification.notify_one();
            }
            notification.notify_one();
        });
        let mut echo = Self {
            input,
            bytes,
            changed,
            fault,
            ready,
            task,
            sequence: 0,
        };
        echo.input
            .send_frame(wire(&Frame::Credit { bytes: 1_048_576 }))
            .await
            .unwrap();
        // The echoed setup command must not itself contain the readiness marker.
        echo.send(b"stty raw -echo; exec python3 -u -c 'import os; os.write(1,bytes.fromhex(\"52454144597c\")); exec(\"while True:\\n b=os.read(0,4096)\\n if not b: break\\n os.write(1,b)\")'\r").await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notified = echo.changed.notified();
                if echo
                    .bytes
                    .lock()
                    .await
                    .windows(6)
                    .any(|window| window == b"READY|")
                {
                    break;
                }
                assert!(!echo.fault.load(std::sync::atomic::Ordering::Acquire));
                notified.await;
            }
        })
        .await
        .unwrap();
        echo.bytes.lock().await.clear();
        echo.ready.store(true, std::sync::atomic::Ordering::Release);
        echo
    }
    pub(crate) async fn send(&mut self, bytes: &[u8]) {
        self.send_result(bytes)
            .await
            .expect("terminal input unavailable");
    }
    /// Preserve a closed baseline writer as a failed receipt, never a replacement.
    pub(crate) async fn send_result(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        self.input
            .send_frame(wire(&Frame::Input {
                in_seq: self.sequence,
                bytes,
            }))
            .await
            .map_err(|_| "terminal input unavailable")?;
        self.sequence += bytes.len() as u64;
        Ok(())
    }
    pub(crate) async fn wait(&self, expected: &[u8]) {
        self.wait_result(expected)
            .await
            .expect("terminal integrity failed");
    }
    /// Baseline receipts retain a failed byte proof instead of treating a
    /// repaint/snapshot as equivalent to an intact raw terminal stream.
    pub(crate) async fn wait_result(&self, expected: &[u8]) -> Result<(), &'static str> {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let notified = self.changed.notified();
                if self.fault.load(std::sync::atomic::Ordering::Acquire) {
                    return Err("terminal retired or required an approximate repaint");
                }
                let received = self.bytes.lock().await;
                if !expected.starts_with(&received) {
                    return Err("terminal byte ordering issue");
                }
                if received.len() == expected.len() {
                    return Ok(());
                }
                drop(received);
                notified.await;
            }
        })
        .await
        .map_err(|_| "terminal echo timed out")?
    }
    async fn samples(&mut self, expected: &mut Vec<u8>, tag: u8) -> Vec<u128> {
        let mut samples = Vec::new();
        for index in 0..31 {
            let bytes = format!("{}{:05}|", char::from(tag), index).into_bytes();
            let started = tokio::time::Instant::now();
            self.send(&bytes).await;
            expected.extend_from_slice(&bytes);
            self.wait(expected).await;
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        samples
    }
}

pub(crate) fn root_fixture_home(scratch: &Path) {
    // Private mount propagation is mandatory before binding public login-account fixtures.
    command("mount", &["--make-rprivate", "/"]);
    let home = scratch.join("h");
    std::fs::create_dir_all(&home).unwrap();
    let passwd = scratch.join("proof-passwd");
    std::fs::write(
        &passwd,
        format!("root:x:0:0:Mesh proof:{}:/bin/sh\n", home.display()),
    )
    .unwrap();
    let group = scratch.join("proof-group");
    std::fs::write(&group, "root:x:0:\n").unwrap();
    let profile = scratch.join("proof-profile");
    std::fs::write(
        &profile,
        "# Isolated real-PTY login profile for the mesh proof.\n",
    )
    .unwrap();
    for (file, target) in [
        (&passwd, "/etc/passwd"),
        (&group, "/etc/group"),
        (&profile, "/etc/profile"),
    ] {
        command("mount", &["--bind", file.to_str().unwrap(), target]);
    }
}

/// Share the proof-only physical route resolver without exposing listener fields.
pub(crate) fn proof_routes(
    listeners: &RemoteListeners,
) -> Arc<infraternal_plugin_remote::remote_bindings::Bindings> {
    listeners.bindings.clone()
}

pub(crate) fn local_daemon(binary: &Path, state: &Path) -> (Child, EmbeddedAgent) {
    let (socket, inherited) = std::os::unix::net::UnixStream::pair().unwrap();
    nix::fcntl::fcntl(
        &inherited,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let child = Command::new("bash")
        .args([
            "-c",
            INHERITED_SOCKET_EXEC,
            "mesh-proof",
            &inherited.as_raw_fd().to_string(),
        ])
        .arg(binary)
        .args(["agent", "--fd", "3", "--state"])
        .arg(state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(inherited);
    socket.set_nonblocking(true).unwrap();
    (
        child,
        EmbeddedAgent::from_test_socket(tokio::net::UnixStream::from_std(socket).unwrap()),
    )
}

// Match production's durable SQLite storage. Cancelling pool checkout can
// discard its connection before ownership reaches the caller; the last
// in-memory connection would then erase the schema, unrelated to transaction
// cancellation. Each namespace lifecycle owns a fresh file outside the repo.
pub(crate) async fn namespace_pool(options: sqlx::sqlite::SqlitePoolOptions) -> sqlx::SqlitePool {
    let scratch = proof_scratch();
    std::fs::create_dir_all(&scratch).unwrap();
    let database = scratch.join(format!("namespace-{}.sqlite", Uuid::new_v4()));
    options
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(database)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Normal),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn namespace_store_survives_cancelled_pool_checkout() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let armed = Arc::new(AtomicBool::new(false));
    let reached = Arc::new(tokio::sync::Notify::new());
    let options = sqlx::sqlite::SqlitePoolOptions::new().before_acquire({
        let armed = armed.clone();
        let reached = reached.clone();
        move |_, _| {
            let armed = armed.clone();
            let reached = reached.clone();
            Box::pin(async move {
                if armed.swap(false, Ordering::AcqRel) {
                    reached.notify_one();
                    std::future::pending::<()>().await;
                }
                Ok(true)
            })
        }
    });
    let pool = namespace_pool(options).await;
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    let runtime = crate::plugins::compiled(&pool).await.unwrap();
    armed.store(true, Ordering::Release);
    let checkout = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire().await }
    });
    reached.notified().await;
    checkout.abort();
    assert!(checkout.await.unwrap_err().is_cancelled());
    // Disable must still persist after an aborted coordinator checkout; this
    // is a connection replacement, independent of BEGIN/COMMIT cancellation.
    runtime.set_enabled("mesh", false).await.unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM plugin_settings WHERE role='server' AND plugin='mesh'"
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    );
    let database = pool.connect_options().get_filename().to_owned();
    pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", database.display()));
    }
}

async fn root_store(host: &Identity, root: &X509) -> (EnrollmentStore, sqlx::SqlitePool, Uuid) {
    let pool = namespace_pool(sqlx::sqlite::SqlitePoolOptions::new()).await;
    let (store, pool, id) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    // The generic fixture has a synthetic rootless enrollment. Start a fresh
    // rootful fixture row rather than changing an enrolled execution mode.
    for table in ["remote_join_tokens", "remote_certificates", "remote_hosts"] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE {}=?",
            if table == "remote_hosts" {
                "id"
            } else {
                "host_id"
            }
        ))
        .bind(id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootful', 0, 100)")
        .bind(id.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let instant = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let public_key: [u8; 32] = host.key.raw_public_key().unwrap().try_into().unwrap();
    let key_digest = openssl::sha::sha256(&public_key);
    let token = store
        .issue(
            "owner",
            id,
            crate::enrollment::Mode::Rootful,
            instant,
            &key_digest,
        )
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            id,
            crate::enrollment::Mode::Rootful,
            instant,
            &crate::enrollment::CertificateRecord {
                fingerprint: openssl::sha::sha256(&host.certificate.to_der().unwrap()),
                issuer_fingerprint: openssl::sha::sha256(&root.to_der().unwrap()),
                public_key,
                not_before: instant,
                not_after: instant + 604_800,
            },
        )
        .await
        .unwrap();
    (store, pool, id)
}

async fn peer_evidence(actor: &EmbeddedAgent) -> (usize, u64, u64) {
    let mut cursor = serde_json::Value::Null;
    let (mut count, mut sent, mut received) = (0, 0, 0);
    loop {
        let input = serde_json::to_vec(&serde_json::json!({"cursor":cursor})).unwrap();
        let page: serde_json::Value =
            serde_json::from_slice(&actor.call("mesh.peers".into(), input).await.unwrap()).unwrap();
        for peer in page["peers"].as_array().unwrap() {
            assert_eq!(peer["counters"]["persistent_keepalive_secs"], 25);
            count += 1;
            sent += peer["counters"]["sent_bytes"].as_u64().unwrap();
            received += peer["counters"]["received_bytes"].as_u64().unwrap();
        }
        cursor = page["next_cursor"].clone();
        if cursor.is_null() {
            return (count, sent, received);
        }
    }
}

fn firewall(pid: Option<u32>, port: u16, scratch: &Path) {
    let admission = if pid.is_none() {
        format!("udp dport {port} accept; tcp dport {port} accept;")
    } else {
        String::new()
    };
    let rules = format!(
        "table inet mesh_proof {{ chain input {{ type filter hook input priority 0; policy drop; iifname lo accept; ct state established,related accept; {admission} }}\n}}\n"
    );
    let mut child = if let Some(pid) = pid {
        let mut child = Command::new("nsenter");
        child.args(["-t", &pid.to_string(), "-n", "nft", "-f", "-"]);
        child
    } else {
        let mut child = Command::new("nft");
        child.args(["-f", "-"]);
        child
    };
    let diagnostics = std::fs::File::create(scratch.join(if pid.is_some() {
        "node-firewall-error.log"
    } else {
        "server-firewall-error.log"
    }))
    .unwrap();
    let mut child = child
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostics))
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(rules.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    // The evidence contains only the original infraternal agent port, never a WireGuard port grant.
    std::fs::write(
        scratch.join(if pid.is_some() {
            "node-firewall.nft"
        } else {
            "server-firewall.nft"
        }),
        rules,
    )
    .unwrap();
}

/// Save only public firewall rules from the proof's two private namespaces.
fn firewall_listing(pid: Option<u32>, scratch: &Path) {
    let result = if let Some(pid) = pid {
        Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n", "nft", "list", "ruleset"])
            .output()
            .unwrap()
    } else {
        Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .unwrap()
    };
    assert!(result.status.success(), "firewall listing refused");
    std::fs::write(
        scratch.join(if pid.is_some() {
            "node-firewall-observed.nft"
        } else {
            "server-firewall-observed.nft"
        }),
        result.stdout,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Run as real root inside disposable network AND mount namespaces, in the local CPUWeight scope."]
// Keep the complete path/PTY lifecycle in one fixture so every assertion observes the same open attachment.
#[allow(clippy::too_many_lines)]
async fn mesh_transport_real_namespaces_preserve_the_terminal() {
    if std::env::var("INFRATERNAL_MESH_PROOF").ok().as_deref() != Some("1") {
        return;
    }
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "stop: host network namespace"
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt").unwrap(),
        std::fs::read_link("/proc/1/ns/mnt").unwrap(),
        "stop: host mount namespace"
    );
    let scratch = proof_scratch();
    std::fs::create_dir_all(&scratch).unwrap();
    let load_start = std::fs::read_to_string("/proc/loadavg").unwrap();
    root_fixture_home(&scratch);
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_MESH_BINARY").unwrap());
    let mut processes = Processes {
        children: Vec::new(),
        shim: None,
        states: Vec::new(),
    };
    let state_scratch = std::env::var_os("INFRATERNAL_MESH_PROOF_STATE")
        .map_or_else(|| PathBuf::from(STATE_SCRATCH), PathBuf::from);
    assert!(
        !state_scratch.exists(),
        "stop: fixture state already exists"
    );
    // Own cleanup before creating the short parent or any private child state.
    processes.states.push(state_scratch.clone());
    std::fs::create_dir(&state_scratch).unwrap();
    processes.children.push(
        Command::new("unshare")
            .args(["-n", "sleep", "600"])
            .spawn()
            .unwrap(),
    );
    let namespace_pid = processes.children[0].id();
    tokio::time::timeout(Duration::from_secs(2), async {
        while std::fs::read_link(format!("/proc/{namespace_pid}/ns/net")).unwrap()
            == std::fs::read_link("/proc/self/ns/net").unwrap()
        {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    command("ip", &["link", "set", "lo", "up"]);
    command(
        "ip",
        &[
            "link", "add", "m_srv", "type", "veth", "peer", "name", "m_node",
        ],
    );
    command(
        "ip",
        &["link", "set", "m_node", "netns", &namespace_pid.to_string()],
    );
    command("ip", &["addr", "add", "10.220.0.1/24", "dev", "m_srv"]);
    command("ip", &["link", "set", "m_srv", "up"]);
    namespace(namespace_pid, "ip", &["link", "set", "lo", "up"]);
    namespace(
        namespace_pid,
        "ip",
        &["addr", "add", "10.220.0.2/24", "dev", "m_node"],
    );
    namespace(namespace_pid, "ip", &["link", "set", "m_node", "up"]);
    let rtt_ms =
        std::env::var("INFRATERNAL_TEST_RTT").map_or(300, |value| value.parse::<u64>().unwrap());
    if rtt_ms != 0 {
        let delay = format!("{}ms", rtt_ms / 2);
        let jitter = format!("{}ms", rtt_ms / 20);
        command(
            "tc",
            &[
                "qdisc", "add", "dev", "m_srv", "root", "netem", "delay", &delay, &jitter,
            ],
        );
        namespace(
            namespace_pid,
            "tc",
            &[
                "qdisc", "add", "dev", "m_node", "root", "netem", "delay", &delay, &jitter,
            ],
        );
    }
    let (server, host, root, _) = identities();
    let (store, pool, host_id) = root_store(&host, &root).await;
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "10.220.0.1:7443".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let runtime = crate::plugins::compiled(&pool).await.unwrap();
    runtime.set_enabled("mesh", false).await.unwrap();
    let server_state = state_scratch.join("s");
    let node_state = state_scratch.join("n");
    let session_path = node_state
        .join("sessions")
        .join(format!("{}.sock", Uuid::nil().simple()));
    assert!(session_path.as_os_str().len() < 107);
    assert!(
        !server_state.exists() && !node_state.exists(),
        "stop: fixture state already exists"
    );
    // Cleanup is owned before any child can create these private fixture paths.
    processes
        .states
        .extend([server_state.clone(), node_state.clone()]);
    let (daemon, actor) = local_daemon(&binary, &server_state);
    processes.children.push(daemon);
    runtime
        .attach_node(Arc::new(crate::node_bridge::NodeBridge {
            id: "server".into(),
            ip: "10.220.0.1".parse().unwrap(),
            server: true,
            server_paths: true,
            actor: actor.clone(),
            authority: None,
            listeners: Some(hosts.clone()),
            peer_routes: None,
        }))
        .await
        .unwrap();
    hosts.bind_plugins(&runtime).await.unwrap();
    let server_mesh: infraternal_plugin_mesh::dataplane::Identity = serde_json::from_slice(
        &actor
            .call("mesh.identity".into(), b"{}".to_vec())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_ne!(server_mesh.port, 0);
    assert_ne!(server_mesh.port, 51820);
    let inventory = infraternal_plugin_mesh::api::MeshService::new(pool.clone()).dataplane();
    inventory
        .attach(
            "server",
            server_mesh.public_key,
            Some(SocketAddr::new(
                "10.220.0.1".parse().unwrap(),
                server_mesh.port,
            )),
            true,
        )
        .await
        .unwrap();
    // These are public inventory fixtures, not 998 additional running daemons.
    for index in 0_u64..998 {
        let mut key = [0_u8; 32];
        key[..8].copy_from_slice(&index.to_le_bytes());
        key[31] = 1;
        inventory
            .attach(
                &format!("fixture-{index}"),
                infraternal_plugin_mesh::policy::model::PublicKey(key),
                None,
                false,
            )
            .await
            .unwrap();
    }
    firewall(None, 7443, &scratch);
    firewall(Some(namespace_pid), 7443, &scratch);
    let private_pem = zeroize::Zeroizing::new(host.key.private_key_to_pem_pkcs8().unwrap());
    let mut bundle = ClientBundle {
        certificate: String::from_utf8(host.certificate.to_pem().unwrap()).unwrap(),
        private_key: std::str::from_utf8(&private_pem)
            .map_err(|_| "fixture encoding refused")
            .unwrap()
            .to_owned(),
        root: String::from_utf8(root.to_pem().unwrap()).unwrap(),
        endpoint: listeners.local_addr().unwrap(),
        state: node_state.clone(),
        binary,
        session: None,
        server_key: server_mesh.public_key,
    };
    let (mut client, session, shim, mut timestamps) = node_process(namespace_pid, &bundle).await;
    processes.shim = Some(shim);
    let remote = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(actor) = hosts.actor(host_id).await {
                return actor;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    wait_link(&remote, ServerLinkKind::Fallback).await;
    println!("CHECK enrolled_fallback result=PASS");
    let node_mesh: infraternal_plugin_mesh::dataplane::Identity = serde_json::from_slice(
        &remote
            .call("mesh.identity".into(), b"{}".to_vec())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_ne!(node_mesh.port, 0);
    assert_ne!(node_mesh.port, 51820);
    let mut echo = Echo::start(&remote, session).await;
    let mut expected = Vec::new();
    let direct = echo.samples(&mut expected, b'd').await;
    println!("CHECK real_terminal result=PASS");
    let writer = echo.input.clone();
    let first_sequence = echo.sequence;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = stop.clone();
    let typing = tokio::spawn(async move {
        let mut sequence = first_sequence;
        let mut moving = Vec::new();
        let mut tail = 0;
        for index in 0..100_000 {
            let bytes = format!("u{index:05}|");
            writer
                .send_frame(wire(&Frame::Input {
                    in_seq: sequence,
                    bytes: bytes.as_bytes(),
                }))
                .await
                .unwrap();
            moving.extend_from_slice(bytes.as_bytes());
            sequence += bytes.len() as u64;
            if finished.load(std::sync::atomic::Ordering::Acquire) {
                tail += 1;
                if tail == 32 {
                    return moving;
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("stop: move did not finish within bounded input proof");
    });
    // Separately observe a working bidirectional kernel path. This distinguishes
    // configuration bootstrap from transport replacement; observation is 200 ms.
    let node_key = node_mesh.public_key;
    let working = tokio::spawn(async move {
        loop {
            if infraternal_plugin_mesh::wireguard::Device::counters().is_ok_and(|peers| {
                peers
                    .get(&node_key)
                    .is_some_and(|peer| peer.sent_bytes > 0 && peer.received_bytes > 0)
            }) {
                return tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let capture = crate::remote_autoswitch_probe::Capture::start(|peer| match peer.ip() {
        std::net::IpAddr::V4(ip) => ip.octets()[..2] == [10, 254] || ip.octets() == [10, 220, 0, 2],
        std::net::IpAddr::V6(_) => false,
    })
    .with_routes(listeners.bindings.clone());
    let enabled_wall = std::time::SystemTime::now();
    let moved = tokio::time::Instant::now();
    runtime.set_enabled("mesh", true).await.unwrap();
    let mesh_link = wait_link(&remote, ServerLinkKind::Mesh).await;
    println!("CHECK mesh_preferred result=PASS");
    let arrived = tokio::time::Instant::now();
    let move_us = arrived.duration_since(moved).as_micros();
    let working_at = tokio::time::timeout(Duration::from_secs(5), working)
        .await
        .unwrap()
        .unwrap();
    let move_from_working_mesh_us = arrived.saturating_duration_since(working_at).as_micros();
    firewall_listing(None, &scratch);
    firewall_listing(Some(namespace_pid), &scratch);
    stop.store(true, std::sync::atomic::Ordering::Release);
    let moving = typing.await.unwrap();
    echo.sequence += moving.len() as u64;
    expected.extend_from_slice(&moving);
    echo.wait(&expected).await;
    let joined = tokio::time::timeout(Duration::from_secs(5), timing::handshake(&mut timestamps))
        .await
        .unwrap()
        .unwrap();
    let events = capture.events();
    let first_byte = events
        .iter()
        .filter(|event| {
            event.kind == crate::remote_autoswitch_probe::Kind::TerminalByte
                && event.peer.ip() != "10.220.0.2".parse::<std::net::IpAddr>().unwrap()
        })
        .min_by_key(|event| event.monotonic)
        .unwrap();
    assert_ne!(first_byte.stream, 0);
    let milestone = |kind| {
        events
            .iter()
            .find(|event| event.kind == kind && event.peer == first_byte.peer)
    };
    // An in-place move keeps the admitted connection: no mesh peer may complete
    // a new mTLS handshake, and none of the setup milestones exist for it.
    let tls = milestone(crate::remote_autoswitch_probe::Kind::TlsHandshake);
    let admitted = milestone(crate::remote_autoswitch_probe::Kind::LedgerAdmission);
    let control = milestone(crate::remote_autoswitch_probe::Kind::ControlReady);
    let preserved = !events.iter().any(|event| {
        event.kind == crate::remote_autoswitch_probe::Kind::TlsHandshake
            && event.peer.ip() != "10.220.0.2".parse::<std::net::IpAddr>().unwrap()
    });
    assert!(preserved, "the move opened a new mesh connection");
    timing::validate_lifecycle(
        enabled_wall,
        joined,
        tls.map(|event| event.wall),
        first_byte.wall,
        first_byte.monotonic.duration_since(moved.into_std()),
    )
    .unwrap();
    let between = |from: Option<&crate::remote_autoswitch_probe::Event>,
                   to: Option<&crate::remote_autoswitch_probe::Event>| {
        from.zip(to)
            .map(|(from, to)| to.monotonic.duration_since(from.monotonic).as_micros())
    };
    let phases = serde_json::json!({
        "terminal_byte_boundary": "authenticated_transport_arrival_before_actor_delivery",
        "fresh_kernel_peer": true,
        "lifecycle_and_clock_validated": true,
        "preserved_connection": preserved,
        "fixture_enable_to_node_wg_handshake_us": joined.duration_since(enabled_wall).unwrap().as_micros(),
        "node_wg_handshake_to_first_mesh_byte_us": first_byte.wall.duration_since(joined).unwrap().as_micros(),
        "fixture_enable_to_first_mesh_byte_us": first_byte.monotonic.duration_since(moved.into_std()).as_micros(),
        "server_mtls_to_ledger_admission_us": between(tls, admitted),
        "ledger_admission_to_control_ready_us": between(admitted, control),
        "control_ready_to_first_mesh_byte_us": between(control, Some(first_byte)),
        "server_mtls_to_first_mesh_byte_us": between(tls, Some(first_byte)),
        "first_mesh_byte_stream": first_byte.stream,
        "add_host_completion_measured": false,
    });
    assert_ne!(
        mesh_link.endpoint.unwrap().ip(),
        listeners.local_addr().unwrap().ip()
    );
    let mesh = echo.samples(&mut expected, b'm').await;
    let server_peers = peer_evidence(&actor).await;
    let node_peers = peer_evidence(&remote).await;
    assert_eq!((server_peers.0, node_peers.0), (999, 999));
    assert!(server_peers.1 > 0 && server_peers.2 > 0 && node_peers.1 > 0 && node_peers.2 > 0);
    // Refuse packets while retaining the owned interface and routes. An
    // administrative interface down also removes Linux host routes and would
    // test operator configuration recovery rather than transport interruption.
    command("nft", &["add", "table", "inet", "mesh_link_cut"]);
    for (chain, hook, direction) in [("input", "input", "dport"), ("output", "output", "sport")] {
        command(
            "nft",
            &[
                "add",
                "chain",
                "inet",
                "mesh_link_cut",
                chain,
                &format!("{{ type filter hook {hook} priority -10; policy accept; }}"),
            ],
        );
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "mesh_link_cut",
                chain,
                "udp",
                direction,
                &server_mesh.port.to_string(),
                "drop",
            ],
        );
    }
    // Start after both cut rules are installed. Observe the restored terminal
    // directly: status RPCs add their own network round trip and scheduling.
    let interrupted = tokio::time::Instant::now();
    echo.send(b"cut-survives|").await;
    expected.extend_from_slice(b"cut-survives|");
    echo.wait(&expected).await;
    let fallback_us = interrupted.elapsed().as_micros();
    wait_link(&remote, ServerLinkKind::Fallback).await;
    let fallback_status_us = interrupted.elapsed().as_micros();
    let fallback = echo.samples(&mut expected, b'f').await;
    println!("CHECK fallback_retains_bytes result=PASS");
    // Persist latency before later lifecycle assertions: a failed mesh reprobe
    // must not discard the already measured terminal recovery evidence.
    let partial = serde_json::json!({
        "machine": std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(), "head_profile": "in-place-path",
        "configured_rtt_ms": rtt_ms, "configured_rtt_jitter_ms": 2 * (rtt_ms / 20),
        "real_kernel": true, "real_pty": true, "live_nodes": 2,
        "live_terminals": 1, "public_inventory": 1000,
        "silent_cut_to_echo_us": fallback_us,
        "silent_cut_to_fallback_status_us": fallback_status_us,
        "direct": {"n": 31, "p50_us": direct[15], "p99_us": direct[30]},
        "mesh": {"n": 31, "p50_us": mesh[15], "p99_us": mesh[30]},
        "fallback": {"n": 31, "p50_us": fallback[15], "p99_us": fallback[30]},
        "load_start": load_start.trim(),
        "load": std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        "lifecycle_complete": false
    });
    let mut partial = partial;
    partial["phases"] = phases.clone();
    std::fs::write(
        scratch.join(format!("namespace-transport-{rtt_ms}.json")),
        serde_json::to_vec_pretty(&partial).unwrap(),
    )
    .unwrap();
    println!(
        "METRIC cut_to_echo_us={fallback_us} configured_rtt_ms={rtt_ms} mesh_p99_us={} direct_p99_us={}",
        mesh[30], direct[30]
    );
    command("nft", &["delete", "table", "inet", "mesh_link_cut"]);
    wait_link(&remote, ServerLinkKind::Mesh).await;
    println!("CHECK mesh_restored result=PASS");
    // Refuse only the underlay listener. A retained mesh path must join without
    // first reaching the original infraternal agent port.
    command("nft", &["add", "table", "inet", "fallback_cut"]);
    command(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "fallback_cut",
            "input",
            "{ type filter hook input priority -10; policy accept; }",
        ],
    );
    command(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "fallback_cut",
            "input",
            "iifname",
            "m_srv",
            "udp",
            "dport",
            "7443",
            "drop",
        ],
    );
    command(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "fallback_cut",
            "input",
            "iifname",
            "m_srv",
            "tcp",
            "dport",
            "7443",
            "drop",
        ],
    );
    client.kill().await.unwrap();
    client.wait().await.unwrap();
    bundle.session = Some(session);
    let restarted = tokio::time::Instant::now();
    let (next, same_session, same_shim, next_timestamps) =
        node_process(namespace_pid, &bundle).await;
    assert_eq!((same_session, same_shim), (session, shim));
    wait_link(&remote, ServerLinkKind::Mesh).await;
    println!("CHECK restarted_on_mesh result=PASS");
    echo.send(b"restart-survives|").await;
    expected.extend_from_slice(b"restart-survives|");
    echo.wait(&expected).await;
    let restart_us = restarted.elapsed().as_micros();
    println!("CHECK restart_retains_bytes result=PASS");
    command("nft", &["delete", "table", "inet", "fallback_cut"]);
    runtime.set_enabled("mesh", false).await.unwrap();
    wait_link(&remote, ServerLinkKind::Fallback).await;
    echo.send(b"disabled-survives|").await;
    expected.extend_from_slice(b"disabled-survives|");
    echo.wait(&expected).await;
    let report = serde_json::json!({"machine":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),"real_kernel":true,"real_pty":true,"stateful_input_firewall":true,"wireguard_port_grants":0,"namespaces":2,"live_nodes":2,"public_inventory":1000,"live_terminals":1,"server_wireguard_port":server_mesh.port,"node_wireguard_port":node_mesh.port,"server_peer_counters":server_peers,"node_peer_counters":node_peers,"moving_input_bytes":moving.len(),"expected_bytes":expected.len(),"received_bytes":echo.bytes.lock().await.len(),"bootstrap_and_move_us":move_us,"move_from_observed_working_mesh_us":move_from_working_mesh_us,"working_mesh_observation_interval_ms":200,"fallback_us":fallback_us,"restart_us":restart_us,"direct":{"n":31,"p50_us":direct[15],"p99_us":direct[30]},"mesh":{"n":31,"p50_us":mesh[15],"p99_us":mesh[30]},"fallback":{"n":31,"p50_us":fallback[15],"p99_us":fallback[30]},"load":std::fs::read_to_string("/proc/loadavg").unwrap().trim()});
    let mut report = report;
    report["configured_rtt_ms"] = rtt_ms.into();
    report["configured_rtt_jitter_ms"] = (2 * (rtt_ms / 20)).into();
    report["silent_cut_to_echo_us"] = serde_json::json!(fallback_us);
    report["silent_cut_to_fallback_status_us"] = serde_json::json!(fallback_status_us);
    report["load_start"] = load_start.trim().into();
    report["head_profile"] = "in-place-path".into();
    report["lifecycle_complete"] = true.into();
    report["phases"] = phases;
    std::fs::write(
        scratch.join(format!("namespace-transport-{rtt_ms}.json")),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "METRIC mesh_transport namespaces=2 terminals=1 bytes={} configured_rtt_ms={rtt_ms} move_us={move_us} silent_cut_to_echo_us={fallback_us} silent_cut_to_fallback_status_us={fallback_status_us} lifecycle=PASS",
        expected.len()
    );
    let recovery_budget_us = u128::from(rtt_ms) * 1000 + 250_000;
    let recovery_pass = fallback_us <= recovery_budget_us;
    let local_echo_pass = rtt_ms != 0 || mesh[30] <= direct[30] + 2000;
    println!(
        "BUDGET silent_cut_to_echo_us={fallback_us} budget_us={recovery_budget_us} pass={recovery_pass} local_mesh_p99_us={} direct_p99_us={} allowed_extra_us=2000 pass={local_echo_pass}",
        mesh[30], direct[30]
    );
    // Keep the complete report even when functional recovery misses latency.
    // Runtime handles clean up their owned namespaces and state on either path.
    assert!(recovery_pass, "silent mesh cut exceeded one RTT plus 250ms");
    assert!(
        local_echo_pass,
        "local mesh echo p99 exceeded direct by 2ms"
    );
    drop(next);
    drop(next_timestamps);
    drop(echo);
    drop(runtime);
    drop(listeners);
    drop(processes);
    bundle.private_key.zeroize();
}
