//! Opt-in real-SSH enrollment and retry timing through a disposable target (#169, #230).
use super::*;
use infraternal_plugin_ssh::auth_order::{AuthProvider, AutoAuth, NetworkProvider};
use infraternal_plugin_ssh::openssh::OpenSsh;
use infraternal_plugin_ssh::transport::TransferChoice;
use std::{io::Read, path::PathBuf, time::Instant};

#[path = "bootstrap_browser_tests.rs"]
mod browser;
#[path = "bootstrap_instant_tests.rs"]
mod instant;
static FULLY_JOINED: Mutex<Option<Instant>> = Mutex::new(None);

/// Own only this live controller's private fixture files until its bindings drop.
struct LiveFixtureDirectory(PathBuf);
impl Drop for LiveFixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A public test CA that the ordinary disposable target can read during preflight.
struct TestHttpsRoot(PathBuf);
impl TestHttpsRoot {
    fn write(root: &openssl::x509::X509Ref) -> Self {
        // Not std::env::temp_dir(): a dev shell points TMPDIR at a private
        // directory that the ordinary target account cannot traverse.
        let path = std::path::Path::new("/tmp").join(format!(
            "infraternal-breakit2-root-{}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, root.to_pem().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestHttpsRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn live_fixture(scratch: &std::path::Path) -> (LiveFixtureDirectory, Fixture) {
    let directory =
        LiveFixtureDirectory(scratch.join(format!("live-authority-{}", Uuid::new_v4())));
    // Use the runtime's private persistent pool, including its connection and
    // journal settings. A cancelled acquisition must not reset authority.
    let pool = crate::runtime::test_open_database(&directory.0)
        .await
        .unwrap();
    let (store, pool, prior) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    (
        directory,
        fixture_with_store(true, store, pool, prior).await,
    )
}

#[tokio::test]
async fn live_fixture_keeps_authority_after_connection_retirement() {
    let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/addhost-instant")
        },
        PathBuf::from,
    );
    // Retain the file owner until after the fixture and its pool handles drop.
    let (_directory, fixture) = live_fixture(&scratch).await;
    let connection = fixture.pool.acquire().await.unwrap();
    connection.close().await.unwrap();
    let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id='owner'")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
        .bind(crate::auth::hash(&fixture.cookie))
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(owners, 1);
    assert_eq!(sessions, 1);
}

// Fixture images are explicit trusted inputs, independent of release HTTP/signing tests.
struct FixturePayloads {
    binaries: BinaryPaths,
    session: Option<PathBuf>,
}
impl infraternal_plugin_ssh::install::PayloadSource for FixturePayloads {
    fn get(
        &self,
        architecture: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, PathBuf> {
        infraternal_plugin_ssh::install::PayloadSource::get(&self.binaries, architecture)
    }
    fn session(
        &self,
        _architecture: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, Option<PathBuf>> {
        Box::pin(async { Ok(self.session.clone()) })
    }
}
fn fixture_payload_source(
    binaries: BinaryPaths,
    session: Option<PathBuf>,
) -> Arc<dyn infraternal_plugin_ssh::install::PayloadSource> {
    Arc::new(FixturePayloads { binaries, session })
}

#[tokio::test]
async fn live_fixture_keeps_the_full_image_and_selects_the_explicit_session_image() {
    let full = PathBuf::from("full-fixture");
    let session = PathBuf::from("session-fixture");
    let binaries = BinaryPaths {
        x86_64: full.clone(),
        aarch64: full.clone(),
    };
    let legacy = fixture_payload_source(binaries.clone(), None);
    assert_eq!(
        legacy
            .get(infraternal_plugin_ssh::probe::Architecture::X86_64)
            .await
            .unwrap(),
        full
    );
    assert!(
        legacy
            .session(infraternal_plugin_ssh::probe::Architecture::X86_64)
            .await
            .unwrap()
            .is_none()
    );
    let instant = fixture_payload_source(binaries, Some(session.clone()));
    assert_eq!(
        instant
            .get(infraternal_plugin_ssh::probe::Architecture::X86_64)
            .await
            .unwrap(),
        full
    );
    assert_eq!(
        instant
            .session(infraternal_plugin_ssh::probe::Architecture::X86_64)
            .await
            .unwrap(),
        Some(session)
    );
}

#[test]
/// Check that timing probes observe the nested setup shell.
fn retry_lock_timing_runs_inside_the_nested_setup_shell() {
    let script = r#"# INFRATERNAL_SETUP_STEPS_V1
setup_step() {
    printf 'STEP %s\n' "$1"
    if sh -c "$2"; then :; else status=$?; printf 'FAIL %s %s\n' "$1" "$status"; exit 0; fi
}
lease_birth_field() {
    flock -n 7 || exit 73
}
setup_step upload 'exec 9< .; exec 7< Cargo.toml; flock -n 9 || exit 73; flock -n 7 || exit 73; flock -w 2 7 || exit 73'
"#;
    let trace_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("retry-lock-trace-{}", std::process::id()));
    let _ = std::fs::remove_file(&trace_path);
    std::fs::File::create(&trace_path).unwrap();
    let trace_path_text = trace_path.to_str().unwrap();
    let instrumented =
        instrument_retry_setup_with_timing(script, true, true, Some(trace_path_text));
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(instrumented)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "nested setup script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TRACE_SETUP_STEP upload "));
    assert!(!stdout.contains("TRACE_LOCK"));
    let trace = std::fs::read_to_string(&trace_path).unwrap();
    assert!(trace.contains("guard_try "));
    assert!(trace.contains("lease_try "));
    assert!(
        trace.contains("lease_wait "),
        "nested setup lock trace was incomplete: {trace}"
    );
    std::fs::remove_file(trace_path).unwrap();
}

#[test]
/// Keep the real upload exit status when timing setup.
fn retry_setup_timing_preserves_transfer_upload_status() {
    let script = r#"# INFRATERNAL_TRANSFER_SETUP_V1
setup_step() {
    printf 'STEP %s\n' "$1"
    if sh -c "$2"; then :; else status=$?; printf 'FAIL %s %s\n' "$1" "$status"; if [ "$1" = upload ]; then exit "$status"; fi; exit 0; fi
}
setup_step upload 'exit 31'
"#;
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(instrument_retry_setup_with_timing(
            script, true, false, None,
        ))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(31));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TRACE_SETUP_STEP upload "));
    assert!(stdout.contains("FAIL upload 31"));
}

/// The provisioning listener's socket admission is exercised directly below.
fn enrollment_acceptor(
    config: axum_server::tls_openssl::OpenSSLConfig,
) -> axum_server::tls_openssl::OpenSSLAcceptor<axum_server::accept::NoDelayAcceptor> {
    crate::server_tls::acceptor(config)
}

#[tokio::test]
async fn provisioning_https_uses_production_tcp_admission() {
    crate::server_tls::tests::assert_nodelay_with(enrollment_acceptor).await;
}

static FIRST_INSTALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static UPLOAD_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn timeline(step: &'static str, state: &'static str) {
    if std::env::var_os("ADDHOST_BROWSER_TIMELINE").is_some()
        || std::env::var_os("ADDHOST_RETRY_PHASE_TIMING").is_some()
    {
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        println!(
            "TIMELINE source=server step={step} state={state} epoch_ms={:.3}",
            epoch.as_secs_f64() * 1000.0
        );
    }
}

fn retry_phase_timing() -> bool {
    std::env::var_os("ADDHOST_RETRY_PHASE_TIMING").is_some()
}

fn retry_lock_timing() -> bool {
    std::env::var_os("ADDHOST_RETRY_LOCK_TIMING").is_some()
}

/// Add fixed, test-only markers around remote setup steps and setup-lock waits.
/// The real output parser never sees these markers; `strip_retry_trace` removes them.
fn instrument_retry_setup(script: &str) -> String {
    let trace_path = std::env::var("ADDHOST_RETRY_LOCK_TRACE_PATH").ok();
    instrument_retry_setup_with_timing(
        script,
        retry_phase_timing(),
        retry_lock_timing(),
        trace_path.as_deref(),
    )
}

fn instrument_retry_setup_with_timing(
    script: &str,
    enabled: bool,
    lock_timing_enabled: bool,
    trace_path: Option<&str>,
) -> String {
    let transfer_setup = script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n");
    let ordinary_setup = script.starts_with("# INFRATERNAL_SETUP_STEPS_V1\n");
    if !enabled || !(transfer_setup || ordinary_setup) {
        return script.to_owned();
    }
    let original_header = if transfer_setup {
        r#"setup_step() {
    printf 'STEP %s\n' "$1"
    if sh -c "$2"; then :; else status=$?; printf 'FAIL %s %s\n' "$1" "$status"; if [ "$1" = upload ]; then exit "$status"; fi; exit 0; fi
}
"#
    } else {
        r#"setup_step() {
    printf 'STEP %s\n' "$1"
    if sh -c "$2"; then :; else status=$?; printf 'FAIL %s %s\n' "$1" "$status"; exit 0; fi
}
"#
    };
    let timed_header = r#"trace_now() {
    IFS= read -r trace_uptime < /proc/uptime
    printf '%s' "${trace_uptime%% *}"
}
setup_step() {
    printf 'STEP %s\n' "$1"
    trace_started=$(trace_now)
    if sh -c "$2"; then trace_status=0; else trace_status=$?; fi
    trace_ended=$(trace_now)
    printf "TRACE_SETUP_STEP %s %s %s %s\n" "$1" "$trace_started" "$trace_ended" "$trace_status"
    if [ "$trace_status" -ne 0 ]; then printf 'FAIL %s %s\n' "$1" "$trace_status"; exit 0; fi
}
"#;
    let timed_transfer_header = r#"trace_now() {
    IFS= read -r trace_uptime < /proc/uptime
    printf '%s' "${trace_uptime%% *}"
}
setup_step() {
    printf 'STEP %s\n' "$1"
    trace_started=$(trace_now)
    if sh -c "$2"; then trace_status=0; else trace_status=$?; fi
    trace_ended=$(trace_now)
    printf "TRACE_SETUP_STEP %s %s %s %s\n" "$1" "$trace_started" "$trace_ended" "$trace_status"
    if [ "$trace_status" -ne 0 ]; then
        printf 'FAIL %s %s\n' "$1" "$trace_status"
        if [ "$1" = upload ]; then exit "$trace_status"; fi
        exit 0
    fi
}
"#;
    assert!(
        script.contains(original_header),
        "retry setup header changed; update the test timing adapter"
    );
    let mut instrumented = script.replacen(
        original_header,
        if transfer_setup {
            timed_transfer_header
        } else {
            timed_header
        },
        1,
    );
    let Some(trace_path) = trace_path.filter(|_| lock_timing_enabled) else {
        return instrumented;
    };
    let exported_trace_path = format!(
        "ADDHOST_RETRY_LOCK_TRACE_PATH={}\nexport ADDHOST_RETRY_LOCK_TRACE_PATH\ntrace_now() {{",
        infraternal_plugin_ssh::transport::shell_quote(trace_path)
    );
    instrumented = instrumented.replacen("trace_now() {", &exported_trace_path, 1);

    // Setup steps run nested shells, so write lock timings to a private test
    // receipt instead of the setup protocol stream.
    let lock_prelude = "lease_birth_field() {";
    assert!(
        instrumented.contains(lock_prelude),
        "retry lock prelude changed; update the test timing adapter"
    );
    let lock_call = |name: &str, call: &str| {
        format!(
            "{{ trace_lock_started=$(IFS= read -r trace_uptime < /proc/uptime; printf \"%s\" \"${{trace_uptime%% *}}\"); if command {call}; then trace_lock_status=0; else trace_lock_status=$?; fi; trace_lock_ended=$(IFS= read -r trace_uptime < /proc/uptime; printf \"%s\" \"${{trace_uptime%% *}}\"); printf \"%s %s %s %s\\n\" \"{name}\" \"$trace_lock_started\" \"$trace_lock_ended\" \"$trace_lock_status\" >> \"$ADDHOST_RETRY_LOCK_TRACE_PATH\" 2>/dev/null || true; [ \"$trace_lock_status\" -eq 0 ]; }} || exit 73"
        )
    };
    instrumented = instrumented
        .replace(
            "flock -n 9 || exit 73",
            &lock_call("guard_try", "flock -n 9"),
        )
        .replace(
            "flock -n 7 || exit 73",
            &lock_call("lease_try", "flock -n 7"),
        )
        .replace(
            "flock -w 2 7 || exit 73",
            &lock_call("lease_wait", "flock -w 2 7"),
        );
    assert!(
        instrumented.contains("lease_wait"),
        "retry lock wrapper was not inserted"
    );
    instrumented
}

/// Remove bounded test-only phase receipts before the production setup decoder sees stdout.
fn strip_retry_trace(stdout: &mut Vec<u8>) {
    if !retry_phase_timing() {
        return;
    }
    let mut filtered = Vec::with_capacity(stdout.len());
    for line in stdout.split_inclusive(|byte| *byte == b'\n') {
        let Some(receipt) = line.strip_prefix(b"TRACE_") else {
            filtered.extend_from_slice(line);
            continue;
        };
        let Ok(receipt) = std::str::from_utf8(receipt) else {
            filtered.extend_from_slice(line);
            continue;
        };
        let fields = receipt.split_whitespace().collect::<Vec<_>>();
        let parsed = match fields.as_slice() {
            ["SETUP_STEP", step, start, end, status]
                if ["upload", "join", "install", "start", "linger"].contains(step) =>
            {
                Some((format!("setup_{step}"), *start, *end, *status))
            }
            ["LOCK", step, start, end, status]
                if ["guard_try", "lease_try", "lease_wait"].contains(step) =>
            {
                Some((format!("setup_lock_{step}"), *start, *end, *status))
            }
            _ => None,
        };
        let Some((step, start, end, status)) = parsed else {
            filtered.extend_from_slice(line);
            continue;
        };
        let (Ok(start), Ok(end), Ok(status)) = (
            start.parse::<f64>(),
            end.parse::<f64>(),
            status.parse::<i32>(),
        ) else {
            filtered.extend_from_slice(line);
            continue;
        };
        if !start.is_finite() || !end.is_finite() || end < start || !(0..=255).contains(&status) {
            filtered.extend_from_slice(line);
            continue;
        }
        println!("TIMELINE source=target step={step} state=start uptime_s={start:.3}");
        println!("TIMELINE source=target step={step} state=end uptime_s={end:.3}");
        println!(
            "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
            (end - start) * 1000.0,
            status == 0
        );
    }
    *stdout = filtered;
}

static RETRY_LOCK_TRACE_REPORTED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Print only complete fixed lock receipts appended by the colocated native fixture.
fn report_retry_lock_trace(path: &std::path::Path) {
    let Ok(receipts) = std::fs::read_to_string(path) else {
        return;
    };
    let bytes = receipts.as_bytes();
    let offset = loop {
        let previous = RETRY_LOCK_TRACE_REPORTED.load(Ordering::Acquire);
        if previous >= bytes.len() {
            return;
        }
        if RETRY_LOCK_TRACE_REPORTED
            .compare_exchange(previous, bytes.len(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break previous;
        }
    };
    let Ok(pending) = std::str::from_utf8(&bytes[offset..]) else {
        return;
    };
    for line in pending.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let [step, start, end, status] = fields.as_slice() else {
            continue;
        };
        if !["guard_try", "lease_try", "lease_wait"].contains(step) {
            continue;
        }
        let (Ok(start), Ok(end), Ok(status)) = (
            start.parse::<f64>(),
            end.parse::<f64>(),
            status.parse::<i32>(),
        ) else {
            continue;
        };
        if !start.is_finite() || !end.is_finite() || end < start || !(0..=255).contains(&status) {
            continue;
        }
        let step = format!("setup_lock_{step}");
        println!("TIMELINE source=target step={step} state=start uptime_s={start:.3}");
        println!("TIMELINE source=target step={step} state=end uptime_s={end:.3}");
        println!(
            "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
            (end - start) * 1000.0,
            status == 0
        );
    }
}

/// Time only the delegated production operation; emit no arguments or payload.
async fn measured<T>(step: &'static str, operation: Operation<'_, T>) -> Result<T, Failure> {
    let started = Instant::now();
    timeline(step, "start");
    let result = operation.await;
    timeline(step, "end");
    println!(
        "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
        started.elapsed().as_secs_f64() * 1000.0,
        result.is_ok()
    );
    result
}

/// Name test SSH receipts from the command that actually crossed the transport.
fn breakit2_step(script: &str, input: &Input<'_>) -> &'static str {
    match input {
        Input::Negotiated { .. } | Input::PayloadAndInvitation { .. } => "upload_setup",
        Input::Bytes(_) if script.contains("zstd -dc >") || script.contains("gzip -dc >") => {
            "upload"
        }
        Input::File(_) | Input::Transfer(_) => "upload",
        Input::Bytes(_) if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1") => "reuse_setup",
        Input::Bytes(_) if script.starts_with("# INFRATERNAL_SETUP_STEPS_V1") => "setup",
        Input::Bytes(_) => "join",
        Input::Empty if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) => "check",
        Input::Empty if script.contains("ln \"$cache/payload\" \"$stage/payload\"") => {
            "reuse_payload"
        }
        Input::Empty if script.contains("validate_cache") => "payload_lookup",
        Input::Empty if script.contains("validate_receipt") => "rollback",
        Input::Empty if script.contains("enable --now") => "start",
        Input::Empty if script.contains("enable-linger") => "linger",
        Input::Empty if script.contains("stage/activating") => "install",
        Input::Empty if script.contains("prepare-join-key") => "connect",
        Input::Signal(_) => "commit",
        Input::Empty => "command",
    }
}

/// Trust the disposable HTTPS root for the join-key preflight command only.
///
/// That preflight verifies the public origin with system roots. OpenSSL's default verify
/// paths honour `SSL_CERT_FILE`, so the harness points it at the test CA instead of
/// adding a trust hook to the shipped binary or the target's system store.
fn breakit2_test_https_root(script: &str, root: Option<&std::path::Path>) -> String {
    if !script.contains("prepare-join-key") {
        return script.to_owned();
    }
    let Some(root) = root else {
        return script.to_owned();
    };
    let root = root.to_str().expect("test HTTPS root path is UTF-8");
    let quoted = format!("'{}'", root.replace('\'', "'\\''"));
    format!("export SSL_CERT_FILE={quoted}\n{script}")
}

#[test]
/// Classify join-key preflight under connection timing.
fn breakit2_step_labels_join_key_preflight_as_connect() {
    let script = "payload agent --data state prepare-join-key https://server:4930";

    assert_eq!(breakit2_step(script, &Input::Empty), "connect");
    assert_eq!(
        breakit2_step("unclassified command", &Input::Empty),
        "command"
    );
    let (sender, signal) = tokio::sync::oneshot::channel();
    drop(sender);
    assert_eq!(breakit2_step("commit", &Input::Signal(signal)), "commit");
}

#[test]
/// Recognize both supported setup script headers.
fn breakit2_step_labels_both_setup_headers_as_setup() {
    let transfer = "# INFRATERNAL_TRANSFER_SETUP_V1\ntransfer_setup";
    let setup = "# INFRATERNAL_SETUP_STEPS_V1\nsetup_step";

    assert_eq!(
        breakit2_step(transfer, &Input::Bytes(b"fixture")),
        "reuse_setup"
    );
    assert_eq!(breakit2_step(setup, &Input::Bytes(b"fixture")), "setup");
}

#[test]
/// Restrict fixture TLS trust to its join-key command.
fn breakit2_test_https_root_is_scoped_to_join_key_preflight() {
    let path = std::path::Path::new("/tmp/test 'root.pem");
    let preflight = "payload agent --data state prepare-join-key https://server:4930";
    let command = breakit2_test_https_root(preflight, Some(path));

    assert!(command.starts_with("export SSL_CERT_FILE='"));
    assert!(command.contains("test '\\''root.pem'\n"));
    assert!(command.ends_with(preflight));
    assert_eq!(
        breakit2_test_https_root("other command", Some(path)),
        "other command"
    );
    assert_eq!(breakit2_test_https_root(preflight, None), preflight);
}

struct TimedSession {
    inner: Arc<dyn SshSession>,
    test_https_root: Option<PathBuf>,
}
impl SshSession for TimedSession {
    fn session_bridge(&self) -> bool {
        std::env::var_os("ADDHOST_INSTANT").is_some() && self.inner.session_bridge()
    }
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        if script.contains("setup_step upload") {
            UPLOAD_STARTED.store(true, Ordering::SeqCst);
        }
        let step = if script.contains("__ssh-session --state") {
            "reattach"
        } else {
            "launch_channel_helper"
        };
        Box::pin(measured(step, self.inner.stream(script)))
    }

    fn check_stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<
        'a,
        (
            CommandOutput,
            Option<infraternal_plugin_ssh::install::Checked>,
        ),
    > {
        Box::pin(measured(
            "check_and_retain_channel",
            self.inner.check_stream(script),
        ))
    }
    fn setup_steps(&self) -> bool {
        self.inner.setup_steps()
    }
    fn authentication(&self) -> Option<infraternal_plugin_ssh::auth_order::Authentication> {
        self.inner.authentication()
    }
    fn trust_lookup(&self) -> Option<String> {
        self.inner.trust_lookup()
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let step = breakit2_step(script, &input);
            if matches!(step, "upload" | "upload_setup") {
                UPLOAD_STARTED.store(true, Ordering::SeqCst);
            }
            // A Replace or Re-enroll that fails after the stuck install was set
            // aside: refuse the new enrollment before it runs (#305 P1-1).
            if std::env::var_os("BREAKIT2_FAIL_JOIN").is_some()
                && script.contains("agent --data \"$stage/state\" join ")
            {
                println!("STUCK breakit2 inject=join_refusal step={step}");
                return Err(Failure::install(
                    "The fixture refused the enrollment after the set-aside.",
                ));
            }
            if step == "install"
                && std::env::var_os("BREAKIT2_RETRY").is_some()
                && FIRST_INSTALL.swap(false, Ordering::SeqCst)
            {
                println!("RETRY breakit2 inject=first_install_refusal uploaded_and_joined=true");
                return Err(Failure::install(
                    "The fixture refused its first install boundary.",
                ));
            }
            let negotiated_sizes = if let Input::Negotiated {
                raw, gzip, zstd, ..
            } = &input
            {
                Some((
                    match raw {
                        infraternal_plugin_ssh::transport::PayloadInput::Bytes(bytes) => {
                            bytes.len() as u64
                        }
                        infraternal_plugin_ssh::transport::PayloadInput::File { size, .. } => *size,
                    },
                    gzip.map_or(0, |bytes| bytes.len() as u64),
                    zstd.map_or(0, |bytes| bytes.len() as u64),
                ))
            } else {
                None
            };
            let mut file_bytes = if let Input::PayloadAndInvitation { payload, .. }
            | Input::Transfer(payload) = &input
            {
                Some(match payload {
                    infraternal_plugin_ssh::transport::PayloadInput::Bytes(bytes) => {
                        bytes.len() as u64
                    }
                    infraternal_plugin_ssh::transport::PayloadInput::File { size, .. } => *size,
                })
            } else if let Input::File(path) = &input {
                path.metadata().ok().map(|metadata| metadata.len())
            } else if let Input::Bytes(bytes) = &input {
                (step == "upload").then(|| u64::try_from(bytes.len()).unwrap())
            } else {
                None
            };
            let lock_trace_path = if retry_lock_timing() {
                std::env::var_os("ADDHOST_RETRY_LOCK_TRACE_PATH").map(PathBuf::from)
            } else {
                None
            };
            // Refuse activation only after the real staged enrollment has run.
            // A compound command's outer transport receipt remains successful;
            // its fixed FAIL receipt is classified by the production decoder.
            let instrumented = instrument_retry_setup(script);
            let refusal_candidate = matches!(step, "setup" | "upload_setup" | "reuse_setup")
                && std::env::var_os("BREAKIT2_RETRY").is_some()
                && instrumented.contains("if sh -c \"$2\"; then");
            let refused =
                (refusal_candidate && FIRST_INSTALL.swap(false, Ordering::SeqCst)).then(|| {
                    println!("RETRY breakit2 inject=first_install_refusal boundary=install");
                    instrumented.replacen(
                        "if sh -c \"$2\"; then",
                        "if [ \"$1\" != install ] && sh -c \"$2\"; then",
                        1,
                    )
                });
            let command = refused.as_deref().unwrap_or(&instrumented);
            let test_https_root = if step == "connect" {
                self.test_https_root.as_deref()
            } else {
                None
            };
            let command = breakit2_test_https_root(command, test_https_root);
            let started = Instant::now();
            let mut result = self.inner.run(&command, input).await;
            if let Some(path) = lock_trace_path.as_deref() {
                report_retry_lock_trace(path);
            }
            let failed_start = result.as_ref().is_ok_and(|output| {
                output
                    .stdout
                    .split_inclusive(|byte| *byte == b'\n')
                    .any(|line| line.starts_with(b"FAIL start "))
            }) || result.as_ref().is_err_and(|failure| {
                matches!(
                    failure.failed_step,
                    Some(infraternal_plugin_ssh::model::InstallStep::Start)
                )
            });
            if failed_start && retry_phase_timing() {
                let diagnostic = r#"if [ "$(id -u)" = 0 ]; then
    manager=systemctl
    unit=/etc/systemd/system/infraternal-agent.service
else
    manager="systemctl --user"
    unit="$HOME/.config/systemd/user/infraternal-agent.service"
fi
if [ -f "$unit" ] && [ ! -L "$unit" ]; then unit_state=present; else unit_state=missing; fi
state=$($manager show --property=LoadState --property=UnitFileState --property=ActiveState --property=SubState --property=Result --property=ExecMainCode --property=ExecMainStatus --value infraternal-agent.service 2>/dev/null | tr '\n' ' ')
if [ -z "$state" ]; then state=unavailable; fi
printf 'DIAG_START unit_file=%s state=%s\n' "$unit_state" "$state"
"#;
                if let Ok(output) = self.inner.run(diagnostic, Input::Empty).await {
                    for line in output.stdout.split(|byte| *byte == b'\n') {
                        if line.starts_with(b"DIAG_START ")
                            && line.len() <= 256
                            && line.iter().all(|byte| {
                                byte.is_ascii_alphanumeric() || b" _=-\r".contains(byte)
                            })
                        {
                            println!("{}", String::from_utf8_lossy(line));
                        }
                    }
                }
            }
            if let Ok(output) = &mut result {
                strip_retry_trace(&mut output.stdout);
            }
            if let (Some((raw, gzip, zstd)), Ok(output)) = (negotiated_sizes, &result) {
                let choice = output
                    .stdout
                    .split_inclusive(|byte| *byte == b'\n')
                    .find_map(TransferChoice::parse);
                file_bytes = match choice {
                    Some(TransferChoice::Raw) => Some(raw),
                    Some(TransferChoice::Gzip) => Some(gzip),
                    Some(TransferChoice::Zstd) => Some(zstd),
                    _ => None,
                };
            }
            if let Some(bytes) = file_bytes {
                println!(
                    "METRIC breakit2 file_input_bytes={bytes} accepted={}",
                    result.is_ok()
                );
            }

            println!(
                "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
                started.elapsed().as_secs_f64() * 1000.0,
                result.is_ok()
            );
            result
        })
    }

    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        timeout: Duration,
    ) -> Operation<'a, CommandOutput> {
        // Keep the live timing adapter transparent to the commit's bounded
        // deadline while preserving the same commit receipt as ordinary runs.
        Box::pin(measured(
            "commit",
            self.inner.run_with_timeout(script, input, timeout),
        ))
    }
}
pub(super) struct TimedTransport {
    pub(super) adapter: OpenSsh,
    pub(super) test_https_root: Option<PathBuf>,
}
impl SshTransport for TimedTransport {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            let step = if matches!(credentials, Credentials::Network) {
                "network_discovery"
            } else {
                "key_sign_in"
            };
            let started = Instant::now();
            timeline(step, "start");
            let result = self.adapter.open(destination, credentials, mesh).await;
            timeline(step, "end");
            println!(
                "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
                started.elapsed().as_secs_f64() * 1000.0,
                result.is_ok()
            );
            Ok(Arc::new(TimedSession {
                inner: result?,
                test_https_root: self.test_https_root.clone(),
            }) as Arc<dyn SshSession>)
        })
    }
}

struct FixtureProvider(Mutex<Option<Secret>>);
impl AuthProvider for FixtureProvider {
    fn network(&self) -> Option<NetworkProvider> {
        None
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async move {
            let key = self.0.lock().unwrap().take();
            println!(
                "DIAG breakit2 auth_provider=user_key key_present={}",
                key.is_some()
            );
            Ok(key.map(|key| Credentials::PrivateKey {
                key,
                passphrase: None,
            }))
        })
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
}
pub(super) struct FixtureTransport {
    pub(super) transport: Arc<dyn SshTransport>,
    pub(super) private: Mutex<Option<Secret>>,
}
impl SshTransport for FixtureTransport {
    fn open(
        &self,
        destination: Destination,
        _: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            // Feed only a generated one-use identity to the production automatic
            // order: real network-only refusal, then lazy key authentication.
            // Browser passkey unlocking is outside this native fixture.
            let key = self.private.lock().unwrap().take();
            println!("DIAG breakit2 transport_open key_present={}", key.is_some());
            AutoAuth::new(self.transport.clone())
                .open(
                    destination,
                    Credentials::Automatic(Arc::new(FixtureProvider(Mutex::new(key)))),
                    mesh,
                )
                .await
        })
    }
}

// Keep diagnosis in a test adapter: the production backend/functions remain
// unchanged, and this prints only fixed boundaries and typed local errors.
pub(super) type CanaryHook = Arc<dyn Fn() -> Result<(), Failure> + Send + Sync>;
pub(super) type CanaryReturnHook = Arc<
    dyn Fn(Uuid, Option<Failure>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
pub(super) struct ObservedBackend(
    pub(super) Arc<RemoteBackend>,
    pub(super) Option<CanaryHook>,
    pub(super) Option<CanaryReturnHook>,
);

/// Seed the prior host record only after the real target presents its existing key digest.
/// The live fixture owns the user files; the disposable server owns this matching ledger row.
/// It is seeded at Check time, where the server decides whether to offer replacement (#305).
async fn seed_replacement_host(
    backend: &RemoteBackend,
    authority: &Authority,
    request: &StuckInstallCheck<'_>,
) {
    let digest = request
        .enrolled
        .expect("the live replacement fixture reports its enrolled identity")
        .digest;
    let (mode, execution_uid) = match request.target.mode {
        InstallMode::Rootless => (Mode::Rootless, i64::from(request.check.uid)),
        InstallMode::Root => (Mode::Rootful, 0),
    };
    let address = match &request.target.address {
        infraternal_plugin_ssh::model::TargetAddress::Manual(address) => address,
        infraternal_plugin_ssh::model::TargetAddress::Discovered(_) => {
            panic!("the live replacement fixture needs a manual address")
        }
    };
    let now = unix_now().unwrap();
    sqlx::query(
        "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(request.host.as_bytes().as_slice())
    .bind(&authority.owner)
    .bind(mode.as_str())
    .bind(execution_uid)
    .bind(now)
    .execute(&backend.issuer.store().0)
    .await
    .unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,?,?)")
        .bind(request.host.as_bytes().as_slice())
        .bind(address)
        .bind(request.lookup.as_deref())
        .execute(&backend.issuer.store().0)
        .await
        .unwrap();
    let _ = backend
        .issuer
        .store()
        .issue(&authority.owner, request.host, mode, now, &digest)
        .await
        .unwrap();
}

impl Backend for ObservedBackend {
    fn enrollment_origin(&self) -> Option<String> {
        self.0.enrollment_origin()
    }
    /// The server's own D359 answer; without this the trait's default (never)
    /// would refuse every Take over in the live replay.
    fn takeover_allowed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, bool> {
        self.0.takeover_allowed(a, h)
    }
    fn observe_link(&self, a: &Authority, h: Uuid, round_trip: Duration) {
        self.0.observe_link(a, h, round_trip);
    }
    fn setup_commit_timeout(&self, a: &Authority, h: Uuid) -> Option<Duration> {
        self.0.setup_commit_timeout(a, h)
    }
    fn early_terminal(&self) -> bool {
        std::env::var_os("ADDHOST_INSTANT").is_some() && self.0.early_terminal()
    }
    fn publish_terminal<'a>(
        &'a self,
        a: &'a Authority,
        h: Uuid,
        id: Uuid,
        channel: infraternal_plugin_ssh::duplex::Duplex,
        session: Arc<dyn SshSession>,
    ) -> Operation<'a, ()> {
        Box::pin(measured(
            "publish_terminal",
            self.0.publish_terminal(a, h, id, channel, session),
        ))
    }
    fn authority_cancelled<'a>(&'a self, a: &'a Authority) -> Operation<'a, ()> {
        self.0.authority_cancelled(a)
    }
    fn setup_cancelled(&self, h: Uuid) -> Operation<'_, ()> {
        self.0.setup_cancelled(h)
    }
    fn reissue_invitation<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, JoinMaterial> {
        Box::pin(measured(
            "reissue_invitation",
            self.0.reissue_invitation(a, h),
        ))
    }
    fn check_stuck_install<'a>(
        &'a self,
        authority: &'a Authority,
        request: StuckInstallCheck<'a>,
    ) -> Operation<'a, StuckInstall> {
        let backend = self.0.clone();
        Box::pin(async move {
            // BREAKIT2_REPLACE_STUCK replays a stuck install this server
            // enrolled; without it the fixture is another server's (D335).
            // Seeded once: the attempt asks again right before the stop (#305 P1-1).
            if std::env::var_os("BREAKIT2_REPLACE_STUCK").is_some() {
                let seeded: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=?)")
                        .bind(request.host.as_bytes().as_slice())
                        .fetch_one(&backend.issuer.store().0)
                        .await
                        .unwrap();
                if !seeded {
                    seed_replacement_host(&backend, authority, &request).await;
                }
            }
            let verdict = backend.check_stuck_install(authority, request).await;
            println!("STUCK breakit2 verdict={verdict:?}");
            verdict
        })
    }
    fn reissue_stuck_install<'a>(
        &'a self,
        authority: &'a Authority,
        request: StuckInstallRequest<'a>,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        self.0.reissue_stuck_install(authority, request, register)
    }
    fn stop(&self) -> Operation<'_, ()> {
        self.0.stop()
    }
    fn owns_failed_setup<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        host: Uuid,
        lookup: Option<String>,
    ) -> Operation<'a, bool> {
        self.0.owns_failed_setup(a, t, c, host, lookup)
    }

    fn record_failure(&self, t: &Target, h: Option<Uuid>, p: Step, f: &Failure) {
        // Fixed public fields only: the typed kind, step, status and boundary tail.
        println!(
            "FAILURE breakit2 phase={p:?} kind={:?} step={:?} status={:?} tail={:?}",
            f.kind, f.failed_step, f.exit_status, f.log_tail
        );
        self.0.record_failure(t, h, p, f);
    }
    fn invitation_with_trust<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        lookup: Option<String>,
    ) -> Operation<'a, JoinMaterial> {
        self.0.invitation_with_trust(a, t, c, lookup)
    }
    fn invitation_registered<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        lookup: Option<String>,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(measured(
            "invitation",
            self.0.invitation_registered(a, t, c, lookup, register),
        ))
    }
    // Since D291 a fresh install's invitation is bound to the key that
    // join-key preparation proved; without this the replay saw the trait
    // default ("SSH host-key proof is unavailable").
    fn invitation_registered_with_key<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        lookup: Option<String>,
        binding: PreparedHostKey,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(measured(
            "invitation",
            self.0
                .invitation_registered_with_key(a, t, c, lookup, binding, register),
        ))
    }
    fn resolve<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(measured("resolve", self.0.resolve(a, t, c)))
    }
    fn invitation<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        self.0.invitation(a, t, c)
    }
    fn connected_facts<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(measured("facts", self.0.connected_facts(a, h)))
    }
    fn terminal_canary<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            if let Some(before_canary) = &self.1 {
                before_canary()?;
            }
            if self.1.is_some() || self.2.is_some() || std::env::var_os("BREAKIT2_DIAG").is_none() {
                // Optional observations run only after the unmodified production
                // canary returns, before Bootstrap can roll back its authority.
                let result = measured("readiness", self.0.terminal_canary(a, h)).await;
                if let Some(after_canary) = &self.2 {
                    after_canary(h, result.as_ref().err().cloned()).await;
                }
                return result;
            }
            let actor = self.0.actor(a, h).await?;
            let result = actor
                .open_readiness(TerminalSize {
                    cols: 80,
                    rows: 24,
                    px_w: 0,
                    px_h: 0,
                })
                .await;
            println!(
                "DIAG breakit2 canary_open_ok={} error={:?}",
                result.is_ok(),
                result.as_ref().err()
            );
            let session = result.map_err(|_| unavailable())?;
            self.0.attempts.lock().unwrap().get_mut(&h).unwrap().canary =
                Some((actor.clone(), session, [2, 4]));
            let output = tokio::time::timeout(
                Duration::from_secs(10),
                diagnostic_canary_output(&actor, session),
            )
            .await
            .unwrap_or_else(|_| Err(unavailable()));
            println!("DIAG breakit2 canary_output_ok={}", output.is_ok());
            if output.is_ok() {
                self.0.attempts.lock().unwrap().get_mut(&h).unwrap().canary = None;
                println!("DIAG breakit2 canary_cleanup_ok=true primary_exit=true");
            } else {
                let cleanup = finish_canary(&actor, session, 4).await;
                println!("DIAG breakit2 canary_cleanup_ok={}", cleanup.is_ok());
            }
            output
        })
    }
    fn cleanup_sessions<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.cleanup_sessions(a, h)
    }
    fn retire_failed(&self, a: &Authority, h: Uuid) -> Result<(), Failure> {
        self.0.retire_failed(a, h)
    }
    fn failed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(measured("authority_retirement", self.0.failed(a, h)))
    }
    fn completed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            measured("authority_commit", self.0.completed(a, h)).await?;
            *FULLY_JOINED.lock().unwrap() = Some(Instant::now());
            Ok(())
        })
    }
}

#[tokio::test]
async fn observed_backend_preserves_the_public_enrollment_origin() {
    let fixture = fixture(false).await;
    let backend = ObservedBackend(fixture.backend.clone(), None, None);

    assert_eq!(
        backend.enrollment_origin().as_deref(),
        Some("https://remote.example.test")
    );
}

// Mirror the fixed production canary only for opt-in boundary diagnostics.
// No remote text or capability is logged; normal measurements delegate unchanged.
async fn diagnostic_canary_output(actor: &EmbeddedAgent, session: [u8; 16]) -> Result<(), Failure> {
    use infraternal_protocol::{Frame, encode_muxed_frame_into};
    let (handle, mut output) = actor
        .attach(session, 0, 0, 2)
        .await
        .map_err(|_| unavailable())?
        .split();
    println!("DIAG breakit2 canary_attach_ok=true");
    let marker = "infraternal-ready";
    // The fixed non-login command waits for input so its output cannot precede
    // attachment. No user shell startup or echoed marker supplies readiness.
    let command = "\n";
    let mut wire = Vec::new();
    let delayed_credit = std::env::var_os("BREAKIT2_DELAY_CREDIT").is_some();
    let input = Frame::Input {
        in_seq: 0,
        bytes: command.as_bytes(),
    };
    let credit = Frame::Credit { bytes: 65536 };
    let frames = if delayed_credit {
        [input, credit]
    } else {
        [credit, input]
    };
    for frame in frames {
        // A valid unfunded attachment makes owner EOF win while final PTY bytes
        // remain queued. Normal timing runs preserve the production input order.
        if delayed_credit && matches!(frame, Frame::Credit { .. }) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Input is leg A (odd); the attachment maps it onto its even leg-B stream.
        encode_muxed_frame_into(1, &frame, &mut wire).map_err(|_| unavailable())?;
        handle
            .send_frame(bytes::Bytes::copy_from_slice(&wire))
            .await
            .map_err(|_| unavailable())?;
    }
    let mut received = Vec::new();
    let mut confirmed = false;
    while let Some(event) = output.recv().await {
        match event {
            // A fast first command may be included in the initial faithful
            // repaint; snapshots carry confirmed PTY output just as deltas do.
            TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => {
                if received.len() + bytes.len() > 65536 {
                    return Err(unavailable());
                }
                println!("DIAG breakit2 confirmed_output_bytes={}", bytes.len());
                received.extend_from_slice(&bytes);
                confirmed = received
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes());
            }
            TerminalOutput::Event { event_json } => {
                let notice: serde_json::Value =
                    serde_json::from_slice(&event_json).map_err(|_| unavailable())?;
                if notice["type"] == "terminal.exited" {
                    let exited = notice["session_id"]
                        .as_str()
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .is_some_and(|id| id.as_bytes() == &session);
                    println!(
                        "DIAG breakit2 primary_exit_matches={exited} marker_found={confirmed}"
                    );
                    return if confirmed && exited && notice["status"] == 0 {
                        Ok(())
                    } else {
                        Err(unavailable())
                    };
                }
            }
            TerminalOutput::Closed { code, .. } => {
                println!("DIAG breakit2 output_closed_code={code}");
                break;
            }
            TerminalOutput::Ack { .. }
            | TerminalOutput::Reconnecting
            | TerminalOutput::LinkDoubt
            | TerminalOutput::Recovered
            | TerminalOutput::RouteExpired => {}
        }
    }
    println!("DIAG breakit2 canary_stream_ended=true marker_found=false");
    Err(unavailable())
}

#[tokio::test]
#[ignore = "#169 live disposable Docker target; invoke docs/verification/addhost-breakit2/measure.py"]
/// Exercise installation, enrollment and terminal input on a disposable SSH host.
async fn breakit2_live_ssh_install_join_and_terminal() {
    let scratch = PathBuf::from(std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap());
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    let address = std::env::var("BREAKIT2_TARGET").unwrap();
    let controller_ip = std::env::var("BREAKIT2_CONTROLLER_IP")
        .unwrap_or_else(|_| "10.69.69.125".into())
        .parse::<std::net::IpAddr>()
        .unwrap();
    let mode = if std::env::var("BREAKIT2_MODE").unwrap_or_default() == "root" {
        InstallMode::Root
    } else {
        InstallMode::Rootless
    };
    let mut private = Vec::new();
    std::io::stdin()
        .take(24577)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 24576);
    let (_directory, mut f) = live_fixture(&scratch).await;
    let server_name =
        std::env::var("BREAKIT2_SERVER_NAME").unwrap_or_else(|_| "addhost-breakit2.test".into());
    let (identity, material) = crate::remote_runtime::tests::server_material_for_name(&server_name);
    let test_https_root = TestHttpsRoot::write(material.issuer());
    let source: Arc<dyn CaKeySource> = Arc::new(Signer(Some(material.clone())));
    let hosts = RemoteHosts::from_source(Some(source.clone()));
    let store = f.backend.issuer.store().clone();
    let listeners = crate::remote_runtime::RemoteListeners::start(
        std::net::SocketAddr::new(controller_ip, 0),
        &identity,
        &[material.issuer().clone()],
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let local_endpoint = listeners.local_addr().unwrap();
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: local_endpoint,
        server_name: server_name.clone(),
    };
    let auth = Auth::new(
        f.pool.clone(),
        &server_name,
        &format!("https://{server_name}:4930"),
    )
    .await
    .unwrap();
    let service = EnrollmentService {
        source: source.clone(),
        endpoint: endpoint.clone(),
    };
    let http = crate::remote_http::router_with_store(
        auth.clone(),
        f.pool.clone(),
        store.clone(),
        source,
        endpoint,
    )
    .merge(crate::remote_agent_http::router(
        hosts.clone(),
        store.clone(),
    ));
    let http_tls = axum_server::tls_openssl::OpenSSLConfig::from_der(
        &identity.certificate.to_der().unwrap(),
        &identity.key.private_key_to_der().unwrap(),
    )
    .unwrap();
    f.backend = Arc::new(RemoteBackend {
        base: PendingRemoteRuntime {
            auth: Some(auth.clone()),
            key: Arc::new(crate::ssh_key::UnavailableSshKey),
        },
        issuer: InvitationIssuer::new(auth.clone(), f.pool.clone(), store, service),
        hosts: hosts.clone(),
        attempts: Mutex::default(),
        sessions_changed: Mutex::default(),
    });
    let timeout_retry = std::env::var_os("BREAKIT2_TIMEOUT_RETRY").is_some();
    // Confirm the stuck-install action: replace (this server's host) or
    // join as a new host (another server's, D335).
    let replace_stuck = std::env::var_os("BREAKIT2_REPLACE_STUCK").is_some()
        || std::env::var_os("BREAKIT2_REENROLL_STUCK").is_some();
    let retry_private =
        (timeout_retry || std::env::var_os("BREAKIT2_RETRY").is_some()).then(|| private.clone());
    // Adding the same host a second time must name the existing host (#189).
    let readd_private = std::env::var_os("BREAKIT2_READD")
        .is_some()
        .then(|| private.clone());
    // D337: after the join, leave the install stuck with a terminal open, then
    // Replace it and require that terminal in the new infraternal agent.
    let replace_private = std::env::var_os("BREAKIT2_REPLACE_AFTER_JOIN")
        .is_some()
        .then(|| private.clone());
    let transport = Arc::new(FixtureTransport {
        transport: Arc::new(TimedTransport {
            adapter: OpenSsh {
                ssh: scratch.join("ssh"),
                ssh_agent: "/usr/bin/ssh-agent".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
                askpass_binary: binary.clone(),
                tcp_connector: Some(binary.clone()),
                scratch: scratch.clone(),
                command_timeout: Duration::from_secs(30),
            },
            test_https_root: Some(test_https_root.path().to_owned()),
        }),
        private: Mutex::new(Some(Secret::new(private))),
    });
    let binaries = BinaryPaths {
        x86_64: binary.clone(),
        aarch64: binary.clone(),
    };
    let session_image =
        std::env::var_os("INFRATERNAL_REMOTE_TEST_SESSION_BINARY").map(PathBuf::from);
    let runner = Bootstrap::new(
        transport.clone(),
        Arc::new(ObservedBackend(f.backend.clone(), None, None)),
        BinaryPaths {
            x86_64: binary.clone(),
            aarch64: binary,
        },
    )
    .with_payload_source(fixture_payload_source(binaries, session_image));
    let prepared = Instant::now();
    runner.prepare_payloads().await;
    println!(
        "METRIC payload_prepare startup_ms={:.3}",
        prepared.elapsed().as_secs_f64() * 1000.0
    );
    if std::env::var_os("ADDHOST_BROWSER_TIMELINE").is_some() {
        browser::run(&f, auth, runner, http, http_tls, controller_ip, &address).await;
        drop(listeners);
        return;
    }
    let server = tokio::spawn(
        axum_server::bind(std::net::SocketAddr::new(controller_ip, 4930))
            .acceptor(enrollment_acceptor(http_tls))
            .serve(http.into_make_service_with_connect_info::<std::net::SocketAddr>()),
    );
    let started = Instant::now();
    *FULLY_JOINED.lock().unwrap() = None;
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "live".into(),
                address: TargetAddress::Manual(address.clone()),
                credential: None,
                mode,
                root_consent: mode == InstallMode::Root,
            }],
            None,
        )
        .unwrap();
    if std::env::var_os("BREAKIT2_CANCEL_UPLOAD").is_some() {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !UPLOAD_STARTED.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        println!("CANCEL breakit2 boundary=upload action=drop_batch");
        drop(batch);
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if f.backend.attempts.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        println!("CANCEL breakit2 active_hosts={active} prior_hosts=1 attempts=0");
        server.abort();
        drop(listeners);
        assert_eq!(active, 1, "cancel must retire enrollment authority");
        return;
    }
    if let Some(delay) = std::env::var("BREAKIT2_CANCEL_AFTER_CONFIRM_MS")
        .ok()
        .and_then(|delay| delay.parse::<u64>().ok())
    {
        // #305 P2-1: confirm the stuck-install offer, then close the sheet while
        // the host is still setting the install aside. The host's own journal
        // dates the stop; this line dates the drop.
        let mut changed = batch.subscribe();
        let challenge = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if let Some(challenge) = batch.events(0).1.iter().find_map(|event| {
                    event
                        .leftovers
                        .as_deref()
                        .map(|leftovers| leftovers.challenge)
                }) {
                    return challenge;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        runner
            .start_fresh(&batch, "owner", "live", challenge)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        println!("CANCEL breakit2 boundary=confirmed+{delay}ms action=drop_batch epoch_us={at}");
        drop(batch);
        tokio::time::timeout(Duration::from_secs(90), async {
            while !f.backend.attempts.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        // The attempt record goes before its restore has run; keep the runtime
        // up past the restore's 45 s cap so the restore is never cut short.
        tokio::time::sleep(Duration::from_secs(50)).await;
        println!("CANCEL breakit2 attempt_ended=true");
        server.abort();
        drop(listeners);
        return;
    }
    let mut changed = batch.subscribe();
    let mut retry_private = retry_private;
    let mut selected_attempt = 1;
    let mut published_retry = false;
    let mut prompt_published_at = None;
    let mut retry_started_at = None;
    let mut joined_host = None;
    let mut replacement_started = false;
    let result = tokio::time::timeout(Duration::from_secs(220), async {
        loop {
            let events = batch.events(0).1;
            if replace_stuck
                && !replacement_started
                && let Some(challenge) = events
                    .iter()
                    .find_map(|event| event.leftovers.as_deref().map(|leftovers| leftovers.challenge))
            {
                // Record the confirmation exactly as the person reads it.
                if let Some(event) = events.iter().find(|event| event.leftovers.is_some()) {
                    let failure = serde_json::to_value(&event.failure).unwrap();
                    println!(
                        "CONFIRMATION breakit2 message={} setup_lock={}",
                        failure["message"], failure["setup_lock"]
                    );
                }
                runner.start_fresh(&batch, "owner", "live", challenge).unwrap();
                replacement_started = true;
                println!("REPLACEMENT breakit2 action=start_fresh accepted=true");
            }
            if let Some(event) = events.iter().find(|event| {
                event.attempt == selected_attempt && matches!(event.step, Step::Done | Step::Failed)
            }) {
                if event.step == Step::Done && event.session_id.is_some() && prompt_published_at.is_none() {
                    prompt_published_at = Some(Instant::now());
                }
                if event.step == Step::Failed
                    && selected_attempt == 1
                    && let Some(private) = retry_private.take()
                {
                    if timeout_retry {
                        assert_eq!(event.step, Step::Failed);
                        assert!(events.iter().any(|phase| phase.step == Step::Facts));
                        assert!(std::process::Command::new("nft")
                            .args(["delete", "table", "inet", "addhost_retry_230"])
                            .status().unwrap().success());
                        println!("RETRY timeout=facts network_restored=true");
                    }
                    *transport.private.lock().unwrap() = Some(Secret::new(private));
                    println!(
                        "RETRY breakit2 first_failure_step={:?}",
                        event.failure.as_ref().and_then(|f| f.failed_step)
                    );
                    retry_started_at = Some(Instant::now());
                    runner.retry(&batch, "owner", "live").unwrap();
                    selected_attempt = 2;
                    continue;
                }
                for phase in &events {
                    println!(
                        "METRIC breakit2 event={:?} cumulative_ms={} message={}",
                        phase.step, phase.elapsed_ms, phase.message
                    );
                }
                if let Some(failure) = &event.failure {
                    println!(
                        "METRIC breakit2 failed_step={:?} status={:?}",
                        failure.failed_step, failure.exit_status
                    );
                    // The fixed public text and lease fields the person reads (#305, D337).
                    let wire = serde_json::to_value(failure).unwrap();
                    println!(
                        "FAILURE breakit2 message={} setup_lock={}",
                        wire["message"], wire["setup_lock"]
                    );
                }
                if event.step == Step::Done {
                    joined_host = event.host_id;
                }
                if event.step == Step::Done && std::env::var_os("ADDHOST_INSTANT").is_some() {
                    assert!(event.session_id.is_some(), "instant acceptance requires a published shim, never a legacy completion");
                }
                if event.step == Step::Done && let (Some(host), Some(session)) = (event.host_id, event.session_id) {
                    // Persist the native fixture's writer exactly as a browser
                    // would, so private readiness shares its real allocator.
                    let connection = Uuid::new_v4();
                    sqlx::query("INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,active) VALUES(?,?,'owner',unixepoch(),1)")
                        .bind(connection.as_bytes().as_slice()).bind([0_u8;32].as_slice()).execute(&f.pool).await.unwrap();
                    sqlx::query("INSERT INTO terminal_writers(connection_id,client_stream,session_id) VALUES(?,1,?)")
                        .bind(connection.as_bytes().as_slice()).bind(session.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
                    let actor = f.backend.hosts.actor(host).await.unwrap();
                    let terminal = instant::EarlyTerminal::attach(&actor, session, started).await;
                    // Once the published shim is interactive, closing the wizard
                    // must leave the same bounded background setup alive.
                    drop(batch);
                    let status = runner.setup_status();
                    let mut setup_changed = status.subscribe("owner", host).unwrap();
                    // A published setup that fails after the network kill retries
                    // through the same owner path the browser uses (#230).
                    let mut retried_attempt = None;
                    loop {
                        let events = status.events("owner", host, 0).unwrap().1;
                        let current = |event: &&infraternal_plugin_ssh::setup::Event| retried_attempt.is_none_or(|attempt| event.attempt > attempt);
                        if let Some(failure) = events.iter().filter(current).find(|event| event.state == infraternal_plugin_ssh::setup::State::Failed) {
                            if (timeout_retry || std::env::var_os("BREAKIT2_RETRY").is_some())
                                && retried_attempt.is_none()
                            {
                                if timeout_retry {
                                    assert!(std::process::Command::new("nft")
                                        .args(["delete", "table", "inet", "addhost_retry_230"])
                                        .status().unwrap().success());
                                    println!("RETRY timeout=published_setup stage={:?} failed_step={:?} network_restored=true", failure.stage, failure.failed_step);
                                } else {
                                    println!("RETRY published_setup stage={:?} failed_step={:?} injected=true", failure.stage, failure.failed_step);
                                }
                                retried_attempt = Some(failure.attempt);
                                published_retry = true;
                                // A retry re-authenticates when its saved route is gone;
                                // hand the fixture key over again, as the batch retry does.
                                if let Some(private) = retry_private.take() {
                                    *transport.private.lock().unwrap() = Some(Secret::new(private));
                                }
                                retry_started_at = Some(Instant::now());
                                runner.retry_setup("owner".into(), Secret::new(f.cookie.as_bytes().to_vec()), host).unwrap();
                                continue;
                            }
                            panic!("published setup failed at {:?}: step={:?} message={:?}", failure.stage, failure.failed_step, failure.message);
                        }
                        if events.iter().filter(current).any(|event| event.stage == infraternal_plugin_ssh::setup::Stage::Ready && event.state == infraternal_plugin_ssh::setup::State::Done) { break; }
                        setup_changed.changed().await.unwrap();
                    }
                    let joined = FULLY_JOINED.lock().unwrap().unwrap();
                    if retry_phase_timing() {
                        println!("METRIC addhost_instant fully_joined_ms={:.3}", joined.duration_since(started).as_secs_f64() * 1000.0);
                    }
                    if retry_phase_timing() && let Some(prompt) = prompt_published_at {
                        let prompt_to_ready_ms = joined.duration_since(prompt).as_secs_f64() * 1000.0;
                        println!("METRIC addhost_instant prompt_to_ready_ms={prompt_to_ready_ms:.3}");
                        let retry_mode = timeout_retry || std::env::var_os("BREAKIT2_RETRY").is_some();
                        if retry_mode {
                            let retry = retry_started_at.expect("the injected setup failure must invoke Retry");
                            let retry_to_ready_ms = joined.duration_since(retry).as_secs_f64() * 1000.0;
                            println!("METRIC addhost_instant retry_to_ready_ms={retry_to_ready_ms:.3}");
                            if let Ok(limit) = std::env::var("BREAKIT2_RETRY_MAX_MS") {
                                let limit_ms = limit.parse::<f64>().expect("retry timing budget must be numeric");
                                assert!(retry_to_ready_ms <= limit_ms, "Retry took {retry_to_ready_ms:.3} ms, over the {limit_ms:.3} ms budget");
                                if std::env::var_os("BREAKIT2_RETRY").is_some() {
                                    assert!(prompt_to_ready_ms <= limit_ms, "published shell to ready took {prompt_to_ready_ms:.3} ms, over the {limit_ms:.3} ms budget");
                                }
                            }
                        }
                    }
                    assert!(f.backend.hosts.installed(host).await);
                    terminal.after_handover().await;
                    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE remote_host_id=?")
                        .bind(host.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
                    assert_eq!(sessions, 1, "handover cannot create another public shell");
                }
                return event.step;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    if timeout_retry {
        assert!(
            selected_attempt == 2 || published_retry,
            "a network timeout must precede the retry"
        );
    }
    if std::env::var_os("BREAKIT2_RETRY").is_some() {
        assert!(
            published_retry,
            "the injected published setup failure must be retried"
        );
    }
    if replace_stuck {
        assert!(
            replacement_started,
            "the stale install did not offer replacement"
        );
        assert_eq!(result, Step::Done, "the stuck install replacement failed");
        let address_records: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap WHERE address=?")
                .bind(&address)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(
            address_records, 1,
            "replacement left duplicate host records"
        );
        println!("REPLACEMENT breakit2 completed=true address_records=1");
    }
    if let Some(private) = readd_private
        && result == Step::Done
    {
        let host = joined_host.expect("a finished add names its host");
        already_added_opens_a_terminal(&f, &runner, &transport, private, host).await;
    }
    if let Some(private) = replace_private
        && result == Step::Done
    {
        let host = joined_host.expect("a finished add names its host");
        replace_keeps_a_terminal(&f, &runner, &transport, &scratch, private, host).await;
    }
    if std::env::var_os("BREAKIT2_REMOVE").is_some() {
        // #235: removal asks the joined host to uninstall itself through the
        // same server path as the canvas, then revokes it. The harness then
        // proves on the machine that nothing is left and that it re-adds.
        let host = joined_host.expect("removal needs a joined host");
        // Let the harness place the kernel objects a running rootful mesh node
        // owns before removal starts, so their removal is observed, not assumed.
        std::fs::write(scratch.join("removal-ready"), b"").unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            while !scratch.join("removal-go").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the harness did not release removal");
        let (cleanup, left) =
            crate::remote_removal::request_uninstall(&f.backend.hosts, host).await;
        println!("REMOVAL breakit2 host_cleanup={cleanup} left={left:?}");
        assert_eq!(
            cleanup, "requested",
            "the joined host did not accept its uninstall"
        );
        // The harness seeds marked mesh objects this installation never
        // recorded on a rootful host; the host must name them as left (#235).
        if std::env::var("BREAKIT2_MODE").as_deref() == Ok("root") {
            assert_eq!(left, ["infraternal0", "infraternal_mesh"]);
        }
        f.backend
            .issuer
            .store()
            .revoke("owner", host, crate::runtime::unix_seconds().unwrap())
            .await
            .unwrap();
    }
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let usable: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens t JOIN remote_hosts h ON h.id=t.host_id WHERE t.consumed_at IS NULL AND h.revoked_at IS NULL").fetch_one(&f.pool).await.unwrap();
    println!(
        "LEDGER breakit2 active_hosts={active} prior_hosts=1 unconsumed_live_tokens={usable} attempts={}",
        f.backend.attempts.lock().unwrap().len()
    );
    server.abort();
    drop(listeners);
    if std::env::var_os("BREAKIT2_EXPECT_FAILURE").is_some() {
        assert_eq!(result, Step::Failed, "target restriction must be refused");
        assert_eq!(active, 1, "failed attempt must retire its host authority");
        assert_eq!(usable, 0, "failed attempt must retire its invitation");
    } else {
        assert_eq!(result, Step::Done, "real SSH bootstrap did not complete");
    }
}

/// Adds the just-added host again, then opens a terminal on the host id the
/// refusal names, the way the wizard's "Open a terminal" does (#189).
async fn already_added_opens_a_terminal(
    f: &Fixture,
    runner: &Bootstrap,
    transport: &FixtureTransport,
    private: Vec<u8>,
    host: Uuid,
) {
    *transport.private.lock().unwrap() = Some(Secret::new(private));
    let address = std::env::var("BREAKIT2_TARGET").unwrap();
    let mode = if std::env::var("BREAKIT2_MODE").unwrap_or_default() == "root" {
        InstallMode::Root
    } else {
        InstallMode::Rootless
    };
    let started = Instant::now();
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "again".into(),
                address: TargetAddress::Manual(address),
                credential: None,
                mode,
                root_consent: mode == InstallMode::Root,
            }],
            None,
        )
        .unwrap();
    let mut changed = batch.subscribe();
    let failure = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(event) = batch
                .events(0)
                .1
                .into_iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                return event;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        failure.step,
        Step::Failed,
        "a second add of the same host must be refused"
    );
    let failure = failure.failure.expect("the refusal carries its failure");
    let wire = serde_json::to_value(&failure).unwrap();
    println!(
        "PROOF already_added={} host_id_matches={} refused_ms={}",
        failure.already_added,
        wire["host_id"] == host.to_string(),
        started.elapsed().as_millis()
    );
    assert!(failure.already_added);
    assert_eq!(wire["host_id"], host.to_string());
    let actor = f.backend.hosts.actor(host).await.unwrap();
    let session = actor
        .open(TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    instant::EarlyTerminal::open_on_named_host(&actor, Uuid::from_bytes(session)).await;
}

/// D337: a host script (`BREAKIT2_REPLACE_AFTER_JOIN`, run over SSH with the
/// fixture key `BREAKIT2_CRAFT_KEY`) leaves this server's freshly joined install
/// stuck mid-upgrade: agent stopped, journal in place, one shim running. Adding
/// the host again must Replace it, and that shim's terminal must carry over:
/// it is attached through the new infraternal agent and runs a command.
async fn replace_keeps_a_terminal(
    f: &Fixture,
    runner: &Bootstrap,
    transport: &FixtureTransport,
    scratch: &std::path::Path,
    private: Vec<u8>,
    host: Uuid,
) {
    let session = leave_install_stuck(scratch);
    // The verdict is Finish while the server still counts the stopped agent
    // as connected; wait until it does not, so it is Replace.
    let gone = Instant::now();
    tokio::time::timeout(Duration::from_secs(120), async {
        while f.backend.hosts.online(host).await {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the server still counts the stopped infraternal agent as connected");
    println!(
        "SURVIVOR breakit2 disconnected_after_ms={}",
        gone.elapsed().as_millis()
    );
    *transport.private.lock().unwrap() = Some(Secret::new(private));
    let finished = replace_again(f, runner).await;
    assert_eq!(finished.host_id, Some(host), "a Replace keeps the host");
    let echoed = echo_through_new_agent(f, host, session).await;
    println!("SURVIVOR breakit2 attached=true echoed={echoed}");
    assert!(echoed, "the carried-over terminal did not run the command");
}

/// Run the host script and return the session id of the shim it left running.
fn leave_install_stuck(scratch: &std::path::Path) -> [u8; 16] {
    use std::io::Write as _;
    let script = std::fs::read(std::env::var_os("BREAKIT2_REPLACE_AFTER_JOIN").unwrap()).unwrap();
    let key =
        std::env::var_os("BREAKIT2_CRAFT_KEY").expect("BREAKIT2_CRAFT_KEY names the fixture key");
    let target = std::env::var("BREAKIT2_TARGET").unwrap();
    let (login, port) = target
        .rsplit_once(':')
        .expect("BREAKIT2_TARGET is user@host:port");
    let mut craft = std::process::Command::new(scratch.join("ssh"))
        .arg("-i")
        .arg(&key)
        .args(["-o", "IdentitiesOnly=yes", "-p", port, login, "sh -s"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    craft.stdin.take().unwrap().write_all(&script).unwrap();
    let crafted = craft.wait_with_output().unwrap();
    // The script prints only fixed lines: ids, counts and PIDs.
    let report = String::from_utf8(crafted.stdout).unwrap();
    print!("{report}");
    assert!(
        crafted.status.success(),
        "the stuck-install script failed: {}",
        String::from_utf8_lossy(&crafted.stderr)
    );
    let survivor = report
        .lines()
        .find_map(|line| line.strip_prefix("SURVIVOR session="))
        .and_then(|rest| rest.split(' ').next())
        .expect("the script names the shim it started");
    *Uuid::parse_str(survivor).unwrap().as_bytes()
}

/// Add the host again, confirm the Replace it offers, and return its last event.
async fn replace_again(f: &Fixture, runner: &Bootstrap) -> Event {
    let target = std::env::var("BREAKIT2_TARGET").unwrap();
    let mode = if std::env::var("BREAKIT2_MODE").unwrap_or_default() == "root" {
        InstallMode::Root
    } else {
        InstallMode::Rootless
    };
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "replace".into(),
                address: TargetAddress::Manual(target.clone()),
                credential: None,
                mode,
                root_consent: mode == InstallMode::Root,
            }],
            None,
        )
        .unwrap();
    let mut changed = batch.subscribe();
    let mut confirmed = false;
    let finished = tokio::time::timeout(Duration::from_secs(220), async {
        loop {
            let events = batch.events(0).1;
            if !confirmed && let Some(event) = events.iter().find(|event| event.leftovers.is_some())
            {
                let failure = serde_json::to_value(&event.failure).unwrap();
                println!(
                    "CONFIRMATION breakit2 replace message={} findings={:?}",
                    failure["message"],
                    event.leftovers.as_ref().unwrap().findings
                );
                let challenge = event.leftovers.as_ref().unwrap().challenge;
                runner
                    .start_fresh(&batch, "owner", "replace", challenge)
                    .unwrap();
                confirmed = true;
            }
            if let Some(event) = events
                .iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                for phase in &events {
                    println!(
                        "METRIC breakit2 replace event={:?} cumulative_ms={} message={}",
                        phase.step, phase.elapsed_ms, phase.message
                    );
                }
                return event.clone();
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(confirmed, "the stuck install was not offered for Replace");
    assert_eq!(
        finished.step,
        Step::Done,
        "the Replace did not finish: {}",
        finished.message
    );
    finished
}

/// Attach to `session` through the host's current infraternal agent and run a command in it.
async fn echo_through_new_agent(f: &Fixture, host: Uuid, session: [u8; 16]) -> bool {
    use infraternal_protocol::{Frame, encode_muxed_frame_into};
    let actor = f.backend.hosts.actor(host).await.unwrap();
    let (handle, mut output) = actor
        .attach(session, 0, 0, 2)
        .await
        .expect("the earlier terminal is attachable through the new infraternal agent")
        .split();
    let mut wire = Vec::new();
    for frame in [
        Frame::Credit { bytes: 65536 },
        Frame::Input {
            in_seq: 0,
            bytes: b"echo carried-$((6*7))\n",
        },
    ] {
        wire.clear();
        encode_muxed_frame_into(1, &frame, &mut wire).unwrap();
        handle
            .send_frame(bytes::Bytes::copy_from_slice(&wire))
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut received = Vec::new();
        while let Some(event) = output.recv().await {
            if let TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } =
                event
            {
                received.extend_from_slice(&bytes);
                if received.windows(9).any(|window| window == b"carried-4") {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

/// Observe only whether the test fixture reaches the intended fixed failure step.
struct RetryObservation {
    injected: std::sync::atomic::AtomicBool,
    lock_wrapper: std::sync::atomic::AtomicBool,
    lock_tries: std::sync::atomic::AtomicUsize,
    lock_waits: std::sync::atomic::AtomicUsize,
}
impl SshSession for RetryObservation {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            self.injected.store(
                script.contains("if [ \"$1\" != install ] && sh -c"),
                Ordering::SeqCst,
            );
            self.lock_wrapper.store(
                script.contains("ADDHOST_RETRY_LOCK_TRACE_PATH=")
                    && script.contains("\"lease_try\""),
                Ordering::SeqCst,
            );
            self.lock_tries
                .store(script.matches("\"lease_try\"").count(), Ordering::SeqCst);
            self.lock_waits
                .store(script.matches("\"lease_wait\"").count(), Ordering::SeqCst);
            Ok(CommandOutput {
                stdout: b"STEP upload\nTRACE_SETUP_STEP upload 1.000 1.250 0\nTRACE_LOCK lease_try 1.250 1.251 0\nSTEP join\nSTEP install\nFAIL install 1\n".to_vec(),
            })
        })
    }
}

#[tokio::test]
async fn compound_retry_fixture_reaches_install_boundary() {
    // Environment changes belong to a fresh child, never to concurrent tests.
    if std::env::var_os("ADDHOST_FAST_RETRY_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["bootstrap_runtime::remote_backend::tests::breakit2_live::compound_retry_fixture_reaches_install_boundary", "--exact"])
            .env("ADDHOST_FAST_RETRY_CHILD", "1")
            .env("BREAKIT2_RETRY", "1")
            .env("ADDHOST_RETRY_PHASE_TIMING", "1")
            .env("ADDHOST_RETRY_LOCK_TIMING", "1")
            .env("ADDHOST_RETRY_LOCK_TRACE_PATH", "/dev/null")
            .output().unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "compound retry fixture did not inject at install"
        );
        return;
    }
    let observation = Arc::new(RetryObservation {
        injected: std::sync::atomic::AtomicBool::new(false),
        lock_wrapper: std::sync::atomic::AtomicBool::new(false),
        lock_tries: std::sync::atomic::AtomicUsize::new(0),
        lock_waits: std::sync::atomic::AtomicUsize::new(0),
    });
    let session = TimedSession {
        inner: observation.clone(),
        test_https_root: None,
    };
    let script = r#"# INFRATERNAL_SETUP_STEPS_V1
setup_step() {
    printf 'STEP %s\n' "$1"
    if sh -c "$2"; then :; else status=$?; printf 'FAIL %s %s\n' "$1" "$status"; exit 0; fi
}
lease_birth_field() {
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
    flock -n 7 || exit 73
    flock -w 2 7 || exit 73
}
if sh -c "$2"; then :; fi
"#;
    let output = session
        .run(script, Input::Bytes(b"public-fixture"))
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("TRACE_"));
    assert!(observation.injected.load(Ordering::SeqCst));
    assert!(observation.lock_wrapper.load(Ordering::SeqCst));
    assert_eq!(observation.lock_tries.load(Ordering::SeqCst), 6);
    assert_eq!(observation.lock_waits.load(Ordering::SeqCst), 6);
}
