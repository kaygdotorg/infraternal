//! Checks that a failed Replace or Re-enroll restores the stuck installation (#305).
//! Set-aside and restore programs run in a private HOME with a stateful service fixture.
//! Only read-only ownership proofs are stubbed; previous_attempt_shell.py covers those.
use super::*;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

/// Where the fake host's work stops, so a test can act at that point.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Run to the end; the fixture refuses the enrollment command.
    Join,
    /// Wait in key preparation, after the stuck install was set aside, until
    /// released (never, unless the test releases it).
    AfterSetAside,
    /// Hang inside the set-aside script, after it moved the install: the
    /// attempt is dropped before it learns the script's result.
    InSetAside,
}

/// Stand-ins for the set-aside's read-only proofs, defined just before its
/// call. The guard, the service stop, the journal move and the traps stay real.
const SET_ASIDE_PROOFS: &str = "\ninspect_previous() { printf '%s\\n' \"$replace_expected\"; }\nruntime_helper() { helper=true; }\nscan_holders() { :; }\nnot_live() { :; }\nstop_stage_shims() { :; }";

/// A private HOME holding a stuck rootless install and a mock service manager.
struct Home {
    root: PathBuf,
    transaction: Uuid,
}
impl Home {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("isr-{}", Uuid::new_v4().simple()));
        let transaction = Uuid::new_v4();
        let home = Self { root, transaction };
        for directory in [
            home.base().join(".bootstrap-lock"),
            home.root.join(".config/systemd/user"),
            home.root.join(".local/bin"),
            home.root.join("bin"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        for directory in [
            home.root.clone(),
            home.root.join(".local"),
            home.root.join(".local/share"),
            home.base(),
            home.base().join(".bootstrap-lock"),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self::private(
            &home.base().join(".bootstrap-lock/transaction"),
            &format!("{}\n", transaction.simple()),
        );
        Self::private(&home.unit(), "# infraternal bootstrap fixture\n");
        std::os::unix::fs::symlink(
            home.base().join("bin/current"),
            home.root.join(".local/bin/infraternal"),
        )
        .unwrap();
        // Enabled is a file, active is a file: the restore must recreate both.
        // With slow-stop present, stop marks "stopping" and takes 2 s, as a
        // real agent's shutdown does (#305 P3-3).
        let manager = home.root.join("bin/systemctl");
        std::fs::write(
            &manager,
            "#!/bin/sh\n[ \"$1\" = --user ] && shift\nprintf '%s\\n' \"$*\" >> \"$HOME/manager.log\"\ncase \"$1\" in\n enable) : > \"$HOME/enabled\"; [ \"$2\" != --now ] || : > \"$HOME/active\";;\n disable) rm -f \"$HOME/enabled\";;\n start) : > \"$HOME/active\";;\n stop) if [ -e \"$HOME/slow-stop\" ]; then : > \"$HOME/stopping\"; sleep 2; fi; rm -f \"$HOME/active\";;\n is-enabled) [ -e \"$HOME/enabled\" ]; exit;;\n is-active) [ -e \"$HOME/active\" ]; exit;;\nesac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o700)).unwrap();
        // As found on the field host: enabled and running.
        for state in ["enabled", "active"] {
            std::fs::write(home.root.join(state), "").unwrap();
        }
        home
    }
    /// The stuck install's setup directory under the private HOME.
    fn base(&self) -> PathBuf {
        self.root.join(".local/share/infraternal")
    }
    /// The stuck install's user unit file.
    fn unit(&self) -> PathBuf {
        self.root
            .join(".config/systemd/user/infraternal-agent.service")
    }
    /// Write `text` to `path` as an owner-only (0600) file.
    fn private(path: &std::path::Path, text: &str) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    /// (enabled, active) as the mock service manager holds it.
    fn service(&self) -> (bool, bool) {
        (
            self.root.join("enabled").exists(),
            self.root.join("active").exists(),
        )
    }
    /// Run a host program in sh as the private HOME's user, with its mock
    /// service manager first on PATH. Never killed on drop: like sshd, the
    /// host runs a command to the end after the client goes away (#305 P2-1).
    fn sh(&self, script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(script).env("HOME", &self.root).env(
            "PATH",
            format!(
                "{}:{}",
                self.root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        command
    }
    /// What `supersede_stuck_install` leaves: the whole install, its unit and
    /// the service state found set aside, the launcher removed.
    fn supersede(&self) {
        let aside = PathBuf::from(format!(
            "{}.bootstrap-superseded-{}",
            self.base().display(),
            self.transaction.simple()
        ));
        std::fs::rename(self.base(), &aside).unwrap();
        Self::private(&aside.join(".superseded-service"), "yes yes\n");
        std::fs::rename(self.unit(), aside.join(".superseded-unit")).unwrap();
        std::fs::remove_file(self.root.join(".local/bin/infraternal")).unwrap();
        self.stop();
    }
    /// Stop and disable the mock service, as a set-aside leaves it.
    fn stop(&self) {
        for state in ["enabled", "active"] {
            std::fs::remove_file(self.root.join(state)).unwrap();
        }
    }
    /// The stuck install is back where it was, with its service as found.
    fn assert_as_found(&self) {
        assert_eq!(
            std::fs::read_to_string(self.base().join(".bootstrap-lock/transaction")).unwrap(),
            format!("{}\n", self.transaction.simple())
        );
        assert!(!self.base().join(".bootstrap-lock/found-service").exists());
        assert!(self.unit().exists());
        assert_eq!(
            self.service(),
            (true, true),
            "enabled and running, as found"
        );
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Simulates independently bounded SSH commands against the private host fixture.
struct HostSession {
    check: Vec<u8>,
    digest: [u8; 32],
    home: Arc<Home>,
    stop: Stop,
    scripts: Arc<Mutex<Vec<String>>>,
    /// Notified when the work reaches `Stop::AfterSetAside`.
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    /// Each mock SSH command has the same independent bound as production.
    command_timeout: Duration,
}
impl SshTransport for HostSession {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            Ok(Arc::new(Self {
                check: self.check.clone(),
                digest: self.digest,
                home: self.home.clone(),
                stop: self.stop,
                scripts: self.scripts.clone(),
                reached: self.reached.clone(),
                release: self.release.clone(),
                command_timeout: self.command_timeout,
            }) as Arc<dyn SshSession>)
        })
    }
}
impl SshSession for HostSession {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        let script = script.to_owned();
        Box::pin(async move {
            tokio::time::timeout(self.command_timeout, async move {
                self.scripts.lock().unwrap().push(script.clone());
                let stdout = if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) {
                    self.check.clone()
                } else if let Some(call) =
                    ["\nreplace_stuck_install ", "\nsupersede_stuck_install "]
                        .into_iter()
                        .find(|call| script.contains(call))
                {
                    // The real set-aside program; a dropped attempt leaves it running.
                    let script = script.replacen(call, &format!("{SET_ASIDE_PROOFS}{call}"), 1);
                    let output = self.home.sh(&script).output().await.unwrap();
                    if !output.status.success() {
                        eprintln!(
                            "set-aside stderr: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        let mut failure = Failure::install("the set-aside program failed");
                        failure.exit_status =
                            output.status.code().and_then(|c| u8::try_from(c).ok());
                        return Err(failure);
                    }
                    if self.stop == Stop::InSetAside {
                        self.reached.notify_one();
                        std::future::pending::<()>().await;
                    }
                    Vec::new()
                } else if script.contains("\nrestore_replaced_install ")
                    || script.contains("\nrestore_superseded_install ")
                {
                    // The real restore program, against the private HOME.
                    let output = self.home.sh(&script).output().await.unwrap();
                    if !output.status.success() {
                        let mut failure = Failure::install("the restore program refused");
                        failure.exit_status =
                            output.status.code().and_then(|c| u8::try_from(c).ok());
                        return Err(failure);
                    }
                    output.stdout
                } else if script.contains("prepare-join-key") {
                    if self.stop == Stop::AfterSetAside {
                        self.reached.notify_one();
                        self.release.notified().await;
                    }
                    format!("KEY-DIGEST {}\n", hex(&self.digest)).into_bytes()
                } else if script.contains("agent --data \"$stage/state\" join ") {
                    return Err(Failure::install("stop after the invitation"));
                } else {
                    Vec::new()
                };
                Ok(CommandOutput { stdout })
            })
            .await
            .map_err(|_| Failure::install("The SSH command exceeded its time limit."))?
        })
    }
}

/// A check record for the fixture's stuck upgrade of `host`, enrolled under `digest` with `server`.
fn home_check(home: &Home, host: Uuid, digest: &[u8; 32], server: &str) -> Vec<u8> {
    format!(
        "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_UPGRADE {} {} 1:2 fixture 99999999 1 2026-11-02T04:05:06Z 0 {} {server} idle\n",
        host.simple(),
        home.transaction.simple(),
        hex(digest)
    )
    .into_bytes()
}

struct Run {
    runner: Bootstrap,
    batch: Option<Batch>,
    scripts: Arc<Mutex<Vec<String>>>,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl Run {
    fn start(f: &Fixture, home: &Arc<Home>, check: Vec<u8>, digest: [u8; 32], stop: Stop) -> Self {
        Self::start_with(f, home, check, digest, stop, None)
    }
    fn start_with(
        f: &Fixture,
        home: &Arc<Home>,
        check: Vec<u8>,
        digest: [u8; 32],
        stop: Stop,
        deadline: Option<Duration>,
    ) -> Self {
        Self::start_many(f, home, check, digest, stop, deadline, 1)
    }
    /// Start one batch of `hosts` targets ("one", then "host-1", "host-2", ...).
    fn start_many(
        f: &Fixture,
        home: &Arc<Home>,
        check: Vec<u8>,
        digest: [u8; 32],
        stop: Stop,
        deadline: Option<Duration>,
        hosts: usize,
    ) -> Self {
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let binary = std::env::current_exe().unwrap();
        let runner = Bootstrap::new(
            Arc::new(HostSession {
                check,
                digest,
                home: home.clone(),
                stop,
                scripts: scripts.clone(),
                reached: reached.clone(),
                release: release.clone(),
                command_timeout: deadline.unwrap_or(Duration::from_secs(30)),
            }),
            f.backend.clone(),
            BinaryPaths {
                x86_64: binary.clone(),
                aarch64: binary,
            },
        );
        let batch = runner
            .start_authenticated(
                "owner".into(),
                Secret::new(f.cookie.as_bytes().to_vec()),
                (0..hosts)
                    .map(|index| Target {
                        id: if index == 0 {
                            "one".into()
                        } else {
                            format!("host-{index}")
                        },
                        address: TargetAddress::Manual(if index == 0 {
                            "user@fixture".into()
                        } else {
                            format!("user@fixture-{index}")
                        }),
                        credential: None,
                        mode: InstallMode::Rootless,
                        root_consent: false,
                    })
                    .collect(),
                None,
            )
            .unwrap();
        Self {
            runner,
            batch: Some(batch),
            scripts,
            reached,
            release,
        }
    }
    /// The running add-host batch; dropping it cancels the attempt.
    fn batch(&self) -> &Batch {
        self.batch.as_ref().unwrap()
    }
    /// Wait for the confirmation offer and return its challenge.
    async fn offer(&self) -> Uuid {
        let mut changed = self.batch().subscribe();
        tokio::time::timeout(TEST_HANG_BOUND, async {
            loop {
                let events = self.batch().events(0).1;
                if let Some(leftovers) = events.iter().find_map(|event| event.leftovers.as_ref()) {
                    return leftovers.challenge;
                }
                assert!(
                    events.iter().all(|event| event.step != Step::Failed),
                    "the stuck install must be offered first: {events:?}"
                );
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
    /// Confirm the offered stuck-install action, as the person does.
    fn confirm(&self, challenge: Uuid) {
        self.runner
            .start_fresh(self.batch(), "owner", "one", challenge)
            .unwrap();
    }
    /// Whether any host script containing `needle` has been sent.
    fn ran(&self, needle: &str) -> bool {
        self.scripts
            .lock()
            .unwrap()
            .iter()
            .any(|script| script.contains(needle))
    }
    /// Wait until a script containing `needle` has finished running.
    async fn wait_ran(&self, needle: &str, home: &Home) {
        tokio::time::timeout(TEST_HANG_BOUND, async {
            while !(self.ran(needle) && home.service() == (true, true)) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{needle} did not run and restore the service"));
    }
}

/// This server's own host with a stuck upgrade: the record, its address binding and digest.
async fn own_stuck_host(f: &Fixture) -> [u8; 32] {
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
        .bind(f.prior.as_bytes().as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    f.backend
        .issuer
        .store()
        .host_key_digest(f.prior)
        .await
        .unwrap()
        .unwrap()
}

/// A Replace whose join fails puts the stuck install back as found (#305).
#[tokio::test]
async fn a_replace_whose_join_fails_puts_the_stuck_install_back_as_found() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let run = Run::start(&f, &home, check, digest, Stop::Join);
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert_eq!(event.step, Step::Failed);
    assert!(run.ran("\nreplace_stuck_install "));
    assert!(
        run.ran("\nrestore_replaced_install "),
        "the replaced journal is put back: {:?}",
        run.batch().events(0).1
    );
    home.assert_as_found();
    assert!(
        run.batch()
            .events(0)
            .1
            .iter()
            .any(|event| event.message.contains("put back as it was found"))
    );
}

/// A Replace that exceeds its command bound puts the stuck install back as found (#305).
#[tokio::test]
async fn a_replace_that_exceeds_its_command_bound_puts_the_stuck_install_back_as_found() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let run = Run::start_with(
        &f,
        &home,
        check,
        digest,
        Stop::AfterSetAside,
        Some(Duration::from_secs(5)),
    );
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert!(event.message.contains("time limit"), "{}", event.message);
    assert!(run.ran("\nrestore_replaced_install "));
    home.assert_as_found();
}

/// A Replace the browser cancels puts the stuck install back as found (#305).
#[tokio::test]
async fn a_replace_the_browser_cancels_puts_the_stuck_install_back_as_found() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let mut run = Run::start(&f, &home, check, digest, Stop::AfterSetAside);
    run.confirm(run.offer().await);
    tokio::time::timeout(TEST_HANG_BOUND, run.reached.notified())
        .await
        .unwrap_or_else(|_| panic!("never set aside: {:?}", run.batch().events(0).1));
    // Closing the add-host window drops its batch, which cancels unpublished work.
    drop(run.batch.take());
    run.wait_ran("\nrestore_replaced_install ", &home).await;
    home.assert_as_found();
}

/// Cancel the attempt while the host is still stopping the stuck install's
/// service: the set-aside runs on, and the restore must wait for it and put
/// the install back, not give up on the setup guard (#305 P2-1, P3-3).
async fn cancel_during_the_stop(own: bool) {
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    std::fs::write(home.root.join("slow-stop"), "").unwrap();
    let (check, digest) = if own {
        let digest = own_stuck_host(&f).await;
        (
            home_check(&home, f.prior, &digest, "remote.example.test"),
            digest,
        )
    } else {
        (
            home_check(&home, Uuid::new_v4(), &[9; 32], "old.example"),
            [7; 32],
        )
    };
    let mut run = Run::start(&f, &home, check, digest, Stop::Join);
    run.confirm(run.offer().await);
    tokio::time::timeout(TEST_HANG_BOUND, async {
        while !home.root.join("stopping").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("never stopped: {:?}", run.batch().events(0).1));
    // Closing the sheet (or locking the phone) closes its socket mid-stop.
    drop(run.batch.take());
    let restore = if own {
        "\nrestore_replaced_install "
    } else {
        "\nrestore_superseded_install "
    };
    run.wait_ran(restore, &home).await;
    // The set-aside has ended by now, and nothing stops the service again.
    tokio::time::sleep(Duration::from_secs(3)).await;
    home.assert_as_found();
}

/// A Replace cancelled during the stop is put back as found (#305).
#[tokio::test]
async fn a_replace_cancelled_during_the_stop_is_put_back_as_found() {
    cancel_during_the_stop(true).await;
}

/// A Re-enroll cancelled during the stop is put back as found (#305).
#[tokio::test]
async fn a_reenroll_cancelled_during_the_stop_is_put_back_as_found() {
    cancel_during_the_stop(false).await;
}

/// Unanswered confirmations leave the add-host slots free (#305, J160 P3-2).
#[tokio::test]
async fn unanswered_confirmations_leave_the_add_host_slots_free() {
    // #305 P3-2: each attempt waiting for a person hands its server-wide slot
    // back, so one more stuck host than there are slots is still offered.
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, Uuid::new_v4(), &[9; 32], "old.example");
    let hosts = 9;
    let run = Run::start_many(&f, &home, check, [7; 32], Stop::Join, None, hosts);
    let mut changed = run.batch().subscribe();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let events = run.batch().events(0).1;
            let offered: std::collections::HashSet<_> = events
                .iter()
                .filter(|event| event.leftovers.is_some())
                .map(|event| event.target.clone())
                .collect();
            if offered.len() == hosts {
                return;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("not every host was offered: {:?}", run.batch().events(0).1));
    assert!(
        !run.ran("\nsupersede_stuck_install "),
        "nothing is stopped before a confirmation"
    );
}

/// A host revoked while its confirmation waits is never stopped (#305).
#[tokio::test]
async fn a_host_revoked_while_its_confirmation_waits_is_never_stopped() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let run = Run::start(&f, &home, check, digest, Stop::Join);
    let challenge = run.offer().await;
    // Another administrator revokes the host while the person decides.
    sqlx::query("UPDATE remote_hosts SET revoked_at=created_at WHERE id=?")
        .bind(f.prior.as_bytes().as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    run.confirm(challenge);
    let event = finished(run.batch()).await;
    assert_eq!(event.step, Step::Failed);
    assert!(
        !run.ran("\nreplace_stuck_install "),
        "the server is asked again right before the stop: {}",
        event.message
    );
    assert_eq!(home.service(), (true, true), "nothing was stopped");
}

/// A host revoked after the stop is put back as found (#305).
#[tokio::test]
async fn a_host_revoked_after_the_stop_is_put_back_as_found() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let run = Run::start(&f, &home, check, digest, Stop::AfterSetAside);
    run.confirm(run.offer().await);
    tokio::time::timeout(TEST_HANG_BOUND, run.reached.notified())
        .await
        .unwrap_or_else(|_| panic!("never set aside: {:?}", run.batch().events(0).1));
    // Revoked after the stop: reissuing the enrollment now refuses.
    sqlx::query("UPDATE remote_hosts SET revoked_at=created_at WHERE id=?")
        .bind(f.prior.as_bytes().as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    run.release.notify_one();
    let event = finished(run.batch()).await;
    assert_eq!(event.step, Step::Failed);
    assert!(run.ran("\nreplace_stuck_install "));
    assert!(run.ran("\nrestore_replaced_install "));
    home.assert_as_found();
}

/// A Re-enroll whose join fails puts the whole install back as found (#305).
#[tokio::test]
async fn a_reenroll_whose_join_fails_puts_the_whole_install_back_as_found() {
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, Uuid::new_v4(), &[9; 32], "old.example");
    let run = Run::start(&f, &home, check, [7; 32], Stop::Join);
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert_eq!(event.step, Step::Failed);
    assert!(run.ran("\nsupersede_stuck_install "));
    assert!(run.ran("\nrestore_superseded_install "));
    home.assert_as_found();
    assert!(home.root.join(".local/bin/infraternal").is_symlink());
    assert!(
        run.batch()
            .events(0)
            .1
            .iter()
            .any(|event| event.message.contains("put back as it was found"))
    );
}

/// A Re-enroll dropped while it sets the install aside still puts it back (#305).
#[tokio::test]
async fn a_reenroll_dropped_while_it_sets_the_install_aside_still_puts_it_back() {
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, Uuid::new_v4(), &[9; 32], "old.example");
    let run = Run::start_with(
        &f,
        &home,
        check,
        [7; 32],
        Stop::InSetAside,
        Some(Duration::from_secs(5)),
    );
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert!(event.message.contains("time limit"), "{}", event.message);
    // Recorded before the script ran, so the restore runs anyway (#305 P2-1).
    assert!(run.ran("\nrestore_superseded_install "));
    home.assert_as_found();
}

/// The confirmation wait does not use up a later command bound (#305).
#[tokio::test]
async fn the_confirmation_wait_does_not_use_up_a_later_command_bound() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let deadline = Duration::from_secs(10);
    let run = Run::start_with(&f, &home, check, digest, Stop::Join, Some(deadline));
    let challenge = run.offer().await;
    // sleep: the person decides after a later command’s entire budget has elapsed.
    tokio::time::sleep(deadline + Duration::from_secs(1)).await;
    run.confirm(challenge);
    let event = finished(run.batch()).await;
    assert!(!event.message.contains("time limit"), "{}", event.message);
    assert!(
        run.ran("\nreplace_stuck_install "),
        "the confirmed action runs"
    );
    home.assert_as_found();
}

/// Check offers back an install an earlier attempt left set aside (#305).
#[tokio::test]
async fn check_offers_back_an_install_an_earlier_attempt_left_set_aside() {
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    // An earlier Re-enroll set the install aside, and its restore never ran.
    home.supersede();
    let check = format!(
        "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_SET_ASIDE superseded {} {} fixture yes yes\n",
        Uuid::new_v4().simple(),
        home.transaction.simple()
    )
    .into_bytes();
    let run = Run::start(&f, &home, check, [7; 32], Stop::Join);
    let lock = {
        run.offer().await;
        run.batch()
            .events(0)
            .1
            .iter()
            .find_map(|event| event.failure.as_ref())
            .map(|failure| serde_json::to_value(failure).unwrap()["setup_lock"].clone())
            .unwrap()
    };
    assert_eq!(lock["set_aside"], true);
    assert!(
        !run.ran("prepare-join-key"),
        "nothing is installed beside it"
    );
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert!(
        event.message.contains("put back as it was found"),
        "{}",
        event.message
    );
    assert!(run.ran("\nrestore_superseded_install "));
    assert!(!run.ran("prepare-join-key"));
    home.assert_as_found();
}

/// A live install is named live before it is disconnected from its server (#305).
#[tokio::test]
async fn a_live_install_is_named_live_before_it_is_disconnected_from_its_server() {
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    let check = String::from_utf8(home_check(&home, Uuid::new_v4(), &[9; 32], "old.example"))
        .unwrap()
        .replace(" idle\n", " live\n")
        .into_bytes();
    let run = Run::start(&f, &home, check, [7; 32], Stop::Join);
    run.offer().await;
    let events = run.batch().events(0).1;
    let offer = events
        .iter()
        .find(|event| event.leftovers.is_some())
        .unwrap();
    let failure = serde_json::to_value(offer.failure.as_ref().unwrap()).unwrap();
    assert_eq!(failure["setup_lock"]["live"], true);
    let message = failure["message"].as_str().unwrap();
    assert!(
        message.contains("running and may be connected to old.example now")
            && message.contains("disconnects it from old.example"),
        "{message}"
    );
    assert!(offer.leftovers.as_ref().unwrap().findings[1].contains("joining here disconnects it"));
    assert!(
        !run.ran("\nsupersede_stuck_install "),
        "nothing is stopped before the person confirms"
    );
}

/// Another server's install running with open terminals is refused by name (D337, #305).
#[tokio::test]
async fn another_servers_install_running_with_open_terminals_is_refused_by_name() {
    // D337: it may be in use by its server, and the host cannot see the
    // connection. Nothing is offered and nothing is stopped.
    let f = fixture(true).await;
    let home = Arc::new(Home::new());
    let check = String::from_utf8(home_check(&home, Uuid::new_v4(), &[9; 32], "old.example"))
        .unwrap()
        .replace(" 2026-11-02T04:05:06Z 0 ", " 2026-11-02T04:05:06Z 2 ")
        .replace(" idle\n", " live\n")
        .into_bytes();
    let run = Run::start(&f, &home, check, [7; 32], Stop::Join);
    let event = finished(run.batch()).await;
    assert_eq!(event.step, Step::Failed);
    let failure = serde_json::to_value(event.failure.as_ref().unwrap()).unwrap();
    assert_eq!(failure["setup_lock"]["in_use"], true);
    assert_eq!(failure["setup_lock"]["sessions"], 2);
    let message = failure["message"].as_str().unwrap();
    assert!(
        message.contains("running with 2 open terminals and may still be connected to old.example")
            && message.contains("Prove you own old.example to take it over"),
        "{message}"
    );
    assert!(
        run.batch()
            .events(0)
            .1
            .iter()
            .all(|event| event.leftovers.is_none()),
        "no confirmation is offered"
    );
    assert!(!run.ran("\nsupersede_stuck_install "));
    assert_eq!(home.service(), (true, true), "nothing was stopped");
}
