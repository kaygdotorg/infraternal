// SPDX-License-Identifier: AGPL-3.0-only
// A Replace or Re-enroll that fails after the stuck install was set aside puts
// it back as it was found (#305 P1-1, P2-1, P3-3). The fake host simulates the
// set-aside step on real files; the restore script itself runs for real in sh
// against a private HOME, with a service manager that keeps state.
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
        let manager = home.root.join("bin/systemctl");
        std::fs::write(
            &manager,
            "#!/bin/sh\n[ \"$1\" = --user ] && shift\nprintf '%s\\n' \"$*\" >> \"$HOME/manager.log\"\ncase \"$1\" in\n enable) : > \"$HOME/enabled\"; [ \"$2\" != --now ] || : > \"$HOME/active\";;\n disable) rm -f \"$HOME/enabled\";;\n start) : > \"$HOME/active\";;\n stop) rm -f \"$HOME/active\";;\n is-enabled) [ -e \"$HOME/enabled\" ]; exit;;\n is-active) [ -e \"$HOME/active\" ]; exit;;\nesac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o700)).unwrap();
        // As found on the field host: enabled and running.
        for state in ["enabled", "active"] {
            std::fs::write(home.root.join(state), "").unwrap();
        }
        home
    }
    fn base(&self) -> PathBuf {
        self.root.join(".local/share/infraternal")
    }
    fn unit(&self) -> PathBuf {
        self.root.join(".config/systemd/user/infraternal-agent.service")
    }
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
    /// What `replace_stuck_install` leaves: the journal moved aside with the
    /// service state found, and the service stopped and disabled.
    fn replace(&self) {
        let replaced = PathBuf::from(format!(
            "{}.bootstrap-replaced-{}",
            self.base().display(),
            self.transaction.simple()
        ));
        std::fs::rename(self.base().join(".bootstrap-lock"), &replaced).unwrap();
        Self::private(&replaced.join("found-service"), "yes yes\n");
        self.stop();
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
        assert_eq!(self.service(), (true, true), "enabled and running, as found");
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct HostSession {
    check: Vec<u8>,
    digest: [u8; 32],
    home: Arc<Home>,
    stop: Stop,
    scripts: Arc<Mutex<Vec<String>>>,
    /// Notified when the work reaches `Stop::AfterSetAside`.
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
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
            }) as Arc<dyn SshSession>)
        })
    }
}
impl SshSession for HostSession {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        let script = script.to_owned();
        Box::pin(async move {
            self.scripts.lock().unwrap().push(script.clone());
            let stdout = if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) {
                self.check.clone()
            } else if script.contains("\nreplace_stuck_install ") {
                self.home.replace();
                Vec::new()
            } else if script.contains("\nsupersede_stuck_install ") {
                self.home.supersede();
                if self.stop == Stop::InSetAside {
                    self.reached.notify_one();
                    std::future::pending::<()>().await;
                }
                Vec::new()
            } else if script.contains("\nrestore_replaced_install ")
                || script.contains("\nrestore_superseded_install ")
            {
                // The real restore program, against the private HOME.
                let output = tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&script)
                    .env("HOME", &self.home.root)
                    .env(
                        "PATH",
                        format!(
                            "{}:{}",
                            self.home.root.join("bin").display(),
                            std::env::var("PATH").unwrap_or_default()
                        ),
                    )
                    .output()
                    .await
                    .unwrap();
                if !output.status.success() {
                    let mut failure = Failure::install("the restore program refused");
                    failure.exit_status = output.status.code().and_then(|c| u8::try_from(c).ok());
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
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let binary = std::env::current_exe().unwrap();
        let mut runner = Bootstrap::new(
            Arc::new(HostSession {
                check,
                digest,
                home: home.clone(),
                stop,
                scripts: scripts.clone(),
                reached: reached.clone(),
                release: release.clone(),
            }),
            f.backend.clone(),
            BinaryPaths {
                x86_64: binary.clone(),
                aarch64: binary,
            },
        );
        if let Some(deadline) = deadline {
            runner = runner.with_attempt_deadline(deadline);
        }
        let batch = runner
            .start_authenticated(
                "owner".into(),
                Secret::new(f.cookie.as_bytes().to_vec()),
                vec![Target {
                    id: "one".into(),
                    address: TargetAddress::Manual("user@fixture".into()),
                    credential: None,
                    mode: InstallMode::Rootless,
                    root_consent: false,
                }],
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
    fn confirm(&self, challenge: Uuid) {
        self.runner
            .start_fresh(self.batch(), "owner", "one", challenge)
            .unwrap();
    }
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

#[tokio::test]
async fn a_replace_that_passes_its_deadline_puts_the_stuck_install_back_as_found() {
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

#[tokio::test]
async fn the_confirmation_wait_does_not_use_up_the_attempt_deadline() {
    let f = fixture(true).await;
    let digest = own_stuck_host(&f).await;
    let home = Arc::new(Home::new());
    let check = home_check(&home, f.prior, &digest, "remote.example.test");
    let deadline = Duration::from_secs(10);
    let run = Run::start_with(&f, &home, check, digest, Stop::Join, Some(deadline));
    let challenge = run.offer().await;
    // The person takes longer than the whole attempt deadline to decide.
    tokio::time::sleep(deadline + Duration::from_secs(1)).await;
    run.confirm(challenge);
    let event = finished(run.batch()).await;
    assert!(!event.message.contains("time limit"), "{}", event.message);
    assert!(run.ran("\nreplace_stuck_install "), "the confirmed action runs");
    home.assert_as_found();
}

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
    assert!(!run.ran("prepare-join-key"), "nothing is installed beside it");
    run.confirm(run.offer().await);
    let event = finished(run.batch()).await;
    assert!(event.message.contains("put back as it was found"), "{}", event.message);
    assert!(run.ran("\nrestore_superseded_install "));
    assert!(!run.ran("prepare-join-key"));
    home.assert_as_found();
}

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
    let offer = events.iter().find(|event| event.leftovers.is_some()).unwrap();
    let failure = serde_json::to_value(offer.failure.as_ref().unwrap()).unwrap();
    assert_eq!(failure["setup_lock"]["live"], true);
    let message = failure["message"].as_str().unwrap();
    assert!(
        message.contains("running and may be connected to old.example now")
            && message.contains("disconnects it from old.example"),
        "{message}"
    );
    assert!(
        offer.leftovers.as_ref().unwrap().findings[1].contains("joining here disconnects it")
    );
    assert!(!run.ran("\nsupersede_stuck_install "), "nothing is stopped before the person confirms");
}
