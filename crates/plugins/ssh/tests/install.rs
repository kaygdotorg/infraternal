//! Exercises transaction failure recovery on real files while replacing the service manager with a deterministic fixture.
#![allow(clippy::unwrap_used)]

mod common;
/// Remote-consumption and inactivity oracles for duplex setup.
#[path = "install/progress.rs"]
mod progress;
#[path = "install/streaming.rs"]
mod streaming;

use infraternal_plugin_ssh::{
    install::{Installation, JoinMaterial},
    model::{Failure, InstallMode, Target, TargetAddress},
    transport::{CommandOutput, Input, Operation, PayloadInput, Secret, SshSession},
};
use std::fmt::Write as _;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command};

/// Hang guard for this file's positive waits (#334 rule): the fixture's own
/// run of a generated install script, and waits for an install batch to reach
/// a state, a marker file to appear or a stage to finish. Each wait ends on
/// its event; the bound only detects a hang. The former 60 s values failed
/// three tests under gate load, where local shell work alone outlasted them
/// (`exit_status: None` after the fixture timed the upload script out, #355).
const INSTALL_HANG: std::time::Duration = std::time::Duration::from_secs(300);

struct Local {
    root: PathBuf,
}
struct Compound(Local);
impl SshSession for Compound {
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        self.0.stream(script)
    }
    fn setup_steps(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.0.run(script, input)
    }
}
impl Local {
    /// Fixture-only rewrites of a generated program before the real shell runs it.
    fn fixture_script(&self, script: &str, input: &Input<'_>) -> String {
        // Map the remote user's home to isolated fixture storage without
        // changing the process's HOME or touching a real user's installation.
        let script = script.replace("$HOME", self.root.to_str().unwrap());
        // Model a lease child that has forked but has not yet been scheduled
        // to close its inherited parent lock; this exercises a real fd race.
        let script = if self.root.join("delay-lease-exec").exists() {
            script.replace("(exec 9<&-; if", "(sleep 1; exec 9<&-; if")
        } else {
            script
        };
        // A test-only public marker proves that the real shell has reached
        // its blocking admission read; yielding alone would not prove overlap.
        let script = if matches!(input, Input::Signal(_)) {
            script.replace(
                "read -r approved",
                &format!(
                    ": > {}\nread -r approved",
                    infraternal_plugin_ssh::transport::shell_quote(
                        self.root.join("commit-admitted").to_str().unwrap()
                    )
                ),
            )
        } else {
            script
        };
        // Retain the shell parent through the reply. An interrupted final
        // command must never target the test runner through exec optimization.
        format!("{script}\nbootstrap_test_status=$?\nexit \"$bootstrap_test_status\"")
    }
}
impl SshSession for Local {
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        Box::pin(async move {
            let script = script.replace("$HOME", self.root.to_str().unwrap());
            let mut command = Command::new("/bin/sh");
            command.args(["-c", &script]);
            infraternal_plugin_ssh::duplex::Duplex::spawn(&mut command)
        })
    }

    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let script = self.fixture_script(script, &input);
            if matches!(&input, Input::Negotiated { .. } | Input::Transfer(_)) {
                // A real SSH client's process group excludes its remote lease.
                // Keep the direct-transfer shell in a separate session too, so
                // retiring the synthetic client cannot kill that remote lease.
                let mut command = if matches!(&input, Input::Transfer(_)) {
                    let mut command = Command::new("/usr/bin/setsid");
                    command.args(["--fork", "--wait", "/bin/sh"]);
                    command
                } else {
                    Command::new("/bin/sh")
                };
                command.args(["-c", &script]).env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.root.join("tools").display()),
                );
                let output =
                    infraternal_plugin_ssh::process::execute(&mut command, input, INSTALL_HANG)
                        .await?;
                if !output.success {
                    let mut error = Failure::install("The synthetic remote command failed.");
                    error.exit_status = output.exit_status;
                    return Err(error);
                }
                return Ok(CommandOutput {
                    stdout: output.stdout,
                });
            }
            let mut child = Command::new("/bin/sh")
                .args(["-c", &script])
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.root.join("tools").display()),
                )
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            // A refusal may close stdin before consuming an upload. Inspect the
            // command status first; successful commands still require a full write.
            let written = match input {
                Input::Negotiated { .. } | Input::Transfer(_) => {
                    unreachable!("negotiation uses the bounded process helper")
                }
                Input::PayloadAndInvitation {
                    payload,
                    invitation,
                } => {
                    let payload = match payload {
                        PayloadInput::Bytes(bytes) => bytes.to_vec(),
                        PayloadInput::File { path, size } => {
                            let bytes = std::fs::read(path).unwrap();
                            assert_eq!(bytes.len() as u64, size);
                            bytes
                        }
                    };
                    match stdin.write_all(&payload).await {
                        Ok(()) => stdin.write_all(invitation).await,
                        Err(error) => Err(error),
                    }
                }
                Input::Signal(release) => match release.await {
                    Ok(()) => stdin.write_all(b"\n").await,
                    Err(_) => Err(std::io::ErrorKind::Interrupted.into()),
                },
                Input::Empty => Ok(()),
                Input::Bytes(bytes) => stdin.write_all(bytes).await,
                Input::File(path) => stdin.write_all(&std::fs::read(path).unwrap()).await,
            };
            drop(stdin);
            let output = child.wait_with_output().await.unwrap();
            if !output.status.success() || written.is_err() {
                let mut failure = Failure::install("The synthetic remote command failed.");
                failure.exit_status = output
                    .status
                    .code()
                    .and_then(|code| u8::try_from(code).ok());
                return Err(failure);
            }
            Ok(CommandOutput {
                stdout: output.stdout,
            })
        })
    }
}

struct Fixture {
    _scratch: common::ScratchRoot,
    root: PathBuf,
    target: Target,
    join: JoinMaterial,
    binary: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        // Keep real control socket paths within sun_path. Exclusive creation
        // preserves isolation even if a shortened random fixture id collides.
        let scratch = common::scratch();
        let root = loop {
            let id = uuid::Uuid::new_v4().simple().to_string();
            let candidate = scratch.join(format!("i{}", &id[..12]));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture directory: {error}"),
            }
        };
        std::fs::create_dir_all(root.join("tools")).unwrap();
        executable(
            &root.join("tools/loginctl"),
            &format!(
                "#!/bin/sh\ncase \"$*\" in\n*show-user*) if [ -f '{}' ]; then printf 'yes\\n'; else printf 'no\\n'; fi;;\n*enable-linger*) [ ! -f '{}' ] || exit 1; [ -f '{}' ] || touch '{}'; [ ! -f '{}' ] || kill -TERM \"$PPID\";;\n*disable-linger*) rm -f '{}';;\n*) exit 1;;\nesac\n",
                root.join("linger").display(),
                root.join("deny-linger").display(),
                root.join("noop-linger").display(),
                root.join("linger").display(),
                root.join("interrupt-linger").display(),
                root.join("linger").display()
            ),
        );
        let manager = root.join("tools/systemctl");
        executable(
            &manager,
            &format!(
                "#!/bin/sh\ncase \"$*\" in\n*is-enabled*|*is-active*) exit 1;;\n*enable*--now*) [ ! -e '{}' ];;\n*) exit 0;;\nesac\n",
                root.join("refuse-start").display()
            ),
        );
        executable(
            &root.join("tools/runtime-helper"),
            &format!(
                "#!/bin/sh\nexec '{}' \"$@\"\n",
                common::runtime_helper().display()
            ),
        );
        let binary = root.join("payload");
        executable(
            &binary,
            "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\n# Synthetic CLI contract, not an infraternal daemon.\n[ \"$1 $2\" = 'agent --data' ] || exit 1\nstate=$3\n[ \"$4\" = join ] && [ \"$6\" = --enroll-only ] || exit 1\nmkdir -p \"$state\"\nprintf 'public-fixture-state\\n' > \"$state/proof\"\ncat >/dev/null\n",
        );
        Self {
            _scratch: scratch,
            root,
            target: Target {
                id: "one".into(),
                address: TargetAddress::Manual("user@fixture".into()),
                credential: None,
                mode: InstallMode::Rootless,
                root_consent: false,
            },
            join: JoinMaterial {
                host: uuid::Uuid::new_v4(),
                url: "https://fixture.invalid:7443/join".into(),
                stdin: Secret::new(b"synthetic-capability\n".to_vec()),
            },
            binary,
        }
    }
    fn transaction(&self) -> Installation {
        Installation::new(
            Arc::new(Local {
                root: self.root.clone(),
            }),
            &self.target,
            &self.join,
        )
        .unwrap()
    }
    fn receipt(&self) -> PathBuf {
        std::fs::read_dir(self.base().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("infraternal.bootstrap-rollback-")
            })
            .unwrap()
    }
    fn base(&self) -> PathBuf {
        self.root.join(".local/share/infraternal")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Test-owned leases must retire before their isolated directory disappears.
        // Never inspect or signal a process outside this fixture's exact journal.
        let stage = self.base().join(".bootstrap-lock");
        if stage.is_dir() {
            let script = format!(
                "set -eu\nstage={}\n{}\nretire_setup_lease",
                infraternal_plugin_ssh::transport::shell_quote(stage.to_str().unwrap()),
                include_str!("../src/setup_lock.sh")
            );
            let _ = std::process::Command::new("/bin/sh")
                .args(["-c", &script])
                .output();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn executable(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

struct CorruptUpload(Local);
impl SshSession for CorruptUpload {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        let input = if script.contains("gzip -dc >") || script.contains("zstd -dc >") {
            Input::Bytes(b"invalid compressed stream")
        } else {
            input
        };
        self.0.run(script, input)
    }
}

/// Staging starts a setup lease; key preparation retires it and must start a new
/// one under `set -C`. A leftover lease file made the restart fail (dash: status 2)
/// on every HTTPS add-host, after which only a stuck lock remained (#305).
/// Enrollment then has to accept the state copy that preparation left.
#[tokio::test]
async fn join_key_preparation_restarts_the_lease_and_feeds_enrollment() {
    let fixture = Fixture::new();
    let binary = fixture.root.join("prepare-payload");
    executable(
        &binary,
        "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\n# Synthetic CLI contract, not an infraternal daemon.\n[ \"$1 $2\" = 'agent --data' ] || exit 1\nstate=$3\nif [ \"$4\" = prepare-join-key ]; then : > \"$state/join-key.pk8\"; printf 'KEY-DIGEST %064d\\n' 0; exit 0; fi\n[ \"$4\" = join ] && [ \"$6\" = --enroll-only ] && [ -f \"$state/join-key.pk8\" ] || exit 1\nprintf 'public-fixture-state\\n' > \"$state/proof\"\ncat >/dev/null\n",
    );
    let transaction = fixture.transaction();
    let digest = transaction
        .prepare_join_key(&binary, "https://fixture.invalid")
        .await
        .unwrap();
    assert_eq!(digest, [0; 32]);
    let lease = std::fs::read_to_string(fixture.base().join(".bootstrap-lock/lease")).unwrap();
    let pid = lease.split(' ').next().unwrap();
    assert!(
        std::path::Path::new("/proc").join(pid).exists(),
        "the setup lease must be held again after key preparation"
    );
    // Enrollment must use the state copy that holds the prepared key, not
    // refuse it as a leftover (#305).
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    assert!(fixture.base().join("state/join-key.pk8").exists());
    transaction.commit().await.unwrap();
}

/// The person sees the HTTPS cause the staged infraternal agent reported, not
/// only the generic Connect remedy (#305).
#[tokio::test]
async fn join_key_preflight_refusal_keeps_its_https_cause() {
    let fixture = Fixture::new();
    let binary = fixture.root.join("prepare-payload");
    executable(
        &binary,
        "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\n# Synthetic CLI contract, not an infraternal daemon.\n[ \"$1 $2 $4\" = 'agent --data prepare-join-key' ] || exit 1\nprintf 'PREPARE-REFUSED TLS\\n'\n",
    );
    let transaction = fixture.transaction();
    let failure = transaction
        .prepare_join_key(&binary, "https://fixture.invalid")
        .await
        .unwrap_err();
    assert!(
        failure
            .message
            .contains("cannot verify the server's public HTTPS certificate"),
        "{}",
        failure.message
    );
    assert!(matches!(
        failure.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Connect)
    ));
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn framed_upload_keeps_invitation_after_verified_raw_and_compressed_payloads() {
    for compressed in [false, true] {
        let fixture = Fixture::new();
        let mut program = std::fs::read_to_string(&fixture.binary).unwrap().replace(
            "cat >/dev/null",
            "received=$(cat); [ \"$received\" = synthetic-capability ] || exit 1",
        );
        if compressed {
            program.push_str("\n# ");
            program.extend(std::iter::repeat_n('x', 70_000));
            program.push('\n');
        }
        std::fs::write(&fixture.binary, program).unwrap();
        let install = Installation::new(
            Arc::new(Compound(Local {
                root: fixture.root.clone(),
            })),
            &fixture.target,
            &fixture.join,
        )
        .unwrap();
        assert!(
            install
                .stage_and_setup(&fixture.binary, &fixture.join)
                .await
                .unwrap()
        );
        assert!(fixture.base().join(".bootstrap-lock/activating").exists());
        install.rollback().await.unwrap();
        assert!(!fixture.base().exists());
    }
}

#[tokio::test]
async fn framed_join_refusal_keeps_status_separate_from_upload() {
    let fixture = Fixture::new();
    executable(
        &fixture.binary,
        "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nexit 71\n",
    );
    let install = Installation::new(
        Arc::new(Compound(Local {
            root: fixture.root.clone(),
        })),
        &fixture.target,
        &fixture.join,
    )
    .unwrap();
    let error = install
        .stage_and_setup(&fixture.binary, &fixture.join)
        .await
        .unwrap_err();
    assert!(matches!(
        error.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Join)
    ));
    assert_eq!(error.exit_status, Some(71));
    assert!(!fixture.base().join(".bootstrap-lock/activating").exists());
    install.rollback().await.unwrap();
}

#[test]
fn framed_receipts_preserve_upload_failures_and_reject_extra_output() {
    use infraternal_plugin_ssh::{install::parse_transfer_setup, model::InstallStep};
    assert!(matches!(
        infraternal_plugin_ssh::install::interrupted_transfer_step(
            b"STEP upload\nSTEP join\nSTEP install\n"
        ),
        Some(infraternal_plugin_ssh::model::InstallStep::Install)
    ));
    assert!(
        infraternal_plugin_ssh::install::interrupted_transfer_step(b"STEP upload\r\n").is_none()
    );
    let error = parse_transfer_setup(b"STEP upload\nFAIL upload 71\n").unwrap_err();
    assert!(matches!(error.failed_step, Some(InstallStep::Upload)));
    assert_eq!(error.exit_status, Some(71));
    assert!(
        parse_transfer_setup(
            b"STEP upload\nSTEP join\nSTEP install\nSTEP start\nSTEP linger\nyes\nDONE\n"
        )
        .unwrap()
    );
    assert!(
        parse_transfer_setup(b"STEP upload\nFAIL upload 71\nextra\n")
            .unwrap_err()
            .exit_status
            .is_none()
    );
}

#[tokio::test]
async fn missing_payload_preserves_the_bootstrap_binary_remedy() {
    let fixture = Fixture::new();
    std::fs::remove_file(&fixture.binary).unwrap();
    let error = fixture
        .transaction()
        .stage(&fixture.binary)
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "The matching static infraternal binary is unavailable."
    );
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn successful_stage_releases_the_parent_lock_from_its_lease_child() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("delay-lease-exec"), b"").unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let lease = std::fs::read_to_string(fixture.base().join(".bootstrap-lock/lease")).unwrap();
    let pid = lease.split_ascii_whitespace().next().unwrap();
    assert!(
        std::fs::symlink_metadata(format!("/proc/{pid}/fd/9")).is_err(),
        "a successful upload must not leave its parent guard inherited by the lease"
    );
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.rollback().await.unwrap();
}

struct NegotiatedChoices {
    local: Local,
    choices: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}
impl SshSession for NegotiatedChoices {
    fn setup_steps(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let negotiated = matches!(&input, Input::Negotiated { .. });
            let output = self.local.run(script, input).await?;
            if negotiated {
                let receipt = output
                    .stdout
                    .split_inclusive(|byte| *byte == b'\n')
                    .nth(1)
                    .unwrap();
                assert!(
                    infraternal_plugin_ssh::transport::TransferChoice::parse(receipt).is_some()
                );
                self.choices.lock().unwrap().push(receipt.to_vec());
            }
            Ok(output)
        })
    }
}

#[tokio::test]
async fn negotiated_retry_reuses_only_a_verified_cache_after_activation_refusal() {
    use infraternal_plugin_ssh::model::InstallStep;
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let choices = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transaction = || {
            Installation::new(
                Arc::new(NegotiatedChoices {
                    local: Local {
                        root: fixture.root.clone(),
                    },
                    choices: choices.clone(),
                }),
                &fixture.target,
                &fixture.join,
            )
            .unwrap()
        };
        std::fs::write(fixture.root.join("refuse-start"), b"").unwrap();
        let first = transaction();
        let error = first
            .stage_and_setup(&fixture.binary, &fixture.join)
            .await
            .unwrap_err();
        assert!(matches!(error.failed_step, Some(InstallStep::Start)));
        first.rollback().await.unwrap();
        assert!(!fixture.base().exists());
        if corrupt {
            std::fs::write(
                fixture
                    .base()
                    .with_file_name("infraternal.bootstrap-cache")
                    .join("payload"),
                b"corrupted public cache",
            )
            .unwrap();
        }
        std::fs::remove_file(fixture.root.join("refuse-start")).unwrap();
        let second = transaction();
        second
            .stage_and_setup(&fixture.binary, &fixture.join)
            .await
            .unwrap();
        assert_eq!(
            *choices.lock().unwrap(),
            [
                b"TRANSFER raw\n".to_vec(),
                if corrupt {
                    b"TRANSFER raw\n".to_vec()
                } else {
                    b"TRANSFER reuse\n".to_vec()
                }
            ],
        );
        assert_eq!(
            std::fs::read(fixture.base().join("bin/live")).unwrap(),
            std::fs::read(&fixture.binary).unwrap()
        );
        second.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn compressed_stage_roundtrips_and_rejects_corruption_before_execution() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        // The fixture remains executable shell text and exceeds the raw fallback threshold.
        let mut payload = std::fs::read(&fixture.binary).unwrap();
        payload.extend_from_slice(b"\n# ");
        payload.extend(std::iter::repeat_n(b'x', 70_000));
        payload.push(b'\n');
        std::fs::write(&fixture.binary, &payload).unwrap();
        let local = Local {
            root: fixture.root.clone(),
        };
        let session: Arc<dyn SshSession> = if corrupt {
            Arc::new(CorruptUpload(local))
        } else {
            Arc::new(local)
        };
        let install = Installation::new(session, &fixture.target, &fixture.join).unwrap();
        let result = install.stage(&fixture.binary).await;
        if corrupt {
            assert!(result.is_err());
            assert!(!fixture.base().join(".bootstrap-lock/state").exists());
        } else {
            result.unwrap();
            assert_eq!(
                std::fs::read(fixture.base().join(".bootstrap-lock/payload")).unwrap(),
                payload
            );
        }
        install.rollback().await.unwrap();
        assert!(!fixture.base().exists());
    }
}

#[test]
fn setup_receipts_require_exact_order_and_preserve_failure_boundaries() {
    use infraternal_plugin_ssh::install::{interrupted_setup_step, parse_setup};
    use infraternal_plugin_ssh::model::InstallStep;
    let prefix = "STEP join\nSTEP install\nSTEP start\nSTEP linger\n";
    assert!(parse_setup(format!("{prefix}yes\nDONE\n").as_bytes()).unwrap());
    assert!(!parse_setup(format!("{prefix}no\nDONE\n").as_bytes()).unwrap());
    let mut receipt = String::new();
    for (name, expected) in [
        ("join", InstallStep::Join),
        ("install", InstallStep::Install),
        ("start", InstallStep::Start),
        ("linger", InstallStep::Install),
    ] {
        writeln!(receipt, "STEP {name}").unwrap();
        assert_eq!(
            format!("{:?}", interrupted_setup_step(receipt.as_bytes())),
            format!("{:?}", Some(expected))
        );
        let error = parse_setup(format!("{receipt}FAIL {name} 71\n").as_bytes()).unwrap_err();
        assert_eq!(
            format!("{:?}", error.failed_step),
            format!("{:?}", Some(expected))
        );
        assert_eq!(error.exit_status, Some(71));
    }
    for invalid in [
        "",
        "STEP join",
        "STEP start\n",
        "STEP join\nFAIL join 0\n",
        "STEP join\nFAIL join 071\n",
        "STEP join\nFAIL install 71\n",
        "STEP join\nFAIL join 71\nextra\n",
    ] {
        assert!(parse_setup(invalid.as_bytes()).is_err(), "{invalid:?}");
    }
    assert!(parse_setup(&[b'x'; 257]).is_err());
    let malformed = parse_setup(b"STEP join\r\nFAIL join 71\r\n").unwrap_err();
    assert!(
        malformed.exit_status.is_none(),
        "noncanonical receipt claimed a remote status"
    );
    assert!(interrupted_setup_step(b"STEP join\r\n").is_none());
    assert!(interrupted_setup_step(b"STEP join\nprivate\n").is_none());
}

/// The commit step keeps the setup journal until the shell has proved it
/// reached its blocking admission read, both when the commit is released and
/// when it is cancelled.
#[tokio::test]
async fn commit_signal_retains_journal_until_proof_and_on_cancel() {
    for permit in [false, true] {
        let fixture = Fixture::new();
        let install = Installation::new(
            Arc::new(Compound(Local {
                root: fixture.root.clone(),
            })),
            &fixture.target,
            &fixture.join,
        )
        .unwrap();
        install.stage(&fixture.binary).await.unwrap();
        install.setup(&fixture.join).await.unwrap();
        let stage = fixture.base().join(".bootstrap-lock");
        let (release, receiver) = tokio::sync::oneshot::channel();
        let pending = install.commit_after(receiver, None);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("commit preceded proof: {result:?}"),
            result = tokio::time::timeout(INSTALL_HANG, async {
                while !fixture.root.join("commit-admitted").exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }) => { result.unwrap(); }
        }
        assert!(stage.join("activating").exists());
        // A starting agent takes a shared lock on the installation's parent
        // before it binds; admission waiting for proof must not block it (#230).
        let parent = fixture.base().parent().unwrap().to_owned();
        assert!(
            std::process::Command::new("flock")
                .args(["-s", "-n"])
                .arg(&parent)
                .arg("true")
                .status()
                .unwrap()
                .success(),
            "commit admission holds the setup guard while waiting for proof"
        );
        if permit {
            release.send(()).unwrap();
            pending.await.unwrap();
            assert!(!stage.exists());
        } else {
            drop(release);
            assert!(pending.await.is_err());
            assert!(stage.join("activating").exists());
            install.rollback().await.unwrap();
        }
    }
}

#[tokio::test]
async fn compound_setup_keeps_owned_rollback_and_linger_warning() {
    let fixture = Fixture::new();
    let session = Arc::new(Compound(Local {
        root: fixture.root.clone(),
    }));
    let install = Installation::new(session, &fixture.target, &fixture.join).unwrap();
    install.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("deny-linger"), b"deny").unwrap();
    assert!(!install.setup(&fixture.join).await.unwrap());
    assert!(fixture.base().join(".bootstrap-lock/activating").exists());
    install.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn compound_activation_and_start_failures_keep_exact_step_and_rollback() {
    use infraternal_plugin_ssh::model::InstallStep;
    for refuse_start in [false, true] {
        let fixture = Fixture::new();
        let install = Installation::new(
            Arc::new(Compound(Local {
                root: fixture.root.clone(),
            })),
            &fixture.target,
            &fixture.join,
        )
        .unwrap();
        install.stage(&fixture.binary).await.unwrap();
        let launcher = fixture.root.join(".local/bin/infraternal");
        if refuse_start {
            std::fs::write(fixture.root.join("refuse-start"), b"refuse").unwrap();
        } else {
            std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
            std::fs::write(&launcher, b"foreign").unwrap();
        }
        let error = install.setup(&fixture.join).await.unwrap_err();
        if refuse_start {
            assert!(matches!(error.failed_step, Some(InstallStep::Start)));
            assert_eq!(error.exit_status, Some(1));
        } else {
            assert!(matches!(error.failed_step, Some(InstallStep::Install)));
            assert_eq!(error.exit_status, Some(71));
        }
        install.rollback().await.unwrap();
        if !refuse_start {
            assert_eq!(std::fs::read(&launcher).unwrap(), b"foreign");
        }
        assert!(!fixture.base().exists());
    }
}

#[tokio::test]
async fn compound_join_failure_preserves_the_original_status_and_boundary() {
    let fixture = Fixture::new();
    executable(
        &fixture.binary,
        "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nexit 71\n",
    );
    let session = Arc::new(Compound(Local {
        root: fixture.root.clone(),
    }));
    let install = Installation::new(session, &fixture.target, &fixture.join).unwrap();
    install.stage(&fixture.binary).await.unwrap();
    let error = install.setup(&fixture.join).await.unwrap_err();
    assert!(matches!(
        error.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Join)
    ));
    assert_eq!(error.exit_status, Some(71));
    assert!(!error.message.contains("move"));
    assert!(!fixture.base().join(".bootstrap-lock/activating").exists());
    install.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn review_interrupted_transaction_receipt_allows_owned_cleanup() {
    let fixture = Fixture::new();
    // A full filesystem can create the transaction file but refuse its bytes.
    // The exact pre-mkdir acquisition journal still binds this empty lock.
    executable(
        &fixture.root.join("tools/mkdir"),
        "#!/bin/sh\n/usr/bin/mkdir \"$@\" || exit $?\ncase \"$*\" in *.bootstrap-lock) : > \"$1/transaction\"; exit 42;; esac\n",
    );
    let transaction = fixture.transaction();
    assert!(transaction.stage(&fixture.binary).await.is_err());
    std::fs::remove_file(fixture.root.join("tools/mkdir")).unwrap();
    assert_eq!(
        std::fs::metadata(fixture.base().join(".bootstrap-lock/transaction"))
            .unwrap()
            .len(),
        0
    );
    let cleaned = transaction.rollback().await;
    assert!(
        cleaned.is_ok(),
        "exact acquisition journal did not recover an incomplete transaction receipt: {cleaned:?}"
    );
    assert!(!fixture.base().exists());
}

// These break-it regressions state the desired contract and intentionally stay
// red until the follow-up fix lane. Explicit opt-in keeps the shared fast gate
// useful while preserving executable evidence of the reported defects (#169).
#[tokio::test]
async fn breakit2_rollback_preserves_foreign_launcher_new() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let foreign = fixture.root.join(".local/bin/infraternal.new");
    std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    std::fs::write(&foreign, "unrelated launcher staging data").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    transaction.rollback().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(&foreign).ok().as_deref(),
        Some("unrelated launcher staging data"),
        "rollback deleted a file that this attempt never created"
    );
}

#[tokio::test]
async fn breakit2_rollback_preserves_foreign_unit_new() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let foreign = fixture
        .root
        .join(".config/systemd/user/infraternal-agent.service.new");
    std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    std::fs::write(&foreign, "unrelated unit staging data").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    transaction.rollback().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(&foreign).ok().as_deref(),
        Some("unrelated unit staging data"),
        "noclobber refused the foreign unit, then rollback deleted it"
    );
}

#[tokio::test]
async fn breakit2_stage_refuses_parent_that_cannot_be_rolled_back() {
    let fixture = Fixture::new();
    let parent = fixture.root.join(".local/share");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
    let transaction = fixture.transaction();
    let staged = transaction.stage(&fixture.binary).await;
    let cleanup = transaction.rollback().await;
    assert!(
        staged.is_err() || cleanup.is_ok(),
        "stage accepted mode 0775, then rollback refused the same parent and left its payload/lock"
    );
}

#[tokio::test]
async fn breakit2_interrupted_lock_creation_allows_cleanup_and_retry() {
    let fixture = Fixture::new();
    // A real mkdir succeeds, then the command fails before the transaction and
    // kind records are written. This models an abrupt stop at that boundary.
    executable(
        &fixture.root.join("tools/mkdir"),
        "#!/bin/sh\n/usr/bin/mkdir \"$@\" || exit $?\ncase \"$*\" in *.bootstrap-lock) exit 42;; esac\n",
    );
    let transaction = fixture.transaction();
    assert!(transaction.stage(&fixture.binary).await.is_err());
    std::fs::remove_file(fixture.root.join("tools/mkdir")).unwrap();
    assert!(
        transaction.rollback().await.is_ok(),
        "an owned empty lock has no transaction record; rollback cannot recover it"
    );
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

#[tokio::test]
async fn interrupted_acquisition_cleanup_receipt_can_resume() {
    let fixture = Fixture::new();
    executable(
        &fixture.root.join("tools/mkdir"),
        "#!/bin/sh\n/usr/bin/mkdir \"$@\" || exit $?\ncase \"$*\" in *.bootstrap-lock) exit 42;; esac\n",
    );
    let transaction = fixture.transaction();
    assert!(transaction.stage(&fixture.binary).await.is_err());
    std::fs::remove_file(fixture.root.join("tools/mkdir")).unwrap();
    executable(
        &fixture.root.join("tools/rm"),
        "#!/bin/sh\ncase \"$*\" in *.bootstrap-acquiring) exit 42;; esac\nexec /usr/bin/rm \"$@\"\n",
    );
    assert!(transaction.rollback().await.is_err());
    assert!(fixture.receipt().exists());
    assert!(fixture.base().join(".bootstrap-acquiring").exists());
    assert!(!fixture.base().join(".bootstrap-lock").exists());
    std::fs::remove_file(fixture.root.join("tools/rm")).unwrap();
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

/// Counts actual file input crossing the session boundary while commands execute locally.
struct TransferCount {
    local: Local,
    bytes: Arc<std::sync::atomic::AtomicUsize>,
}
impl SshSession for TransferCount {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            if let Input::File(path) = input {
                self.bytes.fetch_add(
                    usize::try_from(path.metadata().unwrap().len()).unwrap(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            } else if let Input::Transfer(PayloadInput::File { size, .. }) = &input {
                self.bytes.fetch_add(
                    usize::try_from(*size).unwrap(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            self.local.run(script, input).await
        })
    }
}

fn counted_transaction(
    fixture: &Fixture,
    bytes: &Arc<std::sync::atomic::AtomicUsize>,
) -> Installation {
    Installation::new(
        Arc::new(TransferCount {
            local: Local {
                root: fixture.root.clone(),
            },
            bytes: bytes.clone(),
        }),
        &fixture.target,
        &fixture.join,
    )
    .unwrap()
}

#[tokio::test]
async fn retry_reuses_verified_payload_after_owned_rollback() {
    let fixture = Fixture::new();
    let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first = counted_transaction(&fixture, &bytes);
    first.stage(&fixture.binary).await.unwrap();
    first.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    let second = counted_transaction(&fixture, &bytes);
    second.stage(&fixture.binary).await.unwrap();
    assert_eq!(
        std::fs::read(fixture.base().join(".bootstrap-lock/payload")).unwrap(),
        std::fs::read(&fixture.binary).unwrap()
    );
    assert_eq!(
        bytes.load(std::sync::atomic::Ordering::Relaxed),
        usize::try_from(fixture.binary.metadata().unwrap().len()).unwrap()
    );
    second.rollback().await.unwrap();
}

#[tokio::test]
async fn retry_resends_payload_when_cache_content_changes() {
    let fixture = Fixture::new();
    let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first = counted_transaction(&fixture, &bytes);
    first.stage(&fixture.binary).await.unwrap();
    first.rollback().await.unwrap();
    let cache = fixture.base().with_file_name("infraternal.bootstrap-cache");
    assert!(cache.join("payload").exists());
    std::fs::write(cache.join("payload"), b"changed fixture content").unwrap();
    let second = counted_transaction(&fixture, &bytes);
    second.stage(&fixture.binary).await.unwrap();
    assert_eq!(
        std::fs::read(fixture.base().join(".bootstrap-lock/payload")).unwrap(),
        std::fs::read(&fixture.binary).unwrap()
    );
    assert_eq!(
        bytes.load(std::sync::atomic::Ordering::Relaxed),
        2 * usize::try_from(fixture.binary.metadata().unwrap().len()).unwrap()
    );
    second.rollback().await.unwrap();
}

#[tokio::test]
async fn payload_reuse_never_adopts_a_foreign_cache_directory() {
    let fixture = Fixture::new();
    let cache = fixture.base().with_file_name("infraternal.bootstrap-cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(cache.join("owner"), b"foreign data\n").unwrap();
    let transaction = fixture.transaction();
    assert!(transaction.stage(&fixture.binary).await.is_err());
    assert_eq!(
        std::fs::read(cache.join("owner")).unwrap(),
        b"foreign data\n"
    );
}

/// Models receipt allocation being unavailable until the owned payload is freed.
/// The rollback still runs through the real shell and filesystem; the separate
/// disposable-target test exercises a genuinely full home filesystem.
struct ReceiptBudget(Local);
impl SshSession for ReceiptBudget {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let guarded = format!(
                r#"printf() {{
    if [ "$1" = '%s %s fresh %s\n' ] && [ -e "$base/.bootstrap-lock/payload" ]; then return 1; fi
    command printf "$@"
}}
{script}"#
            );
            self.0.run(&guarded, input).await
        })
    }
}

#[tokio::test]
async fn full_stage_frees_payload_before_allocating_a_cleanup_receipt() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let cleanup = Installation::resume_cleanup(
        Arc::new(ReceiptBudget(Local {
            root: fixture.root.clone(),
        })),
        &fixture.target,
        transaction.cleanup_coordinates(),
    )
    .unwrap();
    cleanup.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn fresh_runtime_empty_directories_do_not_block_rollback_and_retry() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    // The real service creates this rendezvous directory even before opening a PTY.
    std::fs::create_dir_all(fixture.base().join("sessions/sessions")).unwrap();
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

#[tokio::test]
async fn fresh_runtime_unexpected_data_keeps_ownership_and_cleanup_receipt() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    let runtime = fixture.base().join("sessions/sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    let unexpected = runtime.join("unknown-data");
    std::fs::write(&unexpected, b"public fixture data").unwrap();
    assert!(transaction.rollback().await.is_err());
    assert_eq!(std::fs::read(&unexpected).unwrap(), b"public fixture data");
    assert!(fixture.base().join(".bootstrap-owner").exists());
    assert!(fixture.receipt().exists());
    assert!(fixture.transaction().stage(&fixture.binary).await.is_err());
    std::fs::remove_file(unexpected).unwrap();
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn fresh_runtime_symlink_never_removes_foreign_empty_directories() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let foreign = fixture.root.join("foreign/sessions");
    std::fs::create_dir_all(&foreign).unwrap();
    let retained_runtime = fixture.root.join("retained-runtime");
    std::fs::rename(fixture.base().join("sessions"), &retained_runtime).unwrap();
    symlink(foreign.parent().unwrap(), fixture.base().join("sessions")).unwrap();
    assert!(transaction.rollback().await.is_err());
    assert!(foreign.exists());
    assert!(fixture.base().join(".bootstrap-owner").exists());
    std::fs::remove_file(fixture.base().join("sessions")).unwrap();
    std::fs::rename(retained_runtime, fixture.base().join("sessions")).unwrap();
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn fresh_failure_removes_owned_artifacts_and_success_can_rejoin() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("refuse-start"), "fixture refusal").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    assert!(!fixture.root.join(".local/bin/infraternal").exists());
    assert!(
        !fixture
            .root
            .join(".config/systemd/user/infraternal-agent.service")
            .exists()
    );
    std::fs::remove_file(fixture.root.join("refuse-start")).unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.base().join("state/proof")).unwrap(),
        "public-fixture-state\n"
    );
    assert!(!fixture.base().join(".bootstrap-lock").exists());
}

#[tokio::test]
async fn failed_upgrade_preserves_previous_binary_state_and_unit() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    let old = std::fs::read(fixture.base().join("bin/live")).unwrap();
    let unit_path = fixture
        .root
        .join(".config/systemd/user/infraternal-agent.service");
    let unit = std::fs::read(&unit_path).unwrap();
    std::fs::write(fixture.base().join("state/proof"), "previous-public-state").unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("refuse-start"), "fixture refusal").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    transaction.rollback().await.unwrap();
    assert_eq!(std::fs::read(fixture.base().join("bin/live")).unwrap(), old);
    assert_eq!(std::fs::read(&unit_path).unwrap(), unit);
    assert_eq!(
        std::fs::read_to_string(fixture.base().join("state/proof")).unwrap(),
        "previous-public-state"
    );
}

#[tokio::test]
async fn foreign_files_and_another_attempt_lock_are_never_removed() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let other = fixture.transaction();
    assert!(other.stage(&fixture.binary).await.is_err());
    assert!(other.rollback().await.is_err());
    assert!(fixture.base().join(".bootstrap-lock/payload").exists());
    std::fs::create_dir_all(fixture.root.join(".local/bin")).unwrap();
    std::fs::write(fixture.root.join(".local/bin/infraternal"), "foreign-file").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    transaction.rollback().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.root.join(".local/bin/infraternal")).unwrap(),
        "foreign-file"
    );
}

#[tokio::test]
async fn retry_cleanup_uses_fresh_session_and_preserves_privilege_consent() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let cleanup = transaction.cleanup_coordinates();
    drop(transaction);
    let resumed = Installation::resume_cleanup(
        Arc::new(Local {
            root: fixture.root.clone(),
        }),
        &fixture.target,
        cleanup,
    )
    .unwrap();
    resumed.rollback().await.unwrap();
    resumed.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    let mut changed = fixture.target.clone();
    changed.mode = InstallMode::Root;
    changed.root_consent = true;
    assert!(
        Installation::resume_cleanup(
            Arc::new(Local {
                root: fixture.root.clone()
            }),
            &changed,
            cleanup
        )
        .is_err()
    );
}

#[tokio::test]
async fn interrupted_rollback_never_deletes_already_restored_state_on_retry() {
    let fixture = Fixture::new();
    let initial = fixture.transaction();
    initial.stage(&fixture.binary).await.unwrap();
    initial.enroll_and_start(&fixture.join).await.unwrap();
    initial.commit().await.unwrap();
    std::fs::write(fixture.base().join("state/proof"), "previous-public-state").unwrap();
    let previous_binary = std::fs::read(fixture.base().join("bin/live")).unwrap();
    let unit_path = fixture
        .root
        .join(".config/systemd/user/infraternal-agent.service");
    let previous_unit = std::fs::read(&unit_path).unwrap();
    let upgrade = fixture.transaction();
    upgrade.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("refuse-start"), "fixture refusal").unwrap();
    assert!(upgrade.enroll_and_start(&fixture.join).await.is_err());
    let marker = fixture.root.join("refuse-reload-once");
    std::fs::write(&marker, "public fixture flag").unwrap();
    executable(
        &fixture.root.join("tools/systemctl"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n*daemon-reload*) if [ -f '{}' ]; then rm '{}'; exit 1; fi;;\nesac\nexit 0\n",
            marker.display(),
            marker.display()
        ),
    );
    assert!(upgrade.rollback().await.is_err());
    upgrade.rollback().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.base().join("bin/live")).unwrap(),
        previous_binary
    );
    assert_eq!(std::fs::read(unit_path).unwrap(), previous_unit);
    assert_eq!(
        std::fs::read_to_string(fixture.base().join("state/proof")).unwrap(),
        "previous-public-state"
    );
}

#[tokio::test]
async fn linger_policy_denial_is_a_warning_and_owned_changes_are_reversible() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("deny-linger"), "deny").unwrap();
    assert!(!transaction.enable_linger().await.unwrap());
    std::fs::remove_file(fixture.root.join("deny-linger")).unwrap();
    // Retry a denied request in the same transaction without truncating its marker.
    transaction.rollback().await.unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    assert!(transaction.enable_linger().await.unwrap());
    assert!(fixture.root.join("linger").exists());
    transaction.rollback().await.unwrap();
    assert!(!fixture.root.join("linger").exists());
    std::fs::write(fixture.root.join("linger"), "prior policy").unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    assert!(transaction.enable_linger().await.unwrap());
    transaction.rollback().await.unwrap();
    assert!(fixture.root.join("linger").exists());
}

#[tokio::test]
async fn interrupted_restore_recreates_links_without_deleting_the_original() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    let old = std::fs::read(fixture.base().join("bin/live")).unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("refuse-start"), "deny").unwrap();
    assert!(transaction.enroll_and_start(&fixture.join).await.is_err());
    executable(
        &fixture.root.join("tools/ln"),
        &format!(
            "#!/bin/sh\nif [ \"$3\" = '{}' ] && [ ! -f '{}' ]; then touch '{}'; exit 1; fi\nexec /usr/bin/ln \"$@\"\n",
            fixture.base().join("bin/current").display(),
            fixture.root.join("restore-link-refused").display(),
            fixture.root.join("restore-link-refused").display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    transaction.rollback().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.base().join("bin/current")).unwrap(),
        old
    );
}

#[tokio::test]
async fn writable_installation_is_refused_before_upload_or_cleanup() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    std::fs::set_permissions(fixture.base(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let transaction = fixture.transaction();
    assert!(
        transaction.stage(&fixture.binary).await.is_err(),
        "accepted a writable install root"
    );
    assert!(
        transaction.rollback().await.is_err(),
        "cleaned an untrusted install root"
    );
}

#[tokio::test]
async fn rejoin_preserves_existing_host_identity_in_the_private_staging_state() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    std::fs::write(
        fixture.base().join("state/public-identity-placeholder"),
        "prior-public-identity",
    )
    .unwrap();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    assert!(
        std::fs::read(fixture.base().join("state/public-identity-placeholder"))
            .is_ok_and(|value| value == b"prior-public-identity")
    );
}

#[tokio::test]
async fn active_service_stop_failure_never_replaces_live_artifacts() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    let old = std::fs::read(fixture.base().join("bin/live")).unwrap();
    executable(
        &fixture.binary,
        &(String::from_utf8(old.clone()).unwrap() + "\n# next fixture version\n"),
    );
    executable(
        &fixture.root.join("tools/systemctl"),
        "#!/bin/sh\ncase \"$*\" in *stop*) exit 1;; *) exit 0;; esac\n",
    );
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    assert!(
        transaction.enroll_and_start(&fixture.join).await.is_err(),
        "ignored active service stop failure"
    );
    assert_eq!(std::fs::read(fixture.base().join("bin/live")).unwrap(), old);
    transaction.rollback().await.unwrap();
    assert_eq!(std::fs::read(fixture.base().join("bin/live")).unwrap(), old);
}

#[tokio::test]
async fn fresh_receipt_is_removed_before_transaction_rollback() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    // Model cancellation between receipt publication and lock release.
    std::fs::write(fixture.base().join(".bootstrap-ready"), b"public-receipt\n").unwrap();
    transaction.rollback().await.unwrap();
    assert!(
        !fixture.base().exists(),
        "fresh manual receipt left an installed artifact behind"
    );
}

#[tokio::test]
async fn rollback_stop_refusal_retains_artifacts_for_later_cleanup() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    assert!(transaction.enable_linger().await.unwrap());
    // Once activation has succeeded, a refused stop leaves the new service live.
    // Its identity and transaction must survive so fresh credentials can retry cleanup.
    executable(
        &fixture.root.join("tools/systemctl"),
        "#!/bin/sh\ncase \"$*\" in *stop*) exit 1;; *) exit 0;; esac\n",
    );
    assert!(
        transaction.rollback().await.is_err(),
        "rollback reported success despite service stop refusal"
    );
    assert!(fixture.base().join("state/proof").exists());
    assert!(fixture.base().join(".bootstrap-lock/transaction").exists());
    assert!(fixture.root.join("linger").exists());
    executable(&fixture.root.join("tools/systemctl"), "#!/bin/sh\nexit 0\n");
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    assert!(!fixture.root.join("linger").exists());
}

#[tokio::test]
async fn denied_linger_request_does_not_undo_a_later_external_enable() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("deny-linger"), "public policy refusal").unwrap();
    assert!(!transaction.enable_linger().await.unwrap());
    // A separate operator enables linger after our denied request. Intent alone
    // is not a receipt that this transaction owns the policy change.
    std::fs::write(fixture.root.join("linger"), "external policy enable").unwrap();
    transaction.rollback().await.unwrap();
    assert!(
        fixture.root.join("linger").exists(),
        "rollback reversed external linger policy"
    );
}

#[tokio::test]
async fn acknowledged_linger_noop_does_not_own_later_external_enable() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("noop-linger"), "public policy no-op").unwrap();
    assert!(!transaction.enable_linger().await.unwrap());
    std::fs::write(fixture.root.join("linger"), "external policy enable").unwrap();
    transaction.rollback().await.unwrap();
    assert!(fixture.root.join("linger").exists());
}

#[tokio::test]
async fn interrupted_linger_reply_retains_intent_for_cleanup() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::write(fixture.root.join("interrupt-linger"), "interrupt reply").unwrap();
    assert!(transaction.enable_linger().await.is_err());
    assert!(fixture.root.join("linger").exists());
    assert!(
        fixture
            .base()
            .join(".bootstrap-lock/linger-requested")
            .exists()
    );
    transaction.rollback().await.unwrap();
    assert!(!fixture.root.join("linger").exists());
}

#[tokio::test]
async fn fresh_rollback_resumes_after_transaction_directory_removal() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    let stage = fixture.base().join(".bootstrap-lock");
    // Model a stop after deleting the transaction directory but before deleting
    // its owner marker and empty base. The caller still has cleanup coordinates.
    executable(
        &fixture.root.join("tools/rm"),
        &format!(
            "#!/bin/sh\n/usr/bin/rm \"$@\" || exit $?\n[ \"${{2-}}\" != '{}' ] || exit 1\n",
            stage.display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    assert!(!stage.exists());
    assert!(fixture.base().join(".bootstrap-owner").exists());
    transaction.rollback().await.unwrap();
    assert!(
        !fixture.base().exists(),
        "resumed fresh rollback retained owned installation root"
    );
}

#[tokio::test]
async fn fresh_cleanup_resumes_after_owner_marker_removal_with_a_fresh_session() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let owner = fixture.base().join(".bootstrap-owner");
    executable(
        &fixture.root.join("tools/rm"),
        &format!(
            "#!/bin/sh\n/usr/bin/rm \"$@\" || exit $?\n[ \"${{2-}}\" != '{}' ] || exit 1\n",
            owner.display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    assert!(!owner.exists());
    let resumed = Installation::resume_cleanup(
        Arc::new(Local {
            root: fixture.root.clone(),
        }),
        &fixture.target,
        transaction.cleanup_coordinates(),
    )
    .unwrap();
    resumed.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn fresh_cleanup_resumes_after_base_removal_and_retires_its_receipt() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    executable(
        &fixture.root.join("tools/rmdir"),
        &format!(
            "#!/bin/sh\n/usr/bin/rmdir \"$@\" || exit $?\n[ \"${{1-}}\" != '{}' ] || exit 1\n",
            fixture.base().display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    assert!(!fixture.base().exists());
    let receipt = fixture.receipt();
    transaction.rollback().await.unwrap();
    assert!(!receipt.exists());
}

#[tokio::test]
async fn pending_fresh_cleanup_refuses_replacement_staging_until_finished() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let stage = fixture.base().join(".bootstrap-lock");
    executable(
        &fixture.root.join("tools/rm"),
        &format!(
            "#!/bin/sh\n/usr/bin/rm \"$@\" || exit $?\n[ \"${{2-}}\" != '{}' ] || exit 1\n",
            stage.display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    let replacement = fixture.transaction();
    assert!(replacement.stage(&fixture.binary).await.is_err());
    std::fs::remove_file(fixture.root.join("tools/rm")).unwrap();
    transaction.rollback().await.unwrap();
    replacement.stage(&fixture.binary).await.unwrap();
    replacement.rollback().await.unwrap();
}

#[tokio::test]
async fn cleanup_receipt_cannot_authorize_a_replaced_unowned_directory() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let owner = fixture.base().join(".bootstrap-owner");
    executable(
        &fixture.root.join("tools/rm"),
        &format!(
            "#!/bin/sh\n/usr/bin/rm \"$@\" || exit $?\n[ \"${{2-}}\" != '{}' ] || exit 1\n",
            owner.display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    // Retain the old directory inode, then replace the path with unowned data.
    std::fs::rename(fixture.base(), fixture.root.join("saved-base")).unwrap();
    std::fs::create_dir(fixture.base()).unwrap();
    std::fs::set_permissions(fixture.base(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let foreign = fixture.base().join(".bootstrap-ready");
    std::fs::write(&foreign, "public foreign readiness receipt").unwrap();
    assert!(transaction.rollback().await.is_err());
    assert!(foreign.exists());
}

#[tokio::test]
async fn malformed_or_exposed_cleanup_receipts_never_remove_the_owned_root() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for kind in ["link", "mode", "length", "binding"] {
        let fixture = Fixture::new();
        let transaction = fixture.transaction();
        transaction.stage(&fixture.binary).await.unwrap();
        let stage = fixture.base().join(".bootstrap-lock");
        executable(
            &fixture.root.join("tools/rm"),
            &format!(
                "#!/bin/sh\n/usr/bin/rm \"$@\" || exit $?\n[ \"${{2-}}\" != '{}' ] || exit 1\n",
                stage.display()
            ),
        );
        assert!(transaction.rollback().await.is_err());
        let receipt = fixture.receipt();
        match kind {
            "link" => {
                let copy = fixture.root.join("public-receipt-copy");
                std::fs::rename(&receipt, &copy).unwrap();
                symlink(copy, &receipt).unwrap();
            }
            "mode" => {
                std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "length" => std::fs::write(&receipt, [b'x'; 115]).unwrap(),
            "binding" => {
                let public = std::fs::read_to_string(&receipt).unwrap();
                std::fs::write(
                    &receipt,
                    public.replacen(
                        &fixture.join.host.simple().to_string(),
                        &uuid::Uuid::new_v4().simple().to_string(),
                        1,
                    ),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(transaction.rollback().await.is_err());
        assert!(fixture.base().join(".bootstrap-owner").exists());
    }
}

#[tokio::test]
async fn fresh_cleanup_refuses_a_shared_writable_receipt_parent_before_mutation() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    std::fs::set_permissions(
        fixture.base().parent().unwrap(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(transaction.rollback().await.is_err());
    assert!(fixture.base().join(".bootstrap-lock/transaction").exists());
}

#[tokio::test]
async fn linked_owner_marker_is_refused_before_retiring_the_transaction() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let public = fixture.root.join("public-host-binding");
    std::fs::write(&public, format!("{}\n", fixture.join.host.simple())).unwrap();
    let owner = fixture.base().join(".bootstrap-owner");
    std::fs::remove_file(&owner).unwrap();
    symlink(public, owner).unwrap();
    assert!(transaction.rollback().await.is_err());
    assert!(fixture.base().join(".bootstrap-lock/transaction").exists());
}

#[tokio::test]
async fn interrupted_upgrade_after_acknowledged_stop_restarts_the_previous_service() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    transaction.commit().await.unwrap();
    let active = fixture.root.join("active");
    let lost = fixture.root.join("shell-lost");
    std::fs::write(&active, "").unwrap();
    // The service manager completes the stop, then the remote shell is lost
    // before its next statement (lost session, OOM, reboot of the login scope).
    // The stopped previous service is live state that rollback must restore.
    executable(
        &fixture.root.join("tools/systemctl"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n*is-enabled*) exit 0;;\n*is-active*) [ -f '{a}' ];;\n*stop*) rm -f '{a}'; if [ ! -f '{l}' ]; then : > '{l}'; kill -KILL $PPID; fi;;\n*start*) [ ! -f '{r}' ] || exit 1; : > '{a}';;\n*) exit 0;;\nesac\n",
            a = active.display(),
            l = lost.display(),
            r = fixture.root.join("refuse-restart").display()
        ),
    );
    let upgrade = fixture.transaction();
    upgrade.stage(&fixture.binary).await.unwrap();
    assert!(upgrade.enroll_and_start(&fixture.join).await.is_err());
    assert!(
        !active.exists(),
        "fixture: the previous service was stopped"
    );
    // A refused restart keeps the journal so a later cleanup can resume.
    let refuse_restart = fixture.root.join("refuse-restart");
    std::fs::write(&refuse_restart, "").unwrap();
    assert!(upgrade.rollback().await.is_err());
    assert!(fixture.base().join(".bootstrap-lock/stopping").exists());
    std::fs::remove_file(refuse_restart).unwrap();
    upgrade.rollback().await.unwrap();
    assert!(
        active.exists(),
        "rollback left the previously active service stopped after an interrupted upgrade"
    );
}

#[tokio::test]
async fn refused_previous_service_stop_only_removes_staging() {
    let fixture = Fixture::new();
    let installed = fixture.transaction();
    installed.stage(&fixture.binary).await.unwrap();
    installed.enroll_and_start(&fixture.join).await.unwrap();
    installed.commit().await.unwrap();
    let before = std::fs::read(fixture.base().join("bin/live")).unwrap();
    let restart = fixture.root.join("unexpected-restart");
    executable(
        &fixture.root.join("tools/systemctl"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n*is-enabled*|*is-active*) exit 0;;\n*stop*) exit 1;;\n*start*) : > '{}' ;;\n*) exit 0;;\nesac\n",
            restart.display()
        ),
    );
    let upgrade = fixture.transaction();
    upgrade.stage(&fixture.binary).await.unwrap();
    assert!(upgrade.enroll_and_start(&fixture.join).await.is_err());
    upgrade.rollback().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.base().join("bin/live")).unwrap(),
        before
    );
    assert!(!restart.exists());
    assert!(!fixture.base().join(".bootstrap-lock").exists());
}

/// A bounded command failure isolates step attribution from filesystem rollback.
struct FailAt(std::sync::atomic::AtomicUsize, usize);
impl SshSession for FailAt {
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.1 {
                Err(Failure::install("The authenticated SSH command failed."))
            } else {
                Ok(CommandOutput { stdout: Vec::new() })
            }
        })
    }
}
#[tokio::test]
async fn command_failure_names_upload_join_install_and_start_separately() {
    let fixture = Fixture::new();
    let upload = Installation::new(
        Arc::new(FailAt(0.into(), 0)),
        &fixture.target,
        &fixture.join,
    )
    .unwrap();
    let failed = upload.stage(&fixture.binary).await.unwrap_err();
    assert_eq!(
        serde_json::to_value(failed).unwrap()["failed_step"],
        "upload"
    );
    for (call, step) in [(0, "join"), (1, "install"), (2, "start")] {
        let transaction = Installation::new(
            Arc::new(FailAt(0.into(), call)),
            &fixture.target,
            &fixture.join,
        )
        .unwrap();
        let failed = transaction
            .enroll_and_start(&fixture.join)
            .await
            .unwrap_err();
        assert_eq!(serde_json::to_value(failed).unwrap()["failed_step"], step);
    }
}

#[tokio::test]
async fn foreign_data_refusal_retains_exit_status_and_actionable_directory() {
    let fixture = Fixture::new();
    let base = fixture.root.join(".local/share/infraternal");
    std::fs::create_dir_all(&base).unwrap();
    let failure = fixture
        .transaction()
        .stage(&fixture.binary)
        .await
        .unwrap_err();
    assert_eq!(serde_json::to_value(&failure).unwrap()["exit_status"], 71);
    // One plain finding; the location is in Details, never in the sentence (#394).
    assert_eq!(
        failure.kind,
        infraternal_plugin_ssh::model::FailureKind::UnrecognizedInstall
    );
    assert!(!failure.message.contains("~/.local/share/infraternal"));
    assert!(
        failure
            .log_tail
            .contains(&"Setup location: ~/.local/share/infraternal")
    );
}

#[tokio::test]
async fn enrollment_process_exit_71_is_not_reported_as_directory_refusal() {
    let fixture = Fixture::new();
    executable(
        &fixture.binary,
        "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nexit 71\n",
    );
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();

    let failure = transaction
        .enroll_and_start(&fixture.join)
        .await
        .unwrap_err();

    assert_eq!(failure.exit_status, Some(71));
    assert_eq!(
        serde_json::to_value(&failure).unwrap()["failed_step"],
        "join"
    );
    assert!(
        failure
            .message
            .starts_with("Joining the host to this server failed.")
    );
    assert!(!failure.message.contains("Move it aside"));
}

#[tokio::test]
async fn setup_transaction_holds_a_live_lock_between_shell_commands() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let session = Local {
        root: fixture.root.clone(),
    };
    let stage = fixture.base().join(".bootstrap-lock");
    let script = format!(
        "exec 9< {}; flock -n 9 || exit 73",
        infraternal_plugin_ssh::transport::shell_quote(stage.to_str().unwrap())
    );
    assert_eq!(
        session
            .run(&script, Input::Empty)
            .await
            .err()
            .unwrap()
            .exit_status,
        Some(73)
    );
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

#[tokio::test]
async fn stale_previous_attempt_socket_can_be_retired_without_manual_cleanup() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let sessions = fixture.base().join("sessions/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    for directory in [&sessions, sessions.parent().unwrap()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let socket = sessions.join(format!("{}.sock", uuid::Uuid::new_v4().simple()));
    assert!(Command::new("python3")
        .args(["-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); __import__(\"os\").chmod(sys.argv[1],0o600)"])
        .arg(socket.file_name().unwrap())
        .current_dir(&sessions)
        .status().await.unwrap().success());
    // A failed earlier setup has retired its transaction but cannot finish
    // removing the rendezvous directory while this stale socket remains.
    assert!(transaction.rollback().await.is_err());
    assert!(fixture.receipt().exists());
    let next = fixture.transaction();
    assert!(next.stage(&fixture.binary).await.is_err());
    // Desired recovery boundary: the earlier attempt owns this socket, and no
    // listener remains. Ordinary rollback currently cannot retire it.
    let session = Local {
        root: fixture.root.clone(),
    };
    let output = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await
        .unwrap();
    let (_, previous) =
        infraternal_plugin_ssh::previous_attempt::parse_check(&output.stdout).unwrap();
    previous
        .unwrap()
        .start_fresh(&session, &fixture.target)
        .await
        .unwrap();
    assert!(!socket.exists());
    next.stage(&fixture.binary).await.unwrap();
    next.enroll_and_start(&fixture.join).await.unwrap();
    next.commit().await.unwrap();
}

#[tokio::test]
async fn active_transaction_is_live_between_ssh_setup_commands() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let session = Local {
        root: fixture.root.clone(),
    };
    let output = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await
        .unwrap();
    let refused =
        infraternal_plugin_ssh::previous_attempt::parse_check(&output.stdout).unwrap_err();
    assert_eq!(
        refused.kind,
        infraternal_plugin_ssh::model::FailureKind::SetupRunning
    );
    assert!(refused.to_string().contains("has held the setup lock"));
    assert!(fixture.base().join(".bootstrap-lock").exists());
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
}

/// #394: a finished install is named, not reported clear; only the exact
/// record with a canonical host id is accepted.
#[test]
fn a_finished_install_record_is_recognized_exactly() {
    use infraternal_plugin_ssh::previous_attempt::{Remains, parse_check_with_absence};
    let check = "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n";
    let valid = format!("{check}INFRATERNAL_SETUP_INSTALLED {}\n", "1".repeat(32));
    let (_, previous, remains) = parse_check_with_absence(valid.as_bytes()).unwrap();
    assert!(previous.is_none());
    assert_eq!(remains, Remains::Installed);
    let clear = format!("{check}INFRATERNAL_SETUP_CLEAR\n");
    assert_eq!(
        parse_check_with_absence(clear.as_bytes()).unwrap().2,
        Remains::Unproven
    );
    for invalid in [
        format!("{check}INFRATERNAL_SETUP_INSTALLED {}\n", "1".repeat(31)),
        format!("{check}INFRATERNAL_SETUP_INSTALLED {}\n", "G".repeat(32)),
        format!("{check}INFRATERNAL_SETUP_INSTALLED {} x\n", "1".repeat(32)),
        format!("{check}INFRATERNAL_SETUP_INSTALLED {}", "1".repeat(32)),
    ] {
        assert!(
            parse_check_with_absence(invalid.as_bytes()).is_err(),
            "{invalid}"
        );
    }
    let failure = infraternal_plugin_ssh::previous_attempt::installed_elsewhere(
        infraternal_plugin_ssh::model::InstallMode::Root,
    );
    assert_eq!(
        failure.kind,
        infraternal_plugin_ssh::model::FailureKind::UnrecognizedInstall
    );
    assert_eq!(
        failure.log_tail,
        vec!["Setup location: /var/lib/infraternal"]
    );
    assert!(!failure.message.contains('/'), "paths go in Details only");
}

#[test]
fn earlier_attempt_records_reject_suffixes_truncation_and_unbounded_counts() {
    let check = "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n";
    let valid = format!(
        "{check}INFRATERNAL_SETUP_STALE {} {} 1:2 1\n",
        "1".repeat(32),
        "2".repeat(32)
    );
    let (_, previous) =
        infraternal_plugin_ssh::previous_attempt::parse_check(valid.as_bytes()).unwrap();
    assert!(previous.is_some());
    for end in 0..valid.len() {
        assert!(
            infraternal_plugin_ssh::previous_attempt::parse_check(&valid.as_bytes()[..end])
                .is_err()
        );
    }
    for invalid in [
        format!("{valid}extra"),
        valid.replace("1:2 1\n", "1:2 1025\n"),
        valid.replace("1:2", "1:2:3"),
        valid.replace("STALE", "UNKNOWN"),
    ] {
        assert!(infraternal_plugin_ssh::previous_attempt::parse_check(invalid.as_bytes()).is_err());
    }
}

#[test]
fn earlier_attempt_lock_diagnostic_names_machine_process_and_start_time() {
    use infraternal_plugin_ssh::model::FailureKind;

    let check = "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n";
    let lock = format!(
        "{check}INFRATERNAL_SETUP_LOCKED build-node 254 9917 2026-11-02T04:05:06Z {}\n",
        "2".repeat(32)
    );
    let error = infraternal_plugin_ssh::previous_attempt::parse_check(lock.as_bytes()).unwrap_err();
    assert_eq!(error.kind, FailureKind::SetupRunning);
    let message = serde_json::to_value(error).unwrap()["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(message.contains("build-node"));
    assert!(message.contains("254"));
    assert!(message.contains("2026-11-02T04:05:06Z"));
    assert!(message.contains("setup attempt 22222222 (process 254) has held the setup lock"));
    // A running setup can only be waited for; replacement is offered only for
    // an upgrade journal whose lease is gone (#305).
    assert!(!message.contains("replace"), "{message}");
    let unknown = lock.replace(&"2".repeat(32), "unknown");
    let message = serde_json::to_value(
        infraternal_plugin_ssh::previous_attempt::parse_check(unknown.as_bytes()).unwrap_err(),
    )
    .unwrap()["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        message.contains("process 254 has held the setup lock"),
        "{message}"
    );
    for bad in ["2", "Z".repeat(32).as_str(), ""] {
        let record = lock.replace(&"2".repeat(32), bad);
        assert!(infraternal_plugin_ssh::previous_attempt::parse_check(record.as_bytes()).is_err());
    }
}

#[test]
fn earlier_attempt_refusal_names_its_cause_from_fixed_text() {
    let check = "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n";
    let parse = |cause: &str| {
        let record = format!("{check}INFRATERNAL_SETUP_REFUSED {cause}\n");
        infraternal_plugin_ssh::previous_attempt::parse_check(record.as_bytes())
            .unwrap_err()
            .message
    };
    assert!(parse("entry").contains("holds a file this version does not recognize"));
    assert!(parse("receipt").contains("older or changed format"));
    // A token this version does not know never reaches the person verbatim.
    assert_eq!(
        parse("something-new"),
        "The earlier setup journal has an unsupported or changed format. Host provisioning left it untouched."
    );
}

#[test]
fn earlier_attempt_classification_preserves_status_boundary_and_authentication() {
    use infraternal_plugin_ssh::model::{FailureKind, InstallStep};
    for status in [71, 72, 73, 75] {
        let mut error = Failure::install("withheld").at(InstallStep::Connect);
        error.exit_status = Some(status);
        let classified = infraternal_plugin_ssh::previous_attempt::classify(error);
        assert_eq!(classified.exit_status, Some(status));
        assert!(matches!(classified.failed_step, Some(InstallStep::Connect)));
        let mut auth = Failure::new(FailureKind::Auth, "Authentication was refused.");
        auth.exit_status = Some(status);
        assert_eq!(
            infraternal_plugin_ssh::previous_attempt::classify(auth).kind,
            FailureKind::Auth
        );
    }
}

#[tokio::test]
async fn start_fresh_resumes_the_same_attempt_after_owner_confirmation() {
    exercise_start_fresh(false, false, CachedHelper::Current).await;
}

#[tokio::test]
async fn turning_off_paused_host_provisioning_preserves_earlier_leftovers() {
    exercise_start_fresh(true, false, CachedHelper::Current).await;
}

#[tokio::test]
async fn known_failed_setup_finishes_without_a_second_confirmation() {
    exercise_start_fresh(false, true, CachedHelper::Current).await;
}

#[tokio::test]
async fn earlier_binary_cache_is_refreshed_before_owned_recovery() {
    exercise_start_fresh(false, true, CachedHelper::Earlier).await;
}
#[derive(Clone, Copy)]
enum CachedHelper {
    Current,
    Earlier,
}

/// Runs one fresh install through the real bootstrap runner on a
/// real-filesystem fixture: it completes (`turn_off` false) or is cancelled by
/// turning the component off (`turn_off` true), with `automatic` choosing
/// whether a known failed setup is retried without asking.
async fn exercise_start_fresh(turn_off: bool, automatic: bool, helper: CachedHelper) {
    use infraternal_plugin_api::{ComponentPlugin, PluginState};
    use infraternal_plugin_ssh::{
        bootstrap::{Authority, Backend, Bootstrap, Resolved},
        install::BinaryPaths,
        model::{Destination, MeshEvidence, Step},
        probe::Check,
        transport::{Credentials, SshTransport},
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct Ready {
        host: uuid::Uuid,
        automatic: bool,
        invitations: AtomicUsize,
        recoveries: Mutex<Vec<&'static str>>,
    }
    impl Backend for Ready {
        fn resolve<'a>(
            &'a self,
            _: &'a Authority,
            _: &'a Target,
            _: Option<&'a str>,
        ) -> Operation<'a, Resolved> {
            Box::pin(async {
                Ok(Resolved {
                    destination: Destination::parse("user@fixture").unwrap(),
                    credentials: Credentials::Network,
                    mesh: MeshEvidence::default(),
                })
            })
        }
        fn owns_failed_setup<'a>(
            &'a self,
            _: &'a Authority,
            _: &'a Target,
            _: &'a Check,
            host: uuid::Uuid,
            _: Option<String>,
        ) -> Operation<'a, bool> {
            Box::pin(async move { Ok(self.automatic && host == self.host) })
        }
        fn invitation<'a>(
            &'a self,
            _: &'a Authority,
            _: &'a Target,
            _: &'a Check,
        ) -> Operation<'a, JoinMaterial> {
            Box::pin(async move {
                self.invitations.fetch_add(1, Ordering::SeqCst);
                Ok(JoinMaterial {
                    host: self.host,
                    url: "https://fixture.invalid/join".into(),
                    stdin: Secret::new(b"synthetic-capability\n".to_vec()),
                })
            })
        }
        fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn record_start_fresh(
            &self,
            _: &Target,
            _: uuid::Uuid,
            _: uuid::Uuid,
            outcome: &'static str,
        ) {
            self.recoveries.lock().unwrap().push(outcome);
        }
        fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }
    struct Transport {
        root: PathBuf,
    }
    impl SshTransport for Transport {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async move {
                Ok(Arc::new(Local {
                    root: self.root.clone(),
                }) as Arc<dyn SshSession>)
            })
        }
    }
    let fixture = Fixture::new();
    let old = fixture.transaction();
    old.stage(&fixture.binary).await.unwrap();
    // A foreign root entry preserves the original journal through rollback.
    let foreign = fixture.base().join("keep");
    std::fs::write(&foreign, "foreign data").unwrap();
    assert!(old.rollback().await.is_err());
    std::fs::remove_file(&foreign).unwrap();
    if matches!(helper, CachedHelper::Earlier) {
        let runtime = fixture.base().join("sessions");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(std::os::unix::net::UnixListener::bind(runtime.join("plugins.sock")).unwrap());
        // A cache from before the internal command must be replaced by the
        // trusted matching executable before recovery can inspect the socket.
        std::fs::write(
            fixture
                .base()
                .with_file_name("infraternal.bootstrap-cache")
                .join("payload"),
            b"#!/bin/sh\nexit 2\n",
        )
        .unwrap();
    }
    let backend = Arc::new(Ready {
        host: fixture.join.host,
        automatic,
        invitations: AtomicUsize::new(0),
        recoveries: Mutex::new(Vec::new()),
    });
    let runner = Bootstrap::new(
        Arc::new(Transport {
            root: fixture.root.clone(),
        }),
        backend.clone(),
        BinaryPaths {
            x86_64: fixture.binary.clone(),
            aarch64: fixture.binary.clone(),
        },
    );
    let batch = runner
        .start("owner".into(), vec![fixture.target.clone()], None)
        .unwrap();
    let mut changes = batch.subscribe();
    if !automatic {
        let challenge = tokio::time::timeout(INSTALL_HANG, async {
            loop {
                let (_, events) = batch.events(0);
                if let Some(event) = events.iter().find(|event| event.leftovers.is_some()) {
                    assert_eq!(event.attempt, 1);
                    assert!(event.host_id.is_none(), "pause must precede enrollment");
                    return event.leftovers.as_ref().unwrap().challenge;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(backend.invitations.load(Ordering::SeqCst), 0);
        assert!(backend.recoveries.lock().unwrap().is_empty());
        if turn_off {
            tokio::time::timeout(INSTALL_HANG, runner.set_enabled(false))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(runner.status().state, PluginState::Off);
            assert_eq!(runner.status().active_work, 0);
            assert!(fixture.receipt().exists());
            assert!(fixture.base().join(".bootstrap-owner").exists());
            assert!(backend.recoveries.lock().unwrap().is_empty());
            assert_eq!(backend.invitations.load(Ordering::SeqCst), 0);
            assert!(
                runner
                    .start_fresh(&batch, "owner", "one", challenge)
                    .is_err()
            );
            return;
        }
        assert!(
            runner
                .start_fresh(&batch, "other-owner", "one", challenge)
                .is_err()
        );
        assert!(
            runner
                .start_fresh(&batch, "owner", "one", uuid::Uuid::new_v4())
                .is_err()
        );
        runner
            .start_fresh(&batch, "owner", "one", challenge)
            .unwrap();
        assert!(
            runner
                .start_fresh(&batch, "owner", "one", challenge)
                .is_err()
        );
    }
    tokio::time::timeout(INSTALL_HANG, async {
        loop {
            let (_, events) = batch.events(0);
            if automatic {
                assert!(
                    events.iter().all(|event| event.leftovers.is_none()),
                    "a known failed setup unexpectedly required another confirmation"
                );
            }
            if let Some(event) = events
                .iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                assert_eq!(event.step, Step::Done, "{}", event.message);
                assert_eq!(event.attempt, 1);
                break;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(fixture.base().join("bin/current").exists());
    assert!(!fixture.base().join(".bootstrap-lock").exists());
    assert_eq!(backend.invitations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *backend.recoveries.lock().unwrap(),
        vec!["started", "completed"]
    );
}

/// Service exit must always retry, including an unexpected successful return.
#[tokio::test]
async fn installed_infraternal_agent_always_restarts_without_start_limit() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    let unit = std::fs::read_to_string(
        fixture
            .root
            .join(".config/systemd/user/infraternal-agent.service"),
    )
    .unwrap();
    assert!(unit.lines().any(|line| line == "Restart=always"));
    assert!(unit.lines().any(|line| line == "RestartSec=2"));
    assert!(unit.lines().any(|line| line == "StartLimitIntervalSec=0"));
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn staged_shell_bridge_keeps_protocol_bytes_and_releases_setup_guard() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    // A real shell process stands in for the CLI only at its fixed receipt
    // boundary. The separate real-binary oracle verifies shim/session ownership.
    let original = std::fs::read_to_string(&f.binary).unwrap();
    let payload = format!(
        "#!/bin/sh\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\n{original}\n#{}\n",
        "x".repeat(100_000)
    );
    executable(&f.binary, &payload);
    let transaction = f.transaction();
    let (actual, channel) = transaction.stage_session(&f.binary).await.unwrap();
    assert_eq!(actual, id);
    let frame = b"\0\xffterminal\n";
    channel.write(frame).await.unwrap();
    let mut output = vec![0; frame.len()];
    let mut offset = 0;
    while offset < output.len() {
        offset += channel.read(&mut output[offset..]).await.unwrap();
    }
    assert_eq!(output, frame);
    let mut lock = Command::new("flock");
    assert!(
        lock.args(["-n", f.base().parent().unwrap().to_str().unwrap(), "true"])
            .status()
            .await
            .unwrap()
            .success()
    );
    // The exact owned transaction remains usable while the bridge is live.
    transaction.setup(&f.join).await.unwrap();
    drop(channel);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn live_setup_retry_preserves_the_bridge_and_host_identity_state() {
    for after_activation in [false, true] {
        let f = Fixture::new();
        let id = uuid::Uuid::new_v4();
        let original = std::fs::read_to_string(&f.binary).unwrap();
        let refuse = f.root.join("refuse-join");
        let payload = format!(
            "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nif [ -f {} ]; then rm {}; mkdir -p \"$3\"; printf 'public-fixture-state\\n' > \"$3/proof\"; exit 1; fi\n{original}",
            infraternal_plugin_ssh::transport::shell_quote(refuse.to_str().unwrap()),
            infraternal_plugin_ssh::transport::shell_quote(refuse.to_str().unwrap())
        );
        executable(&f.binary, &payload);
        if after_activation {
            std::fs::write(f.root.join("refuse-start"), b"").unwrap();
        } else {
            std::fs::write(&refuse, b"").unwrap();
        }
        let transaction = f.transaction();
        let (session, channel) = transaction.stage_session(&f.binary).await.unwrap();
        assert_eq!(session, id);
        assert!(transaction.setup(&f.join).await.is_err());
        if after_activation {
            std::fs::remove_file(f.root.join("refuse-start")).unwrap();
        }
        // A live session's rendezvous and unrelated files cannot be rollback targets.
        // The shim keeps its rendezvous private (0700), as runtime cleanup requires.
        std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700)
            .create(f.base().join("sessions/sessions"))
            .unwrap();
        let sentinel = f.base().join("sessions/sessions/live-marker");
        std::fs::write(&sentinel, b"original live session").unwrap();
        let inode = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&sentinel).unwrap());
        transaction.restart_setup(&f.binary, &f.join).await.unwrap();
        assert_eq!(
            std::fs::read(f.base().join("state/proof")).unwrap(),
            b"public-fixture-state\n"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"original live session");
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&sentinel).unwrap()),
            inode
        );
        channel.write(b"same session\n").await.unwrap();
        assert_eq!(channel.line(32).await.unwrap(), b"same session\n");
        transaction.commit().await.unwrap();
        channel.write(b"after setup commit\n").await.unwrap();
        assert_eq!(channel.line(32).await.unwrap(), b"after setup commit\n");
        drop(channel);
    }
}

#[tokio::test]
async fn early_staging_preserves_canonical_foreign_root_refusal() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.base()).unwrap();
    std::fs::set_permissions(f.base(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let failure = f
        .transaction()
        .stage_session(&f.binary)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        failure.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Upload)
    ));
    assert_eq!(failure.exit_status, Some(71));
}

struct SingleCheckChannel {
    local: Local,
    streams: std::sync::atomic::AtomicUsize,
}
impl SshSession for SingleCheckChannel {
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        assert_eq!(
            self.streams
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            0,
            "a checked upload must not reopen the SSH command channel"
        );
        Box::pin(async move {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]).env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.local.root.join("tools").display()),
            );
            infraternal_plugin_ssh::duplex::Duplex::spawn(&mut command)
        })
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.local.run(script, input)
    }
}

#[tokio::test]
async fn one_command_channel_carries_check_verified_upload_and_bridge_bytes() {
    let f = Fixture::new();
    // Public command text can now arrive through stdin after the first script.
    // Map each shell execution into fixture storage without changing HOME.
    executable(
        &f.root.join("tools/sh"),
        &format!(
            "#!/usr/bin/python3\n\"\"\"Isolate public fixture scripts; preserve their stdin byte stream.\"\"\"\nimport os,sys\nargs=sys.argv[1:]\nif len(args)>1 and args[0]=='-c': args[1]=args[1].replace('$HOME', {root:?})\nos.execv('/bin/sh',['sh',*args])\n",
            root = f.root.to_str().unwrap()
        ),
    );
    let id = uuid::Uuid::new_v4();
    executable(
        &f.binary,
        &format!(
            "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nexit 1\n#{}\n",
            "x".repeat(100_000)
        ),
    );
    let session = Arc::new(SingleCheckChannel {
        local: Local {
            root: f.root.clone(),
        },
        streams: std::sync::atomic::AtomicUsize::new(0),
    });
    let check = "printf 'INFRATERNAL_CHECK_V1\\nLinux\\nx86_64\\nsystemd\\n1002\\nno\\nyes\\nyes\\nno\\nINFRATERNAL_SETUP_CLEAR\\n'";
    let (output, checked) = Installation::check_channel(session.as_ref(), check)
        .await
        .unwrap();
    assert!(
        infraternal_plugin_ssh::previous_attempt::parse_check(&output.stdout)
            .unwrap()
            .1
            .is_none()
    );
    let transaction = Installation::new(session.clone(), &f.target, &f.join).unwrap();
    let (actual, bridge) = transaction
        .stage_session_on(&f.binary, Some(checked))
        .await
        .unwrap();
    assert_eq!(actual, id);
    bridge.write(b"\0\xffsame channel\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"\0\xffsame channel\n");
    assert_eq!(session.streams.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(bridge);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn duplex_check_refuses_named_failures_and_oversized_records_before_staging() {
    for status in [71, 73, 75] {
        let f = Fixture::new();
        let session = Local {
            root: f.root.clone(),
        };
        let failure = Installation::check_channel(&session, &format!("exit {status}"))
            .await
            .err()
            .unwrap();
        assert_eq!(failure.exit_status, Some(status));
        assert!(matches!(
            failure.failed_step,
            Some(infraternal_plugin_ssh::model::InstallStep::Connect)
        ));
        assert!(!f.base().exists());
    }
    let f = Fixture::new();
    let session = Local {
        root: f.root.clone(),
    };
    assert!(
        Installation::check_channel(&session, "printf '%600s\\n' x")
            .await
            .is_err()
    );
    assert!(!f.base().exists());
}

/// Shadow review (#189): the negotiated transfer frames the payload with
/// `head -c N` and then lets the join step read the private invitation from
/// the same stdin. A `head` that reads through a stdio buffer takes more than N bytes from a pipe, so the
/// invitation never reaches `join`. The system GNU head passes; the buffered
/// head models the other supported userlands and must pass too.
#[tokio::test]
async fn negotiated_transfer_delivers_the_invitation_after_a_buffering_head() {
    for buffered in [false, true] {
        let fixture = Fixture::new();
        executable(
            &fixture.binary,
            "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\n[ \"$1 $2\" = 'agent --data' ] || exit 1\nstate=$3\nmkdir -p \"$state\"\ncat > \"$state/invitation\"\n",
        );
        if buffered {
            // Reads whole stdio-sized blocks like getc/fread-based head
            // implementations, then writes only the first N bytes.
            executable(
                &fixture.root.join("tools/head"),
                "#!/usr/bin/python3\nimport os, sys, time\nn = int(sys.argv[sys.argv.index('-c') + 1])\nbuf = b''\nwhile len(buf) < n:\n    time.sleep(0.05)\n    chunk = os.read(0, 4096)\n    if not chunk:\n        break\n    buf += chunk\nview = memoryview(buf[:n])\nwhile view:\n    view = view[os.write(1, view):]\n",
            );
        }
        let session = Arc::new(Compound(Local {
            root: fixture.root.clone(),
        }));
        let install = Installation::new(session, &fixture.target, &fixture.join).unwrap();
        let result = install
            .stage_and_setup(&fixture.binary, &fixture.join)
            .await;
        let delivered = std::fs::read(fixture.base().join("state/invitation")).unwrap_or_default();
        assert!(
            result.is_ok() && delivered == fixture.join.stdin.expose(),
            "buffered head={buffered}: setup={:?} invitation bytes delivered={}",
            result.as_ref().err().map(|error| &error.message),
            delivered.len()
        );
        let _ = install.rollback().await;
    }
}

/// A scripted remote that observes the exact byte order on the checked channel
/// (#189): it never runs the setup program, it only records what arrived when.
struct ScriptedRemote {
    program: String,
}
impl SshSession for ScriptedRemote {
    fn stream<'a>(
        &'a self,
        _script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        Box::pin(async move {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-c", &self.program]);
            infraternal_plugin_ssh::duplex::Duplex::spawn(&mut command)
        })
    }
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async { Err(Failure::install("The scripted remote has one channel.")) })
    }
}

/// `reader` is what the remote reports for its setup-script reader. `then`
/// runs after the framed setup script was read, with `script`, `exact(n)`,
/// `quiet()` (true when no further byte arrives within 300 ms) and `out`.
fn scripted_remote(caps: &str, reader: &str, then: &str) -> ScriptedRemote {
    let caps = caps.replace('\n', "\\n");
    ScriptedRemote {
        program: format!(
            r"
import os, re, select, sys
out = sys.stdout.buffer
def exact(n):
    data = b''
    while len(data) < n:
        chunk = os.read(0, n - len(data))
        if not chunk: sys.exit(3)
        data += chunk
    return data
def line():
    data = b''
    while not data.endswith(b'\n'):
        byte = os.read(0, 1)
        if not byte: sys.exit(3)
        data += byte
    return data
def quiet():
    return not select.select([0], [], [], 0.3)[0]
def size(choice):
    return int(re.search(choice.encode() + rb'\)[^\n]*?read_payload (\d+)', script)[1])
out.write(b'STEP connect\nINFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n{caps}CHECK ready {reader}\n')
out.flush()
script = exact(int(line()))
{then}
out.flush()
os.execvp('cat', ['cat'])
"
        ),
    }
}

/// Stages the session image through a scripted remote, and fails the test if
/// staging hangs (the payload and its receipts must not be serialized).
async fn scripted_staging(
    f: &Fixture,
    remote: ScriptedRemote,
) -> Result<(uuid::Uuid, infraternal_plugin_ssh::duplex::Duplex), Failure> {
    let session = Arc::new(remote);
    let (_, checked) = Installation::check_channel(session.as_ref(), "true")
        .await
        .unwrap();
    let transaction = Installation::new(session, &f.target, &f.join).unwrap();
    tokio::time::timeout(
        INSTALL_HANG,
        transaction.stage_session_on(&f.binary, Some(checked)),
    )
    .await
    .unwrap_or_else(|_| panic!("staging stalled: the payload and its receipts were serialized"))
}

fn large_fixture_binary(f: &Fixture, id: uuid::Uuid) {
    // Large enough for the shared encodings; contents are public fixture bytes.
    executable(
        &f.binary,
        &format!(
            "#!/bin/sh\ncase \"$1\" in --bootstrap-runtime*) exec runtime-helper \"$@\";; esac\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nexit 1\n#{}\n",
            "x".repeat(100_000)
        ),
    );
}

#[tokio::test]
/// Declared payloads flow before receipts while byte counts remain exact.
async fn declared_transfer_sends_the_payload_before_any_selection_receipt() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    // The remote reads the whole payload before writing a single receipt. A
    // server that waits for `STEP upload`/`TRANSFER` first would stall here.
    let remote = scripted_remote(
        "CAPS zstd gzip -\n",
        "dd",
        &format!(
            "choice = re.search(rb'\\nchoice=(\\w+)\\n', script)[1].decode()\nassert choice in ('zstd', 'gzip', 'raw'), choice\npayload = exact(size(choice))\nout.write(b'STEP upload\\nTRANSFER ' + choice.encode() + b'\\nPROGRESS ' + str(len(payload)).encode() + b'\\nSTEP start\\nSESSION {id}\\n')"
        ),
    );
    let (session, bridge) = scripted_staging(&f, remote).await.unwrap();
    assert_eq!(session, id);
    bridge.write(b"bridge bytes\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"bridge bytes\n");
}

#[tokio::test]
/// A buffering setup reader receives only its script until it selects the public payload.
async fn buffering_setup_reader_receives_no_payload_until_selection() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    // Without an exact reader the remote keeps selecting under its lock, and
    // no payload byte may follow the setup script before that receipt.
    let remote = scripted_remote(
        "CAPS zstd gzip -\n",
        "head",
        &format!(
            "assert b'\\nchoice=raw\\nif ' in script\nassert quiet(), 'payload followed the setup script'\nout.write(b'STEP upload\\nTRANSFER raw\\n'); out.flush()\npayload = exact(size('raw'))\nout.write(b'PROGRESS ' + str(len(payload)).encode() + b'\\nSTEP start\\nSESSION {id}\\n')"
        ),
    );
    assert_eq!(scripted_staging(&f, remote).await.unwrap().0, id);
}

#[tokio::test]
async fn reported_cache_digest_selects_reuse_without_sending_payload() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    let digest = {
        use sha2::Digest as _;
        let bytes = sha2::Sha256::digest(std::fs::read(&f.binary).unwrap());
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
    };
    let remote = scripted_remote(
        &format!("CAPS zstd gzip {digest}\n"),
        "dd",
        &format!(
            "assert b'\\nchoice=reuse\\n' in script\nassert quiet(), 'a reused payload was sent'\nout.write(b'STEP upload\\nTRANSFER reuse\\nSTEP start\\nSESSION {id}\\n')"
        ),
    );
    assert_eq!(scripted_staging(&f, remote).await.unwrap().0, id);
}

#[tokio::test]
async fn declared_transfer_refuses_a_different_selection_or_a_named_refusal() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    let remote = scripted_remote(
        "CAPS zstd gzip -\n",
        "dd",
        &format!("out.write(b'STEP upload\\nTRANSFER raw\\nSTEP start\\nSESSION {id}\\n')"),
    );
    let failure = scripted_staging(&f, remote).await.err().unwrap();
    assert!(matches!(
        failure.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Upload)
    ));
    // A lock refusal arrives while payload bytes are still in flight.
    let remote = scripted_remote(
        "CAPS zstd gzip -\n",
        "dd",
        "out.write(b'STEP upload\\nFAIL upload 72\\n'); out.flush(); sys.exit(0)",
    );
    let failure = scripted_staging(&f, remote).await.err().unwrap();
    assert_eq!(failure.exit_status, Some(72));
}

#[tokio::test]
async fn checked_staging_survives_a_buffering_payload_reader_and_reuses_the_cache() {
    let f = Fixture::new();
    executable(
        &f.root.join("tools/sh"),
        &format!(
            "#!/usr/bin/python3\n\"\"\"Isolate public fixture scripts; preserve their stdin byte stream.\"\"\"\nimport os,sys\nargs=sys.argv[1:]\nif len(args)>1 and args[0]=='-c': args[1]=args[1].replace('$HOME', {root:?})\nos.execv('/bin/sh',['sh',*args])\n",
            root = f.root.to_str().unwrap()
        ),
    );
    // Reads whole stdio-sized blocks like getc/fread-based head implementations.
    executable(
        &f.root.join("tools/head"),
        "#!/usr/bin/python3\nimport os, sys\nn = int(sys.argv[sys.argv.index('-c') + 1])\nbuf = b''\nwhile len(buf) < n:\n    chunk = os.read(0, 4096)\n    if not chunk:\n        break\n    buf += chunk\nview = memoryview(buf[:n])\nwhile view:\n    view = view[os.write(1, view):]\n",
    );
    let log = f.root.join("decoded");
    for tool in ["zstd", "gzip"] {
        executable(
            &f.root.join(format!("tools/{tool}")),
            &format!(
                "#!/bin/sh\nprintf '{tool}\\n' >> '{}'\nexec /usr/bin/{tool} \"$@\"\n",
                log.display()
            ),
        );
    }
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    let check = "printf 'INFRATERNAL_CHECK_V1\\nLinux\\nx86_64\\nsystemd\\n1002\\nno\\nyes\\nyes\\nno\\nINFRATERNAL_SETUP_CLEAR\\n'";
    for attempt in 0..2 {
        let session = Arc::new(SingleCheckChannel {
            local: Local {
                root: f.root.clone(),
            },
            streams: std::sync::atomic::AtomicUsize::new(0),
        });
        let (_, checked) = Installation::check_channel(session.as_ref(), check)
            .await
            .unwrap();
        let transaction = Installation::new(session.clone(), &f.target, &f.join).unwrap();
        let (actual, bridge) = transaction
            .stage_session_on(&f.binary, Some(checked))
            .await
            .unwrap();
        assert_eq!(actual, id);
        assert_eq!(
            std::fs::read(f.base().join(".bootstrap-lock/payload")).unwrap(),
            std::fs::read(&f.binary).unwrap()
        );
        bridge.write(b"\0\xffbridge\n").await.unwrap();
        assert_eq!(bridge.line(64).await.unwrap(), b"\0\xffbridge\n");
        drop(bridge);
        transaction.rollback().await.unwrap();
        // The first attempt decodes one compressed payload; the second finds
        // the published cache through the check and sends nothing to decode.
        let decoded = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(decoded.lines().count(), 1, "attempt {attempt}: {decoded}");
    }
}

#[tokio::test]
async fn streamed_digest_refuses_a_short_file_or_a_changed_stream_before_launch() {
    // `tee` that keeps the stream intact but truncates its file models a
    // failed file write; a decoder that alters one byte models corruption.
    for (tool, text) in [
        (
            "tee",
            "#!/usr/bin/python3\nimport os, sys\ndata = sys.stdin.buffer.read()\nopen(sys.argv[1], 'wb').write(data[:-10])\nsys.stdout.buffer.write(data)\n",
        ),
        (
            "decoders",
            "#!/usr/bin/python3\nimport os, subprocess, sys\ntool = '/usr/bin/' + os.path.basename(sys.argv[0])\ndata = bytearray(subprocess.run([tool, *sys.argv[1:]], stdin=sys.stdin, capture_output=True).stdout)\ndata[100] ^= 1\nsys.stdout.buffer.write(data)\n",
        ),
    ] {
        let f = Fixture::new();
        executable(
            &f.root.join("tools/sh"),
            &format!(
                "#!/usr/bin/python3\nimport os,sys\nargs=sys.argv[1:]\nif len(args)>1 and args[0]=='-c': args[1]=args[1].replace('$HOME', {root:?})\nos.execv('/bin/sh',['sh',*args])\n",
                root = f.root.to_str().unwrap()
            ),
        );
        // Whichever codec the check reports, its decoder alters the stream.
        let names: &[&str] = if tool == "tee" {
            &["tee"]
        } else {
            &["zstd", "gzip"]
        };
        for name in names {
            executable(&f.root.join(format!("tools/{name}")), text);
        }
        let id = uuid::Uuid::new_v4();
        large_fixture_binary(&f, id);
        // The setup program arrives on stdin; the `tools/sh` mapping keeps
        // every remote path inside the fixture root.
        let session = Arc::new(SingleCheckChannel {
            local: Local {
                root: f.root.clone(),
            },
            streams: std::sync::atomic::AtomicUsize::new(0),
        });
        let check = "printf 'INFRATERNAL_CHECK_V1\\nLinux\\nx86_64\\nsystemd\\n1002\\nno\\nyes\\nyes\\nno\\nINFRATERNAL_SETUP_CLEAR\\n'";
        let (_, checked) = Installation::check_channel(session.as_ref(), check)
            .await
            .unwrap();
        let transaction = Installation::new(session, &f.target, &f.join).unwrap();
        let failure = transaction
            .stage_session_on(&f.binary, Some(checked))
            .await
            .err()
            .unwrap_or_else(|| panic!("{tool}: an unverified payload was launched"));
        assert!(
            matches!(
                failure.failed_step,
                Some(infraternal_plugin_ssh::model::InstallStep::Upload)
            ),
            "{tool}: {failure:?}"
        );
        assert_eq!(failure.exit_status, Some(1), "{tool}");
        transaction.rollback().await.unwrap();
    }
}

#[test]
fn optional_session_payload_is_architecture_scoped_and_refuses_symlinks() {
    use infraternal_plugin_ssh::{install::BinaryPaths, probe::Architecture};
    let f = Fixture::new();
    let paths = BinaryPaths {
        x86_64: f.binary.clone(),
        aarch64: f.root.join("arm"),
    };
    assert_eq!(
        paths.session_payload(Architecture::X86_64).unwrap(),
        f.binary
    );
    let x86 = f.root.join("infraternal-x86_64-session-musl");
    std::fs::write(&x86, b"trusted release fixture").unwrap();
    assert_eq!(paths.session_payload(Architecture::X86_64).unwrap(), x86);
    assert_eq!(
        paths.session_payload(Architecture::Aarch64).unwrap(),
        paths.aarch64
    );
    let arm = f.root.join("infraternal-aarch64-session-musl");
    std::os::unix::fs::symlink(&f.binary, &arm).unwrap();
    assert!(paths.session_payload(Architecture::Aarch64).is_err());
    std::fs::remove_file(&x86).unwrap();
    std::fs::create_dir(&x86).unwrap();
    assert!(paths.session_payload(Architecture::X86_64).is_err());
}

#[tokio::test]
async fn full_payload_restaging_preserves_the_running_session_build() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    let starter = f.root.join("session-build");
    executable(
        &starter,
        &format!(
            "#!/bin/sh\n[ \"$1\" = __ssh-session ] || exit 1\nprintf 'SESSION {id}\\n'\nexec cat\n"
        ),
    );
    let transaction = Installation::new(
        Arc::new(Compound(Local {
            root: f.root.clone(),
        })),
        &f.target,
        &f.join,
    )
    .unwrap();
    let (session, channel) = transaction.stage_session(&starter).await.unwrap();
    assert_eq!(session, id);
    channel.write(b"before full upload\n").await.unwrap();
    assert_eq!(channel.line(64).await.unwrap(), b"before full upload\n");
    // Force a real compressed full transfer after the distinct session image.
    let full = format!(
        "#!/bin/sh\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\n{}\n#{}\n",
        std::fs::read_to_string(&f.binary).unwrap(),
        "x".repeat(100_000)
    );
    std::fs::write(&f.binary, full).unwrap();
    transaction
        .restart_setup_with(
            &f.binary,
            &f.join,
            Some(infraternal_plugin_ssh::transport::TransferChoice::Gzip),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(f.base().join("bin/live")).unwrap(),
        std::fs::read(&f.binary).unwrap()
    );
    channel.write(b"after full upload\n").await.unwrap();
    assert_eq!(channel.line(64).await.unwrap(), b"after full upload\n");
    let reopened = transaction.resume_session(id).await.unwrap();
    reopened.write(b"verified full bridge\n").await.unwrap();
    assert_eq!(reopened.line(64).await.unwrap(), b"verified full bridge\n");
    drop(reopened);
    transaction.commit().await.unwrap();
    channel.write(b"after commit\n").await.unwrap();
    assert_eq!(channel.line(64).await.unwrap(), b"after commit\n");
}

/// Restaging after the early prompt must reuse compound upload/enrollment;
/// separate rollback, cache lookup, upload and setup commands add SSH round trips.
#[tokio::test]
async fn session_restaging_uses_one_compound_command() {
    struct Counted {
        local: Local,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl SshSession for Counted {
        fn setup_steps(&self) -> bool {
            true
        }
        fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.local.run(script, input)
        }
    }
    let f = Fixture::new();
    let counted = Arc::new(Counted {
        local: Local {
            root: f.root.clone(),
        },
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let transaction = Installation::new(counted.clone(), &f.target, &f.join).unwrap();
    transaction.stage(&f.binary).await.unwrap();
    counted.calls.store(0, std::sync::atomic::Ordering::SeqCst);
    transaction.restart_setup(&f.binary, &f.join).await.unwrap();
    assert_eq!(counted.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(f.base().join("bin/live")).unwrap(),
        std::fs::read(&f.binary).unwrap()
    );
    transaction.commit().await.unwrap();
}

/// A compound restage cannot turn another transaction's lease into permission
/// to upload, enroll or remove its private journal.
#[tokio::test]
async fn compound_restaging_refuses_a_foreign_journal_before_upload() {
    let f = Fixture::new();
    let transaction = Installation::new(
        Arc::new(Compound(Local {
            root: f.root.clone(),
        })),
        &f.target,
        &f.join,
    )
    .unwrap();
    transaction.stage(&f.binary).await.unwrap();
    let journal = f.base().join(".bootstrap-lock/transaction");
    let original = std::fs::read(&journal).unwrap();
    let foreign = uuid::Uuid::new_v4().simple().to_string();
    std::fs::write(&journal, &foreign).unwrap();
    let payload = f.base().join(".bootstrap-lock/payload");
    let before = std::fs::read(&payload).unwrap();
    let refusal = transaction
        .restart_setup_with(
            &f.binary,
            &f.join,
            Some(infraternal_plugin_ssh::transport::TransferChoice::Raw),
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.exit_status, Some(72));
    assert!(matches!(
        refusal.failed_step,
        Some(infraternal_plugin_ssh::model::InstallStep::Upload)
    ));
    assert_eq!(std::fs::read_to_string(&journal).unwrap(), foreign);
    assert_eq!(std::fs::read(&payload).unwrap(), before);
    assert!(!f.base().join("state").exists());
    std::fs::write(&journal, original).unwrap();
    transaction.rollback().await.unwrap();
}

/// A failed deferred upload leaves an incomplete stage; only an admitted cached
/// image may reopen the original shim, and changed cache bytes must not execute.
#[tokio::test]
async fn partial_full_upload_rebridges_from_a_verified_image() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    let starter = f.root.join("session-build");
    executable(
        &starter,
        &format!(
            "#!/bin/sh\n[ \"$1\" = __ssh-session ] || exit 1\nprintf 'SESSION {id}\\n'\nexec cat\n"
        ),
    );
    let transaction = Installation::new(
        Arc::new(Compound(Local {
            root: f.root.clone(),
        })),
        &f.target,
        &f.join,
    )
    .unwrap();
    let (_, original) = transaction.stage_session(&starter).await.unwrap();
    let stage = f.base().join(".bootstrap-lock/payload");
    // Restaging unlinks the old image before writing a new inode; the running
    // shim and verified cache retain the original inode throughout that write.
    std::fs::remove_file(&stage).unwrap();
    std::fs::write(&stage, b"incomplete full executable").unwrap();
    let reopened = transaction.resume_session(id).await.unwrap();
    reopened
        .write(b"same session after partial upload\n")
        .await
        .unwrap();
    assert_eq!(
        reopened.line(64).await.unwrap(),
        b"same session after partial upload\n"
    );
    original
        .write(b"original bridge remains usable\n")
        .await
        .unwrap();
    assert_eq!(
        original.line(64).await.unwrap(),
        b"original bridge remains usable\n"
    );
    drop(reopened);
    let journal = f.base().join(".bootstrap-lock/transaction");
    let owned = std::fs::read(&journal).unwrap();
    std::fs::write(&journal, uuid::Uuid::new_v4().simple().to_string()).unwrap();
    assert!(transaction.resume_session(id).await.is_err());
    std::fs::write(&journal, owned).unwrap();
    let cache = f
        .base()
        .with_file_name("infraternal.bootstrap-cache")
        .join("payload");
    let executed = f.root.join("unverified-executed");
    executable(
        &cache,
        &format!(
            "#!/bin/sh\ntouch {}\nprintf 'SESSION {id}\\n'\nexec cat\n",
            infraternal_plugin_ssh::transport::shell_quote(executed.to_str().unwrap()),
        ),
    );
    assert!(transaction.resume_session(id).await.is_err());
    assert!(!executed.exists(), "changed cache bytes must never execute");
    drop(original);
    transaction.rollback().await.unwrap();
}

/// Bind a canonical fixture path so parallel listeners cannot share a relative basename.
async fn control_listener(runtime: &std::path::Path) -> tokio::process::Child {
    control_listener_at(runtime, &runtime.join("plugins.sock")).await
}

/// Preserve the kernel's bind spelling to check liveness through relative paths too.
async fn control_listener_at(
    runtime: &std::path::Path,
    binding: &std::path::Path,
) -> tokio::process::Child {
    use tokio::io::AsyncReadExt;
    let mut child = Command::new("python3")
        .args(["-u", "-c", "import socket,os,sys,fcntl; lock=os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])),'.lifetime-lock'); held=open(lock,'rb') if os.path.exists(lock) else None; fcntl.flock(held,fcntl.LOCK_EX) if held else None; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1],0o600); s.listen(); os.chdir('/'); print('ready',flush=True); sys.stdin.read()"])
        .arg(binding)
        .current_dir(runtime)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true).spawn().unwrap();
    let mut ready = [0; 6];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .await
        .unwrap();
    assert_eq!(&ready, b"ready\n");
    child
}

/// The daemon binds its local control socket before attempting its server connection.
#[tokio::test]
async fn facts_timeout_retires_stale_plugin_control_socket_before_retry() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(runtime.join("sessions")).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut listener = control_listener(&runtime).await;
    listener.kill().await.unwrap(); // Service-manager SIGTERM also leaves the socket inode.
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.enroll_and_start(&fixture.join).await.unwrap();
    retry.commit().await.unwrap();
}

/// An interrupted cleanup retains exact coordinates; another transaction cannot use them.
#[tokio::test]
async fn interrupted_control_cleanup_is_resumed_only_by_its_original_attempt() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    transaction.enroll_and_start(&fixture.join).await.unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("plugins.sock");
    let mut listener = control_listener(&runtime).await;
    assert!(
        transaction.rollback().await.is_err(),
        "live control listener must survive"
    );
    assert!(socket.exists());
    assert!(fixture.transaction().stage(&fixture.binary).await.is_err());
    let foreign = Installation::new(
        Arc::new(Local {
            root: fixture.root.clone(),
        }),
        &fixture.target,
        &JoinMaterial {
            host: uuid::Uuid::new_v4(),
            url: fixture.join.url.clone(),
            stdin: Secret::new(Vec::new()),
        },
    )
    .unwrap();
    assert!(foreign.rollback().await.is_err());
    assert!(socket.exists());
    listener.kill().await.unwrap();
    let cleanup = Installation::resume_cleanup(
        Arc::new(Local {
            root: fixture.root.clone(),
        }),
        &fixture.target,
        transaction.cleanup_coordinates(),
    )
    .unwrap();
    cleanup.rollback().await.unwrap();
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

#[tokio::test]
async fn control_cleanup_never_follows_a_socket_symlink_or_removes_regular_data() {
    use std::os::unix::fs::symlink;
    for linked in [false, true] {
        let fixture = Fixture::new();
        let transaction = fixture.transaction();
        transaction.stage(&fixture.binary).await.unwrap();
        let runtime = fixture.base().join("sessions");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("plugins.sock");
        let foreign = fixture.root.join("preserved");
        std::fs::write(&foreign, b"preserve").unwrap();
        if linked {
            symlink(&foreign, &socket).unwrap();
        } else {
            std::fs::write(&socket, b"preserve").unwrap();
        }
        assert!(transaction.rollback().await.is_err());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"preserve");
        assert_eq!(std::fs::read(&socket).unwrap(), b"preserve");
    }
}

/// Concurrent commands must leave exactly one original journal and reject the loser.
#[tokio::test]
async fn concurrent_attempts_cannot_replace_or_clean_each_others_transaction() {
    let fixture = Fixture::new();
    let first = fixture.transaction();
    let second = fixture.transaction();
    let (one, two) = tokio::join!(first.stage(&fixture.binary), second.stage(&fixture.binary));
    assert_ne!(one.is_ok(), two.is_ok());
    let (winner, loser) = if one.is_ok() {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let original = std::fs::read(fixture.base().join(".bootstrap-lock/transaction")).unwrap();
    let lease = std::fs::read_to_string(fixture.base().join(".bootstrap-lock/lease")).unwrap();
    let pid = lease.split_whitespace().next().unwrap();
    let descriptor = PathBuf::from(format!("/proc/{pid}/fd/7"));
    assert!(loser.rollback().await.is_err());
    assert_eq!(
        std::fs::canonicalize(std::fs::read_link(&descriptor).unwrap()).unwrap(),
        std::fs::canonicalize(fixture.base().join(".bootstrap-lock")).unwrap(),
        "the losing attempt retired the winner's setup lease"
    );
    assert_eq!(
        std::fs::read(fixture.base().join(".bootstrap-lock/transaction")).unwrap(),
        original
    );
    winner.rollback().await.unwrap();
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

/// A lost start reply after activation must retire the stopped service's control socket.
#[tokio::test]
async fn crash_mid_install_can_roll_back_and_retry() {
    use infraternal_plugin_ssh::model::InstallStep;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let manager = fixture.root.join("tools/systemctl");
    let original_manager = std::fs::read_to_string(&manager).unwrap();
    let runtime = fixture.base().join("sessions");
    executable(
        &manager,
        &format!(
            r#"#!/bin/sh
case "$*" in
*is-enabled*|*is-active*) exit 1;;
*enable*--now*)
    python3 -c 'import os,socket,sys; os.makedirs(sys.argv[1],mode=0o700,exist_ok=True); os.umask(0o022); s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]+"/plugins.sock")' {}
    kill -TERM "$PPID";;
*) exit 0;;
esac
"#,
            infraternal_plugin_ssh::transport::shell_quote(runtime.to_str().unwrap())
        ),
    );
    let failure = transaction
        .enroll_and_start(&fixture.join)
        .await
        .unwrap_err();
    assert!(matches!(failure.failed_step, Some(InstallStep::Start)));
    assert!(runtime.join("plugins.sock").exists());
    executable(&manager, &original_manager);
    transaction.rollback().await.unwrap();
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.enroll_and_start(&fixture.join).await.unwrap();
    retry.commit().await.unwrap();
}

/// Service-manager umasks determine socket mode; the private parent protects access.
#[tokio::test]
async fn stopped_control_socket_modes_from_service_manager_are_recoverable() {
    for mode in [0o600, 0o700, 0o755, 0o775] {
        let fixture = Fixture::new();
        let transaction = fixture.transaction();
        transaction.stage(&fixture.binary).await.unwrap();
        transaction.enroll_and_start(&fixture.join).await.unwrap();
        let runtime = fixture.base().join("sessions");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut listener = control_listener(&runtime).await;
        std::fs::set_permissions(
            runtime.join("plugins.sock"),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        listener.kill().await.unwrap();
        transaction.rollback().await.unwrap();
        assert!(!fixture.base().exists());
    }
}

/// An older failed run has only a fresh receipt; confirmed recovery uses the same guarded cleanup.
#[tokio::test]
async fn earlier_control_socket_receipt_recovers_before_a_new_setup() {
    let fixture = Fixture::new();
    let first = fixture.transaction();
    first.stage(&fixture.binary).await.unwrap();
    first.enroll_and_start(&fixture.join).await.unwrap();
    let keep = fixture.base().join("keep");
    std::fs::write(&keep, b"preserve until observed").unwrap();
    assert!(first.rollback().await.is_err());
    let receipt = fixture.receipt();
    std::fs::remove_file(keep).unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut listener = control_listener(&runtime).await;
    std::fs::set_permissions(
        runtime.join("plugins.sock"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    listener.kill().await.unwrap();
    let session = Local {
        root: fixture.root.clone(),
    };
    let output = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await
        .unwrap();
    let (_, previous) =
        infraternal_plugin_ssh::previous_attempt::parse_check(&output.stdout).unwrap();
    previous
        .unwrap()
        .start_fresh(&session, &fixture.target)
        .await
        .unwrap();
    assert!(!receipt.exists());
    assert!(!fixture.base().exists());
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.enroll_and_start(&fixture.join).await.unwrap();
    retry.commit().await.unwrap();
}

/// After process restart, the outside receipt must survive every cleanup boundary as usable proof.
async fn restart_after_cleanup_boundary(boundary: &str) {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let (tool, retired, argument) = if boundary == "owner" {
        ("rm", fixture.base().join(".bootstrap-owner"), "${2-}")
    } else {
        ("rmdir", fixture.base(), "${1-}")
    };
    // Stop the remote command immediately after the real mutation, before
    // it can retire its outside receipt. A restarted server has no Cleanup.
    executable(
        &fixture.root.join("tools").join(tool),
        &format!(
            "#!/bin/sh\n/usr/bin/{tool} \"$@\" || exit $?\n[ \"{argument}\" != '{}' ] || exit 1\n",
            retired.display()
        ),
    );
    assert!(transaction.rollback().await.is_err());
    let receipt = fixture.receipt();
    assert!(!retired.exists());
    std::fs::remove_file(fixture.root.join("tools").join(tool)).unwrap();
    let session = Local {
        root: fixture.root.clone(),
    };
    let inspected = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await;
    assert!(
        inspected.is_ok(),
        "restart inspection refused after {boundary} retirement: {:?}",
        inspected.as_ref().err()
    );
    let (_, previous) =
        infraternal_plugin_ssh::previous_attempt::parse_check(&inspected.unwrap().stdout).unwrap();
    previous
        .unwrap()
        .start_fresh(&session, &fixture.target)
        .await
        .unwrap();
    assert!(!receipt.exists());
    let retry = fixture.transaction();
    retry.stage(&fixture.binary).await.unwrap();
    retry.rollback().await.unwrap();
}

#[tokio::test]
async fn review_restart_recovers_cleanup_after_owner_retirement() {
    restart_after_cleanup_boundary("owner").await;
}

#[tokio::test]
async fn review_restart_recovers_cleanup_after_base_retirement() {
    restart_after_cleanup_boundary("base").await;
}

/// A live control socket must survive inspection and rollback for every legal bind spelling.
#[tokio::test]
async fn review_live_relative_control_socket_preserves_its_receipt() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let keep = fixture.base().join("keep");
    std::fs::write(&keep, b"preserve until observed").unwrap();
    assert!(transaction.rollback().await.is_err());
    let receipt = fixture.receipt();
    std::fs::remove_file(keep).unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut listener = control_listener_at(
        &fixture.base(),
        std::path::Path::new("sessions/plugins.sock"),
    )
    .await;
    let session = Local {
        root: fixture.root.clone(),
    };
    let inspected = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await;
    let cleanup = transaction.rollback().await;
    let preserved = runtime.join("plugins.sock").exists() && receipt.exists();
    // Retire only this fixture's child before checking either result, including
    // the incorrect-success case where cleanup unlinks a still-live listener.
    listener.kill().await.unwrap();
    assert!(
        inspected
            .as_ref()
            .err()
            .is_some_and(|error| error.exit_status == Some(73))
            && cleanup.is_err()
            && preserved,
        "live relative socket was accepted or removed: inspection_status={:?}, cleanup_status={:?}, socket_and_receipt_preserved={preserved}",
        inspected.as_ref().err().and_then(|error| error.exit_status),
        cleanup.as_ref().err().and_then(|error| error.exit_status),
    );
}

/// Final receipt authority must survive partial retirement of the staging journal too.
#[tokio::test]
async fn restart_recovers_partial_stage_retirement() {
    for retired in ["transaction", "kind", "both"] {
        let fixture = Fixture::new();
        let transaction = fixture.transaction();
        transaction.stage(&fixture.binary).await.unwrap();
        // Include an unfinished enrollment directory: retirement must validate
        // its private tree without reading identity contents or following links.
        let staged = fixture.base().join(".bootstrap-lock/state");
        std::fs::create_dir(&staged).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(staged.join("proof"), b"private fixture state").unwrap();
        std::fs::set_permissions(staged.join("proof"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let stage = fixture.base().join(".bootstrap-lock");
        let names = if retired == "both" {
            "transaction kind"
        } else {
            retired
        };
        executable(
            &fixture.root.join("tools/rm"),
            &format!(
                "#!/bin/sh\ncase \"$*\" in '-rf {}') for name in {names}; do /usr/bin/rm -f \"{}/$name\"; done; exit 1;; esac\nexec /usr/bin/rm \"$@\"\n",
                stage.display(),
                stage.display()
            ),
        );
        assert!(transaction.rollback().await.is_err());
        let receipt = fixture.receipt();
        std::fs::remove_file(fixture.root.join("tools/rm")).unwrap();
        let session = Local {
            root: fixture.root.clone(),
        };
        let output = session
            .run(
                &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
                Input::Empty,
            )
            .await
            .unwrap_or_else(|error| panic!("{retired}: {error:?}"));
        let (_, previous) =
            infraternal_plugin_ssh::previous_attempt::parse_check(&output.stdout).unwrap();
        previous
            .unwrap()
            .start_fresh(&session, &fixture.target)
            .await
            .unwrap();
        assert!(!receipt.exists());
        assert!(!fixture.base().exists());
        let retry = fixture.transaction();
        retry.stage(&fixture.binary).await.unwrap();
        retry.rollback().await.unwrap();
    }
}

const INODE_REUSE_ATTEMPTS: usize = 256;

/// Free a known inode in the private socket directory before each bounded allocation retry.
async fn inode_reuse_listener(base: &std::path::Path) -> Option<tokio::process::Child> {
    use tokio::io::AsyncReadExt;
    // Reuse stays a filesystem fact: the fixture records an inode from a
    // private anchor file, removes it, syncs its directory, and compares the
    // resulting socket inode. Failed replacements stay allocated so the
    // allocator cannot return the same earlier free inode on every retry.
    let attempts = INODE_REUSE_ATTEMPTS.to_string();
    let mut listener = Command::new("python3")
        .args([
            "-u",
            "-c",
            r"
import os,socket,sys,time
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
path='sessions/plugins.sock'
limit=int(sys.argv[1])
directory=os.open('sessions',os.O_RDONLY|os.O_DIRECTORY)
def release_known_inode(attempt):
    anchor='sessions/.inode-anchor-%d'%attempt
    fd=os.open(anchor,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    identity=os.fstat(fd).st_ino
    os.close(fd)
    os.unlink(anchor)
    os.fsync(directory)
    return identity
identity=None
seeded=[]
for attempt in range(limit):
    known=release_known_inode(attempt)
    s=socket.socket(socket.AF_UNIX); s.bind(path)
    if os.stat(path).st_ino==known:
        identity=known
        s.close()
        break
    s.close()
    saved='../inode-seed-retained-%d'%attempt
    os.rename(path,saved); seeded.append(saved)
    time.sleep(0.01)
for saved in seeded: os.unlink(saved)
if identity is None:
    print('inode-seed-not-reused',limit,file=sys.stderr)
    print('skip!',flush=True); sys.exit(77)
print('ready',flush=True)
sys.stdin.readline()
os.unlink(path)
os.fsync(directory)
time.sleep(0.01)
retained=[]
for attempt in range(limit):
    release_known_inode(limit+attempt)
    s=socket.socket(socket.AF_UNIX); s.bind(path)
    if os.stat(path).st_ino == identity: break
    s.close()
    saved='../retained-%d'%attempt
    os.rename(path,saved); retained.append(saved)
    time.sleep(0.01)
else:
    for saved in retained: os.unlink(saved)
    print('inode-replacement-not-reused',identity,limit,file=sys.stderr)
    print('skip!!',flush=True); sys.exit(77)
for saved in retained: os.unlink(saved)
s.listen(); os.close(directory); os.chdir('/')
print('reused',flush=True)
sys.stdin.read()
",
        ])
        .arg(attempts)
        .current_dir(base)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut ready = [0; 6];
    listener
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .await
        .unwrap();
    if &ready == b"skip!\n" {
        let status = listener.wait().await.unwrap();
        assert_eq!(status.code(), Some(77));
        eprintln!(
            "INODE_REUSE_SKIPPED: the filesystem did not reuse a released inode during {INODE_REUSE_ATTEMPTS} initial attempts"
        );
        return None;
    }
    assert_eq!(&ready, b"ready\n");
    Some(listener)
}

/// Reusing a retired filesystem inode cannot authorize unlinking a replacement live socket.
#[tokio::test]
#[ignore = "scripts/test-ssh-inode-reuse reports unsupported filesystems as ignored"]
async fn review_inode_reuse_after_diagnostics_preserves_live_replacement() {
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let keep = fixture.base().join("keep");
    std::fs::write(&keep, b"retained until observed").unwrap();
    assert!(transaction.rollback().await.is_err());
    std::fs::remove_file(keep).unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let control = runtime.join("plugins.sock");
    let Some(mut listener) = inode_reuse_listener(&fixture.base()).await else {
        return;
    };
    let snapshot = fixture.root.join("snapshot");
    let observed = fixture.root.join("observed");
    let replaced = fixture.root.join("replaced");
    // Capture real diagnostics, then pause before the direct probe. The snapshot
    // remains stale across a real inode reuse; it cannot authorize removal.
    executable(
        &fixture.root.join("tools/runtime-helper"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = --bootstrap-runtime ]; then /usr/bin/ss -x -a -n -e -p -H > '{}' || exit $?; : > '{}'; while [ ! -f '{}' ]; do sleep 0.01; done; fi\nexec '{}' \"$@\"\n",
            snapshot.display(),
            observed.display(),
            replaced.display(),
            common::runtime_helper().display(),
        ),
    );
    let cleanup = tokio::spawn(async move { transaction.rollback().await });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while !observed.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    listener
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"replace\n")
        .await
        .unwrap();
    let mut reused = [0; 7];
    listener
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut reused)
        .await
        .unwrap();
    if &reused == b"skip!!\n" {
        std::fs::write(&replaced, b"ready").unwrap();
        drop(listener.stdin.take());
        let exited = listener.wait().await.unwrap();
        assert_eq!(exited.code(), Some(77));
        let _cleanup_result = tokio::time::timeout(std::time::Duration::from_secs(30), cleanup)
            .await
            .unwrap()
            .unwrap();
        eprintln!(
            "INODE_REUSE_SKIPPED: the filesystem did not reuse a released inode during {INODE_REUSE_ATTEMPTS} replacement attempts"
        );
        return;
    }
    std::fs::write(&replaced, b"ready").unwrap();
    let result = cleanup.await.unwrap();
    let socket_preserved = control.exists();
    let receipt_retained = std::fs::read_dir(fixture.base().parent().unwrap())
        .unwrap()
        .any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("infraternal.bootstrap-rollback-")
        });
    drop(listener.stdin.take());
    let exited = listener.wait().await.unwrap();
    assert_eq!(
        &reused, b"reused\n",
        "fixture reported an unexpected inode-reuse outcome"
    );
    assert!(exited.success());
    assert!(
        result.is_err() && socket_preserved && receipt_retained,
        "live replacement accepted after inode reuse: status={:?}, socket_preserved={socket_preserved}, receipt_retained={receipt_retained}",
        result.as_ref().err().and_then(|error| error.exit_status)
    );
}

/// A different Unix user's fixed basename is not liveness proof for this installation.
#[tokio::test]
#[ignore = "requires sudo -n to create an isolated listener as uid 65534"]
async fn review_unrelated_user_relative_socket_does_not_block_stale_cleanup() {
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let keep = fixture.base().join("keep");
    std::fs::write(&keep, b"retain receipt for restart inspection").unwrap();
    assert!(transaction.rollback().await.is_err());
    let receipt = fixture.receipt();
    std::fs::remove_file(keep).unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stale = std::os::unix::net::UnixListener::bind(runtime.join("plugins.sock")).unwrap();
    drop(stale);
    let unrelated = fixture.root.join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o777)).unwrap();
    // Inherit the isolated cwd before dropping uid, so no home-directory
    // permissions change is needed. EOF retires only this fixture's listener.
    let mut listener = Command::new("sudo")
        .args(["-n", "python3", "-u", "-c", "import os,socket,sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); s=socket.socket(socket.AF_UNIX); s.bind('plugins.sock'); s.listen(); os.chdir('/'); print('ready',flush=True); sys.stdin.read()"])
        .current_dir(&unrelated)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn().unwrap();
    let mut ready = [0; 6];
    listener
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .await
        .unwrap();
    assert_eq!(&ready, b"ready\n");
    assert_eq!(
        std::fs::metadata(unrelated.join("plugins.sock"))
            .unwrap()
            .uid(),
        65534
    );
    let session = Local {
        root: fixture.root.clone(),
    };
    let inspected = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await;
    let cleanup = transaction.rollback().await;
    let unrelated_preserved = unrelated.join("plugins.sock").exists();
    drop(listener.stdin.take());
    assert!(listener.wait().await.unwrap().success());
    assert!(unrelated_preserved);
    assert!(
        inspected.is_ok() && cleanup.is_ok() && !receipt.exists(),
        "unrelated user socket blocks stale cleanup: inspection={:?}, cleanup={:?}, receipt_retained={}",
        inspected.as_ref().err().and_then(|error| error.exit_status),
        cleanup.as_ref().err().and_then(|error| error.exit_status),
        receipt.exists(),
    );
}

/// Records generated command lengths; every exec fails at once.
struct LengthRecorder(std::sync::Mutex<Vec<usize>>);
impl SshSession for LengthRecorder {
    fn setup_steps(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        // The session executes `sh -c <quoted script>` as one argument.
        let argument = format!(
            "sh -c {}",
            infraternal_plugin_ssh::transport::shell_quote(script)
        );
        self.0.lock().unwrap().push(argument.len());
        Box::pin(async { Err(Failure::install("recorded")) })
    }
}

#[tokio::test]
async fn every_setup_command_fits_one_kernel_argument_in_both_modes() {
    // The remote shell receives each program as one `sh -c` argument, which
    // Linux bounds at 128 KiB (MAX_ARG_STRLEN). Root restaging nests its
    // cleanup inside the privileged upload step (#230).
    let f = Fixture::new();
    for mode in [InstallMode::Rootless, InstallMode::Root] {
        let recorder = Arc::new(LengthRecorder(std::sync::Mutex::new(Vec::new())));
        let target = Target {
            mode,
            root_consent: mode == InstallMode::Root,
            ..f.target.clone()
        };
        let install = Installation::new(recorder.clone(), &target, &f.join).unwrap();
        let _ = install.restart_setup_with(&f.binary, &f.join, None).await;
        let _ = install.stage_and_setup(&f.binary, &f.join).await;
        let _ = install.rollback().await;
        let lengths = recorder.0.lock().unwrap().clone();
        assert_eq!(lengths.len(), 3, "{mode:?}: {lengths:?}");
        println!("{mode:?} command lengths {lengths:?}");
        assert!(
            lengths.iter().all(|length| *length < 131_072),
            "{mode:?} command lengths {lengths:?}"
        );
    }
}

/// A successful bootstrap publishes both CLI names and rollback retires its alias.
#[tokio::test]
async fn infra_alias_follows_bootstrap_and_is_removed_on_rollback() {
    let fixture = Fixture::new();
    let install = fixture.transaction();
    install.stage(&fixture.binary).await.unwrap();
    install.enroll_and_start(&fixture.join).await.unwrap();
    let alias = fixture.root.join(".local/bin/infra");
    assert_eq!(
        std::fs::read_link(&alias).unwrap(),
        std::path::Path::new("infraternal")
    );
    assert_eq!(
        std::fs::read(&alias).unwrap(),
        std::fs::read(&fixture.binary).unwrap()
    );
    install.rollback().await.unwrap();
    assert!(alias.symlink_metadata().is_err());
}

/// A foreign alias, including a dangling symlink, must survive installation and rollback.
#[tokio::test]
async fn infra_alias_preserves_foreign_paths() {
    for linked in [false, true] {
        let fixture = Fixture::new();
        let alias = fixture.root.join(".local/bin/infra");
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        if linked {
            std::os::unix::fs::symlink("missing-foreign-binary", &alias).unwrap();
        } else {
            std::fs::write(&alias, b"foreign binary").unwrap();
        }
        let install = fixture.transaction();
        install.stage(&fixture.binary).await.unwrap();
        install.enroll_and_start(&fixture.join).await.unwrap();
        assert!(install.alias_skipped());
        install.rollback().await.unwrap();
        if linked {
            assert_eq!(
                std::fs::read_link(&alias).unwrap(),
                std::path::Path::new("missing-foreign-binary")
            );
        } else {
            assert_eq!(std::fs::read(&alias).unwrap(), b"foreign binary");
        }
    }
}

/// Compound setup must surface the same occupied-name receipt as individual steps.
#[tokio::test]
async fn infra_alias_compound_setup_reports_foreign_name() {
    let fixture = Fixture::new();
    let alias = fixture.root.join(".local/bin/infra");
    std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
    std::fs::write(&alias, b"foreign").unwrap();
    let install = Installation::new(
        Arc::new(Compound(Local {
            root: fixture.root.clone(),
        })),
        &fixture.target,
        &fixture.join,
    )
    .unwrap();
    install.stage(&fixture.binary).await.unwrap();
    install.setup(&fixture.join).await.unwrap();
    assert!(install.alias_skipped());
    install.rollback().await.unwrap();
    assert_eq!(std::fs::read(alias).unwrap(), b"foreign");
}

/// Unvalidated receipt text must never turn into a setup warning or a successful parse.
#[test]
fn infra_alias_receipt_is_fixed_and_only_valid_during_install() {
    use infraternal_plugin_ssh::install::{interrupted_setup_step, parse_setup};
    let receipt = "STEP join\nSTEP install\nALIAS skipped\nSTEP start\nSTEP linger\nyes\nDONE\n";
    assert!(parse_setup(receipt.as_bytes()).unwrap());
    for invalid in [
        receipt.replace("ALIAS skipped", "ALIAS arbitrary"),
        receipt.replace("ALIAS skipped\n", "ALIAS skipped\nALIAS skipped\n"),
        receipt.replace("STEP install\nALIAS skipped", "ALIAS skipped\nSTEP install"),
    ] {
        assert!(parse_setup(invalid.as_bytes()).is_err());
    }
    assert!(matches!(
        interrupted_setup_step(b"STEP join\nSTEP install\nALIAS skipped\n"),
        Some(infraternal_plugin_ssh::model::InstallStep::Install)
    ));
}

/// A replaced alias belongs to its new owner even if bootstrap later rolls back.
#[tokio::test]
async fn infra_alias_replaced_after_install_survives_rollback() {
    let fixture = Fixture::new();
    let install = fixture.transaction();
    install.stage(&fixture.binary).await.unwrap();
    install.enroll_and_start(&fixture.join).await.unwrap();
    let alias = fixture.root.join(".local/bin/infra");
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink("foreign", &alias).unwrap();
    install.rollback().await.unwrap();
    assert_eq!(
        std::fs::read_link(alias).unwrap(),
        std::path::Path::new("foreign")
    );
}

/// #305 F-B: issues one fresh host id per invitation, as the server does, and
/// fails the completion of the first one only (production: the login check that
/// runs after the host-side commit).
struct LoginFailsOnce {
    hosts: std::sync::Mutex<Vec<uuid::Uuid>>,
    failing: uuid::Uuid,
}
impl infraternal_plugin_ssh::bootstrap::Backend for LoginFailsOnce {
    fn resolve<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, infraternal_plugin_ssh::bootstrap::Resolved> {
        Box::pin(async {
            Ok(infraternal_plugin_ssh::bootstrap::Resolved {
                destination: infraternal_plugin_ssh::model::Destination::parse("user@fixture")
                    .unwrap(),
                credentials: infraternal_plugin_ssh::transport::Credentials::Network,
                mesh: infraternal_plugin_ssh::model::MeshEvidence::default(),
            })
        })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        _: &'a Target,
        _: &'a infraternal_plugin_ssh::probe::Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move {
            let host = self.hosts.lock().unwrap().remove(0);
            Ok(JoinMaterial {
                host,
                url: "https://fixture.invalid/join".into(),
                stdin: Secret::new(b"synthetic-capability\n".to_vec()),
            })
        })
    }
    fn connected_facts<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn terminal_canary<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn completed<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        host: uuid::Uuid,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            if host == self.failing {
                Err(Failure::install(
                    "The host connected, but its preferred account login could not open.",
                ))
            } else {
                Ok(())
            }
        })
    }
    fn failed<'a>(
        &'a self,
        _: &'a infraternal_plugin_ssh::bootstrap::Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Opens every SSH session as the real-filesystem `Local` fixture under `root`.
struct LocalTransport {
    root: PathBuf,
}
impl infraternal_plugin_ssh::transport::SshTransport for LocalTransport {
    fn open(
        &self,
        _: infraternal_plugin_ssh::model::Destination,
        _: infraternal_plugin_ssh::transport::Credentials,
        _: infraternal_plugin_ssh::model::MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            Ok(Arc::new(Local {
                root: self.root.clone(),
            }) as Arc<dyn SshSession>)
        })
    }
}

/// Gives the fixture's installed binary the real CLI's owner-scoped
/// `--bootstrap-uninstall <host>` contract (see the comment inside).
fn with_owner_scoped_uninstall(fixture: &Fixture) {
    // The installed binary's owner-scoped uninstall contract, as the real CLI's
    // `--bootstrap-uninstall <host>`: take the setup lock on the base's parent
    // without waiting (the real one refuses after a short wait), and remove only
    // when `.bootstrap-owner` names the host. It finds its install from its own
    // path, never from $HOME.
    let payload = std::fs::read_to_string(&fixture.binary).unwrap().replacen(
        "#!/bin/sh\n",
        "#!/bin/sh\nif [ \"$1\" = --bootstrap-uninstall ]; then base=$(dirname \"$(dirname \"$0\")\"); exec 8< \"$(dirname \"$base\")\"; flock -n 8 || exit 75; [ \"$(cat \"$base/.bootstrap-owner\")\" = \"$2\" ] || exit 1; home=$(dirname \"$(dirname \"$(dirname \"$base\")\")\"); rm -rf \"$base\" \"$base.bootstrap-cache\" \"$home/.local/bin/infraternal\" \"$home/.config/systemd/user/infraternal-agent.service\"; exit 0; fi\n",
        1,
    );
    executable(&fixture.binary, &payload);
}

/// The step (Done or Failed) and message `batch` ends with.
async fn outcome(
    batch: infraternal_plugin_ssh::bootstrap::Batch,
) -> (infraternal_plugin_ssh::model::Step, String) {
    use infraternal_plugin_ssh::model::Step;
    let mut changes = batch.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let (_, events) = batch.events(0);
            if let Some(event) = events
                .iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                return (event.step, event.message.to_owned());
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

/// #305 F-B: an attempt whose host-side commit succeeded but whose next step failed
/// (production: the login check after commit) must not leave its install behind.
/// Left in place, its agent keeps running for a host the server revokes, and its
/// `.bootstrap-owner` makes every later add refuse to stage with exit 71, a
/// permissions error with no Start fresh. The retry with a new host id must finish.
#[tokio::test]
async fn a_failure_after_commit_removes_its_install_so_the_retry_finishes() {
    use infraternal_plugin_ssh::{bootstrap::Bootstrap, install::BinaryPaths, model::Step};
    let fixture = Fixture::new();
    with_owner_scoped_uninstall(&fixture);
    let (first, second) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let runner = Bootstrap::new(
        Arc::new(LocalTransport {
            root: fixture.root.clone(),
        }),
        Arc::new(LoginFailsOnce {
            hosts: std::sync::Mutex::new(vec![first, second]),
            failing: first,
        }),
        BinaryPaths {
            x86_64: fixture.binary.clone(),
            aarch64: fixture.binary.clone(),
        },
    );
    let start = || {
        runner
            .start("owner".into(), vec![fixture.target.clone()], None)
            .unwrap()
    };
    let (step, message) = outcome(start()).await;
    assert_eq!(step, Step::Failed, "{message}");
    let owner = fixture.base().join(".bootstrap-owner");
    assert!(
        !owner.exists(),
        "the failed attempt left its install owned by {:?}",
        std::fs::read_to_string(&owner).ok()
    );
    let (step, message) = outcome(start()).await;
    assert_eq!(step, Step::Done, "{message}");
    assert_eq!(
        std::fs::read_to_string(&owner).unwrap().trim(),
        second.simple().to_string()
    );
}
