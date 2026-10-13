//! Exercises transaction failure recovery on real files while replacing the service manager with a deterministic fixture.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    install::{Installation, JoinMaterial},
    model::{Failure, InstallMode, Target, TargetAddress},
    transport::{CommandOutput, Input, Operation, PayloadInput, Secret, SshSession},
};
use std::fmt::Write as _;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command};

struct Local {
    root: PathBuf,
}
struct Compound(Local);
impl SshSession for Compound {
    fn setup_steps(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.0.run(script, input)
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
            // Map the remote user's home to isolated fixture storage without
            // changing the process's HOME or touching a real user's installation.
            let script = script.replace("$HOME", self.root.to_str().unwrap());
            // Model a lease child that has forked but has not yet been scheduled
            // to close its inherited parent lock; this exercises a real fd race.
            let script = if self.root.join("delay-lease-exec").exists() {
                script.replace(
                    "(exec 9<&-; exec sleep 180)",
                    "(sleep 1; exec 9<&-; exec sleep 180)",
                )
            } else {
                script
            };
            // A test-only public marker proves that the real shell has reached
            // its blocking admission read; yielding alone would not prove overlap.
            let script = if matches!(&input, Input::Signal(_)) {
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
            if matches!(&input, Input::Negotiated { .. }) {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", &script]).env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.root.join("tools").display()),
                );
                let output = infraternal_plugin_ssh::process::execute(
                    &mut command,
                    input,
                    std::time::Duration::from_secs(60),
                )
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
                Input::Negotiated { .. } => {
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
    root: PathBuf,
    target: Target,
    join: JoinMaterial,
    binary: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = common::scratch().join(format!("ssh-install-{}", uuid::Uuid::new_v4().simple()));
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
        let binary = root.join("payload");
        executable(
            &binary,
            "#!/bin/sh\n# Synthetic CLI contract, not an infraternal daemon.\n[ \"$1 $2\" = 'agent --data' ] || exit 1\nstate=$3\n[ \"$4\" = join ] && [ \"$6\" = --enroll-only ] || exit 1\nmkdir -p \"$state\"\nprintf 'public-fixture-state\\n' > \"$state/proof\"\ncat >/dev/null\n",
        );
        Self {
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
    executable(&fixture.binary, "#!/bin/sh\nexit 71\n");
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
        let pending = install.commit_after(receiver);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("commit preceded proof: {result:?}"),
            result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                while !fixture.root.join("commit-admitted").exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }) => { result.unwrap(); }
        }
        assert!(stage.join("activating").exists());
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
    executable(&fixture.binary, "#!/bin/sh\nexit 71\n");
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
    symlink(foreign.parent().unwrap(), fixture.base().join("sessions")).unwrap();
    assert!(transaction.rollback().await.is_err());
    assert!(foreign.exists());
    assert!(fixture.base().join(".bootstrap-owner").exists());
    std::fs::remove_file(fixture.base().join("sessions")).unwrap();
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
    assert!(failure.message.contains("~/.local/share/infraternal"));
    assert!(failure.message.contains("Move it aside"));
}

#[tokio::test]
async fn enrollment_process_exit_71_is_not_reported_as_directory_refusal() {
    let fixture = Fixture::new();
    executable(&fixture.binary, "#!/bin/sh\nexit 71\n");
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
    let result = session
        .run(
            &infraternal_plugin_ssh::previous_attempt::check_script(fixture.target.mode),
            Input::Empty,
        )
        .await;
    let refused = infraternal_plugin_ssh::previous_attempt::classify(result.err().unwrap());
    assert_eq!(
        refused.kind,
        infraternal_plugin_ssh::model::FailureKind::SetupRunning
    );
    assert!(fixture.base().join(".bootstrap-lock").exists());
    transaction.rollback().await.unwrap();
    assert!(!fixture.base().exists());
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
    exercise_start_fresh(false).await;
}

#[tokio::test]
async fn turning_off_paused_host_provisioning_preserves_earlier_leftovers() {
    exercise_start_fresh(true).await;
}

// Reuse one real-filesystem fixture for completion and component cancellation.
#[allow(
    clippy::too_many_lines,
    reason = "Keep the real shell fixture and same-attempt admission assertions together."
)]
async fn exercise_start_fresh(turn_off: bool) {
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
    let backend = Arc::new(Ready {
        host: fixture.join.host,
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
    let challenge = tokio::time::timeout(std::time::Duration::from_secs(60), async {
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
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            runner.set_enabled(false),
        )
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
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let (_, events) = batch.events(0);
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
            "#!/bin/sh\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nif [ -f {} ]; then rm {}; mkdir -p \"$3\"; printf 'public-fixture-state\\n' > \"$3/proof\"; exit 1; fi\n{original}",
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
        std::fs::create_dir_all(f.base().join("sessions/sessions")).unwrap();
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
            "#!/bin/sh\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nexit 1\n#{}\n",
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
            "#!/bin/sh\n[ \"$1 $2\" = 'agent --data' ] || exit 1\nstate=$3\nmkdir -p \"$state\"\ncat > \"$state/invitation\"\n",
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
    return int(re.search(choice.encode() + rb'\)[^\n]*?head -c (\d+)', script)[1])
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
        std::time::Duration::from_secs(20),
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
            "#!/bin/sh\nif [ \"$1\" = __ssh-session ]; then printf 'SESSION {id}\\n'; exec cat; fi\nexit 1\n#{}\n",
            "x".repeat(100_000)
        ),
    );
}

#[tokio::test]
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
            "choice = re.search(rb'\\nchoice=(\\w+)\\n', script)[1].decode()\nassert choice in ('zstd', 'gzip', 'raw'), choice\npayload = exact(size(choice))\nout.write(b'STEP upload\\nTRANSFER ' + choice.encode() + b'\\nSTEP start\\nSESSION {id}\\n')"
        ),
    );
    let (session, bridge) = scripted_staging(&f, remote).await.unwrap();
    assert_eq!(session, id);
    bridge.write(b"bridge bytes\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"bridge bytes\n");
}

#[tokio::test]
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
            "assert b'\\nchoice=raw\\nif ' in script\nassert quiet(), 'payload followed the setup script'\nout.write(b'STEP upload\\nTRANSFER raw\\n'); out.flush()\npayload = exact(size('raw'))\nout.write(b'STEP start\\nSESSION {id}\\n')"
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
