//! Exercises transaction failure recovery on real files while replacing the service manager with a deterministic fixture.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    install::{Installation, JoinMaterial},
    model::{Failure, InstallMode, Target, TargetAddress},
    transport::{CommandOutput, Input, Operation, Secret, SshSession},
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command};

struct Local {
    root: PathBuf,
}
impl SshSession for Local {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            // Map the remote user's home to isolated fixture storage without
            // changing the process's HOME or touching a real user's installation.
            // Retain the shell parent through the reply. An interrupted final
            // command must never target the test runner through exec optimization.
            let script = format!(
                "{}\nbootstrap_test_status=$?\nexit \"$bootstrap_test_status\"",
                script.replace("$HOME", self.root.to_str().unwrap())
            );
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
    assert!(failure.message.contains("ownership"));
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
    exercise_start_fresh(false, false).await;
}

#[tokio::test]
async fn turning_off_paused_host_provisioning_preserves_earlier_leftovers() {
    exercise_start_fresh(true, false).await;
}

#[tokio::test]
async fn known_failed_setup_finishes_without_a_second_confirmation() {
    exercise_start_fresh(false, true).await;
}

// Reuse one real-filesystem fixture for completion and component cancellation.
#[allow(
    clippy::too_many_lines,
    reason = "Keep the real shell fixture and same-attempt admission assertions together."
)]
async fn exercise_start_fresh(turn_off: bool, automatic: bool) {
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
    }
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
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
        .args(["-u", "-c", "import socket,os,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); os.chmod(sys.argv[1],0o600); s.listen(); os.chdir('/'); print('ready',flush=True); sys.stdin.read()"])
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
        std::fs::read_link(&descriptor).unwrap(),
        fixture.base().join(".bootstrap-lock"),
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
    std::fs::create_dir(&runtime).unwrap();
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

/// Reusing a retired filesystem inode cannot authorize unlinking a replacement live socket.
#[tokio::test]
async fn review_inode_reuse_after_diagnostics_preserves_live_replacement() {
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::new();
    let transaction = fixture.transaction();
    transaction.stage(&fixture.binary).await.unwrap();
    let runtime = fixture.base().join("sessions");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let control = runtime.join("plugins.sock");
    // One pinned fixture process performs both allocations. This avoids
    // allocator locality changes between unrelated subprocesses; no inode
    // value or kernel diagnostic is mocked. EOF retires only this listener.
    let mut listener = Command::new("python3")
        .args([
            "-u",
            "-c",
            r#"
import os,socket,sys,time
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
path='sessions/plugins.sock'
s=socket.socket(socket.AF_UNIX); s.bind(path); s.close()
identity=os.stat(path).st_ino
print('ready',flush=True)
sys.stdin.readline()
os.unlink(path)
time.sleep(0.1)
for attempt in range(256):
    s=socket.socket(socket.AF_UNIX); s.bind(path)
    if os.stat(path).st_ino == identity: break
    s.close(); os.unlink(path); time.sleep(0.01)
else:
    print('absent',flush=True); sys.exit(1)
s.listen(); os.chdir('/')
print('reused',flush=True)
sys.stdin.read()
"#,
        ])
        .current_dir(fixture.base())
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
    assert_eq!(&ready, b"ready\n");
    let snapshot = fixture.root.join("snapshot");
    let observed = fixture.root.join("observed");
    let replaced = fixture.root.join("replaced");
    // Keep the actual diagnostic bytes and synchronize only the interleaving.
    executable(
        &fixture.root.join("tools/ss"),
        &format!(
            "#!/bin/sh\n/usr/bin/ss \"$@\" > '{}' || exit $?\n: > '{}'\nwhile [ ! -f '{}' ]; do sleep 0.01; done\ncat '{}'\n",
            snapshot.display(),
            observed.display(),
            replaced.display(),
            snapshot.display()
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
        "fixture could not reproduce inode reuse in 256 allocations"
    );
    assert!(exited.success());
    assert!(
        result.is_err() && socket_preserved && receipt_retained,
        "live replacement accepted after inode reuse: status={:?}, socket_preserved={socket_preserved}, receipt_retained={receipt_retained}",
        result.as_ref().err().and_then(|error| error.exit_status)
    );
}
