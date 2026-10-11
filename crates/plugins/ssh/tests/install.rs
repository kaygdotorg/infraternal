//! Exercises transaction failure recovery on real files while replacing the service manager with a deterministic fixture.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    install::{Installation, JoinMaterial},
    model::{Failure, InstallMode, Target, TargetAddress},
    transport::{CommandOutput, Input, Operation, Secret, SshSession},
};
use std::{path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command};

struct Local {
    root: PathBuf,
}
impl SshSession for Local {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            // Map the remote user's home to isolated fixture storage without
            // changing the process's HOME or touching a real user's installation.
            let script = script.replace("$HOME", self.root.to_str().unwrap());
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
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn executable(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
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
    use std::os::unix::fs::PermissionsExt;
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
    use std::os::unix::fs::PermissionsExt;
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
    use std::os::unix::fs::PermissionsExt;
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
