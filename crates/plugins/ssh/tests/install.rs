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
            match input {
                Input::Empty => {}
                Input::Bytes(bytes) => {
                    stdin.write_all(bytes).await.unwrap();
                }
                Input::File(path) => {
                    stdin
                        .write_all(&std::fs::read(path).unwrap())
                        .await
                        .unwrap();
                }
            }
            drop(stdin);
            let output = child.wait_with_output().await.unwrap();
            if !output.status.success() {
                return Err(Failure::install("The synthetic remote command failed."));
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
                "#!/bin/sh\ncase \"$*\" in\n*show-user*) if [ -f '{}' ]; then printf 'yes\\n'; else printf 'no\\n'; fi;;\n*enable-linger*) [ ! -f '{}' ] && touch '{}';;\n*disable-linger*) rm -f '{}';;\n*) exit 1;;\nesac\n",
                root.join("linger").display(),
                root.join("deny-linger").display(),
                root.join("linger").display(),
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
            "#!/bin/sh\n# Synthetic CLI contract, not an infraternal daemon.\n[ \"$1 $2\" = 'agent join' ] || exit 1\nshift 3\n[ \"$1\" = --state ] || exit 1\nmkdir -p \"$2\"\nprintf 'public-fixture-state\\n' > \"$2/proof\"\ncat >/dev/null\n",
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
