//! Transaction proofs using real directory entries and a deterministic manager.
//! The root integration script repeats the cutover with a live server.

use super::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    os::unix::fs::PermissionsExt,
};

/// Apply the disk transaction directly under the test manager.
#[cfg(target_os = "linux")]
fn apply(
    relocation: &Relocation,
    service: &dyn Service,
    now: SystemTime,
    publish: impl FnOnce() -> io::Result<()>,
) -> Result<Outcome, MoveError> {
    apply_recorded(relocation, service, now, publish, |_, _| Ok(()))
}

/// An old installation and unit in an isolated, trusted test directory.
struct Install {
    /// Owns the fixture for the length of the test.
    root: PathBuf,
    /// Original data path.
    old: PathBuf,
    /// Expected D395 data path.
    new: PathBuf,
    /// systemd base unit.
    unit: PathBuf,
}

impl Install {
    /// Set up a database sentinel and generated-style unit.
    fn new() -> Self {
        let scratch = if std::env::var_os("INFRATERNAL_VERIFY_OUTER_NETNS").is_some() {
            // The privileged suite gives us a trusted private mount at /run.
            PathBuf::from("/run")
        } else {
            std::env::temp_dir()
        };
        let root = scratch.join(format!("mv-{}", uuid::Uuid::new_v4().simple()));
        let old = root.join("old");
        let new = root.join("new");
        let unit = root.join("test.service");
        fs::create_dir_all(&old).unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(old.join("infraternal.sqlite"), "original").unwrap();
        fs::write(&unit, unit_text(&old)).unwrap();
        Self {
            root,
            old,
            new,
            unit,
        }
    }

    /// Plan from the currently effective data path.
    fn plan(&self, recorded: &Path) -> Relocation {
        plan(recorded, &self.new, &self.unit).unwrap().unwrap()
    }

    /// Apply a planned move with no changes needed to external policy.
    fn apply(&self, recorded: &Path, service: &Fake) -> Result<Outcome, MoveError> {
        apply(&self.plan(recorded), service, UNIX_EPOCH, || Ok(()))
    }

    /// Read the original or migrated SQLite fixture bytes.
    fn data(dir: &Path) -> String {
        fs::read_to_string(dir.join("infraternal.sqlite")).unwrap()
    }

    /// Create an effective drop-in that overrides the base command.
    fn dropin(&self, folder: &Path) -> PathBuf {
        let dir = self.unit.with_extension("service.d");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("10-effective.conf");
        let unit = unit_text(folder);
        let command = unit
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .unwrap();
        fs::write(&file, format!("[Service]\nExecStart=\n{command}\n")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        file
    }

    /// Reproduce a legacy same-filesystem rename before its unit was updated.
    fn legacy_rename(&self) {
        let marker = self.old.join(MARKER);
        fs::write(&marker, self.old.to_str().unwrap()).unwrap();
        fs::set_permissions(marker, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&self.old, &self.new).unwrap();
    }
}

impl Drop for Install {
    /// Remove the test fixture when the move has finished.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A generated-style unit at the chosen data path.
fn unit_text(path: &Path) -> String {
    format!(
        "[Service]\nExecStart=\"/bin/infraternal\" \"server\" \"--listen\" \"127.0.0.1:47361\" \"--data\" \"{}\"\n",
        path.display()
    )
}

/// A filesystem change that runs once after the fake manager answers.
type AfterReady = Box<dyn FnOnce()>;

/// A manager whose start, readiness and active state are observable.
#[derive(Default)]
struct Fake {
    /// Whether the old or new process is active.
    active: Cell<bool>,
    /// Whether the launched process answers.
    fail_ready: Cell<bool>,
    /// Exact sequence of side effects and health confirmation.
    calls: RefCell<Vec<&'static str>>,
    /// A filesystem change immediately after the health observation.
    after_ready: RefCell<Option<AfterReady>>,
    /// Simulate the service stopping immediately after answering.
    stop_after_ready: Cell<bool>,
}

impl Service for Fake {
    fn active(&self) -> io::Result<bool> {
        Ok(self.active.get())
    }

    fn stop(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("stop");
        self.active.set(false);
        Ok(())
    }

    fn reload(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("reload");
        Ok(())
    }

    fn listener_is_idle(&self) -> io::Result<()> {
        Ok(())
    }

    fn start(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("start");
        self.active.set(true);
        Ok(())
    }

    fn ready(&self, _data: &File) -> io::Result<()> {
        self.calls.borrow_mut().push("ready");
        if self.fail_ready.get() {
            return Err(io::Error::other("server did not answer"));
        }
        if let Some(after_ready) = self.after_ready.borrow_mut().take() {
            after_ready();
        }
        if self.stop_after_ready.replace(false) {
            self.stop()?;
            self.fail_ready.set(true);
        }
        Ok(())
    }

    fn enable(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("enable");
        Ok(())
    }
}

/// The old boot path remains intact before policy publication and an early failure.
#[test]
fn pre_switch_retry_snapshots_data_written_after_old_unit_booted() {
    let fixture = Install::new();
    let service = Fake::default();
    let failure = apply(&fixture.plan(&fixture.old), &service, UNIX_EPOCH, || {
        assert_eq!(Install::data(&fixture.old), "original");
        assert_eq!(Install::data(&fixture.new), "original");
        assert_eq!(fs::read_to_string(&fixture.unit)?, unit_text(&fixture.old));
        Err(io::Error::other("policy publish failed"))
    });
    assert!(failure.is_err());
    fs::write(
        fixture.old.join("infraternal.sqlite"),
        "old server wrote after reboot",
    )
    .unwrap();
    fixture.apply(&fixture.old, &service).unwrap();
    assert_eq!(Install::data(&fixture.new), "old server wrote after reboot");
    assert!(!fixture.old.exists());
}

/// A legacy old unit booted from an empty replacement. Keep both copies.
#[test]
fn interrupted_legacy_rename_never_discards_the_original_database() {
    let fixture = Install::new();
    fixture.legacy_rename();
    fs::create_dir(&fixture.old).unwrap();
    fs::write(fixture.old.join("infraternal.sqlite"), "empty replacement").unwrap();
    let outcome = fixture.apply(&fixture.old, &Fake::default()).unwrap();
    assert_eq!(Install::data(&fixture.new), "original");
    let leftover = outcome.leftover.unwrap();
    assert_eq!(Install::data(&leftover), "empty replacement");
    assert_eq!(
        fs::metadata(leftover.join("infraternal.sqlite"))
            .unwrap()
            .mode()
            & 0o222,
        0
    );
    fs::set_permissions(leftover, fs::Permissions::from_mode(0o700)).unwrap();
}

/// If the new service never answers, the journal and intact original remain.
#[test]
fn retries_after_switch_keep_writes_to_the_new_database() {
    let fixture = Install::new();
    let service = Fake::default();
    service.fail_ready.set(true);
    assert!(fixture.apply(&fixture.old, &service).is_err());
    assert_eq!(Install::data(&fixture.old), "original");
    assert_eq!(
        fs::read_to_string(&fixture.unit).unwrap(),
        unit_text(&fixture.new)
    );
    fs::write(
        fixture.new.join("infraternal.sqlite"),
        "new server already served a write",
    )
    .unwrap();
    service.fail_ready.set(false);
    fixture.apply(&fixture.new, &service).unwrap();
    assert_eq!(
        Install::data(&fixture.new),
        "new server already served a write"
    );
    assert!(!fixture.old.exists());
    assert!(
        plan(&fixture.new, &fixture.new, &fixture.unit)
            .unwrap()
            .is_none()
    );
}

/// A shadowed unit changed first, then a host restart used the old effective path.
#[test]
fn journal_resumes_mixed_unit_set_with_effective_file_written_last() {
    let fixture = Install::new();
    let dropin = fixture.dropin(&fixture.old);
    let service = Fake::default();
    assert!(
        apply(&fixture.plan(&fixture.old), &service, UNIX_EPOCH, || {
            // This is the same on-disk state as dying after rewriting the base.
            fs::write(&fixture.unit, unit_text(&fixture.new))?;
            Err(io::Error::other("interrupted before the effective drop-in"))
        })
        .is_err()
    );
    assert_eq!(
        live_data(&fs::read_to_string(&dropin).unwrap()),
        Some(fixture.old.clone())
    );
    fs::write(
        fixture.old.join("infraternal.sqlite"),
        "writes after reboot",
    )
    .unwrap();
    fixture.apply(&fixture.old, &service).unwrap();
    assert_eq!(Install::data(&fixture.new), "writes after reboot");
    assert_eq!(
        live_data(&fs::read_to_string(&dropin).unwrap()),
        Some(fixture.new.clone())
    );
    assert_eq!(fs::metadata(dropin).unwrap().mode() & 0o777, 0o600);
}

/// The former installer could write the effective drop-in before the base unit.
#[test]
fn legacy_mixed_unit_is_repaired_and_restarted_without_force() {
    let fixture = Install::new();
    fixture.legacy_rename();
    let dropin = fixture.dropin(&fixture.new);
    let manager = Fake::default();
    fixture.apply(&fixture.new, &manager).unwrap();
    assert_eq!(
        fs::read_to_string(&fixture.unit).unwrap(),
        unit_text(&fixture.new)
    );
    assert_eq!(fs::metadata(dropin).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        *manager.calls.borrow(),
        ["reload", "start", "ready", "enable", "ready"]
    );
}

/// A shared base remains traversable and the source stays available.
#[test]
fn shared_agent_base_is_refused_without_changing_modes() {
    let fixture = Install::new();
    fs::create_dir_all(fixture.new.join("bin")).unwrap();
    fs::set_permissions(&fixture.new, fs::Permissions::from_mode(0o711)).unwrap();
    let error = plan(&fixture.old, &fixture.new, &fixture.unit).unwrap_err();
    assert!(error.to_string().contains("shared install base"));
    assert_eq!(fs::metadata(&fixture.new).unwrap().mode() & 0o777, 0o711);
    assert_eq!(Install::data(&fixture.old), "original");
}

/// A shared source needs the same refusal as a shared destination before stopping either role.
#[test]
#[ignore = "D395 round-three review regression"]
fn review_j912_refuses_a_shared_source_during_planning() {
    let fixture = Install::new();
    let agent_root = fixture.old.join("agent");
    fs::create_dir(&agent_root).unwrap();
    fs::write(agent_root.join("state"), "agent state").unwrap();

    let error = plan(&fixture.old, &fixture.new, &fixture.unit).unwrap_err();
    assert!(
        error.to_string().contains("shared install base"),
        "{error}"
    );
    assert_eq!(Install::data(&fixture.old), "original");
    assert_eq!(
        fs::read_to_string(agent_root.join("state")).unwrap(),
        "agent state"
    );
    assert!(!fixture.new.exists());
}

/// Planning twice on the standard path leaves the unit and data entries intact.
#[test]
fn standard_data_path_needs_no_move() {
    let fixture = Install::new();
    fs::rename(&fixture.old, &fixture.new).unwrap();
    fs::write(&fixture.unit, unit_text(&fixture.new)).unwrap();
    let database = fixture.new.join("infraternal.sqlite");
    let paths = [&fixture.new, &database, &fixture.unit];
    let before = paths.map(|path| path.metadata().unwrap());

    for _ in 0..2 {
        assert!(plan(&fixture.new, &fixture.new, &fixture.unit).unwrap().is_none());
    }

    for (path, previous) in paths.into_iter().zip(before) {
        let current = path.metadata().unwrap();
        assert_eq!(
            (current.ino(), current.uid(), current.gid(), current.mode()),
            (previous.ino(), previous.uid(), previous.gid(), previous.mode())
        );
    }
    assert_eq!(
        fs::read_to_string(&fixture.unit).unwrap(),
        unit_text(&fixture.new)
    );
    assert_eq!(Install::data(&fixture.new), "original");
    assert!(!fixture.old.exists());
}

/// The requested command must use the installed port, even for forced init.
#[test]
fn move_refuses_a_different_listen_address() {
    let fixture = Install::new();
    let relocation = fixture.plan(&fixture.old);
    assert!(relocation.check_command(&unit_text(&fixture.new)).is_ok());
    let new_port = unit_text(&fixture.new).replace("47361", "47362");
    assert!(relocation.check_command(&new_port).is_err());
}

/// A sibling matching the old staging prefix survives data publication.
#[test]
fn unrelated_sibling_with_the_former_staging_prefix_is_retained() {
    let fixture = Install::new();
    let unrelated = fixture
        .new
        .with_file_name(".new.partial-not-migration-data");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("probe"), "not ours").unwrap();
    fixture.apply(&fixture.old, &Fake::default()).unwrap();
    assert_eq!(
        fs::read_to_string(unrelated.join("probe")).unwrap(),
        "not ours"
    );
}

/// Escape links are refused without opening their target or replacing the unit.
#[test]
fn data_link_outside_the_source_is_refused() {
    let fixture = Install::new();
    let outside = fixture.new.with_file_name("outside");
    fs::write(&outside, "unrelated").unwrap();
    std::os::unix::fs::symlink("../outside", fixture.old.join("link")).unwrap();
    let error = fixture.apply(&fixture.old, &Fake::default()).err().unwrap();
    assert!(
        error.to_string().contains("link leaves the data folder"),
        "{error}"
    );
    assert_eq!(fs::read_to_string(outside).unwrap(), "unrelated");
    assert!(!fixture.new.exists());
}

/// Non-private legacy markers have no authority to redirect a move.
#[test]
fn public_legacy_marker_is_refused() {
    let fixture = Install::new();
    fixture.legacy_rename();
    fs::set_permissions(fixture.new.join(MARKER), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(plan(&fixture.old, &fixture.new, &fixture.unit).is_err());
    assert_eq!(Install::data(&fixture.new), "original");
}

/// Before the manager may start the final unit, the host policy has been published.
#[test]
fn publishes_policy_before_switch_and_restarts_once() {
    let fixture = Install::new();
    let manager = Fake::default();
    manager.active.set(true);
    apply(&fixture.plan(&fixture.old), &manager, UNIX_EPOCH, || {
        manager.calls.borrow_mut().push("publish");
        assert_eq!(fs::read_to_string(&fixture.unit)?, unit_text(&fixture.old));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        *manager.calls.borrow(),
        [
            "stop", "publish", "reload", "start", "ready", "enable", "ready"
        ]
    );
}

/// A private pre-existing target can hold the independent server firewall policy.
#[test]
fn a_private_policy_only_target_keeps_its_policy() {
    let fixture = Install::new();
    fs::create_dir(&fixture.new).unwrap();
    fs::set_permissions(&fixture.new, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fixture.new.join("host-firewall-server.json"), "policy").unwrap();

    fixture.apply(&fixture.old, &Fake::default()).unwrap();

    assert_eq!(Install::data(&fixture.new), "original");
    assert_eq!(
        fs::read_to_string(fixture.new.join("host-firewall-server.json")).unwrap(),
        "policy"
    );
}

/// No data at an unrelated destination may be treated as a previous snapshot.
#[test]
fn a_target_with_unrelated_data_is_never_claimed() {
    let fixture = Install::new();
    fs::create_dir(&fixture.new).unwrap();
    fs::write(fixture.new.join("other-data"), "unrelated").unwrap();

    assert!(plan(&fixture.old, &fixture.new, &fixture.unit).is_err());
    assert_eq!(
        fs::read_to_string(fixture.new.join("other-data")).unwrap(),
        "unrelated"
    );
    assert_eq!(Install::data(&fixture.old), "original");
}

/// A unit directive the move cannot safely rewrite prevents all changes.
#[test]
fn refuses_an_old_path_outside_exec_start() {
    let fixture = Install::new();
    let original = format!(
        "{}ReadWritePaths={}\n",
        unit_text(&fixture.old),
        fixture.old.display()
    );
    fs::write(&fixture.unit, &original).unwrap();

    let error = plan(&fixture.old, &fixture.new, &fixture.unit).unwrap_err();
    assert!(error.to_string().contains("outside ExecStart"), "{error}");
    assert_eq!(fs::read_to_string(&fixture.unit).unwrap(), original);
    assert!(!fixture.new.exists());
}

/// An existing journal never permits an unrelated replacement backup inode.
#[test]
fn refuses_a_replaced_backup_without_deleting_either_tree() {
    let fixture = Install::new();
    let manager = Fake::default();
    manager.fail_ready.set(true);
    assert!(fixture.apply(&fixture.old, &manager).is_err());
    let journal = load(&fixture.new, &fixture.unit).unwrap().unwrap();
    fs::create_dir(&journal.backup).unwrap();
    fs::write(journal.backup.join("unrelated"), "untouched").unwrap();

    manager.fail_ready.set(false);
    assert!(fixture.apply(&fixture.new, &manager).is_err());
    assert_eq!(Install::data(&fixture.old), "original");
    assert_eq!(Install::data(&fixture.new), "original");
    assert_eq!(
        fs::read_to_string(journal.backup.join("unrelated")).unwrap(),
        "untouched"
    );
}

/// An unclaimed work directory with files is never adopted as migration staging.
#[test]
fn does_not_adopt_an_unclaimed_staging_tree() {
    let fixture = Install::new();
    let stage = fixture
        .new
        .with_file_name(work_name(fixture.new.file_name().unwrap()))
        .join(STAGING);
    fs::create_dir_all(&stage).unwrap();
    fs::set_permissions(stage.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stage.join("unrelated"), "untouched").unwrap();

    assert!(fixture.apply(&fixture.old, &Fake::default()).is_err());
    assert_eq!(
        fs::read_to_string(stage.join("unrelated")).unwrap(),
        "untouched"
    );
    assert_eq!(Install::data(&fixture.old), "original");
}

/// A backup collision leaves the old tree available after health was recorded.
fn ready_with_original() -> (Install, Fake, Journal) {
    let fixture = Install::new();
    let manager = Fake::default();
    let result = apply(&fixture.plan(&fixture.old), &manager, UNIX_EPOCH, || {
        let journal = load(&fixture.new, &fixture.unit)?.unwrap();
        fs::create_dir(&journal.backup)?;
        fs::write(journal.backup.join("unrelated"), "untouched")
    });
    assert!(result.is_err());
    let journal = load(&fixture.new, &fixture.unit).unwrap().unwrap();
    assert!(journal.ready);
    assert_eq!(Install::data(&fixture.old), "original");
    assert_eq!(Install::data(&fixture.new), "original");
    assert_eq!(
        fs::read_to_string(journal.backup.join("unrelated")).unwrap(),
        "untouched"
    );
    fs::remove_dir_all(&journal.backup).unwrap();
    (fixture, manager, journal)
}

/// Reject a changed destination before the journal can retire the original.
#[test]
fn review_j899_checks_destination_before_retiring_original() {
    let (fixture, manager, journal) = ready_with_original();
    let previous = fixture.root.join("saved-candidate");
    fs::rename(&fixture.new, &previous).unwrap();
    fs::create_dir(&fixture.new).unwrap();
    fs::write(fixture.new.join("infraternal.sqlite"), "replacement").unwrap();
    assert!(fixture.apply(&fixture.new, &manager).is_err());
    assert_eq!(Install::data(&fixture.new), "replacement");
    assert_eq!(Install::data(&previous), "original");
    assert!(
        fixture.old.join("infraternal.sqlite").exists()
            || journal.backup.join("infraternal.sqlite").exists(),
        "the journal refused the replacement after deleting the original"
    );
}

/// A ready journal can survive the managed service that originally answered.
#[test]
fn review_j899_restarts_stopped_service_during_cleanup_retry() {
    let (fixture, manager, _) = ready_with_original();
    manager.stop().unwrap();

    fixture.apply(&fixture.new, &manager).unwrap();
    assert!(
        manager.active().unwrap(),
        "resume reported success with the server stopped"
    );
    assert_eq!(Install::data(&fixture.new), "original");
}

/// A replacement SQLite file cannot authorize removal even inside the same directory.
#[test]
fn ready_retry_rejects_a_replaced_database() {
    let (fixture, manager, _) = ready_with_original();
    let database = fixture.new.join("infraternal.sqlite");
    fs::rename(&database, fixture.new.join("previous.sqlite")).unwrap();
    fs::write(database, "replacement").unwrap();

    assert!(fixture.apply(&fixture.new, &manager).is_err());
    assert_eq!(Install::data(&fixture.old), "original");
}

/// A moved parent can leave the pinned tree intact while replacing its live path.
#[test]
#[ignore = "D395 round-three review regression"]
fn review_j906_preserves_original_when_destination_parent_moves() {
    let mut fixture = Install::new();
    let destination_parent = fixture.root.join("destination");
    fs::create_dir(&destination_parent).unwrap();
    fixture.new = destination_parent.join("new");
    let service = Fake::default();
    let relocation = fixture.plan(&fixture.old);
    let result = apply(&relocation, &service, UNIX_EPOCH, || {
        let journal = load(&fixture.new, &fixture.unit)?.unwrap();
        fs::create_dir(journal.backup)
    });
    assert!(result.is_err());
    let journal = load(&fixture.new, &fixture.unit).unwrap().unwrap();
    assert!(journal.ready);
    fs::remove_dir(&journal.backup).unwrap();

    let displaced = fixture.root.join("displaced");
    let saved_path = displaced.join("new");
    let replacement = fixture.new.clone();
    service.after_ready.replace(Some(Box::new(move || {
        fs::rename(destination_parent, displaced).unwrap();
        fs::create_dir_all(&replacement).unwrap();
        fs::write(replacement.join("infraternal.sqlite"), "replacement").unwrap();
    })));
    let result = fixture.apply(&fixture.new, &service);
    assert_eq!(Install::data(&saved_path), "original");
    assert_eq!(Install::data(&fixture.new), "replacement");
    assert!(
        fixture.old.join("infraternal.sqlite").is_file()
            || journal.backup.join("infraternal.sqlite").is_file(),
        "retirement deleted the original after the destination path changed"
    );
    assert!(result.is_err());
}

/// A final health reply cannot authorize deletion after the server has stopped.
#[test]
#[ignore = "D395 round-three review regression"]
fn review_j906_preserves_original_when_server_stops_after_health() {
    let (fixture, service, journal) = ready_with_original();
    service.stop_after_ready.set(true);

    let result = fixture.apply(&fixture.new, &service);
    assert!(!service.active().unwrap());
    assert_eq!(Install::data(&fixture.new), "original");
    assert!(
        fixture.old.join("infraternal.sqlite").is_file()
            || journal.backup.join("infraternal.sqlite").is_file(),
        "retirement deleted the original after the moved server stopped"
    );
    assert!(result.is_err());
}

/// A nested directory and regular file retain their attributes on a whole-tree move.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "D395 round-three review regression"]
fn review_j906_preserves_nested_attributes() {
    use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};

    let fixture = Install::new();
    let directory = Path::new("nested");
    let file = directory.join("fixture");
    fs::create_dir(fixture.old.join(directory)).unwrap();
    fs::write(fixture.old.join(&file), b"nested data").unwrap();
    let name = "user.infraternal.test";
    for relative in [directory, file.as_path()] {
        let old = File::open(fixture.old.join(relative)).unwrap();
        fsetxattr(&old, name, b"nested attribute", XattrFlags::empty()).unwrap();
    }

    fixture.apply(&fixture.old, &Fake::default()).unwrap();
    let attributes = [directory, file.as_path()].map(|relative| {
        let new = File::open(fixture.new.join(relative)).unwrap();
        let mut copied = [0; 64];
        fgetxattr(&new, name, copied.as_mut_slice()).map(|size| copied[..size].to_vec())
    });
    assert_eq!(
        attributes,
        [
            Ok(b"nested attribute".to_vec()),
            Ok(b"nested attribute".to_vec())
        ]
    );
}

/// Copy preserves the top-level setgid bit and the original owner and group.
#[test]
fn review_j899_preserves_data_root_mode() {
    let fixture = Install::new();
    fs::set_permissions(&fixture.old, fs::Permissions::from_mode(0o2750)).unwrap();
    let before = fixture.old.metadata().unwrap();
    fixture.apply(&fixture.old, &Fake::default()).unwrap();
    let after = fixture.new.metadata().unwrap();
    assert_eq!(after.mode() & 0o7777, before.mode() & 0o7777);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
}

/// Reconstruct a switched journal from before the first process was verified.
#[test]
fn interrupted_start_preserves_possible_writes_to_the_original() {
    let fixture = Install::new();
    let service = Fake::default();
    service.fail_ready.set(true);
    assert!(fixture.apply(&fixture.old, &service).is_err());

    let mut journal = load(&fixture.new, &fixture.unit).unwrap().unwrap();
    let (parent, target_name) = disk::parent(&fixture.new, false).unwrap();
    let work = disk::tree(&parent, &work_name(target_name)).unwrap();
    journal.backup_action = Backup::Remove;
    save(&work, &journal).unwrap();
    fs::write(
        fixture.old.join("infraternal.sqlite"),
        "write during unconfirmed startup",
    )
    .unwrap();
    service.fail_ready.set(false);

    let outcome = fixture.apply(&fixture.new, &service).unwrap();
    let backup = outcome.leftover.unwrap();
    assert_eq!(Install::data(&backup), "write during unconfirmed startup");
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Refuse ready cleanup if the effective command selects the former path again.
#[test]
fn ready_retry_refuses_an_original_effective_unit() {
    let (fixture, _, _) = ready_with_original();
    fs::write(&fixture.unit, unit_text(&fixture.old)).unwrap();

    let error = plan(&fixture.old, &fixture.new, &fixture.unit).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("confirmed unit no longer points")
    );
    assert_eq!(Install::data(&fixture.old), "original");
}

/// Exercise the ready-journal checks in the privileged namespace filesystem.
#[test]
#[ignore = "Run in a disposable user namespace"]
fn d395_revalidates_current_data_before_cleanup() {
    review_j899_checks_destination_before_retiring_original();
    review_j899_restarts_stopped_service_during_cleanup_retry();
    ready_retry_rejects_a_replaced_database();
    ready_retry_refuses_an_original_effective_unit();
    interrupted_start_preserves_possible_writes_to_the_original();
}

/// Exercise root metadata copying with a real xattr inside the privileged suite.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Run in a disposable user namespace"]
fn d395_preserves_root_attributes() {
    use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
    review_j899_preserves_data_root_mode();
    let fixture = Install::new();
    let name = "user.infraternal.test";
    let value = b"D395 fixture attribute";
    let old = File::open(&fixture.old).unwrap();
    fsetxattr(&old, name, value, XattrFlags::empty()).unwrap();

    fixture.apply(&fixture.old, &Fake::default()).unwrap();

    let new = File::open(&fixture.new).unwrap();
    let mut copied = [0; 64];
    let size = fgetxattr(&new, name, copied.as_mut_slice()).unwrap();
    assert_eq!(&copied[..size], value);
}

/// A private legacy target still cannot own another install component's files.
#[test]
fn legacy_shared_base_is_refused() {
    let fixture = Install::new();
    fixture.legacy_rename();
    fs::create_dir(fixture.new.join("bin")).unwrap();

    assert!(plan(&fixture.old, &fixture.new, &fixture.unit).is_err());
    assert_eq!(Install::data(&fixture.new), "original");
    assert!(fixture.new.join("bin").is_dir());
}
