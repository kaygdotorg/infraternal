//! Review regressions for the D395 journal and top-level directory metadata.
//! Run with the adjacent driver, which appends these cases to the installer tests.

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
    assert_eq!(fs::read_to_string(journal.backup.join("unrelated")).unwrap(), "untouched");
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
    assert!(manager.active().unwrap(), "resume reported success with the server stopped");
    assert_eq!(Install::data(&fixture.new), "original");
}

/// Copy does not silently discard the root directory's safe metadata.
#[test]
fn review_j899_preserves_data_root_mode() {
    let fixture = Install::new();
    fs::set_permissions(&fixture.old, fs::Permissions::from_mode(0o2700)).unwrap();
    fixture.apply(&fixture.old, &Fake::default()).unwrap();
    assert_eq!(fixture.new.metadata().unwrap().mode() & 0o7777, 0o2700);
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
