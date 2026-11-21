//! Mac proofs that an enrolled restore binds the state folder to this Mac and refuses another
//! Mac's folder or Mesh state with no record, using the real hardware identity (#221).

use super::{
    Node, PUBLIC_STATE, TestDirectory, bound_state, enrolment, test_directory, write_key,
    write_public_state,
};
use crate::enrolment::MachineBindingError;
use std::io;

/// Record this Mac's binding, as an earlier enrolled start would have.
pub(super) fn bind_this_mac(directory: &TestDirectory) {
    crate::macos_machine::bind(&directory.0, crate::macos_machine::fingerprint())
        .expect("bind this Mac");
}

/// The names `macos_machine` uses to spot existing Mesh state are the real file names.
#[test]
fn the_machine_binding_watches_the_real_state_files() {
    assert_eq!(
        crate::macos_machine::MESH_STATE,
        [PUBLIC_STATE, crate::macos_key::KEY_FILE]
    );
}

/// Mesh state with no binding record is refused as unbound and nothing is changed (#221).
#[test]
fn an_enrolled_restore_refuses_mesh_state_that_has_no_machine_record() {
    let directory = test_directory();
    let current = enrolment(b"coordinator B");
    write_public_state(
        &directory.join(PUBLIC_STATE),
        &bound_state(Some(current.clone())),
    )
    .expect("write state");
    write_key(&directory);
    for error in [
        Node::restore(&directory.0, Some(&current))
            .err()
            .expect("restore refused"),
        Node::check_enrolled_machine(&directory.0).expect_err("pre-start check refused"),
    ] {
        assert!(matches!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<MachineBindingError>()),
            Some(MachineBindingError::UnboundRecord)
        ));
    }
    assert!(directory.join(crate::macos_key::KEY_FILE).is_file());
    assert!(!directory.join(crate::macos_machine::MACHINE_FILE).exists());
}

/// Rewrite the recorded fingerprint, as a folder copied from another Mac would carry.
fn forge_machine_record(directory: &TestDirectory) {
    let path = directory.join(crate::macos_machine::MACHINE_FILE);
    std::fs::remove_file(&path).expect("remove record");
    std::fs::write(&path, format!("{{\"machine\":{:?}}}", [7u8; 32])).expect("forge record");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");
}

/// An enrolled restore binds this Mac, restores again, and refuses a folder from another Mac (#221).
#[test]
fn an_enrolled_restore_binds_this_mac_and_refuses_a_folder_from_another() {
    let directory = test_directory();
    // Bound while the folder is still empty: a folder with state and no record is refused.
    bind_this_mac(&directory);
    let current = enrolment(b"coordinator B");
    // A disabled node: an enabled one would need root to open its utun.
    write_public_state(
        &directory.join(PUBLIC_STATE),
        &bound_state(Some(current.clone())),
    )
    .expect("write state");
    write_key(&directory);

    Node::restore(&directory.0, Some(&current)).expect("restore keeps the binding");
    assert!(directory.join(crate::macos_machine::MACHINE_FILE).is_file());
    Node::restore(&directory.0, Some(&current)).expect("same Mac restores");
    Node::check_enrolled_machine(&directory.0).expect("same Mac passes the pre-start check");

    forge_machine_record(&directory);
    let key = std::fs::read(directory.join(crate::macos_key::KEY_FILE)).expect("key");
    for error in [
        Node::restore(&directory.0, Some(&current))
            .err()
            .expect("restore refused"),
        Node::check_enrolled_machine(&directory.0).expect_err("pre-start check refused"),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<MachineBindingError>()),
            Some(MachineBindingError::ForeignMachine)
        ));
    }
    // The refusal changes nothing: the key and the record stay as they were.
    assert_eq!(
        std::fs::read(directory.join(crate::macos_key::KEY_FILE)).expect("key"),
        key
    );
}

/// The real hardware identity can be read and does not change between reads.
#[test]
fn this_mac_reports_a_stable_hardware_fingerprint() {
    let first = crate::macos_machine::fingerprint().expect("hardware identity");
    assert_eq!(Some(first), crate::macos_machine::fingerprint());
}
