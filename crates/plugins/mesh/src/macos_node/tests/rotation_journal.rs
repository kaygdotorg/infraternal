//! The Mac store removes rotation journal temporaries that a kill left behind.

use super::{TestDirectory, test_directory};
use std::{fs, path::PathBuf};

/// Create the file shape left by a SIGKILL while the private journal was being replaced.
fn write_rotation_temporary(directory: &TestDirectory) -> PathBuf {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    let path = directory.join("mesh-key-rotation.4242.1762500000000000000.49.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create journal temporary");
    file.write_all(&[0x5a; 117])
        .expect("write journal-shaped bytes");
    path
}

/// Mac startup removes a journal temporary left by a stop before rename.
#[test]
fn macos_store_open_sweeps_rotation_journal_temporaries() {
    let directory = test_directory();
    drop(
        crate::node_state::Store::open_for_macos(&directory.0).expect("open initial Mac store"),
    );
    let temporary = write_rotation_temporary(&directory);

    drop(
        crate::node_state::Store::open_for_macos(&directory.0)
            .expect("reopen after interrupted journal write"),
    );

    assert!(
        !temporary.exists(),
        "Mac journal temporary survives restart"
    );
}

/// Mac journal writes remove earlier crash-left temporaries before replacing the record.
#[test]
fn macos_save_rotation_secret_sweeps_old_journal_temporaries() {
    let directory = test_directory();
    let store = crate::node_state::Store::open_for_macos(&directory.0).expect("open Mac store");
    let temporary = write_rotation_temporary(&directory);

    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
            sequence: 1,
            previous: [0x11; 32],
            candidate: [0x22; 32],
            commit_requested: false,
            completed: false,
        })
        .expect("write prepared Mac journal");

    assert!(
        !temporary.exists(),
        "Mac journal write leaves no older temporary"
    );
}
