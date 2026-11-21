//! Binds a Mac's Mesh state folder to the Mac it was created on (#221, D-rule of J968).
//!
//! Linux ties the saved enrolment to `/etc/machine-id`. A Mac has no such file, so the state
//! folder carried no record of its machine: copying it to another Mac would start a second node
//! with the same `WireGuard` key. This module gives the Mac the same guarantee.
//!
//! The binding is one fingerprint of two public facts, so that both kinds of change refuse:
//!
//! * the hardware UUID (`IOPlatformUUID`), which differs on every Mac, and
//! * the UUID of the Data volume, which a reinstall that erases the disk replaces. Linux gets
//!   this from the fresh `machine-id` of a new OS; a Mac keeps its hardware UUID across a
//!   reinstall, so the hardware UUID alone would let a restored backup start as the old node.
//!
//! Only the SHA-256 of both is stored (`mesh-machine.json`, mode 0600); neither UUID leaves the
//! machine. The same refusal type and exit code as Linux apply (`MachineBindingError`).
//! A folder with no record is adopted only if it holds no Mesh state yet (a first start). Real
//! Mesh state with no record is refused as unbound, like Linux refuses an unbound sidecar: there
//! is no backwards compatibility to keep, and such a folder could be a copy from another Mac.

use crate::enrolment::MachineBindingError;
use crate::node_state::{read_public, write_public};
use serde::{Deserialize, Serialize};
use std::{io, os::unix::fs::MetadataExt as _, path::Path};

/// Private sidecar in the Mesh state folder holding the machine fingerprint.
pub(crate) const MACHINE_FILE: &str = "mesh-machine.json";

/// Files whose presence shows that a folder already holds this node's Mesh state: the public
/// snapshot and the WireGuard key (`macos_node::PUBLIC_STATE`, `macos_key::KEY_FILE`; a Mac test
/// checks these names still match).
pub(crate) const MESH_STATE: [&str; 2] = ["mesh-public.json", "mesh-wireguard.key"];

/// Whether the folder holds Mesh state of its own (a link is state too, so it is not followed).
fn has_mesh_state(state: &Path) -> io::Result<bool> {
    for name in MESH_STATE {
        match std::fs::symlink_metadata(state.join(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// What `mesh-machine.json` stores.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineRecord {
    /// SHA-256 over the hardware UUID and the Data volume UUID, domain-separated.
    machine: [u8; 32],
}

/// Accept only a canonical UUID (36 characters of hex and dashes) and fold it to upper case.
fn canonical_uuid(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }))
    .then(|| text.to_ascii_uppercase())
}

/// The `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice` output.
fn platform_uuid(ioreg: &str) -> Option<String> {
    ioreg.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "\"IOPlatformUUID\"")
            .then(|| canonical_uuid(value.trim().trim_matches('"')))
            .flatten()
    })
}

/// The `Volume UUID` from `diskutil info` output for the Data volume.
fn volume_uuid(diskutil: &str) -> Option<String> {
    diskutil.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "Volume UUID")
            .then(|| canonical_uuid(value))
            .flatten()
    })
}

/// Combine the command outputs into the stored fingerprint; `None` if either UUID is missing.
fn fingerprint_from(ioreg: &str, diskutil: &str) -> Option<[u8; 32]> {
    let mut digest = openssl::sha::Sha256::new();
    digest.update(b"infraternal macos mesh machine binding v1\0");
    digest.update(platform_uuid(ioreg)?.as_bytes());
    digest.update(b"\0");
    digest.update(volume_uuid(diskutil)?.as_bytes());
    Some(digest.finish())
}

/// Read both UUIDs from the system tools (absolute paths, no shell, no unsafe).
#[cfg(target_os = "macos")]
pub(crate) fn fingerprint() -> Option<[u8; 32]> {
    use std::process::Command;
    let run = |program: &str, arguments: &[&str]| {
        let output = Command::new(program).args(arguments).output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).ok())
            .flatten()
    };
    fingerprint_from(
        &run("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?,
        &run("/usr/sbin/diskutil", &["info", "/System/Volumes/Data"])?,
    )
}

/// Refuse a state folder whose recorded fingerprint is not `current`.
///
/// No record is accepted only for a folder with no Mesh state (a first start); [`bind`] then
/// records one. Mesh state with no record is refused as unbound.
/// # Errors
/// `PermissionDenied` carrying a [`MachineBindingError`], or the read error of the record.
pub(crate) fn check(state: &Path, current: Option<[u8; 32]>) -> io::Result<()> {
    let record: Option<MachineRecord> = read_public(&state.join(MACHINE_FILE))?;
    let refusal = match (record, current) {
        (None, _) if has_mesh_state(state)? => Some(MachineBindingError::UnboundRecord),
        (Some(_), None) => Some(MachineBindingError::MissingId),
        (Some(saved), Some(now)) if saved.machine != now => {
            Some(MachineBindingError::ForeignMachine)
        }
        _ => None,
    };
    refusal.map_or(Ok(()), |error| {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, error))
    })
}

/// Check the binding and, on a folder that has none, record this Mac's.
/// # Errors
/// As [`check`], plus `MissingId` when the fingerprint is unavailable and refusals of an
/// unsafe state folder.
pub(crate) fn bind(state: &Path, current: Option<[u8; 32]>) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(state)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let machine = current.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            MachineBindingError::MissingId,
        )
    })?;
    check(state, Some(machine))?;
    if !state.join(MACHINE_FILE).exists() {
        let body = serde_json::to_vec(&MachineRecord { machine }).map_err(io::Error::other)?;
        write_public(&state.join(MACHINE_FILE), &body)?;
    }
    Ok(())
}

/// Unit tests with injected `ioreg`/`diskutil` text and temporary state folders.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `ioreg` output of a Mac, as the real tool prints it.
    const IOREG: &str = "+-o Root  <class IORegistryEntry>\n  +-o MacBookAir10,1  <class IOPlatformExpertDevice>\n    {\n      \"IOPlatformSerialNumber\" = \"X\"\n      \"IOPlatformUUID\" = \"e233fdb1-f660-59d3-a7bc-606aaa50a521\"\n    }\n";
    /// `diskutil info` output of its Data volume.
    const DISK: &str = "   Device Identifier:         disk3s5\n   Volume Name:               Data\n   Volume UUID:               64E88BF5-E195-4DA2-80E9-4B92AE21034C\n   Disk / Partition UUID:     11111111-E195-4DA2-80E9-4B92AE21034C\n";

    /// A fresh private (0700) state folder.
    fn state() -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "machine-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    /// The typed binding refusal inside an `io::Error`.
    fn refusal(error: &io::Error) -> &MachineBindingError {
        error.get_ref().unwrap().downcast_ref().unwrap()
    }

    /// Both UUIDs are read, upper-cased, and the partition UUID is not mistaken for the volume UUID.
    #[test]
    fn parses_both_uuids_and_ignores_the_partition_uuid() {
        assert_eq!(
            platform_uuid(IOREG).as_deref(),
            Some("E233FDB1-F660-59D3-A7BC-606AAA50A521")
        );
        assert_eq!(
            volume_uuid(DISK).as_deref(),
            Some("64E88BF5-E195-4DA2-80E9-4B92AE21034C")
        );
    }

    /// Without both UUIDs there is no fingerprint to trust.
    #[test]
    fn a_missing_or_malformed_uuid_gives_no_fingerprint() {
        assert!(fingerprint_from(IOREG, DISK).is_some());
        assert!(fingerprint_from("", DISK).is_none());
        assert!(fingerprint_from(IOREG, "Volume UUID: not-a-uuid").is_none());
        assert!(fingerprint_from(&IOREG.replace("e233fdb1", "zzzzzzzz"), DISK).is_none());
    }

    /// A different Mac or an erased disk gives a different fingerprint.
    #[test]
    fn another_mac_or_a_reinstalled_disk_changes_the_fingerprint() {
        let base = fingerprint_from(IOREG, DISK);
        assert_ne!(base, fingerprint_from(&IOREG.replace("e233", "e234"), DISK));
        assert_ne!(
            base,
            fingerprint_from(IOREG, &DISK.replace("64E88BF5", "64E88BF6"))
        );
        let a = "AAAAAAAA-0000-0000-0000-000000000000";
        let b = "BBBBBBBB-0000-0000-0000-000000000000";
        // The hardware and the volume are not interchangeable.
        assert_ne!(
            fingerprint_from(
                &format!("\"IOPlatformUUID\" = \"{a}\""),
                &format!("Volume UUID: {b}")
            ),
            fingerprint_from(
                &format!("\"IOPlatformUUID\" = \"{b}\""),
                &format!("Volume UUID: {a}")
            ),
        );
    }

    /// The first start records the binding and the same Mac keeps restoring.
    #[test]
    fn the_first_start_records_and_the_same_machine_restores() {
        let dir = state();
        let mine = fingerprint_from(IOREG, DISK);
        bind(&dir, mine).unwrap();
        assert!(dir.join(MACHINE_FILE).exists());
        bind(&dir, mine).unwrap();
        check(&dir, mine).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A folder recorded on another Mac is refused and its record is unchanged.
    #[test]
    fn a_folder_recorded_on_another_mac_is_refused_and_left_untouched() {
        let dir = state();
        bind(&dir, fingerprint_from(IOREG, DISK)).unwrap();
        let before = std::fs::read(dir.join(MACHINE_FILE)).unwrap();
        let other = fingerprint_from(&IOREG.replace("e233", "e234"), DISK);
        for error in [
            bind(&dir, other).unwrap_err(),
            check(&dir, other).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(matches!(
                refusal(&error),
                MachineBindingError::ForeignMachine
            ));
        }
        assert_eq!(std::fs::read(dir.join(MACHINE_FILE)).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Mesh state with no record is refused as unbound, and no record is written.
    #[test]
    fn mesh_state_with_no_binding_record_is_refused_and_left_untouched() {
        for name in MESH_STATE {
            let dir = state();
            std::fs::write(dir.join(name), b"x").unwrap();
            let mine = fingerprint_from(IOREG, DISK);
            for error in [
                bind(&dir, mine).unwrap_err(),
                check(&dir, mine).unwrap_err(),
            ] {
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert!(matches!(
                    refusal(&error),
                    MachineBindingError::UnboundRecord
                ));
            }
            assert!(!dir.join(MACHINE_FILE).exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    /// A folder with other files but no Mesh state (the sessions database, say) is a first start.
    #[test]
    fn a_folder_with_no_mesh_state_is_a_first_start() {
        let dir = state();
        std::fs::write(dir.join("infraternal.sqlite"), b"x").unwrap();
        bind(&dir, fingerprint_from(IOREG, DISK)).unwrap();
        assert!(dir.join(MACHINE_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A reinstall on the same hardware (new volume) is refused like Linux refuses a new machine ID.
    #[test]
    fn a_reinstall_on_the_same_hardware_is_refused() {
        let dir = state();
        bind(&dir, fingerprint_from(IOREG, DISK)).unwrap();
        let erased = fingerprint_from(IOREG, &DISK.replace("64E88BF5", "0A0A0A0A"));
        let error = bind(&dir, erased).unwrap_err();
        assert!(matches!(
            refusal(&error),
            MachineBindingError::ForeignMachine
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// No readable identity is a refusal, never a pass.
    #[test]
    fn an_unreadable_identity_is_refused_rather_than_trusted() {
        let dir = state();
        let error = bind(&dir, None).unwrap_err();
        assert!(matches!(refusal(&error), MachineBindingError::MissingId));
        bind(&dir, fingerprint_from(IOREG, DISK)).unwrap();
        let error = check(&dir, None).unwrap_err();
        assert!(matches!(refusal(&error), MachineBindingError::MissingId));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A state folder open to group or others is refused.
    #[test]
    fn an_exposed_folder_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = state();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = bind(&dir, fingerprint_from(IOREG, DISK)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
