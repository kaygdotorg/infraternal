//! Owns the Mac node's `WireGuard` private key as a root-only file (#265).
//!
//! The key lives in `mesh-wireguard.key` (32 raw bytes, mode `0600`, owned by
//! root) inside the root-only `0700` state directory, next to
//! `mesh-public.json`. The trust boundary is the file system: only root can
//! search the directory, so no other local account can open the file, whatever
//! code it runs. The agent's mTLS identity, `identity.json`, which is the
//! stronger credential, already uses the same boundary.
//!
//! Slice-1 builds kept the key in the System keychain. That store was given up
//! because a keychain item's ACL trusts a code identity, not a uid: any local
//! user could run the world-executable daemon binary with an injected library
//! and read the item (J135's review, #265). A key that is still in the keychain
//! is moved into the file once, and the item is deleted before the file is
//! published, so it never stays readable that way. A rebuilt ad-hoc daemon may
//! be refused by the old item's ACL. It then deletes the item and starts with a
//! new key, and the rotation log asks for re-registration with the coordinator.
//!
//! Neither the CLI nor a UI process reads the private key: callers must be root,
//! and the key never reaches JSON state, argv or logs.

use crate::policy::model::PublicKey;
use gotatun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use nix::unistd::Uid;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// File name of the private key inside the node's state directory.
pub const KEY_FILE: &str = "mesh-wireguard.key";
const ROTATION_LOG: &str = "mesh-key-rotation.log";
const KEY_LENGTH: usize = 32;

/// Why a key that the coordinator knew had to be replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RotationReason {
    /// The keychain item from an earlier build refused this build.
    LegacyAccessDenied,
}

impl RotationReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::LegacyAccessDenied => "legacy_keychain_access_denied",
        }
    }
}

/// What the one-time keychain migration found.
pub(crate) enum Legacy {
    /// No item exists: the normal state after the first start of this build.
    Absent,
    /// The item was read and deleted; its key must be published now.
    Moved(Zeroizing<[u8; KEY_LENGTH]>),
    /// The item existed but refused this build, and it was deleted.
    Denied,
}

/// Load the node's key from `state`, creating it on the first start.
///
/// # Errors
/// Refuses non-root callers, an exposed state directory or key file, a key of
/// the wrong length, and failed durable writes.
pub fn load_or_create(state: &Path) -> io::Result<(StaticSecret, PublicKey)> {
    if !Uid::effective().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mesh key access requires the system service.",
        ));
    }
    load_or_create_with(state, legacy::take)
}

/// Delete the key so the next start generates a new one (`agent join`).
///
/// # Errors
/// Refuses an exposed state directory and reports a failed removal.
pub fn remove(state: &Path) -> io::Result<()> {
    check_directory(state)?;
    match fs::remove_file(state.join(KEY_FILE)) {
        Ok(()) => File::open(state)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The testable body of [`load_or_create`]; `take_legacy` performs the migration.
fn load_or_create_with(
    state: &Path,
    take_legacy: impl FnOnce() -> Legacy,
) -> io::Result<(StaticSecret, PublicKey)> {
    check_directory(state)?;
    let path = state.join(KEY_FILE);
    if let Some(bytes) = read_key(&path)? {
        return Ok(identity(&bytes));
    }
    let bytes = match take_legacy() {
        Legacy::Moved(bytes) => bytes,
        Legacy::Absent => generate()?,
        Legacy::Denied => {
            record_rotation(
                &state.join(ROTATION_LOG),
                RotationReason::LegacyAccessDenied,
            )?;
            tracing::warn!(
                "The keychain item from an earlier build refused this daemon; starting with a new WireGuard key for coordinator registration"
            );
            generate()?
        }
    };
    publish(state, &bytes)?;
    // Another start may have published first; the file on disk is authoritative.
    let bytes = read_key(&path)?.ok_or(io::ErrorKind::NotFound)?;
    Ok(identity(&bytes))
}

/// The state directory must be a real directory owned by us and closed to everyone else.
fn check_directory(state: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(state)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// Read the key without following links; refuse a file anyone else could have touched.
fn read_key(path: &Path) -> io::Result<Option<Zeroizing<[u8; KEY_LENGTH]>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if metadata.len() != KEY_LENGTH as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stored Mesh key is invalid.",
        ));
    }
    let mut bytes = Zeroizing::new([0_u8; KEY_LENGTH]);
    file.read_exact(&mut *bytes)?;
    Ok(Some(bytes))
}

/// Publish a new key with no-replace semantics so concurrent starts agree on one key.
fn publish(state: &Path, bytes: &[u8; KEY_LENGTH]) -> io::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let pending = state.join(format!(".{KEY_FILE}.{}.{nonce}.new", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&pending, state.join(KEY_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        File::open(state)?.sync_all()
    })();
    let _ = fs::remove_file(&pending);
    result
}

fn generate() -> io::Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let mut bytes = Zeroizing::new([0_u8; KEY_LENGTH]);
    openssl::rand::rand_bytes(&mut *bytes)
        .map_err(|_| io::Error::other("System random generator unavailable."))?;
    Ok(bytes)
}

fn identity(bytes: &[u8; KEY_LENGTH]) -> (StaticSecret, PublicKey) {
    // `StaticSecret::from` takes the array by value, so one temporary copy is
    // unavoidable with this API; the secret itself zeroizes on drop.
    let secret = StaticSecret::from(*bytes);
    let public = X25519PublicKey::from(&secret);
    (secret, PublicKey(*public.as_bytes()))
}

/// Append one root-only line saying the coordinator must learn a new key; never key material.
fn record_rotation(path: &Path, reason: RotationReason) -> io::Result<()> {
    let uid = Uid::effective().as_raw();
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o777 == 0o600 => {}
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o600 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    writeln!(
        file,
        "unix_time={unix_time} event=mesh_key_rotation reason={} action=register_with_coordinator",
        reason.as_str()
    )?;
    file.sync_data()
}

/// One-time move of a slice-1 key out of the System keychain.
mod legacy {
    use super::{KEY_LENGTH, Legacy};
    use security_framework::{
        item::{ItemClass, ItemSearchOptions},
        os::macos::keychain::SecKeychain,
    };
    use zeroize::Zeroizing;

    const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
    const SERVICE: &str = "org.infraternal.mesh";
    const ACCOUNT: &str = "wireguard-private-key";
    const ERR_SEC_AUTH_FAILED: i32 = -25293;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    /// Read and delete the old item. Runs only while no key file exists.
    ///
    /// The item is deleted before the caller publishes the file. A crash in
    /// between loses the key and the node re-registers a new one; it never
    /// leaves the key in a store that other local users can reach.
    ///
    /// Security returns the secret in a buffer it allocates and frees; zeroing
    /// it would need unsafe code, which this workspace forbids. That copy
    /// exists once, during this migration, and our own copy is zeroized.
    pub(super) fn take() -> Legacy {
        let Ok(_no_interaction) = SecKeychain::disable_user_interaction() else {
            return Legacy::Absent;
        };
        let Ok(mut keychain) = SecKeychain::open(SYSTEM_KEYCHAIN) else {
            return Legacy::Absent;
        };
        // The System keychain may be locked on this host (lock-on-sleep); a
        // null-password unlock uses the system key.
        let _ = keychain.unlock(None);
        let found = keychain.find_generic_password(SERVICE, ACCOUNT);
        let outcome = match found {
            Ok((password, _item)) => {
                let password = password.as_ref();
                if password.len() == KEY_LENGTH {
                    let mut bytes = Zeroizing::new([0_u8; KEY_LENGTH]);
                    bytes.copy_from_slice(password);
                    Legacy::Moved(bytes)
                } else {
                    Legacy::Denied
                }
            }
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Legacy::Absent,
            Err(error)
                if matches!(
                    error.code(),
                    ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED
                ) =>
            {
                Legacy::Denied
            }
            // Any other failure: the keychain is unusable, so there is nothing to move.
            Err(_) => return Legacy::Absent,
        };
        let mut options = ItemSearchOptions::new();
        options
            .keychains(std::slice::from_ref(&keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT);
        if let Err(error) = options.delete()
            && error.code() != ERR_SEC_ITEM_NOT_FOUND
        {
            tracing::warn!(
                code = error.code(),
                "The old Mesh keychain item could not be deleted"
            );
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{KEY_FILE, Legacy, ROTATION_LOG, load_or_create_with, remove};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };
    use zeroize::Zeroizing;

    struct TestDirectory(PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn state() -> TestDirectory {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "infraternal-mesh-key-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create state directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("restrict state");
        TestDirectory(path)
    }

    fn never() -> Legacy {
        panic!("the keychain must not be consulted once a key file exists")
    }

    #[test]
    fn first_start_creates_a_root_only_key_file_and_later_starts_reuse_it() {
        let state = state();
        let (_, first) = load_or_create_with(&state.0, || Legacy::Absent).expect("create key");
        let path = state.0.join(KEY_FILE);
        let metadata = fs::metadata(&path).expect("key file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 32);
        let (_, second) = load_or_create_with(&state.0, never).expect("reuse key");
        assert_eq!(first, second);
        assert!(
            fs::read_dir(&state.0)
                .expect("list state")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".new")),
            "no temporary key file is left behind"
        );
    }

    #[test]
    fn a_keychain_key_is_moved_into_the_file_once() {
        let state = state();
        let legacy = [7_u8; 32];
        let (_, migrated) = load_or_create_with(&state.0, || Legacy::Moved(Zeroizing::new(legacy)))
            .expect("migrate key");
        assert_eq!(fs::read(state.0.join(KEY_FILE)).expect("key"), legacy);
        let (_, again) = load_or_create_with(&state.0, never).expect("read migrated key");
        assert_eq!(migrated, again);
        assert!(!state.0.join(ROTATION_LOG).exists());
    }

    #[test]
    fn a_refused_keychain_item_records_a_rotation_without_key_material() {
        let state = state();
        let (_, public) = load_or_create_with(&state.0, || Legacy::Denied).expect("new key");
        let log = fs::read_to_string(state.0.join(ROTATION_LOG)).expect("rotation log");
        assert!(log.contains("event=mesh_key_rotation"));
        assert!(log.contains("reason=legacy_keychain_access_denied"));
        assert!(log.contains("action=register_with_coordinator"));
        let hex = public.0.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert!(!log.contains(&hex));
        assert_eq!(
            fs::metadata(state.0.join(ROTATION_LOG))
                .expect("log metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn an_exposed_state_directory_or_key_file_is_refused() {
        let state = state();
        fs::set_permissions(&state.0, fs::Permissions::from_mode(0o755)).expect("open state");
        assert!(load_or_create_with(&state.0, || Legacy::Absent).is_err());
        fs::set_permissions(&state.0, fs::Permissions::from_mode(0o700)).expect("close state");

        load_or_create_with(&state.0, || Legacy::Absent).expect("create key");
        let path = state.0.join(KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("expose key");
        assert_eq!(
            load_or_create_with(&state.0, never)
                .map(|_| ())
                .expect_err("a readable key file is refused")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn a_linked_or_truncated_key_file_is_refused() {
        let state = state();
        let elsewhere = state.0.join("elsewhere");
        fs::write(&elsewhere, [1_u8; 32]).expect("write target");
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).expect("mode");
        symlink(&elsewhere, state.0.join(KEY_FILE)).expect("link key");
        assert!(load_or_create_with(&state.0, never).is_err());

        fs::remove_file(state.0.join(KEY_FILE)).expect("remove link");
        fs::write(state.0.join(KEY_FILE), [1_u8; 31]).expect("short key");
        fs::set_permissions(state.0.join(KEY_FILE), fs::Permissions::from_mode(0o600))
            .expect("mode");
        assert_eq!(
            load_or_create_with(&state.0, never)
                .map(|_| ())
                .expect_err("a short key is refused")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn removing_the_key_makes_the_next_start_generate_a_new_one() {
        let state = state();
        let (_, first) = load_or_create_with(&state.0, || Legacy::Absent).expect("create key");
        remove(&state.0).expect("remove key");
        remove(&state.0).expect("removing an absent key succeeds");
        let (_, second) = load_or_create_with(&state.0, || Legacy::Absent).expect("new key");
        assert_ne!(first, second);
    }
}
