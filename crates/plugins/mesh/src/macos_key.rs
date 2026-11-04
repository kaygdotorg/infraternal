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
//! and read the item (J135's review, #265). A slice-1 key is therefore treated
//! as compromised and is never reused: on the first start without a key file,
//! the old keychain item is deleted unread, a fresh key is generated into the
//! file, and the rotation log asks for re-registration with the coordinator.
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
pub(crate) const ROTATION_LOG: &str = "mesh-key-rotation.log";
/// Present while the slice-1 keychain item may still exist; every start retries until it is gone.
const LEGACY_PENDING: &str = "mesh-legacy-keychain.pending";
const KEY_LENGTH: usize = 32;

/// Why a key that the coordinator knew had to be replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationReason {
    /// A slice-1 keychain key existed; it was exposed to local users and is retired.
    LegacyKeyRetired,
    /// The slice-1 keychain could not be checked, so a slice-1 key may exist;
    /// the node starts with a new key and retries the deletion on later starts.
    LegacyKeyUnconfirmed,
    /// The node was enrolled again (`agent join`, or state bound to another
    /// enrolment), so the key the previous coordinator knew is dropped.
    EnrolmentChanged,
}

impl RotationReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::LegacyKeyRetired => "legacy_keychain_key_retired",
            Self::LegacyKeyUnconfirmed => "legacy_keychain_unconfirmed",
            Self::EnrolmentChanged => "enrolment_changed",
        }
    }
}

/// What retiring the slice-1 keychain item found. Its key is never read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Legacy {
    /// The keychain answered and holds no item: a node that never ran a slice-1 build.
    Absent,
    /// An item existed and was deleted; the node needs a new key.
    Retired,
    /// The keychain could not be opened or the item could not be deleted, so
    /// an exposed slice-1 key may still be there (J162 F5). Never reported as
    /// `Absent`: the node rotates as if an item existed, and later starts retry.
    Pending,
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
    load_or_create_with(state, legacy::retire)
}

/// Delete the key so the next start generates a new one, and log why.
///
/// The rotation log gets a line only when a key existed: removing nothing
/// replaces nothing the coordinator knew.
///
/// # Errors
/// Refuses an exposed state directory and reports a failed removal or log write.
pub fn retire_key(state: &Path, reason: RotationReason) -> io::Result<()> {
    check_directory(state)?;
    match fs::remove_file(state.join(KEY_FILE)) {
        Ok(()) => {
            File::open(state)?.sync_all()?;
            record_rotation(&state.join(ROTATION_LOG), reason)?;
            tracing::warn!(
                reason = reason.as_str(),
                "Removed the Mesh WireGuard key; the next start registers a new one"
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The testable body of [`load_or_create`]; `retire_legacy` deletes the slice-1 item.
///
/// The keychain is consulted when no key file exists (a first start, or after
/// a rotation) and on every start while an earlier deletion is pending.
fn load_or_create_with(
    state: &Path,
    retire_legacy: impl FnOnce() -> Legacy,
) -> io::Result<(StaticSecret, PublicKey)> {
    check_directory(state)?;
    let path = state.join(KEY_FILE);
    let pending = state.join(LEGACY_PENDING);
    if let Some(bytes) = read_key(&path)? {
        if marker_present(&pending)? {
            // The key on disk was generated fresh when the deletion first failed,
            // so a retry only removes the old item; nothing rotates again.
            match retire_legacy() {
                Legacy::Pending => tracing::warn!(
                    "The slice-1 Mesh keychain item still could not be checked or deleted; retrying on the next start"
                ),
                outcome => {
                    clear_marker(state, &pending)?;
                    tracing::warn!(
                        deleted = outcome == Legacy::Retired,
                        "Finished retiring the slice-1 Mesh keychain item"
                    );
                }
            }
        }
        return Ok(identity(&bytes));
    }
    match retire_legacy() {
        Legacy::Absent => clear_marker(state, &pending)?,
        Legacy::Retired => {
            clear_marker(state, &pending)?;
            record_rotation(&state.join(ROTATION_LOG), RotationReason::LegacyKeyRetired)?;
            tracing::warn!(
                "Retired the slice-1 keychain WireGuard key; starting with a new key for coordinator registration"
            );
        }
        Legacy::Pending => {
            // The marker is written before the new key, so a crash in between still retries.
            set_marker(state, &pending)?;
            record_rotation(
                &state.join(ROTATION_LOG),
                RotationReason::LegacyKeyUnconfirmed,
            )?;
            tracing::warn!(
                "The slice-1 Mesh keychain item could not be checked or deleted; starting with a new key and retrying on the next start"
            );
        }
    }
    let fresh = generate()?;
    publish(state, &fresh)?;
    // Another start may have published first; the file on disk is authoritative.
    let bytes = read_key(&path)?.ok_or(io::ErrorKind::NotFound)?;
    Ok(identity(&bytes))
}

/// Whether the pending-retirement marker exists; a marker that is not ours is refused.
fn marker_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if owned_private_file(&metadata) => Ok(true),
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Durably record that the slice-1 item must be retried.
fn set_marker(state: &Path, path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    if !owned_private_file(&file.metadata()?) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    file.sync_all()?;
    File::open(state)?.sync_all()
}

fn clear_marker(state: &Path, path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => File::open(state)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn owned_private_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == Uid::effective().as_raw()
        && metadata.mode() & 0o777 == 0o600
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

/// One-time retirement of the slice-1 keychain item; its key is never read.
mod legacy {
    use super::Legacy;
    use security_framework::{
        item::{ItemClass, ItemSearchOptions},
        os::macos::keychain::SecKeychain,
    };

    const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
    pub(super) const SERVICE: &str = "org.infraternal.mesh";
    pub(super) const ACCOUNT: &str = "wireguard-private-key";
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    /// Delete the slice-1 item from the System keychain.
    pub(super) fn retire() -> Legacy {
        retire_from(std::path::Path::new(SYSTEM_KEYCHAIN))
    }

    /// Delete the slice-1 item from the keychain file at `path`.
    ///
    /// `Absent` needs proof: either no keychain file exists, or a file that is
    /// really a keychain answers "no such item". Security also answers "no
    /// such item" for a damaged file, so the file's signature is checked
    /// first. Every failure (an unreadable or unrecognised file, no
    /// user-interaction guard, the keychain will not open, the deletion is
    /// refused) is `Pending` and logged, so the caller retries.
    pub(super) fn retire_from(path: &std::path::Path) -> Legacy {
        match keychain_signature(path) {
            Ok(None) => return Legacy::Absent,
            Ok(Some(signature)) if signature == *b"kych" => {}
            Ok(Some(_)) => {
                tracing::warn!(
                    "The System keychain is not readable as a keychain; the slice-1 Mesh item was not checked"
                );
                return Legacy::Pending;
            }
            Err(error) => {
                tracing::warn!(%error, "The System keychain could not be read; the slice-1 Mesh item was not checked");
                return Legacy::Pending;
            }
        }
        let _no_interaction = match SecKeychain::disable_user_interaction() {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(
                    code = error.code(),
                    "Keychain user interaction could not be disabled; the slice-1 Mesh item was not checked"
                );
                return Legacy::Pending;
            }
        };
        let mut keychain = match SecKeychain::open(path) {
            Ok(keychain) => keychain,
            Err(error) => {
                tracing::warn!(
                    code = error.code(),
                    "The System keychain could not be opened; the slice-1 Mesh item was not checked"
                );
                return Legacy::Pending;
            }
        };
        // The System keychain may be locked on this host (lock-on-sleep); a
        // null-password unlock uses the system key.
        let _ = keychain.unlock(None);
        match delete_item(&keychain) {
            Ok(true) => Legacy::Retired,
            Ok(false) => Legacy::Absent,
            Err(code) => {
                tracing::warn!(code, "The slice-1 Mesh keychain item could not be deleted");
                Legacy::Pending
            }
        }
    }

    /// The first four bytes of the keychain file, or `None` when there is no file.
    fn keychain_signature(path: &std::path::Path) -> std::io::Result<Option<[u8; 4]>> {
        use std::io::Read as _;
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut signature = [0_u8; 4];
        file.read_exact(&mut signature)?;
        Ok(Some(signature))
    }

    /// Delete exactly the Mesh item from `keychain`; `true` when one existed.
    pub(super) fn delete_item(keychain: &SecKeychain) -> Result<bool, i32> {
        let mut options = ItemSearchOptions::new();
        options
            .keychains(std::slice::from_ref(keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT);
        match options.delete() {
            Ok(()) => Ok(true),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(error.code()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{
        KEY_FILE, LEGACY_PENDING, Legacy, ROTATION_LOG, RotationReason, legacy,
        load_or_create_with, retire_key,
    };
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };
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

    /// The orchestrator's decision on #265: a slice-1 key is compromised and is never reused.
    #[test]
    fn a_slice_one_keychain_key_is_retired_and_a_fresh_key_is_generated() {
        let state = state();
        let mut retired = 0;
        let (_, public) = load_or_create_with(&state.0, || {
            retired += 1;
            Legacy::Retired
        })
        .expect("new key");
        assert_eq!(retired, 1, "the slice-1 item is retired once");
        let log = fs::read_to_string(state.0.join(ROTATION_LOG)).expect("rotation log");
        assert_eq!(log.lines().count(), 1);
        assert!(log.contains("event=mesh_key_rotation"));
        assert!(log.contains("reason=legacy_keychain_key_retired"));
        assert!(log.contains("action=register_with_coordinator"));
        let hex = public.0.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert!(!log.contains(&hex), "the log carries no key material");
        assert_eq!(
            fs::metadata(state.0.join(ROTATION_LOG))
                .expect("log metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // The fresh key is the one kept; later starts neither retire nor rotate again.
        let (_, again) = load_or_create_with(&state.0, never).expect("reuse fresh key");
        assert_eq!(public, again);
        assert_eq!(
            fs::read_to_string(state.0.join(ROTATION_LOG))
                .expect("rotation log")
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn a_node_without_a_slice_one_item_records_no_rotation() {
        let state = state();
        load_or_create_with(&state.0, || Legacy::Absent).expect("create key");
        assert!(!state.0.join(ROTATION_LOG).exists());
    }

    #[test]
    fn retiring_deletes_exactly_the_mesh_item_without_reading_it() {
        use security_framework::os::macos::keychain::CreateOptions;
        const PASSWORD: &str = "j80d-test-only-keychain-password";
        let state = state();
        let mut keychain = CreateOptions::new()
            .password(PASSWORD)
            .create(state.0.join("retire-test.keychain"))
            .expect("create temporary file keychain");
        keychain
            .unlock(Some(PASSWORD))
            .expect("unlock temporary keychain");
        keychain
            .add_generic_password(legacy::SERVICE, legacy::ACCOUNT, &[7_u8; 32])
            .expect("add slice-1 item");
        keychain
            .add_generic_password("org.infraternal.mesh.unrelated-test", "keep-me", b"keep")
            .expect("add unrelated item");

        assert_eq!(legacy::delete_item(&keychain), Ok(true));
        assert_eq!(
            keychain
                .find_generic_password(legacy::SERVICE, legacy::ACCOUNT)
                .map(|_| ())
                .expect_err("the slice-1 item is gone")
                .code(),
            -25300
        );
        let (kept, _) = keychain
            .find_generic_password("org.infraternal.mesh.unrelated-test", "keep-me")
            .expect("the unrelated item stays");
        assert_eq!(kept.as_ref(), b"keep");
        assert_eq!(
            legacy::delete_item(&keychain),
            Ok(false),
            "a second retire finds nothing"
        );

        // The whole path a start takes, against a real keychain file.
        keychain
            .add_generic_password(legacy::SERVICE, legacy::ACCOUNT, &[7_u8; 32])
            .expect("add slice-1 item again");
        let file = fs::read_dir(&state.0)
            .expect("list state")
            .map(|entry| entry.expect("entry").path())
            .find(|path| path.to_string_lossy().contains("retire-test.keychain"))
            .expect("keychain file");
        assert_eq!(legacy::retire_from(&file), Legacy::Retired);
        assert_eq!(legacy::retire_from(&file), Legacy::Absent);
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
        retire_key(&state.0, RotationReason::EnrolmentChanged).expect("remove key");
        retire_key(&state.0, RotationReason::EnrolmentChanged)
            .expect("removing an absent key succeeds");
        assert_eq!(
            reasons(&state),
            ["enrolment_changed"],
            "only a real removal is logged"
        );
        let (_, second) = load_or_create_with(&state.0, || Legacy::Absent).expect("new key");
        assert_ne!(first, second);
    }

    fn reasons(state: &TestDirectory) -> Vec<String> {
        fs::read_to_string(state.0.join(ROTATION_LOG))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("reason="))
            })
            .map(str::to_owned)
            .collect()
    }

    /// J162 F5: a keychain that cannot be checked is never taken as "no item".
    #[test]
    fn an_unchecked_keychain_rotates_and_is_retried_until_it_answers() {
        let state = state();
        let (_, public) = load_or_create_with(&state.0, || Legacy::Pending).expect("new key");
        assert_eq!(reasons(&state), ["legacy_keychain_unconfirmed"]);
        let marker = state.0.join(LEGACY_PENDING);
        assert_eq!(
            fs::metadata(&marker).expect("marker").permissions().mode() & 0o777,
            0o600
        );

        // Still unreachable: retried, the key is kept and nothing rotates again.
        let mut calls = 0;
        let (_, again) = load_or_create_with(&state.0, || {
            calls += 1;
            Legacy::Pending
        })
        .expect("reuse key");
        assert_eq!((calls, again), (1, public));
        assert!(marker.exists());

        // The keychain answers: the item is deleted, the marker goes, the key stays.
        let (_, after) = load_or_create_with(&state.0, || Legacy::Retired).expect("retry");
        assert_eq!(after, public);
        assert!(!marker.exists());
        assert_eq!(reasons(&state), ["legacy_keychain_unconfirmed"]);
        // Done: later starts do not consult the keychain.
        load_or_create_with(&state.0, never).expect("no more retries");
    }

    #[test]
    fn a_pending_retirement_ends_when_the_keychain_reports_no_item() {
        let state = state();
        load_or_create_with(&state.0, || Legacy::Pending).expect("new key");
        load_or_create_with(&state.0, || Legacy::Absent).expect("retry");
        assert!(!state.0.join(LEGACY_PENDING).exists());
        load_or_create_with(&state.0, never).expect("no more retries");
    }

    /// Security answers "no such item" for a damaged file; that must not read as `Absent`.
    #[test]
    fn a_keychain_that_cannot_be_read_is_pending_not_absent() {
        let state = state();
        let path = state.0.join("damaged.keychain");
        fs::write(&path, b"not a keychain").expect("write damaged keychain");
        assert_eq!(legacy::retire_from(&path), Legacy::Pending);
        fs::write(&path, b"").expect("truncate keychain");
        assert_eq!(legacy::retire_from(&path), Legacy::Pending);
        assert_eq!(
            legacy::retire_from(&state.0.join("no-such.keychain")),
            Legacy::Absent,
            "without a keychain file no slice-1 item can exist"
        );
    }
}
