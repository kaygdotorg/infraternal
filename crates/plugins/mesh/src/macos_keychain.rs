//! Owns the Mesh WireGuard identity in the explicitly selected System keychain.
//!
//! Only the root `org.infraternal.mesh` LaunchDaemon may access the item. It
//! unlocks this explicit keychain with `SecKeychainUnlock`'s null-password
//! SystemKey semantics before each operation and retries once after a locked-
//! keychain status. A new item is added by the root LaunchDaemon so Security
//! creates its creator-application ACL atomically with the secret. For a signed
//! daemon, that trust is its designated code requirement (signing identifier
//! and Team ID), which survives builds with different CDHashes. Do not add a
//! later ACL metadata update: it can require interaction and is not needed for
//! creation. Ad-hoc builds have no stable Team ID and their requirement is
//! build-specific; after access is still denied, the daemon deletes only this
//! service/account item, creates a replacement, and logs that its new public
//! identity must be registered with the coordinator. Neither the CLI nor a UI
//! process reads the private key. This path never changes the keychain search
//! list or lock policy.

use crate::policy::model::PublicKey;
use gotatun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use nix::unistd::Uid;
use security_framework::{
    base::Error as SecurityError,
    item::{ItemClass, ItemSearchOptions},
    os::macos::keychain::SecKeychain,
    random::SecRandom,
};
use std::{
    io,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const SERVICE: &str = "org.infraternal.mesh";
const ACCOUNT: &str = "wireguard-private-key";
const LAUNCHD_SERVICE_LABEL: &str = "org.infraternal.mesh";
#[cfg(test)]
const TEST_LAUNCHD_SERVICE_LABEL: &str = "org.infraternal.mesh.keychain-upgrade-test";
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[derive(Debug, Eq, PartialEq)]
enum CodeSigningIdentity {
    Stable { identifier: String, team_id: String },
    AdHoc,
    Unknown,
}

#[derive(Debug)]
enum KeychainOperationError {
    Io(io::Error),
    Security(SecurityError),
}

impl From<io::Error> for KeychainOperationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl KeychainOperationError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Io(error) => error,
            Self::Security(error) => map_keychain_error(error),
        }
    }
}

/// Load the persistent private identity, creating it once when this node first starts.
///
/// The keychain path is explicit: this service never consults or changes a user's
/// search list. The returned public key is safe to put in the node's public state.
/// # Errors
/// Refuses non-root callers, malformed stored keys and unavailable keychain access.
pub(crate) fn load_or_create() -> io::Result<(StaticSecret, PublicKey)> {
    let launchd_label = std::env::var("XPC_SERVICE_NAME").ok();
    if !system_service_context(Uid::effective().as_raw(), launchd_label.as_deref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mesh key access requires the system service.",
        ));
    }
    let _no_user_interaction = SecKeychain::disable_user_interaction().map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "System keychain unavailable.",
        )
    })?;
    unlock_system_keychain()?;
    let keychain = SecKeychain::open(SYSTEM_KEYCHAIN).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "System keychain unavailable.",
        )
    })?;
    match read_key(&keychain) {
        Ok(identity) => Ok(identity),
        Err(KeychainOperationError::Security(error)) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {
            create_key(&keychain).map_err(KeychainOperationError::into_io)
        }
        Err(KeychainOperationError::Security(error))
            if should_rotate_after_access_denied(error.code(), &current_signing_identity()) =>
        {
            tracing::warn!(
                service = SERVICE,
                account = ACCOUNT,
                "System Keychain access was denied for an ad-hoc daemon; rotating its WireGuard identity for coordinator registration"
            );
            delete_exact_item(&keychain)?;
            create_key(&keychain).map_err(KeychainOperationError::into_io)
        }
        Err(KeychainOperationError::Security(error)) => Err(map_keychain_error(error)),
        Err(KeychainOperationError::Io(error)) => Err(error),
    }
}

fn system_service_context(effective_uid: u32, launchd_label: Option<&str>) -> bool {
    let is_system_service = launchd_label == Some(LAUNCHD_SERVICE_LABEL);
    #[cfg(test)]
    let is_system_service = is_system_service || launchd_label == Some(TEST_LAUNCHD_SERVICE_LABEL);
    effective_uid == 0 && is_system_service
}

fn read_key(keychain: &SecKeychain) -> Result<(StaticSecret, PublicKey), KeychainOperationError> {
    let (password, _item) = with_unlocked_keychain(
        || keychain.find_generic_password(SERVICE, ACCOUNT),
        unlock_system_keychain,
    )?;
    let password = password.as_ref();
    if password.len() != 32 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "Stored Mesh key is invalid.").into(),
        );
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(password);
    Ok(public_identity(StaticSecret::from(*bytes)))
}

fn create_key(keychain: &SecKeychain) -> Result<(StaticSecret, PublicKey), KeychainOperationError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    SecRandom::default()
        .copy_bytes(&mut *bytes)
        .map_err(|_| io::Error::other("System random generator unavailable."))?;
    let secret = StaticSecret::from(*bytes);
    match with_unlocked_keychain(
        // Security derives the item ACL from this creator process at insertion.
        // A stable signing requirement therefore follows the daemon identity
        // across upgrades; ad-hoc builds use the explicit rotation path above.
        || keychain.add_generic_password(SERVICE, ACCOUNT, &*bytes),
        unlock_system_keychain,
    ) {
        Ok(()) => Ok(public_identity(secret)),
        Err(KeychainOperationError::Security(error)) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
            read_key(keychain)
        }
        Err(error) => Err(error),
    }
}

fn unlock_system_keychain() -> io::Result<()> {
    let mut keychain = SecKeychain::open(SYSTEM_KEYCHAIN).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "System keychain unavailable.",
        )
    })?;
    keychain.unlock(None).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "System keychain unlock failed.",
        )
    })
}

fn with_unlocked_keychain<T, Access, Unlock>(
    mut access: Access,
    mut unlock: Unlock,
) -> Result<T, KeychainOperationError>
where
    Access: FnMut() -> security_framework::base::Result<T>,
    Unlock: FnMut() -> io::Result<()>,
{
    unlock().map_err(KeychainOperationError::Io)?;
    match access() {
        Ok(value) => Ok(value),
        Err(error) if needs_unlock_retry(error.code()) => {
            unlock().map_err(KeychainOperationError::Io)?;
            access().map_err(KeychainOperationError::Security)
        }
        Err(error) => Err(KeychainOperationError::Security(error)),
    }
}

fn needs_unlock_retry(code: i32) -> bool {
    matches!(code, ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED)
}

fn parse_signing_identity(details: &str) -> CodeSigningIdentity {
    let field = |name: &str| {
        details
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let signature = field("Signature=");
    let team_id = field("TeamIdentifier=");
    if signature == Some("adhoc") || team_id == Some("not set") {
        return CodeSigningIdentity::AdHoc;
    }
    match (field("Identifier="), team_id) {
        (Some(identifier), Some(team_id)) if !identifier.is_empty() && !team_id.is_empty() => {
            CodeSigningIdentity::Stable {
                identifier: identifier.to_owned(),
                team_id: team_id.to_owned(),
            }
        }
        _ => CodeSigningIdentity::Unknown,
    }
}

fn current_signing_identity() -> CodeSigningIdentity {
    let Ok(executable) = std::env::current_exe() else {
        return CodeSigningIdentity::Unknown;
    };
    let Ok(output) = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(executable)
        .stdin(Stdio::null())
        .output()
    else {
        return CodeSigningIdentity::Unknown;
    };
    if !output.status.success() {
        return CodeSigningIdentity::Unknown;
    }
    let details = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_signing_identity(&details)
}

fn should_rotate_after_access_denied(code: i32, identity: &CodeSigningIdentity) -> bool {
    needs_unlock_retry(code) && matches!(identity, CodeSigningIdentity::AdHoc)
}

fn delete_exact_item(keychain: &SecKeychain) -> io::Result<()> {
    delete_exact_item_from_keychain(keychain, unlock_system_keychain)
}

fn delete_exact_item_from_keychain(
    keychain: &SecKeychain,
    unlock: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut options = ItemSearchOptions::new();
    options
        .keychains(std::slice::from_ref(keychain))
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .account(ACCOUNT);
    match with_unlocked_keychain(|| options.delete(), unlock) {
        Ok(()) => Ok(()),
        Err(KeychainOperationError::Security(error)) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {
            Ok(())
        }
        Err(error) => Err(error.into_io()),
    }
}

fn map_keychain_error(error: SecurityError) -> io::Error {
    let kind = match error.code() {
        ERR_SEC_ITEM_NOT_FOUND => io::ErrorKind::NotFound,
        ERR_SEC_DUPLICATE_ITEM => io::ErrorKind::AlreadyExists,
        _ => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(
        kind,
        format!("System keychain operation failed ({})", error.code()),
    )
}

fn public_identity(secret: StaticSecret) -> (StaticSecret, PublicKey) {
    let public = X25519PublicKey::from(&secret);
    (secret, PublicKey(*public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{
        ACCOUNT, CodeSigningIdentity, ERR_SEC_AUTH_FAILED, ERR_SEC_INTERACTION_NOT_ALLOWED,
        ERR_SEC_ITEM_NOT_FOUND, SERVICE, parse_signing_identity, should_rotate_after_access_denied,
        system_service_context, with_unlocked_keychain,
    };
    use security_framework::{base::Error as SecurityError, os::macos::keychain::CreateOptions};

    #[test]
    fn system_keychain_access_is_bound_to_the_root_mesh_launch_daemon() {
        assert!(system_service_context(0, Some("org.infraternal.mesh")));
        assert!(system_service_context(
            0,
            Some("org.infraternal.mesh.keychain-upgrade-test")
        ));
        assert!(!system_service_context(501, Some("org.infraternal.mesh")));
        assert!(!system_service_context(0, None));
        assert!(!system_service_context(0, Some("other.service")));
    }

    #[test]
    fn locked_system_keychain_is_unlocked_and_retried_once() {
        for status in [ERR_SEC_AUTH_FAILED, ERR_SEC_INTERACTION_NOT_ALLOWED] {
            let mut accesses = 0;
            let mut unlocks = 0;
            let value = with_unlocked_keychain(
                || {
                    accesses += 1;
                    if accesses == 1 {
                        Err(SecurityError::from_code(status))
                    } else {
                        Ok("mesh identity")
                    }
                },
                || {
                    unlocks += 1;
                    Ok(())
                },
            )
            .expect("one unlock should recover a locked System keychain");

            assert_eq!(value, "mesh identity");
            assert_eq!(accesses, 2);
            assert_eq!(unlocks, 2);
        }
    }

    #[test]
    fn unrelated_keychain_errors_are_not_retried() {
        let mut accesses = 0;
        let mut unlocks = 0;
        let result = with_unlocked_keychain::<(), _, _>(
            || {
                accesses += 1;
                Err(SecurityError::from_code(-50))
            },
            || {
                unlocks += 1;
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(accesses, 1);
        assert_eq!(unlocks, 1);
    }

    #[test]
    fn locked_keychain_gets_only_one_retry() {
        let mut accesses = 0;
        let mut unlocks = 0;
        let result = with_unlocked_keychain::<(), _, _>(
            || {
                accesses += 1;
                Err(SecurityError::from_code(ERR_SEC_AUTH_FAILED))
            },
            || {
                unlocks += 1;
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(accesses, 2);
        assert_eq!(unlocks, 2);
    }

    #[test]
    fn a_signed_upgrade_keeps_the_designated_identity_when_its_cdhash_changes() {
        let first = parse_signing_identity(
            "Identifier=org.infraternal.mesh\nCDHash=old-cdhash\nTeamIdentifier=TEAM123456\n",
        );
        let rebuilt = parse_signing_identity(
            "Identifier=org.infraternal.mesh\nCDHash=new-cdhash\nTeamIdentifier=TEAM123456\n",
        );

        assert_eq!(
            first,
            CodeSigningIdentity::Stable {
                identifier: "org.infraternal.mesh".to_owned(),
                team_id: "TEAM123456".to_owned(),
            }
        );
        assert_eq!(first, rebuilt);
    }

    #[test]
    fn only_an_ad_hoc_build_rotates_after_a_keychain_access_denial() {
        let ad_hoc = parse_signing_identity(
            "Identifier=infraternal-build-hash\nSignature=adhoc\nTeamIdentifier=not set\n",
        );
        let signed =
            parse_signing_identity("Identifier=org.infraternal.mesh\nTeamIdentifier=TEAM123456\n");

        assert!(should_rotate_after_access_denied(
            ERR_SEC_AUTH_FAILED,
            &ad_hoc
        ));
        assert!(should_rotate_after_access_denied(
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            &ad_hoc
        ));
        assert!(!should_rotate_after_access_denied(
            ERR_SEC_AUTH_FAILED,
            &signed
        ));
        assert!(!should_rotate_after_access_denied(-50, &ad_hoc));
        assert!(!should_rotate_after_access_denied(
            ERR_SEC_AUTH_FAILED,
            &CodeSigningIdentity::Unknown
        ));
    }

    #[test]
    fn exact_item_rotation_preserves_unrelated_items_in_the_selected_keychain() {
        const TEST_KEYCHAIN_PASSWORD: &str = "j80-test-only-keychain-password";
        const OTHER_SERVICE: &str = "org.infraternal.mesh.unrelated-test";
        const OTHER_ACCOUNT: &str = "preserve-me";
        const OTHER_VALUE: &[u8] = b"unrelated test item";

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "infraternal-mesh-keychain-delete-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create private temporary directory");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restrict temporary directory permissions");
        struct RemoveTemporaryDirectory(std::path::PathBuf);
        impl Drop for RemoveTemporaryDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _remove_directory = RemoveTemporaryDirectory(directory.clone());
        let keychain_path = directory.join("rotation-test.keychain");
        let mut keychain = CreateOptions::new()
            .password(TEST_KEYCHAIN_PASSWORD)
            .create(&keychain_path)
            .expect("create temporary file keychain");
        keychain
            .unlock(Some(TEST_KEYCHAIN_PASSWORD))
            .expect("unlock temporary file keychain");
        keychain
            .add_generic_password(SERVICE, ACCOUNT, b"temporary J80 identity")
            .expect("add target item");
        keychain
            .add_generic_password(OTHER_SERVICE, OTHER_ACCOUNT, OTHER_VALUE)
            .expect("add unrelated item");

        let mut unlock_keychain = keychain.clone();
        super::delete_exact_item_from_keychain(&keychain, || {
            unlock_keychain
                .unlock(Some(TEST_KEYCHAIN_PASSWORD))
                .map_err(super::map_keychain_error)
        })
        .expect("delete exact item from selected keychain");

        match keychain.find_generic_password(SERVICE, ACCOUNT) {
            Err(error) => assert_eq!(error.code(), ERR_SEC_ITEM_NOT_FOUND),
            Ok(_) => panic!("exact J80 item remains after rotation"),
        }
        let (preserved, unrelated) = keychain
            .find_generic_password(OTHER_SERVICE, OTHER_ACCOUNT)
            .expect("unrelated item remains");
        assert_eq!(preserved.as_ref(), OTHER_VALUE);
        unrelated.delete();
    }

    #[test]
    #[ignore = "run through the disposable root LaunchDaemon upgrade fixture"]
    fn signed_launch_daemon_reads_the_same_key_across_rebuilds() {
        if std::env::var_os("J80_ROTATE_TEST_KEY").is_some() {
            let keychain = super::SecKeychain::open(super::SYSTEM_KEYCHAIN)
                .expect("open explicit System Keychain");
            super::delete_exact_item(&keychain).expect("remove only the J80 test key");
        }
        let (_private_key, public_key) = super::load_or_create().expect("read System keychain key");
        let actual = public_key.0.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("write public key hex");
            hex
        });

        if let Ok(expected) = std::env::var("J80_EXPECT_PUBLIC_KEY") {
            assert_eq!(
                actual, expected,
                "the rebuilt daemon read a different Mesh key"
            );
        }
        println!("J80_PUBLIC_KEY={actual}");
    }
}
