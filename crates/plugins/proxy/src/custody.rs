//! Keeps DNS provider credentials in interim owner-only node files; node-key sealing or `OpenBao` can replace this implementation without changing callers [#281, #289].

use nix::fcntl::{Flock, FlockArg};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const SECRET_DIRECTORY: &str = "proxy-secrets";
const SECRET_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// A credential whose bytes are cleared when the caller releases it.
pub struct SecretToken(Zeroizing<Vec<u8>>);

impl SecretToken {
    /// Take ownership of provider secret bytes without making them printable.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        f.write_str("SecretToken([REDACTED])")
    }
}

/// Storage boundary for provider tokens; callers receive paths, never token values.
pub trait DnsTokenCustody {
    /// Store a provider credential if it does not already exist.
    ///
    /// # Errors
    /// Returns an I/O error when the provider identity or owner-only store is invalid.
    fn put(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf>;
    /// Return the checked path to a stored provider credential.
    ///
    /// # Errors
    /// Returns an I/O error when the provider identity or credential file is invalid.
    fn get(&self, provider: &str, name: &str) -> io::Result<PathBuf>;
    /// Atomically replace one provider credential.
    ///
    /// # Errors
    /// Returns an I/O error when the provider identity or credential file is invalid.
    fn rotate(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf>;
    /// Remove every credential associated with a DNS provider.
    ///
    /// # Errors
    /// Returns an I/O error when the provider directory is unsafe or cannot be removed.
    fn delete(&self, provider: &str) -> io::Result<()>;
}

/// Interim file-backed custody; callers depend on the trait so later sealing stays behind this boundary.
pub struct FileDnsTokenCustody {
    root: PathBuf,
}

impl FileDnsTokenCustody {
    /// Open the private proxy secret directory beneath an owner-only infraternal state directory.
    ///
    /// # Errors
    /// Returns an I/O error when the state directory or private custody directory is unsafe.
    pub fn open(state: &Path) -> io::Result<Self> {
        validate_directory(state, PRIVATE_DIRECTORY_MODE)?;
        let root = state.join(SECRET_DIRECTORY);
        ensure_private_directory(&root)?;
        Ok(Self { root })
    }

    fn provider_directory(&self, provider: &str, create: bool) -> io::Result<PathBuf> {
        validate_provider(provider)?;
        let directory = self.root.join(provider);
        if create {
            ensure_private_directory(&directory)?;
        } else {
            validate_directory(&directory, PRIVATE_DIRECTORY_MODE)?;
        }
        Ok(directory)
    }

    fn lock_provider(directory: &Path, exclusive: bool) -> io::Result<Flock<File>> {
        let lock_path = directory.join(".custody.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(SECRET_MODE)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(lock_path)?;
        validate_file_metadata(&lock_file.metadata()?)?;
        let mode = if exclusive {
            FlockArg::LockExclusive
        } else {
            FlockArg::LockShared
        };
        Flock::lock(lock_file, mode).map_err(|(_, error)| io::Error::from(error))
    }

    fn checked_secret_path(directory: &Path, name: &str) -> io::Result<PathBuf> {
        validate_variable(name)?;
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        validate_file_metadata(&metadata)?;
        Ok(path)
    }

    fn write_atomic(
        directory: &Path,
        name: &str,
        token: &SecretToken,
        replace: bool,
    ) -> io::Result<PathBuf> {
        validate_variable(name)?;
        let destination = directory.join(name);
        if !replace && path_exists(&destination)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "provider token already exists",
            ));
        }

        let mut temporary = TemporaryPath::create(directory, &token.0)?;
        fs::rename(&temporary.path, &destination)?;
        temporary.disarm();
        sync_directory(directory)?;
        Ok(destination)
    }
}

impl DnsTokenCustody for FileDnsTokenCustody {
    fn put(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf> {
        let directory = self.provider_directory(provider, true)?;
        let _lock = Self::lock_provider(&directory, true)?;
        Self::write_atomic(&directory, name, &token, false)
    }

    fn get(&self, provider: &str, name: &str) -> io::Result<PathBuf> {
        let directory = self.provider_directory(provider, false)?;
        let _lock = Self::lock_provider(&directory, false)?;
        Self::checked_secret_path(&directory, name)
    }

    fn rotate(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf> {
        let directory = self.provider_directory(provider, false)?;
        let _lock = Self::lock_provider(&directory, true)?;
        Self::checked_secret_path(&directory, name)?;
        Self::write_atomic(&directory, name, &token, true)
    }

    fn delete(&self, provider: &str) -> io::Result<()> {
        validate_provider(provider)?;
        let directory = self.root.join(provider);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) => validate_directory(&directory, PRIVATE_DIRECTORY_MODE)?,
        }
        let _lock = Self::lock_provider(&directory, true)?;
        validate_directory(&directory, PRIVATE_DIRECTORY_MODE)?;
        fs::remove_dir_all(directory)
    }
}

/// Map an explicit provider environment variable to its file-only counterpart.
///
/// # Errors
/// Returns an I/O error when the variable name or token path is not safe for provider use.
pub fn provider_file_variable(name: &str, path: &Path) -> io::Result<(String, String)> {
    validate_variable(name)?;
    if !path.is_absolute() {
        return Err(invalid_input("provider token path must be absolute"));
    }
    let path = path
        .to_str()
        .ok_or_else(|| invalid_input("provider token path is not valid UTF-8"))?;
    Ok((format!("{name}_FILE"), path.to_owned()))
}

fn validate_provider(provider: &str) -> io::Result<()> {
    let valid = !provider.is_empty()
        && provider.len() <= 63
        && provider
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && provider.as_bytes()[0].is_ascii_lowercase()
        && provider.as_bytes()[provider.len() - 1].is_ascii_alphanumeric();
    if valid {
        Ok(())
    } else {
        Err(invalid_input("invalid DNS provider name"))
    }
}

fn validate_variable(name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        && !name.ends_with("_FILE");
    if valid {
        Ok(())
    } else {
        Err(invalid_input("invalid DNS provider environment variable"))
    }
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_directory(path, PRIVATE_DIRECTORY_MODE),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    let created = match builder.create(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    if created {
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        sync_directory(path)?;
    }
    validate_directory(path, PRIVATE_DIRECTORY_MODE)
}

fn validate_directory(path: &Path, expected_mode: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(permission_error(
            "owner-only directory has unsafe owner or mode",
        ));
    }
    Ok(())
}

fn validate_file_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != SECRET_MODE
        || metadata.nlink() != 1
    {
        return Err(permission_error(
            "owner-only file has unsafe owner, mode, or links",
        ));
    }
    Ok(())
}

fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn permission_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct TemporaryPath {
    path: PathBuf,
    armed: bool,
}

impl TemporaryPath {
    fn create(directory: &Path, bytes: &[u8]) -> io::Result<Self> {
        let name = format!(".dns-token-{}.tmp", uuid::Uuid::new_v4());
        let path = directory.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_MODE)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        let temporary = Self { path, armed: true };
        file.set_permissions(fs::Permissions::from_mode(SECRET_MODE))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_file_metadata(&file.metadata()?)?;
        Ok(temporary)
    }

    fn disarm(&mut self) {
        // `rename` has moved the staged inode to its final path.
        self.armed = false;
    }
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}
