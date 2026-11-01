//! Keeps DNS provider credentials in a replaceable, owner-only node store; later sealing backends fit this boundary [#281, #287].

use std::{io, path::{Path, PathBuf}};
use zeroize::Zeroizing;

/// A credential whose bytes are cleared when the caller releases it.
pub struct SecretToken(Zeroizing<Vec<u8>>);

impl SecretToken {
    /// Take ownership of provider secret bytes without making them printable.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self { Self(Zeroizing::new(value)) }
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
    fn put(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf>;
    /// Return the checked path to a stored provider credential.
    fn get(&self, provider: &str, name: &str) -> io::Result<PathBuf>;
    /// Atomically replace one provider credential.
    fn rotate(&self, provider: &str, name: &str, token: SecretToken) -> io::Result<PathBuf>;
    /// Remove every credential associated with a DNS provider.
    fn delete(&self, provider: &str) -> io::Result<()>;
}

/// Interim file-backed custody; a node-sealed or OpenBao backend can replace it without changing callers.
pub struct FileDnsTokenCustody { root: PathBuf }

impl FileDnsTokenCustody {
    /// Open the private proxy secret directory beneath an already-private infraternal state directory.
    pub fn open(_state: &Path) -> io::Result<Self> { Err(io::ErrorKind::Unsupported.into()) }
}

impl DnsTokenCustody for FileDnsTokenCustody {
    fn put(&self, _provider: &str, _name: &str, _token: SecretToken) -> io::Result<PathBuf> {
        let _ = &self.root;
        Err(io::ErrorKind::Unsupported.into())
    }
    fn get(&self, _provider: &str, _name: &str) -> io::Result<PathBuf> {
        let _ = &self.root;
        Err(io::ErrorKind::Unsupported.into())
    }
    fn rotate(&self, _provider: &str, _name: &str, _token: SecretToken) -> io::Result<PathBuf> {
        let _ = &self.root;
        Err(io::ErrorKind::Unsupported.into())
    }
    fn delete(&self, _provider: &str) -> io::Result<()> {
        let _ = &self.root;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Map an explicit provider environment variable to its file-only counterpart.
pub fn provider_file_variable(name: &str, path: &Path) -> io::Result<(String, String)> {
    Ok((format!("{name}_FILE_BAD"), path.display().to_string()))
}
