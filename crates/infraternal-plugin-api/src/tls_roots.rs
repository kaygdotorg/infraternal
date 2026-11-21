//! Where to find the operating system's public TLS roots (#483).
//!
//! The binaries link a vendored OpenSSL, whose built-in default path names the
//! build machine's prefix, which usually does not exist on the host. Each
//! public-root TLS client enables the `tls-roots` feature and gets a fresh
//! store from `public_root_store`. It loads only the first fixed bundle that
//! exists and passes root ownership and permission checks, so OpenSSL's
//! environment-selected defaults are not kept.
//!
//! The list is in order. The Linux distributions come first, then
//! `/etc/ssl/cert.pem`, the bundle macOS ships (also on Alpine and the BSDs,
//! where it is normally the same file as the Linux name). Before macOS was on
//! the list, a Mac's `infraternal up` could not reach any public HTTPS server.

#[cfg(feature = "tls-roots")]
use openssl::{
    error::ErrorStack,
    ssl::SslFiletype,
    x509::store::{X509Lookup, X509Store, X509StoreBuilder},
};
use std::path::Path;
#[cfg(unix)]
use std::{fs, os::unix::fs::MetadataExt};

/// System CA bundle files, most common first. Each is a PEM file of trusted roots.
pub const SYSTEM_CA_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The first fixed bundle that is a protected, root-owned regular file, if any.
///
/// `None` means none of the listed files is safe to trust. Callers must not
/// fall back to OpenSSL's defaults, because those defaults can include paths
/// selected by the process environment.
#[must_use]
pub fn first_present() -> Option<&'static str> {
    SYSTEM_CA_BUNDLES
        .into_iter()
        .find(|bundle| root_owned_bundle(Path::new(bundle)))
}

/// Build a fresh store containing only the first trusted fixed system bundle.
///
/// The empty store is intentional when no approved bundle exists: public
/// servers then fail verification rather than inheriting environment-selected
/// OpenSSL roots. A caller with a separately configured server CA builds its
/// own store for that explicit trust decision.
///
/// # Errors
///
/// Returns an OpenSSL error if it cannot create the store or file lookup, or
/// parse the selected bundle.
#[cfg(feature = "tls-roots")]
pub fn public_root_store() -> Result<X509Store, ErrorStack> {
    Ok(public_root_store_builder()?.build())
}

/// The same store as [`public_root_store`], still open so a caller that has an
/// explicit, compile-time-gated reason (a test-only build) can add one more
/// root before building it. Production callers use [`public_root_store`].
///
/// # Errors
///
/// As [`public_root_store`].
#[cfg(feature = "tls-roots")]
pub fn public_root_store_builder() -> Result<X509StoreBuilder, ErrorStack> {
    let mut store = X509StoreBuilder::new()?;
    if let Some(bundle) = first_present() {
        store
            .add_lookup(X509Lookup::file())?
            .load_cert_file(bundle, SslFiletype::PEM)?;
    }
    Ok(store)
}

/// Accept only a fixed bundle whose source and resolved path are root-owned and protected.
fn root_owned_bundle(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let Ok(resolved) = fs::canonicalize(path) else {
            return false;
        };
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        metadata.is_file()
            && trusted_path_chain(path, Path::new("/"))
            && trusted_path_chain(&resolved, Path::new("/"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Check every path component for root ownership and disallow group/other writes.
#[cfg(unix)]
fn trusted_path_chain(path: &Path, boundary: &Path) -> bool {
    let mut current = path;
    loop {
        let Ok(metadata) = fs::symlink_metadata(current) else {
            return false;
        };
        let symlink = metadata.file_type().is_symlink();
        if metadata.uid() != 0 || (!symlink && metadata.mode() & 0o022 != 0) {
            return false;
        }
        if current == boundary {
            return true;
        }
        let Some(parent) = current.parent() else {
            return false;
        };
        current = parent;
    }
}

/// The list keeps its order and finds what the host has.
#[cfg(test)]
mod tests {
    /// The macOS bundle is on the list, after every Linux name, so Linux hosts load what they did before.
    #[test]
    fn macos_bundle_is_listed_last() {
        assert_eq!(super::SYSTEM_CA_BUNDLES.last(), Some(&"/etc/ssl/cert.pem"));
        assert_eq!(
            super::SYSTEM_CA_BUNDLES[0],
            "/etc/ssl/certs/ca-certificates.crt"
        );
    }

    /// On a host with a trusted bundle, the selected file and both path chains are root-owned.
    #[test]
    #[cfg(unix)]
    fn first_present_returns_only_a_root_owned_bundle_on_a_protected_path() {
        use std::os::unix::fs::MetadataExt;

        let Some(bundle) = super::first_present() else {
            return;
        };
        let path = std::path::Path::new(bundle);
        let resolved = std::fs::canonicalize(path).unwrap();
        assert!(std::fs::metadata(path).unwrap().is_file());
        for chain in [path, resolved.as_path()] {
            let mut current = chain;
            loop {
                let metadata = std::fs::symlink_metadata(current).unwrap();
                assert_eq!(metadata.uid(), 0, "{} is not root-owned", current.display());
                if !metadata.file_type().is_symlink() {
                    assert_eq!(
                        metadata.mode() & 0o022,
                        0,
                        "{} allows group or other writes",
                        current.display()
                    );
                }
                if current == std::path::Path::new("/") {
                    break;
                }
                current = current.parent().unwrap();
            }
        }
    }
}
