//! Persists accepted public node intent and write-ahead peer-route ownership; kernel memory retains private keys [166,198].
use crate::dataplane::Config;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub enabled: bool,
    pub config: Option<Config>,
    #[serde(default)]
    pub backend: Option<crate::firewall::Backend>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            backend: None,
        }
    }
}
pub struct Store {
    path: PathBuf,
    route_path: PathBuf,
    // Canonical public bytes avoid repeated journal fsyncs on endpoint updates
    // without retaining a second per-peer tree. No private material is cached.
    route_body: Mutex<Vec<u8>>,
}
impl Store {
    /// Read an owned private directory's public snapshot without following symlinks.
    /// # Errors
    /// Refuses ownership/mode changes, invalid snapshots or filesystem errors.
    pub fn open(parent: &Path) -> io::Result<(Self, State)> {
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir()
            || meta.uid() != nix::unistd::Uid::effective().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let path = parent.join("mesh-public.json");
        let route_path = parent.join("mesh-routes.json");
        let state = read_public(&path)?.unwrap_or_default();
        let routes: BTreeSet<IpAddr> = read_public(&route_path)?.unwrap_or_default();
        let route_body = serde_json::to_vec(&routes).map_err(io::Error::other)?;
        Ok((
            Self {
                path,
                route_path,
                route_body: Mutex::new(route_body),
            },
            state,
        ))
    }
    /// Read only the public host addresses recorded before kernel mutation.
    /// # Errors
    /// Refuses a poisoned cache or invalid journal without changing kernel state.
    pub fn route_inventory(&self) -> io::Result<BTreeSet<IpAddr>> {
        let body = self.route_body.lock().map_err(|_| io::ErrorKind::Other)?;
        serde_json::from_slice(&body).map_err(io::Error::other)
    }
    /// Persist route ownership separately from accepting an in-flight config.
    /// # Errors
    /// Uses the same private-file checks and atomic durable writer as `save`.
    pub fn record_routes(&self, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
        let body = serde_json::to_vec(routes).map_err(io::Error::other)?;
        let mut previous = self.route_body.lock().map_err(|_| io::ErrorKind::Other)?;
        if *previous != body {
            write_public(&self.route_path, &body)?;
            *previous = body;
        }
        Ok(())
    }
    /// Atomically publish public intent and fsync the replacement and directory.
    /// # Errors
    /// Reports incomplete persistence; no existing temporary file is overwritten.
    pub fn save(&self, state: &State) -> io::Result<()> {
        let body = serde_json::to_vec(state).map_err(io::Error::other)?;
        write_public(&self.path, &body)
    }
}

// Both public files must pass the same ownership, mode and no-follow boundary.
fn read_public<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != nix::unistd::Uid::effective().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            serde_json::from_reader(file)
                .map(Some)
                .map_err(io::Error::other)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
// Write the journal before kernel mutation and the accepted snapshot afterwards.
// A crash between writes can recover ownership from the journal, the accepted
// peer list and the retained kernel peer list; no cross-file atomicity is assumed.
fn write_public(path: &Path, body: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let base = std::env::var_os("CARGO_TARGET_DIR")
                .map_or_else(
                    || std::env::current_dir().map(|path| path.join("target")),
                    |path| Ok(PathBuf::from(path)),
                )
                .expect("test target directory");
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let path = base.join(format!("mesh-state-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("test mode");
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn explicit_off_survives_restart_and_snapshot_contains_only_public_fields() {
        let directory = Directory::new();
        let (store, initial) = Store::open(&directory.0).expect("initial state");
        assert!(initial.enabled);
        store
            .save(&State {
                enabled: false,
                config: None,
                backend: Some(crate::firewall::Backend::Nft),
            })
            .expect("save");
        let (_, restored) = Store::open(&directory.0).expect("restore");
        assert!(!restored.enabled);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).expect("public file"))
                .expect("public JSON");
        assert_eq!(value.as_object().expect("object").len(), 3);
        assert_eq!(
            fs::metadata(&store.path).expect("mode").mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn route_recording_preserves_the_legacy_accepted_state_format() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let config = Config {
            local_key: None,
            node: crate::policy::model::NodeId(1),
            version: 7,
            addresses: crate::policy::model::Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: crate::dataplane::DefaultPolicy::Deny,
            peers: std::collections::BTreeMap::new(),
        };
        store
            .save(&State {
                enabled: false,
                config: Some(config.clone()),
                backend: Some(crate::firewall::Backend::Nft),
            })
            .expect("accepted intent");
        let before = fs::read(&store.path).expect("accepted bytes");
        assert!(
            store
                .route_inventory()
                .expect("legacy inventory")
                .is_empty()
        );
        let routes = BTreeSet::from([
            "10.254.0.2".parse().expect("peer IPv4"),
            "fd01::2".parse().expect("peer IPv6"),
        ]);
        store.record_routes(&routes).expect("write-ahead record");
        assert_eq!(fs::read(&store.path).expect("accepted bytes"), before);
        let (restored, state) = Store::open(&directory.0).expect("restore journal");
        assert_eq!(restored.route_inventory().expect("recorded routes"), routes);
        assert_eq!(state.config, Some(config));
        assert!(!state.enabled);
        assert!(matches!(state.backend, Some(crate::firewall::Backend::Nft)));
        assert_eq!(
            fs::metadata(&store.route_path)
                .expect("journal mode")
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn unsafe_route_journal_and_existing_temporary_files_are_preserved() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let routes = BTreeSet::from(["10.254.0.2".parse().expect("peer IPv4")]);
        let temporary = store
            .route_path
            .with_extension(format!("{}.new", std::process::id()));
        fs::write(&temporary, b"unrelated").expect("collision fixture");
        assert_eq!(
            store.record_routes(&routes).expect_err("collision").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(&temporary).expect("preserved collision"),
            b"unrelated"
        );
        assert!(store.route_inventory().expect("unchanged cache").is_empty());
        fs::remove_file(temporary).expect("remove fixture");
        store.record_routes(&routes).expect("record");
        fs::set_permissions(&store.route_path, fs::Permissions::from_mode(0o644))
            .expect("unsafe mode");
        assert!(Store::open(&directory.0).is_err());
        fs::remove_file(&store.route_path).expect("remove fixture");
        let other = directory.0.join("other-public-routes");
        fs::write(&other, b"[\"10.254.0.2\"]").expect("public fixture");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).expect("private mode");
        symlink(&other, &store.route_path).expect("journal symlink");
        assert!(Store::open(&directory.0).is_err());
        assert_eq!(fs::read(other).expect("foreign bytes"), b"[\"10.254.0.2\"]");
    }
    #[test]
    fn unsafe_snapshots_and_preexisting_temporary_files_are_not_followed_or_removed() {
        let directory = Directory::new();
        let (store, state) = Store::open(&directory.0).expect("initial state");
        let other = directory.0.join("other");
        fs::write(&other, b"unrelated").expect("fixture");
        symlink(&other, &store.path).expect("symlink");
        assert!(Store::open(&directory.0).is_err());
        fs::remove_file(&store.path).expect("unlink fixture");
        let temporary = store
            .path
            .with_extension(format!("{}.new", std::process::id()));
        fs::write(&temporary, b"unrelated").expect("fixture");
        assert_eq!(
            store.save(&state).expect_err("collision").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&temporary).expect("retained"), b"unrelated");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755))
            .expect("expose fixture");
        assert!(Store::open(&directory.0).is_err());
    }
}
