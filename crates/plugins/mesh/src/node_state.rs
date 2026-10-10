//! Persists public node intent/configuration only; kernel memory retains the private key across daemon restarts [166,198].
use crate::dataplane::Config;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
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
        let store = Self {
            path: parent.join("mesh-public.json"),
        };
        let state = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&store.path)
        {
            Ok(file) => {
                let meta = file.metadata()?;
                if !meta.is_file()
                    || meta.uid() != nix::unistd::Uid::effective().as_raw()
                    || meta.mode() & 0o777 != 0o600
                {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                serde_json::from_reader(file).map_err(io::Error::other)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error),
        };
        Ok((store, state))
    }
    /// Atomically publish public intent and fsync the replacement and directory.
    /// # Errors
    /// Reports incomplete persistence; no existing temporary file is overwritten.
    pub fn save(&self, state: &State) -> io::Result<()> {
        let temporary = self
            .path
            .with_extension(format!("{}.new", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            let body = serde_json::to_vec(state).map_err(io::Error::other)?;
            file.write_all(&body)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::File::open(self.path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
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
