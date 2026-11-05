//! Keeps the fresh-host install's inode ownership durable across abrupt termination (#338).
//!
//! The 0600 journal is also the transaction lock. Its inode is retained after
//! cleanup so concurrent installers cannot lock different files at the same name.
//! Complete records are synced before publication; an interrupted last append
//! cannot authorize a deletion. Recovery never removes a replacement inode.
use super::{Created, existing, refused};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

/// Bound corrupt input before allocating or deserializing recovery instructions.
const LIMIT: u64 = 1024 * 1024;
/// A stable private file outside both server data and enrollment directories.
const NAME: &str = ".infraternal-up.journal";

/// A complete synced line records either inode ownership or a lifecycle boundary.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum Record {
    /// Start a new append-only transaction after the previous one was cleaned up.
    Begin {
        /// Unknown formats must refuse instead of granting older code deletion authority.
        version: u8,
    },
    /// Mark an operation before it can create or publish filesystem state.
    Step,
    /// Authorize cleanup only for this exact inode at this namespace-relative path.
    Created {
        /// A validated path relative to the trusted namespace root.
        path: PathBuf,
        /// Device number retained across pathname replacements.
        device: u64,
        /// Inode number retained across pathname replacements.
        inode: u64,
        /// Newly created enrollment directories own their private descendants.
        enrollment: bool,
    },
    /// Revoke a never-published staging inode's claim before a fallback creates a new inode.
    Unpublished {
        /// Relative destination whose prior claim is being revoked.
        path: PathBuf,
        /// Only this device/inode claim is removed; other entries remain intact.
        device: u64,
        /// Inode of the unpublished staging directory.
        inode: u64,
    },
    /// Service registration can require stopping our unit during recovery.
    Registered,
    /// A successful active check transfers ownership to the installed service.
    Committed,
}

/// A read-only view of the last complete transaction, used by both preflight and recovery.
#[derive(Default)]
pub(super) struct Snapshot {
    /// An ordinary user cannot read root's journal; only the privileged repeat may validate or recover it.
    pub(super) needs_root: bool,
    /// Entries stay in publication order so rollback visits children first.
    pub(super) created: Vec<Created>,
    /// The manager might already have started this run's service.
    pub(super) registered: bool,
    /// Committed installations must be managed normally, never recovered as partial installs.
    pub(super) committed: bool,
}

impl Snapshot {
    /// Test ownership against the entry itself; symlink targets never grant deletion rights.
    pub(super) fn owns(&self, path: &Path) -> bool {
        !self.committed
            && self.created.iter().any(|entry| {
                entry.path == path
                    && existing(path)
                        .ok()
                        .flatten()
                        .is_some_and(|metadata| entry.identity == (metadata.dev(), metadata.ino()))
            })
    }
}

/// A retained exclusive file lock serializes recovery and installation through commit or rollback.
pub(super) struct Journal {
    /// The open inode stays locked while any installation paths are owned.
    file: File,
    /// Absolute namespace root used to encode only constrained relative paths.
    root: PathBuf,
}

/// Refuse unsafe recovery metadata without printing any journal contents.
fn invalid() -> io::Error {
    refused(
        "The existing /.infraternal-up.journal cannot be read or trusted. Inspect it as root, then retry sudo infraternal up; no existing installation paths were changed.",
    )
}

/// Refuse an installer that is still alive instead of recovering its active transaction.
fn lock_error(error: fs::TryLockError) -> io::Error {
    match error {
        fs::TryLockError::WouldBlock => refused(
            "Another infraternal up installation is still running. Wait for it to finish before retrying.",
        ),
        fs::TryLockError::Error(error) => error,
    }
}

/// Validate both the open inode and its pathname before trusting private recovery instructions.
fn checked(file: &File, path: &Path, owner: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
        || metadata.len() > LIMIT
    {
        return Err(invalid());
    }
    Ok(())
}

/// Constrain durable deletion authority to installation destinations and their staging siblings.
fn allowed(path: &Path, enrollment: bool) -> bool {
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return false;
    }
    let Some(value) = path.to_str() else {
        return false;
    };
    if enrollment {
        return value == "var/lib/infraternal/agent";
    }
    let exact = [
        "var",
        "var/lib",
        "var/lib/infraternal",
        "var/lib/infraternal/agent",
        "var/lib/infraternal/bin",
        "var/lib/infraternal/bin/infraternal",
        "usr",
        "usr/local",
        "usr/local/bin",
        "usr/local/bin/infraternal",
        "usr/local/bin/infra",
        "etc",
        "etc/systemd",
        "etc/systemd/system",
        "etc/systemd/system/infraternal-agent.service",
        "etc/systemd/system/multi-user.target.wants",
        "etc/systemd/system/multi-user.target.wants/infraternal-agent.service",
    ];
    exact.contains(&value)
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".infraternal-up-") && name.ends_with(".pending"))
            && path.parent().is_some_and(|parent| {
                exact.contains(&parent.to_str().unwrap_or_default())
                    || parent.as_os_str().is_empty()
            })
}

/// Decode complete records only; the producer always syncs a full line before its next operation.
fn snapshot(file: &mut File, root: &Path) -> io::Result<Snapshot> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(invalid());
    }
    let mut state = Snapshot::default();
    let mut begun = false;
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if !bytes.is_empty() && end == 0 {
        return Err(invalid());
    }
    for line in bytes[..end]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: Record = serde_json::from_slice(line).map_err(|_| invalid())?;
        match record {
            Record::Begin { version: 1 } if !begun => {
                begun = true;
            }
            Record::Step if begun && !state.committed => {}
            Record::Created {
                path,
                device,
                inode,
                enrollment,
            } if begun && !state.committed && allowed(&path, enrollment) => {
                state.created.push(Created {
                    path: root.join(path),
                    identity: (device, inode),
                    enrollment,
                });
            }
            Record::Unpublished {
                path,
                device,
                inode,
            } if begun && !state.committed && allowed(&path, false) => {
                let path = root.join(path);
                state
                    .created
                    .retain(|entry| entry.path != path || entry.identity != (device, inode));
            }
            Record::Registered if begun && !state.committed => {
                state.registered = true;
            }
            Record::Committed if begun && !state.committed => {
                state.committed = true;
            }
            _ => return Err(invalid()),
        }
    }
    Ok(state)
}

/// Inspect without changing permissions, contents, locks held by a live installer, or install paths.
pub(super) fn inspect(root: &Path, owner: u32) -> io::Result<Snapshot> {
    let path = root.join(NAME);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Snapshot::default()),
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                && owner == 0
                && !nix::unistd::geteuid().is_root() =>
        {
            let metadata = fs::symlink_metadata(&path).map_err(|_| invalid())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > LIMIT
            {
                return Err(invalid());
            }
            // This is no deletion authority. Root must reopen, lock and validate
            // both the inode and records before any installation write.
            return Ok(Snapshot {
                needs_root: true,
                ..Snapshot::default()
            });
        }
        Err(_) => return Err(invalid()),
    };
    checked(&file, &path, owner)?;
    file.try_lock_shared().map_err(lock_error)?;
    checked(&file, &path, owner)?;
    snapshot(&mut file, root)
}

impl Journal {
    /// Acquire the stable private journal after read-only preflight has accepted this host.
    pub(super) fn open(root: &Path, owner: u32) -> io::Result<(Self, Snapshot)> {
        let path = root.join(NAME);
        let mut file = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                // Only our exclusively created inode may have umask-filtered permissions fixed.
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.sync_all()?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .append(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)?,
            Err(error) => return Err(error),
        };
        checked(&file, &path, owner)?;
        file.try_lock().map_err(lock_error)?;
        checked(&file, &path, owner)?;
        File::open(root)?.sync_all()?;
        let state = snapshot(&mut file, root)?;
        Ok((
            Self {
                file,
                root: root.to_owned(),
            },
            state,
        ))
    }

    /// Append and sync before the caller performs the operation authorized by this record.
    fn append(&mut self, record: &Record) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        if self.file.metadata()?.len() + bytes.len() as u64 > LIMIT {
            return Err(invalid());
        }
        self.file.write_all(&bytes)?;
        self.file.sync_all()
    }

    /// Clear recovered records while retaining the same lock inode across every retry.
    pub(super) fn clear(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.sync_all()
    }

    /// Start ownership tracking after every previous owned entry has been recovered.
    pub(super) fn begin(&mut self) -> io::Result<()> {
        self.append(&Record::Begin { version: 1 })
    }

    /// Persist an operation boundary before the first write in that step.
    pub(super) fn step(&mut self) -> io::Result<()> {
        self.append(&Record::Step)
    }

    /// Sync exact inode ownership before publishing a destination or writing enrollment data.
    pub(super) fn record(
        &mut self,
        path: &Path,
        metadata: &fs::Metadata,
        enrollment: bool,
    ) -> io::Result<()> {
        let path = path
            .strip_prefix(&self.root)
            .map_err(|_| invalid())?
            .to_owned();
        if !allowed(&path, enrollment) {
            return Err(invalid());
        }
        self.append(&Record::Created {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            enrollment,
        })
    }

    /// Sync revocation before exclusive mkdir can allocate a different destination inode.
    pub(super) fn unpublish(&mut self, path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
        let path = path
            .strip_prefix(&self.root)
            .map_err(|_| invalid())?
            .to_owned();
        if !allowed(&path, false) {
            return Err(invalid());
        }
        self.append(&Record::Unpublished {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Persist manager ownership before any registration operation can start the service.
    pub(super) fn register(&mut self) -> io::Result<()> {
        self.append(&Record::Registered)
    }

    /// Transfer ownership only after the service has passed its active check.
    pub(super) fn commit(&mut self) -> io::Result<()> {
        self.append(&Record::Committed)
    }
}
