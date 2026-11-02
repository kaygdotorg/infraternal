//! Publishes immutable, account-readable copies of the current binary for host login workers [D247].
#![forbid(unsafe_code)]

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Make a root-started account worker executable through otherwise private install paths.
/// Rootless workers already use their own executable and need no additional copy.
/// # Errors
/// Refuses arbitrary links, untrusted ownership, writable published images and changing sources.
pub(crate) fn accessible(exe: &Path, root: &Path) -> io::Result<Published> {
    if nix::unistd::Uid::effective().is_root() {
        publish(exe, root)
    } else {
        Ok(Published {
            path: exe.to_path_buf(),
            _launch: None,
        })
    }
}

fn private_directory(path: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted login binary directory",
        ));
    }
    Ok(())
}

fn opened(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
}

fn identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn validate_image(path: &Path, uid: u32, length: u64) -> io::Result<()> {
    let file = opened(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.len() != length
        || !matches!(metadata.mode() & 0o7777, 0o555 | 0o755)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted login worker image",
        ));
    }
    Ok(())
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn executable_filesystem(path: &Path) -> io::Result<()> {
    if nix::sys::statvfs::statvfs(path)
        .map_err(io::Error::from)?
        .flags()
        .contains(nix::sys::statvfs::FsFlags::ST_NOEXEC)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host login image cache filesystem is not executable",
        ));
    }
    Ok(())
}

/// A launch retains a shared image lock until readiness authenticates its exec.
/// The running worker's executable mapping then protects the image on upgrades.
pub(crate) struct Published {
    path: PathBuf,
    _launch: Option<nix::fcntl::Flock<File>>,
}
impl Published {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

fn lock_directory(root: &Path, uid: u32) -> io::Result<PathBuf> {
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("invalid login cache directory name"))?;
    let directory = root
        .parent()
        .ok_or_else(|| io::Error::other("login cache parent absent"))?
        .join(format!(".{name}-locks"));
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted private login cache locks",
        ));
    }
    Ok(directory)
}

fn image_lock(path: &Path, locks: &Path, uid: u32) -> io::Result<File> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("login image name absent"))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(locks.join(name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted private login image lock",
        ));
    }
    Ok(file)
}

fn retained(path: PathBuf, locks: &Path, uid: u32) -> io::Result<Published> {
    // Public executable inodes are readable by accounts, which can take flock
    // EX even on read-only FDs. Synchronize only on private controller inodes.
    let lock = nix::fcntl::Flock::lock(
        image_lock(&path, locks, uid)?,
        nix::fcntl::FlockArg::LockShared,
    )
    .map_err(|(_, error)| io::Error::from(error))?;
    Ok(Published {
        path,
        _launch: Some(lock),
    })
}

#[cfg(test)]
fn staged(exe: &Path, root: &Path) -> io::Result<PathBuf> {
    Ok(publish(exe, root)?.path)
}

// Inspect only public executable identities, never process argv or memory.
// If root cannot inspect a live process, retain all old images conservatively.
fn running_images() -> io::Result<Option<std::collections::HashSet<PathBuf>>> {
    let mut images = std::collections::HashSet::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        match fs::read_link(entry.path().join("exe")) {
            Ok(path) => {
                images.insert(path);
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                if nix::unistd::Uid::effective().is_root() {
                    return Ok(None);
                }
                // Production staging is root-only. Rootless publication tests
                // cannot inspect other users, which cannot be their workers.
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.raw_os_error() == Some(nix::libc::ESRCH) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Some(images))
}

// Keep the probe FD alive through unlink. Linux refuses write opens of a live
// executable with ETXTBSY and refuses exec while this writer is held. No byte
// is written. This detects any live image without inspecting unrelated PIDs.
fn inactive_image(path: &Path) -> io::Result<Option<File>> {
    if nix::unistd::Uid::effective().is_root() {
        match OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => Ok(Some(file)),
            Err(error)
                if error.raw_os_error() == Some(nix::libc::ETXTBSY)
                    || error.kind() == io::ErrorKind::PermissionDenied =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    } else {
        // Publication is root-only in production. Unprivileged ownership
        // fixtures cannot write-open 0555 images; inspect their own executables.
        if running_images()?.is_some_and(|live| !live.contains(path)) {
            opened(path).map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Reclaim old images and staging copies after a publication.
///
/// Staging copies (`.pending-*`, other than this publisher's own `staging`)
/// are left by a publisher that stopped before its `Temporary` guard ran.
/// Removing them is safe because:
/// - the caller holds the exclusive publisher lock, which every publisher
///   holds from before it creates its staging file until after it removes it,
///   so no other staging file has a live writer, in this process or another;
/// - workers exec only published `infraternal-*` names; a staging name that
///   was already hard-linked is a second name for the published inode, and
///   unlinking it leaves the image and any running login untouched;
/// - the directory is private to `uid` (checked by the caller), so no account
///   can plant entries; non-regular entries are never followed or removed.
///
/// This runs only on the publication path, never when a terminal adopts an
/// existing image.
fn prune(root: &Path, current: &Path, staging: &Path, locks: &Path, uid: u32) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.as_encoded_bytes();
        if name.starts_with(b".pending-") {
            if path != staging && entry.file_type()?.is_file() {
                fs::remove_file(&path)?;
            }
            continue;
        }
        if path == current || !name.starts_with(b"infraternal-") {
            continue;
        }
        let file = opened(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o555 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted old login image",
            ));
        }
        // The private directory serializes publishers; a private shared image
        // guard excludes any launch that has not yet completed authenticated exec.
        match nix::fcntl::Flock::lock(
            image_lock(&path, locks, uid)?,
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        ) {
            Ok(_unused) => {
                if let Some(_probe) = inactive_image(&path)? {
                    fs::remove_file(&path)?;
                    fs::remove_file(locks.join(&file_name))?;
                }
            }
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => {}
            Err((_, error)) => return Err(io::Error::from(error)),
        }
    }
    File::open(root)?.sync_all()?;
    File::open(locks)?.sync_all()
}

fn publish(exe: &Path, root: &Path) -> io::Result<Published> {
    let uid = nix::unistd::Uid::effective().as_raw();
    // Linux binds this exact magic link to the executing image, even after an
    // anonymous upgrade. It is not an arbitrary pathname alias. All sources
    // retain the same inode ownership, mode and change checks below.
    let mut source = if cfg!(target_os = "linux") && exe == Path::new("/proc/self/exe") {
        File::open(exe)?
    } else {
        opened(exe)?
    };
    let metadata = source.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted login binary source",
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| io::Error::other("login binary directory has no parent"))?;
    private_directory(parent, uid)?;
    match DirBuilder::new().mode(0o755).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_directory(root, uid)?;
    let locks = lock_directory(root, uid)?;
    // Accounts can read the image directory. Only the private sibling can be
    // used as a controller lock without exposing dispatch to account-held flock.
    let _publisher =
        nix::fcntl::Flock::lock(File::open(&locks)?, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| io::Error::from(error))?;
    // Runtime filesystems are commonly mounted noexec. The host policy stays
    // intact: use an executable cache filesystem, or refuse before unit launch.
    executable_filesystem(root)?;
    // A restrictive inherited umask can reduce create's mode. Ownership and
    // absence of outside writers are checked before granting account traversal.
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    let signature = identity(&metadata);
    let candidate = root.join(format!(
        "infraternal-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}",
        signature.0, signature.1, signature.2, signature.3, signature.4, signature.5, signature.6
    ));
    match fs::symlink_metadata(&candidate) {
        Ok(_) => {
            validate_image(&candidate, uid, metadata.len())?;
            return retained(candidate, &locks, uid);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary_path = root.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        // A process-local counter restarts at zero after PID reuse. A fresh
        // publication identity avoids claiming an interrupted writer's name;
        // create_new remains the final fence and prune reclaims the old copy
        // only while this publisher holds the exclusive directory lock.
        uuid::Uuid::new_v4().simple()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o555)
        .open(&temporary_path)?;
    let temporary = Temporary(temporary_path);
    let bytes = io::copy(&mut source, &mut output)?;
    if bytes != metadata.len() || identity(&source.metadata()?) != signature {
        return Err(io::Error::other("login binary changed while copying"));
    }
    output.set_permissions(fs::Permissions::from_mode(0o555))?;
    output.sync_all()?;
    // Close the writable handle before publication so a racing worker exec
    // cannot fail with ETXTBSY despite observing a fully copied image.
    drop(output);
    // Hard-link publication never replaces an existing object. Concurrent
    // callers validate the winner; no reader can observe an incomplete image.
    match fs::hard_link(&temporary.0, &candidate) {
        Ok(()) => File::open(root)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_image(&candidate, uid, metadata.len())?;
    prune(root, &candidate, &temporary.0, &locks, uid)?;
    retained(candidate, &locks, uid)
}

#[cfg(test)]
mod tests {
    //! Publication boundaries are tested with private copies of the running test executable.
    use super::*;
    use std::{
        fs,
        os::unix::{
            fs::MetadataExt,
            fs::{PermissionsExt, symlink},
        },
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let parent = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/real-logins");
            fs::create_dir_all(&parent).unwrap();
            let directory = parent.join(format!(
                "binary-review-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            Self(directory)
        }
        fn source(&self) -> PathBuf {
            let source = self.0.join("source");
            fs::copy(std::env::current_exe().unwrap(), &source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
            source
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn noexec_host_mount_is_refused_before_image_publication() {
        // proc is a read-only fixture here: this test neither remounts it nor
        // creates runtime files. Linux advertises its noexec policy via statvfs.
        let path = Path::new("/proc");
        assert!(
            nix::sys::statvfs::statvfs(path)
                .unwrap()
                .flags()
                .contains(nix::sys::statvfs::FsFlags::ST_NOEXEC)
        );
        assert_eq!(
            executable_filesystem(path).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_kernel_image_can_be_published() {
        let fixture = Fixture::new();
        let root = fixture.0.join("published");
        let image = staged(Path::new("/proc/self/exe"), &root).unwrap();
        assert!(
            fs::read(&image).unwrap() == fs::read("/proc/self/exe").unwrap(),
            "published kernel image bytes differ"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_image_source_alias_is_refused() {
        let fixture = Fixture::new();
        let alias = fixture.0.join("source-alias");
        std::os::unix::fs::symlink("/proc/self/exe", &alias).unwrap();
        assert!(staged(&alias, &fixture.0.join("published")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn anonymous_kernel_image_can_be_published_after_unlink() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let output = std::process::Command::new(&source)
            .args([
                "--exact",
                "login_binary::tests::running_image_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("INFRATERNAL_IMAGE_FIXTURE", "1")
            .env("INFRATERNAL_IMAGE_PUBLISH_ROOT", &root)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "anonymous image publication failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!source.exists());
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }

    #[test]
    fn loaded_binary_is_copied_once_and_readable_by_accounts() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let first = staged(&source, &root).unwrap();
        let inode = fs::metadata(&first).unwrap().ino();
        assert_eq!(first, staged(&source, &root).unwrap());
        assert_eq!(inode, fs::metadata(&first).unwrap().ino());
        assert_eq!(fs::read(&source).unwrap(), fs::read(&first).unwrap());
        assert_eq!(fs::metadata(&first).unwrap().mode() & 0o777, 0o555);
        assert_eq!(fs::metadata(root).unwrap().mode() & 0o777, 0o755);
    }
    #[test]
    fn symlink_directory_and_symlink_source_are_refused() {
        let fixture = Fixture::new();
        let source = fixture.source();
        symlink(&fixture.0, fixture.0.join("linked-root")).unwrap();
        assert!(staged(&source, &fixture.0.join("linked-root")).is_err());
        symlink(source, fixture.0.join("linked-source")).unwrap();
        assert!(
            staged(
                &fixture.0.join("linked-source"),
                &fixture.0.join("published")
            )
            .is_err()
        );
    }
    #[test]
    fn writable_or_symlink_published_image_is_refused() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let image = staged(&source, &root).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(staged(&source, &root).is_err());
        fs::set_permissions(&image, fs::Permissions::from_mode(0o4555)).unwrap();
        assert!(staged(&source, &root).is_err());
        fs::remove_file(&image).unwrap();
        symlink(&source, &image).unwrap();
        assert!(staged(&source, &root).is_err());
    }
    #[test]
    fn outside_writable_source_and_directory_are_refused() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(staged(&source, &root).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(staged(&source, &root).is_err());
    }

    /// Shadow review #172: each binary identity (inode, size, mtime, ctime)
    /// publishes a full new copy under /var/cache/infraternal-login-bin, and
    /// nothing removes the old ones. Production updates itself (D251), so the
    /// cache grows by one binary per update with no bound.
    #[test]
    fn upgraded_binary_does_not_accumulate_stale_login_images() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        staged(&source, &root).unwrap();
        // Model an update: the installed binary is replaced with new bytes.
        let mut bytes = fs::read(&source).unwrap();
        bytes.extend_from_slice(b"\0update");
        let replacement = fixture.0.join("source.new");
        fs::write(&replacement, bytes).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&replacement, &source).unwrap();
        staged(&source, &root).unwrap();
        let images = fs::read_dir(&root)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("infraternal-")
            })
            .count();
        assert_eq!(images, 1, "every update leaves another full binary copy");
    }

    #[test]
    fn public_image_locks_cannot_serialize_login_admission() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let launch = publish(&source, &root).unwrap();
        // Any account can open a published read-only image and take flock EX.
        // A launch must synchronize on a private inode instead of that image.
        let _outside = nix::fcntl::Flock::lock(
            opened(launch.path()).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .expect("a launch guard still uses the public image inode");
        assert_eq!(publish(&source, &root).unwrap().path(), launch.path());
    }

    #[test]
    fn public_directory_locks_do_not_block_publication() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        staged(&source, &root).unwrap();
        let _outside = nix::fcntl::Flock::lock(
            File::open(&root).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        assert!(publish(&source, &root).is_ok());
    }

    #[test]
    fn readable_private_lock_directory_is_refused() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let locks = fixture.0.join(".published-locks");
        fs::create_dir(&locks).unwrap();
        fs::set_permissions(&locks, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            publish(&source, &fixture.0.join("published"))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    fn update(fixture: &Fixture, source: &Path, suffix: &[u8]) {
        let mut bytes = fs::read(source).unwrap();
        bytes.extend_from_slice(suffix);
        let replacement = fixture.0.join("replacement");
        fs::write(&replacement, bytes).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(replacement, source).unwrap();
    }

    #[test]
    fn cleanup_retains_inflight_launches_then_reclaims_them() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let launch = publish(&source, &root).unwrap();
        let old = launch.path.clone();
        update(&fixture, &source, b"first");
        staged(&source, &root).unwrap();
        assert!(old.exists());
        drop(launch);
        update(&fixture, &source, b"second");
        staged(&source, &root).unwrap();
        assert!(!old.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    #[ignore = "private subprocess fixture; waits for its parent pipe to close"]
    fn running_image_fixture() {
        use std::io::Read as _;
        assert_eq!(
            std::env::var("INFRATERNAL_IMAGE_FIXTURE").as_deref(),
            Ok("1")
        );
        #[cfg(target_os = "linux")]
        if let Some(root) = std::env::var_os("INFRATERNAL_IMAGE_PUBLISH_ROOT") {
            fs::remove_file(std::env::current_exe().unwrap()).unwrap();
            assert!(
                std::env::current_exe()
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .ends_with(b" (deleted)")
            );
            staged(Path::new("/proc/self/exe"), Path::new(&root)).unwrap();
        }
        std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
    }

    #[test]
    fn cleanup_preserves_running_images_for_fallback_adoption() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let old = staged(&source, &root).unwrap();
        let mut child = std::process::Command::new(&old)
            .args([
                "--exact",
                "login_binary::tests::running_image_fixture",
                "--ignored",
            ])
            .env("INFRATERNAL_IMAGE_FIXTURE", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // The spawning parent can resume before the kernel switches the
        // child's exe link to the new image, so wait (bounded) for the exec.
        let exe = format!("/proc/{}/exe", child.id());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while fs::read_link(&exe).unwrap() != old && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(fs::read_link(&exe).unwrap(), old);
        update(&fixture, &source, b"new");
        staged(&source, &root).unwrap();
        assert!(old.exists());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        update(&fixture, &source, b"next");
        staged(&source, &root).unwrap();
        assert!(!old.exists());
    }

    #[test]
    fn concurrent_publication_returns_one_complete_image() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let source = source.clone();
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let image = staged(&source, &root).unwrap();
                    assert!(
                        std::process::Command::new(&image)
                            .arg("--list")
                            .stdout(std::process::Stdio::null())
                            .status()
                            .unwrap()
                            .success()
                    );
                    image
                })
            })
            .collect();
        let images: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(images.iter().all(|image| image == &images[0]));
        assert_eq!(fs::read(source).unwrap(), fs::read(&images[0]).unwrap());
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }
    #[test]
    fn staging_name_of_a_published_image_is_removed_without_touching_the_image() {
        let fixture = Fixture::new();
        let first = fixture.source();
        let root = fixture.0.join("published");
        fs::create_dir(&root).unwrap();
        // Independent of the caller's umask: publication refuses group write.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let published = staged(&first, &root).unwrap();
        // A stop after the hard link but before Temporary::drop leaves a second
        // name for the published inode. The next publication of a new build
        // must drop that name while the old image stays valid for its workers
        // (here the old image is kept by this test's own pending launch guard).
        let leftover = root.join(".pending-2147483647-1");
        fs::hard_link(&published, &leftover).unwrap();
        let guard = publish(&first, &root).unwrap();
        let second = fixture.0.join("second");
        fs::copy(&first, &second).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o755)).unwrap();
        let next = staged(&second, &root).unwrap();
        assert_ne!(next, published);
        assert!(!leftover.exists(), "hard-linked staging name was retained");
        assert!(published.exists(), "a guarded published image was removed");
        assert_eq!(fs::read(&first).unwrap(), fs::read(guard.path()).unwrap());
    }

    #[test]
    fn interrupted_publication_does_not_retain_abandoned_binary_copies() {
        let fixture = Fixture::new();
        let source = fixture.source();
        let root = fixture.0.join("published");
        fs::create_dir(&root).unwrap();
        // Independent of the caller's umask: publication refuses group write.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        // An abrupt stop bypasses Temporary::drop. Model a complete copy left
        // before its hard-link publication; no worker or launch owns this file.
        let abandoned = root.join(".pending-2147483647-0");
        fs::copy(&source, &abandoned).unwrap();
        fs::set_permissions(&abandoned, fs::Permissions::from_mode(0o555)).unwrap();
        staged(&source, &root).unwrap();
        assert!(
            !abandoned.exists(),
            "a subsequent publication retained an abandoned binary copy"
        );
    }

    /// A restarted publisher can reuse a previous PID with its counter reset.
    /// Exclusive publisher ownership makes that old staging name reclaimable.
    #[test]
    fn reused_publisher_pid_does_not_refuse_abandoned_staging_name() {
        const FIXTURE: &str = "INFRATERNAL_REVIEW_REUSED_PUBLISHER";
        if std::env::var_os(FIXTURE).is_none() {
            // A dedicated process starts the publication counter at zero,
            // independent of other tests and without mutating shared state.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "login_binary::tests::reused_publisher_pid_does_not_refuse_abandoned_staging_name",
                    "--nocapture",
                ])
                .env(FIXTURE, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "restarted publication refused:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let fixture = Fixture::new();
        let source = fixture.0.join("source");
        fs::copy("/bin/true", &source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        let root = fixture.0.join("published");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        // Model a previous process that stopped before publication. Its
        // numeric PID has now been reused; no live writer owns the old inode.
        let abandoned = root.join(format!(".pending-{}-0", std::process::id()));
        fs::copy(&source, &abandoned).unwrap();
        fs::set_permissions(&abandoned, fs::Permissions::from_mode(0o555)).unwrap();
        let result = staged(&source, &root);
        assert!(
            result.is_ok(),
            "abandoned staging name refused a restarted publisher: {result:?}"
        );
    }
}
