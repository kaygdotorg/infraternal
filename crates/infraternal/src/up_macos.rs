//! Installs the Mac system service after the server approves a fresh machine (#483).
//!
//! The enrollment, running image and launchd job are separate publications.
//! Each path created by this attempt is tracked by inode until launchd runs
//! the job. An interrupted install can only roll back its own paths.
//!
//! A build with app windows also publishes the per-user desktop helper and
//! the signed capture app beside the service binary, root-owned, when the
//! release folder `up` runs from holds them. Both must be signed by the same
//! signer as this binary (the root service admits only such a helper), and
//! the copies carry no set-id bit or access-control list. The root service
//! starts that helper as the console user (D203 C2, #146); root ownership
//! keeps the person from swapping either one.
use super::{hash_stream, termination};
/// Data passed to the enrollment client before the system daemon starts.
pub(super) use infraternal_plugin_mesh::macos_service::MACHINE_DATA as SERVICE_DATA;
use infraternal_plugin_mesh::macos_service::{self, MACHINE_BASE, MACHINE_BINARY, MACHINE_STATE};
use std::{
    fs,
    io::{self, ErrorKind},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The launchd job `up` installs; also reported by `up --json` as `service`.
pub(super) const SERVICE_NAME: &str = macos_service::LABEL;
/// The launchd property list `macos_service` writes for that job.
const PLIST: &str = macos_service::PLIST;
/// How long `up` waits for launchd to report the started service as running.
const START_WAIT: Duration = Duration::from_secs(15);
/// The desktop helper's file name, in the release folder and beside the service.
#[cfg(feature = "desktop")]
const DESKTOP_HELPER: &str = "infraternal-desktop-helper";
/// The signed capture app's folder name, in the release folder and beside the service.
#[cfg(feature = "desktop")]
const CAPTURE_APP: &str = "InfraternalCaptureHelper.app";

/// Explain a local refusal in words a person can act on, with no private input.
fn refused(message: String) -> io::Error {
    io::Error::new(ErrorKind::AlreadyExists, message)
}

/// Inspect a path itself (a dangling link counts as present) without following it.
fn existing(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Refuse a Mac that already has any part of a machine install.
///
/// Runs twice: once as the person before the approval is requested, so a
/// conflict never wastes a passkey approval, and again as root before the
/// first write. Existing installations are managed by their own service.
pub(super) fn preflight() -> io::Result<()> {
    for path in [
        MACHINE_BASE,
        PLIST,
        // An install of a build before the move to `kayg.infraternal` (#580) is still an install.
        infraternal_plugin_mesh::macos_user_mode::legacy::DAEMON_PLIST,
        super::PATH_BINARY,
        "/var/lib/infraternal/agent",
        "/var/lib/infraternal/state",
    ] {
        if existing(Path::new(path))?.is_some() {
            return Err(refused(format!(
                "{path} already exists. Manage the existing installation before running infraternal up again."
            )));
        }
    }
    if nix::unistd::Uid::effective().is_root()
        && macos_service::control("status", false, Path::new(MACHINE_BINARY), false)?
            .is_some_and(|status| status.loaded)
    {
        return Err(refused(
            "The infraternal launchd job is already loaded.".to_owned(),
        ));
    }
    Ok(())
}

/// One path this run created, and how rollback removes it.
struct Created {
    /// The path as published.
    path: PathBuf,
    /// Its own inode, so a replacement at the same name is never removed.
    identity: (u64, u64),
    /// Directories that later receive files we do not track one by one (the
    /// enrolment, the mesh state) are removed with their contents.
    recursive: bool,
}

/// A fresh install owned by this run until the service is confirmed running.
pub(super) struct Install {
    /// Hold the system lock through activation and any rollback in Drop.
    lock: macos_service::MachineLock,
    /// Paths created by this run, oldest first.
    created: Vec<Created>,
    /// Set once the service install was attempted, so rollback stops it.
    service: bool,
    /// The PATH alias belongs to this install only if it created the link.
    alias_created: bool,
    /// Set after launchd reports the service running; rollback is then skipped.
    committed: bool,
    /// Raised by the helper's signal scope; checked between steps.
    interrupted: Option<Arc<AtomicBool>>,
}

impl Install {
    /// Repeat the preflight as root, then create the private directories the join writes into.
    pub(super) fn begin() -> io::Result<Self> {
        if !nix::unistd::Uid::effective().is_root() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "This step needs root. Run infraternal up again and approve the sudo prompt.",
            ));
        }
        let lock = macos_service::MachineLock::acquire()?;
        preflight()?;
        let mut install = Self {
            lock,
            created: Vec::new(),
            service: false,
            alias_created: false,
            committed: false,
            interrupted: None,
        };
        super::check_directory(&fs::symlink_metadata("/Library/Application Support")?, 0)?;
        install.create_directory(Path::new(MACHINE_BASE), 0o711, false)?;
        install.directory(Path::new(SERVICE_DATA), 0o700, true)?;
        install.directory(Path::new(MACHINE_BASE).join("bin").as_path(), 0o755, false)?;
        Ok(install)
    }

    /// Attach the root helper's signal flag before enrolment can yield.
    #[must_use]
    pub(super) fn interrupt_on(mut self, interrupted: Arc<AtomicBool>) -> Self {
        self.interrupted = Some(interrupted);
        self
    }

    /// Stop between steps when a termination signal arrived.
    fn check_interruption(&self) -> io::Result<()> {
        if self
            .interrupted
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(termination::interrupted());
        }
        Ok(())
    }

    /// Remember a new path by inode for rollback.
    fn record(&mut self, path: &Path, recursive: bool) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        self.created.push(Created {
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
            recursive,
        });
        Ok(())
    }

    /// Create a missing directory with `mode`. An existing one must be root's and not writable by others.
    fn directory(&mut self, path: &Path, mode: u32, recursive: bool) -> io::Result<()> {
        if let Some(metadata) = existing(path)? {
            return super::check_directory(&metadata, 0);
        }
        self.create_directory(path, mode, recursive)
    }

    /// Claim a fresh directory privately, then publish its intended traversal permissions.
    ///
    /// Sudo can preserve a restrictive umask. After recording the new inode,
    /// explicitly allow traversal where the CLI link needs it. Enrollment stays private.
    fn create_directory(&mut self, path: &Path, mode: u32, recursive: bool) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        self.record(path, recursive)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    /// Copy the running image to the service binary path, verified and never over an existing file.
    fn binary(&mut self, source: &Path) -> io::Result<()> {
        self.publish(source, Path::new(MACHINE_BINARY))
    }

    /// Copy one executable to `destination`, verified and never over an existing file.
    fn publish(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        let mut input = fs::File::open(source)?;
        if !input.metadata()?.is_file() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "The running image is not a regular file. Run infraternal up from the downloaded binary.",
            ));
        }
        let staging =
            destination.with_file_name(format!(".infraternal-up-{}.pending", uuid::Uuid::new_v4()));
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&staging)?;
        let result = publish_binary(&mut input, output, &staging, destination);
        let _ = fs::remove_file(&staging);
        result?;
        self.record(destination, false)
    }

    /// Publish the desktop helper and the signed capture app beside the
    /// service binary, when the release folder `up` runs from has both.
    /// Without them the Mac still enrolls, with terminals only, and `up` says so.
    #[cfg(feature = "desktop")]
    fn desktop(&mut self, source: &Path) -> io::Result<()> {
        let bin = Path::new(MACHINE_BINARY)
            .parent()
            .ok_or_else(|| io::Error::other("missing service folder"))?;
        let release = source.parent().unwrap_or_else(|| Path::new("/"));
        let helper = release.join(DESKTOP_HELPER);
        let app = release.join(CAPTURE_APP);
        if !existing(&helper)?.is_some_and(|metadata| metadata.is_file())
            || !existing(&app)?.is_some_and(|metadata| metadata.is_dir())
        {
            eprintln!(
                "infraternal: app windows skipped; {DESKTOP_HELPER} and {CAPTURE_APP} were not next to this binary."
            );
            return Ok(());
        }
        // The root agent admits only a helper from its own signer, so a
        // build without a certificate would install a helper it then refuses.
        let Ok(signer) = infraternal_shim::code_identity::own_signer() else {
            eprintln!(
                "infraternal: app windows skipped; this infraternal build is not signed with a certificate."
            );
            return Ok(());
        };
        let destination = bin.join(DESKTOP_HELPER);
        self.publish(&helper, &destination)?;
        // Checked on the root-owned copy, which nobody else can change; a
        // failure rolls the published file back with the rest of the install.
        verify_signature(
            &destination,
            &infraternal_shim::code_identity::requirement(DESKTOP_HELPER, &signer)?,
        )?;
        self.check_interruption()?;
        self.capture_app(
            &app,
            &bin.join(CAPTURE_APP),
            &infraternal_shim::code_identity::signed_by(&signer),
        )
    }

    /// Copy the capture app bundle with its signature intact, make it root's
    /// with no group or other write bit, no set-id bit and no access-control
    /// list, check that it is signed by `requirement` (this binary's own
    /// signer), then publish it under its final name, never over an existing
    /// path.
    #[cfg(feature = "desktop")]
    fn capture_app(
        &mut self,
        source: &Path,
        destination: &Path,
        requirement: &str,
    ) -> io::Result<()> {
        if existing(destination)?.is_some() {
            return Err(refused(format!(
                "{} already exists.",
                destination.display()
            )));
        }
        // The staging name keeps the `.app` extension so codesign reads it as
        // a bundle, and a leading dot so nothing lists it as an app.
        let staging =
            destination.with_file_name(format!(".capture-{}.app", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            // ditto copies the bundle with its extended attributes and
            // signature; chown and chmod then take it away from the person.
            // Access-control lists are not copied: an entry granting the
            // person write access would outlive the chown, and the signature
            // seal does not cover it.
            run_tool(
                "/usr/bin/ditto",
                &["--noacl".as_ref(), source.as_os_str(), staging.as_os_str()],
            )?;
            run_tool(
                "/usr/sbin/chown",
                &[
                    "-R".as_ref(),
                    "-h".as_ref(),
                    "root:wheel".as_ref(),
                    staging.as_os_str(),
                ],
            )?;
            // Root's chown keeps set-id bits, and the signature seal does not
            // cover file modes: a set-uid bit planted in the release folder
            // would otherwise become a set-uid root program here.
            run_tool(
                "/bin/chmod",
                &["-R".as_ref(), "go-w,ug-s".as_ref(), staging.as_os_str()],
            )?;
            verify_signature(&staging, requirement)?;
            fs::rename(&staging, destination)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        self.record(destination, true)
    }

    /// Add `/usr/local/bin/infraternal` (and `infra` beside it) pointing at the service binary.
    fn command_links(&mut self) -> io::Result<()> {
        let path = Path::new(super::PATH_BINARY);
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("missing PATH directory"))?;
        // A fresh Mac does not always have /usr/local or /usr/local/bin.
        if existing(directory)?.is_none()
            && let Some(parent) = directory.parent()
            && existing(parent)?.is_none()
        {
            self.directory(parent, 0o755, false)?;
        }
        self.directory(directory, 0o755, false)?;
        std::os::unix::fs::symlink(MACHINE_BINARY, path)?;
        self.record(path, false)?;
        let alias = path.with_file_name("infra");
        let alias_present = existing(&alias)?.is_some();
        if infraternal_plugin_api::cli_alias::install(path, 0)? {
            if !alias_present {
                self.record(&alias, false)?;
                self.alias_created = true;
            }
        } else {
            eprintln!("infraternal: skipped infra; an existing path belongs to another command.");
        }
        Ok(())
    }

    /// Publish the binary and links, start the `LaunchDaemon`, and commit once launchd runs it.
    pub(super) fn activate(mut self, source: &Path, host: uuid::Uuid) -> io::Result<()> {
        self.check_interruption()?;
        self.binary(source)?;
        self.check_interruption()?;
        #[cfg(feature = "desktop")]
        self.desktop(source)?;
        self.check_interruption()?;
        self.command_links()?;
        self.check_interruption()?;
        let receipt = Path::new(MACHINE_BASE).join(macos_service::MACHINE_OWNER);
        let recorded =
            macos_service::record_installation(&host.simple().to_string(), self.alias_created);
        if existing(&receipt)?.is_some() {
            self.record(&receipt, false)?;
        }
        recorded?;
        let binary = Path::new(MACHINE_BINARY);
        let state = Path::new(MACHINE_STATE);
        let alias = binary.with_file_name("infra");
        let alias_existed = existing(&alias)?.is_some();
        self.service = true;
        // `mesh up --system-service`'s own install: checks the image, writes the
        // plist, creates the state directory and kickstarts the job.
        let installed = self.lock.set_service("up", binary);
        if existing(state)?.is_some() {
            self.record(state, true)?;
        }
        if !alias_existed && existing(&alias)?.is_some() {
            self.record(&alias, false)?;
        }
        if existing(Path::new(PLIST))?.is_some() {
            self.record(Path::new(PLIST), false)?;
        }
        installed?;
        let deadline = Instant::now() + START_WAIT;
        loop {
            self.check_interruption()?;
            if macos_service::control("status", false, binary, false)?
                .is_some_and(|status| status.running)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "launchd did not report the machine service as running",
                ));
            }
            // sleep: launchd exposes job readiness through polling.
            std::thread::sleep(Duration::from_millis(200));
        }
        self.committed = true;
        Ok(())
    }

    /// Stop the service if this run started it, then remove only this run's own paths.
    fn rollback(&mut self) {
        if self.service {
            // Bootout and disable; a job that never loaded is already stopped.
            let _ = self.lock.set_service("down", Path::new(MACHINE_BINARY));
        }
        for entry in self.created.drain(..).rev() {
            // Skip a path that is gone or now names another inode: not ours to remove.
            let Some(metadata) = existing(&entry.path)
                .ok()
                .flatten()
                .filter(|metadata| (metadata.dev(), metadata.ino()) == entry.identity)
            else {
                continue;
            };
            let result = if metadata.is_dir() && entry.recursive {
                fs::remove_dir_all(&entry.path)
            } else if metadata.is_dir() {
                fs::remove_dir(&entry.path)
            } else {
                fs::remove_file(&entry.path)
            };
            if let Err(error) = result {
                eprintln!(
                    "infraternal: could not remove {} during rollback ({:?}); remove it before retrying.",
                    entry.path.display(),
                    error.kind()
                );
            }
        }
    }
}

/// Check that the code at `path` has a valid, strict signature that meets
/// `requirement` (code requirement language), through `codesign`.
#[cfg(feature = "desktop")]
fn verify_signature(path: &Path, requirement: &str) -> io::Result<()> {
    run_tool(
        "/usr/bin/codesign",
        &[
            "--verify".as_ref(),
            "--strict".as_ref(),
            "-R".as_ref(),
            format!("={requirement}").as_ref(),
            path.as_os_str(),
        ],
    )
}

/// Run a system tool by absolute path with an empty environment and no
/// output; any failure, including a non-zero exit, is an error.
#[cfg(feature = "desktop")]
fn run_tool(program: &str, arguments: &[&std::ffi::OsStr]) -> io::Result<()> {
    let status = std::process::Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{program} failed while installing app windows"
        )))
    }
}

/// Fill the private staging file, check it, and link it to `destination` without replacing anything.
///
/// The copy is hashed on the way in and read back, so a short write or a
/// changed file fails here rather than at the first service start.
pub(super) fn publish_binary(
    input: &mut fs::File,
    output: fs::File,
    staging: &Path,
    destination: &Path,
) -> io::Result<()> {
    stage_binary(input, output, staging)?;
    // A hard link publishes without replacing: it fails if the name exists.
    fs::hard_link(staging, destination)
}

/// Copy `input` into the open `output` at `staging`, make it 0755, and check it.
///
/// The staged copy is hashed again from disk and must match what was read, and it must pass
/// the dyld check that a launchd job needs. Callers then publish `staging` under its final
/// name: a first install by hard link, a user-mode refresh by rename (#146).
/// # Errors
/// Reports a failed copy, a changed image, or a dyld check failure.
pub(super) fn stage_binary(
    input: &mut fs::File,
    mut output: fs::File,
    staging: &Path,
) -> io::Result<()> {
    let read = hash_stream(input, Some(&mut output))?;
    output.set_permissions(fs::Permissions::from_mode(0o755))?;
    output.sync_all()?;
    drop(output);
    if hash_stream(&mut fs::File::open(staging)?, None)? != read {
        return Err(io::Error::other(
            "installed binary differs from the running image",
        ));
    }
    // The LaunchDaemon refuses an image that could make dyld load a user's library.
    infraternal_plugin_mesh::macos_image::check_file(staging)
}

impl Drop for Install {
    /// An install dropped before commit (error, signal, panic) undoes itself.
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}
