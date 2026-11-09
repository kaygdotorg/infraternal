//! Keeps binaries that systemd starts executable under `SELinux` (#401).
//!
//! systemd (`init_t`) may exec a service only from a file whose `SELinux` type is
//! an executable entrypoint. A file created under `/var` inherits its
//! directory's type instead: `var_t` under `/var/cache`, `var_lib_t` under
//! `/var/lib`. The policy refuses both, so the unit fails with `203/EXEC`.
//! Three kinds of image hit this: published login images (D240, D247), the
//! root infraternal agent installed by `up` or by SSH setup under
//! `/var/lib/infraternal`, and that agent after each update.
//!
//! [`executable_label`] gives one open file the policy's generic executable
//! type, `bin_t`. It keeps the user, role and level `SELinux` chose and leaves
//! files without an `SELinux` label alone, so hosts without `SELinux` behave
//! exactly as before. The host policy itself is never changed.
//! [`heal_running_image`] re-applies the label to the running root agent's
//! install image at start, so a later `restorecon` or full relabel cannot stop
//! the next restart. Rootless installs live under `~/.local/share`
//! (`data_home_t`), which the user's own service manager may already exec.
#![forbid(unsafe_code)]

use std::{fs::File, io, path::Path};

/// The extended attribute that holds a file's `SELinux` context.
#[cfg(target_os = "linux")]
pub(crate) const SELINUX_ATTRIBUTE: &str = "security.selinux";

/// The `SELinux` type our executables carry: the policy's generic type for
/// programs in `/usr/bin` and `/usr/libexec`, which systemd may exec as a
/// service entrypoint.
#[cfg(target_os = "linux")]
pub(crate) const EXECUTABLE_TYPE: &[u8] = b"bin_t";

/// Where root installs keep the infraternal agent binaries that systemd runs:
/// `up` publishes `bin/infraternal`, SSH setup publishes `bin/live`.
const ROOT_INSTALL_BINARIES: &str = "/var/lib/infraternal/bin/";

/// Give an executable an `SELinux` context that systemd may exec, keeping the
/// user, role and level `SELinux` chose for the file and replacing only its type.
///
/// A file has a `security.selinux` attribute only while `SELinux` labels the
/// filesystem, so a file without one (no `SELinux`, or a filesystem without
/// labels) is left alone. The label is read back after writing. A policy
/// without `bin_t`, or a domain that may not relabel, fails here, before the
/// file is published: callers log the reason, instead of a later opaque
/// `203/EXEC` in the unit. Call it on a private staging descriptor before the
/// file becomes visible under its final name.
/// # Errors
/// Every failure is a [`label_failure`]: a host or policy condition, never a
/// malformed request.
#[cfg(target_os = "linux")]
pub fn executable_label(file: &File) -> io::Result<()> {
    use xattr::FileExt as _;
    let current = match file.get_xattr(SELINUX_ATTRIBUTE) {
        Ok(Some(current)) => current,
        Ok(None) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(nix::libc::EOPNOTSUPP) => return Ok(()),
        Err(error) => {
            return Err(label_failure(&format!(
                "cannot read its SELinux label: {error}"
            )));
        }
    };
    let wanted = with_type(&current, EXECUTABLE_TYPE)
        .ok_or_else(|| label_failure("its SELinux label is unreadable"))?;
    if context(&current) == context(&wanted) {
        return Ok(());
    }
    file.set_xattr(SELINUX_ATTRIBUTE, &wanted)
        .map_err(|error| label_failure(&format!("cannot label it bin_t for SELinux: {error}")))?;
    match file.get_xattr(SELINUX_ATTRIBUTE) {
        Ok(Some(applied)) if context(&applied) == context(&wanted) => Ok(()),
        _ => Err(label_failure("SELinux kept a non-executable label on it")),
    }
}

/// An infraternal executable that could not be made executable for `SELinux`
/// (#401).
///
/// The kind is `Unsupported`, as for a `noexec` cache filesystem: the host or
/// its policy does not allow it, the request itself was fine. A terminal open
/// is therefore refused as unavailable, not as an invalid request.
#[cfg(target_os = "linux")]
pub(crate) fn label_failure(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("infraternal executable: {reason}"),
    )
}

/// Other systems have no `SELinux` labels to keep.
#[cfg(not(target_os = "linux"))]
pub fn executable_label(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Re-label the running root infraternal agent's own install image (#401).
///
/// Only an image under [`ROOT_INSTALL_BINARIES`], owned by root and writable by
/// nobody else, is touched: a binary the administrator placed elsewhere (a
/// package, `/opt`) keeps the label the host policy gives it. A replaced or
/// deleted image (after an update) is skipped, because the new one was labelled
/// when it was published. Rootless agents return at once.
/// # Errors
/// Returns failures to inspect or label the install image.
pub fn heal_running_image() -> io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    heal_image(&std::env::current_exe()?, Path::new(ROOT_INSTALL_BINARIES))
}

/// [`heal_running_image`] for an explicit image and install directory, so tests
/// can use a private directory.
fn heal_image(image: &Path, install: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if !image.starts_with(install)
        || image
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)")
    {
        return Ok(());
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(image)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Ok(());
    }
    executable_label(&file)
}

/// A context without the trailing NUL that the kernel may include.
#[cfg(target_os = "linux")]
pub(crate) fn context(label: &[u8]) -> &[u8] {
    label.strip_suffix(b"\0").unwrap_or(label)
}

/// Replace the type field of an `SELinux` context `user:role:type[:level]`.
///
/// The level may itself contain colons (`s0:c0.c1023`), so only the first three
/// separators split fields. Returns `None` unless user, role and type are all
/// present and non-empty. The result ends with a NUL, as `SELinux`'s own tools
/// write it.
#[cfg(target_os = "linux")]
pub(crate) fn with_type(label: &[u8], kind: &[u8]) -> Option<Vec<u8>> {
    let mut fields = context(label).splitn(4, |byte| *byte == b':');
    let user = fields.next().filter(|field| !field.is_empty())?;
    let role = fields.next().filter(|field| !field.is_empty())?;
    fields.next().filter(|field| !field.is_empty())?;
    let level = fields.next();
    let mut result = [user, role, kind].join(&b':');
    if let Some(level) = level {
        result.push(b':');
        result.extend_from_slice(level);
    }
    result.push(0);
    Some(result)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Label parsing runs everywhere; labelling itself runs where the test
    //! filesystem carries `SELinux` labels (the enforcing guest in #401).
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use xattr::FileExt as _;

    /// Only the type field changes; user, role and an MLS level that contains
    /// colons survive, and malformed contexts are refused.
    #[test]
    fn selinux_type_rewrite_keeps_user_role_and_level() {
        assert_eq!(
            with_type(b"system_u:object_r:var_t:s0\0", b"bin_t").unwrap(),
            b"system_u:object_r:bin_t:s0\0"
        );
        assert_eq!(
            with_type(b"unconfined_u:object_r:cache_home_t:s0:c0.c1023", b"bin_t").unwrap(),
            b"unconfined_u:object_r:bin_t:s0:c0.c1023\0"
        );
        assert_eq!(
            with_type(b"user_u:object_r:var_t", b"bin_t").unwrap(),
            b"user_u:object_r:bin_t\0"
        );
        for malformed in [
            &b""[..],
            b"\0",
            b"system_u",
            b"system_u:object_r",
            b"a::var_t:s0",
        ] {
            assert!(with_type(malformed, b"bin_t").is_none(), "{malformed:?}");
        }
    }

    /// A private scratch directory under the test account's cache.
    fn scratch(name: &str) -> std::path::PathBuf {
        let directory = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/exec-label")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// The `SELinux` type of a file, or `None` where the filesystem has no labels.
    fn kind(path: &Path) -> Option<Vec<u8>> {
        let label = File::open(path)
            .unwrap()
            .get_xattr(SELINUX_ATTRIBUTE)
            .unwrap()?;
        Some(
            context(&label)
                .split(|byte| *byte == b':')
                .nth(2)
                .unwrap()
                .to_vec(),
        )
    }

    /// #401: the root agent's install image falls back to its directory's type
    /// after a relabel (`var_lib_t` on a real host), and systemd then refuses to
    /// start the agent. Healing at start gives it `bin_t` again, but only for
    /// our own non-shared image inside the install directory.
    #[test]
    fn healing_relabels_only_our_own_install_image() {
        let install = scratch("heal");
        let image = install.join("live");
        std::fs::write(&image, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outside = scratch("heal-outside").join("live");
        std::fs::copy(&image, &outside).unwrap();
        if kind(&image).is_none() {
            eprintln!("no SELinux labels on this filesystem; nothing to check");
            return;
        }
        assert_ne!(kind(&image).unwrap(), EXECUTABLE_TYPE);
        heal_image(&outside, &install).unwrap();
        assert_ne!(
            kind(&outside).unwrap(),
            EXECUTABLE_TYPE,
            "outside the install"
        );
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o775)).unwrap();
        heal_image(&image, &install).unwrap();
        assert_ne!(
            kind(&image).unwrap(),
            EXECUTABLE_TYPE,
            "group-writable image"
        );
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
        heal_image(&image, &install).unwrap();
        assert_eq!(kind(&image).unwrap(), EXECUTABLE_TYPE, "install image");
        let _ = std::fs::remove_dir_all(install);
        let _ = std::fs::remove_dir_all(outside.parent().unwrap());
    }
}
