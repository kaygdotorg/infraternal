//! Keeps binaries that systemd starts executable under `SELinux` (#401).
//!
//! systemd (`init_t`) may exec a service only from a file whose `SELinux` type is
//! an executable entrypoint. A file created under `/var` inherits its
//! directory's type instead (`var_t` under `/var/cache`), which the policy
//! refuses, so the unit fails with `203/EXEC`.
//!
//! [`executable_label`] gives one open file the policy's generic executable
//! type, `bin_t`. It keeps the user, role and level `SELinux` chose and leaves
//! files without an `SELinux` label alone, so hosts without `SELinux` behave
//! exactly as before. The host policy itself is never changed.
#![forbid(unsafe_code)]

use std::{fs::File, io};

/// The extended attribute that holds a file's `SELinux` context.
#[cfg(target_os = "linux")]
pub(crate) const SELINUX_ATTRIBUTE: &str = "security.selinux";

/// The `SELinux` type our executables carry: the policy's generic type for
/// programs in `/usr/bin` and `/usr/libexec`, which systemd may exec as a
/// service entrypoint.
#[cfg(target_os = "linux")]
pub(crate) const EXECUTABLE_TYPE: &[u8] = b"bin_t";

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
    //! Label parsing runs everywhere.
    use super::*;

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
}
