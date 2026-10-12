//! Pins replacement code to one opened inode and separates root-only CA transfer from cold compatibility [217], #154.

use std::os::fd::AsRawFd;
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, PathBuf},
};

pub(crate) struct Opened {
    pub file: File,
    pub path: PathBuf,
    pub warm: bool,
}
impl Opened {
    pub(crate) fn open(path: PathBuf) -> io::Result<Self> {
        #[cfg(test)]
        TEST_OPENS.with(|count| count.set(count.get() + 1));
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Refuse FIFO/device candidates without waiting for a writer before
        // fstat can validate the inode. Never follow the final symlink, and keep
        // the checked image close-on-exec until fexecve consumes this exact fd.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        let owner = nix::unistd::Uid::effective().as_raw();
        if !metadata.is_file()
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o6022 != 0
            || (metadata.uid() != owner && metadata.uid() != 0)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Only a regular inode reaches any read/signature/ELF probe. Preserve
        // every other status flag when returning to ordinary blocking reads.
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)?;
        let flags = nix::fcntl::OFlag::from_bits_retain(flags);
        nix::fcntl::fcntl(
            &file,
            nix::fcntl::FcntlArg::F_SETFL(flags & !nix::fcntl::OFlag::O_NONBLOCK),
        )?;
        // A closed standard descriptor can be reused by open. Keep the checked
        // image above fd2 so stdin redirection cannot overwrite its inode handle.
        // Clones retain this exact inode; the target pathname is still opened once.
        let mut reserved = Vec::new();
        while file.as_raw_fd() < 3 {
            let duplicate = file.try_clone()?;
            reserved.push(file);
            file = duplicate;
        }
        drop(reserved);
        let mut root_protected = metadata.uid() == 0;
        let mut private = false;
        let ancestors: Vec<_> = path
            .parent()
            .ok_or(io::ErrorKind::InvalidInput)?
            .ancestors()
            .collect();
        for parent in ancestors.iter().rev() {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir()
                || (metadata.uid() != owner && metadata.uid() != 0)
                || metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0 && !private)
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            root_protected &= metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
            if metadata.uid() == owner && metadata.mode() & 0o777 == 0o700 {
                private = true;
            }
        }
        verify_release_fd(&file)?;
        let warm = owner == 0
            && root_protected
            && infraternal_server::ca_handoff_binary::capable(&file).unwrap_or(false);
        Ok(Self { file, path, warm })
    }
}

/// D184/D224 integration hook: verify SSHSIG namespace `infraternal-release`
/// against `release/allowed_signers` on this already-opened fd. No pathname reopen
/// is permitted here. This round checks compatibility/ownership, not signatures.
#[allow(clippy::unnecessary_wraps)] // Preserve the fallible signature for release verification.
fn verify_release_fd(_file: &File) -> io::Result<()> {
    // Release-signature enforcement belongs to the signed-update lane.
    Ok(())
}

#[cfg(test)]
std::thread_local! { static TEST_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_test_opens() {
    TEST_OPENS.with(|count| count.set(0));
}
#[cfg(test)]
pub(crate) fn test_opens() -> usize {
    TEST_OPENS.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "restart_signature_audit_tests.rs"]
mod audit_tests;
