//! Pins and authenticates the executable of an owned SSH prompt helper, including after anonymous-image replacement.

use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// The open inode prevents reuse; its digest also refuses same-owner in-place changes.
pub(crate) struct PromptImage {
    file: File,
    digest: [u8; 32],
}
impl PromptImage {
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let digest = hash(&mut file)?;
        Ok(Self { file, digest })
    }

    pub(crate) fn matches(&self, path: &Path) -> bool {
        let Ok(mut peer) = File::open(path) else {
            return false;
        };
        let Ok(expected) = self.file.metadata() else {
            return false;
        };
        let Ok(actual) = peer.metadata() else {
            return false;
        };
        actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && hash(&mut peer).is_ok_and(|digest| digest == self.digest)
    }
}

/// External SSH processes cannot resolve the server's /proc/self/exe themselves.
/// Copy only the kernel-pinned running image into the existing owned 0700 scope.
/// Close the writable descriptor before execution; secret admission separately
/// checks the child's kernel executable inode and original digest (ETXTBSY
/// prevents ordinary writes while that named executable is running).
pub(crate) fn materialize(
    source: &Path,
    directory: &Path,
) -> std::io::Result<(std::path::PathBuf, PromptImage)> {
    if source != Path::new("/proc/self/exe") {
        return Ok((source.to_owned(), PromptImage::open(source)?));
    }
    let mut input = File::open(source)?;
    let digest = hash(&mut input)?;
    input.rewind()?;
    let path = directory.join("askpass-image");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&path)?;
    let copied = std::io::copy(&mut (&mut input).take(MAX_IMAGE + 1), &mut output)?;
    if copied > MAX_IMAGE {
        return Err(std::io::Error::other("SSH helper image exceeds its limit"));
    }
    output.flush()?;
    output.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    drop(output);
    let file = File::open(&path)?;
    Ok((path, PromptImage { file, digest }))
}

// Native debug fixtures can exceed the release admission limit; this is the
// trusted kernel running image, never an incoming replacement candidate.
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
fn hash(file: &mut File) -> std::io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut bytes = vec![0; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        total += count as u64;
        if total > MAX_IMAGE {
            return Err(std::io::Error::other("SSH helper image exceeds its limit"));
        }
        digest.update(&bytes[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helper_identity_refuses_in_place_and_path_replacement() {
        let root = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap()
            .join(".cache/codex-scratch/ssh-bootstrap");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("prompt-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"original").unwrap();
        let image = PromptImage::open(&path).unwrap();
        assert!(image.matches(&path));
        std::fs::write(&path, b"modified").unwrap();
        assert!(!image.matches(&path));
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"original").unwrap();
        assert!(!image.matches(&path));
        std::fs::remove_file(path).unwrap();
    }
}
