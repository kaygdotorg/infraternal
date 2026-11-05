//! The files mesh SSH writes on a client machine, shared so uninstall removes exactly them [D235 Q2], #221.
//!
//! The mesh SSH component writes them; uninstalling the infraternal agent
//! removes them. Both use these paths so they cannot drift apart. Removal
//! checks content, so a file of the same name that infraternal did not write
//! is left alone.

use std::{
    io,
    path::{Path, PathBuf},
};

/// The one `ssh_config.d` file (D235 Q2).
pub const CONFIG_PATH: &str = "/etc/ssh/ssh_config.d/50-infraternal-mesh.conf";
/// The known-hosts file with the mesh CA's `@cert-authority` line.
pub const KNOWN_HOSTS_PATH: &str = "/etc/ssh/infraternal-mesh-known_hosts";
/// The key socket's own directory, traversable by every account.
pub const SOCKET_DIRECTORY: &str = "/run/infraternal-mesh-ssh";
/// The key socket.
pub const SOCKET_PATH: &str = "/run/infraternal-mesh-ssh/agent.sock";
/// The first line of the config file starts with this.
pub const HEADER: &str = "# Managed by infraternal: mesh SSH";

/// `path` under `root` (`/` in production; a scratch directory in tests).
fn under(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// Remove a file only if its content starts with `prefix`.
fn remove_if_ours(path: &Path, prefix: &str) -> io::Result<()> {
    match std::fs::read_to_string(path) {
        Ok(content) if content.starts_with(prefix) => std::fs::remove_file(path),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Remove the `ssh_config.d` file and the known-hosts file under `root`, each
/// only if infraternal wrote it (checked by content). The mesh SSH component
/// uses this when a person's client is turned off; the key socket stays.
///
/// # Errors
/// Returns filesystem errors other than a missing file.
pub fn remove_client_config(root: &Path) -> io::Result<()> {
    remove_if_ours(&under(root, CONFIG_PATH), HEADER)?;
    remove_if_ours(&under(root, KNOWN_HOSTS_PATH), "@cert-authority ")
}

/// Remove the mesh SSH client files under `root`.
///
/// # Errors
/// Returns filesystem errors other than a missing file.
pub fn remove_client_files(root: &Path) -> io::Result<()> {
    remove_client_config(root)?;
    match std::fs::remove_file(under(root, SOCKET_PATH)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    match std::fs::remove_dir(under(root, SOCKET_DIRECTORY)) {
        Err(error)
            if !matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Err(error)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "mesh_ssh_files_tests.rs"]
mod tests;
