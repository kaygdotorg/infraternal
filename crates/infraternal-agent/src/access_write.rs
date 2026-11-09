//! Ask the kernel about a host account's write authority, including ACLs.
//! One isolated setpriv child drops supplementary groups, gid and uid before running a
//! fixed shell builtin over path arguments. Paths are never evaluated as shell
//! code; the child does not execute a job or open its content. NSS or query
//! failures are unknown, never proof of lack of access.
use nix::unistd::User;
use std::{collections::BTreeSet, os::unix::fs::MetadataExt as _, path::PathBuf, process::Stdio};

/// Return indices the account can write or owns (an owner can chmod a read-only
/// file). The caller supplies bounded targets/parents and handles missing paths.
/// No credentials of the parent process are changed.
pub(crate) fn writable(account: &User, paths: &[PathBuf]) -> Option<BTreeSet<usize>> {
    if paths.len() > 4096
        || paths
            .iter()
            .map(|path| path.as_os_str().len())
            .sum::<usize>()
            > 128 * 1024
    {
        return None;
    }
    let groups = crate::access_privilege::account_groups(account)?;
    let shell = crate::logins::account_tool("sh")?;
    let setpriv = crate::logins::account_tool("setpriv")?;
    let groups = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if groups.is_empty() {
        return None;
    }
    let mut found = BTreeSet::new();
    for (index, path) in paths.iter().enumerate() {
        match std::fs::metadata(path) {
            Ok(meta) if meta.uid() == account.uid.as_raw() => {
                found.insert(index);
            }
            Ok(_) => {}
            // A file removed since it was listed is not writable as that file.
            // The job scan lists its parents too (recreating it needs one),
            // and the socket probe treats a missing socket as absent.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    let mut command = crate::sessions::isolated(&setpriv);
    command
        .args([
            "--no-new-privs",
            "--reuid",
            &account.uid.to_string(),
            "--regid",
            &account.gid.to_string(),
            "--groups",
            &groups,
            "--",
        ])
        .arg(shell);
    command
        .env_clear()
        .args([
            "-c",
            "i=0; for p do if [ -w \"$p\" ]; then printf '%s\\n' \"$i\"; fi; i=$((i+1)); done",
            "access-write",
        ])
        .args(paths)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = crate::access_privilege::command_output(command)?;
    for line in output.lines() {
        let index = line.parse::<usize>().ok()?;
        if index >= paths.len() {
            return None;
        }
        found.insert(index);
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    //! This test asks the real kernel, never a mode-bit imitation.
    use super::*;

    /// Retire this fixture directory even when a red assertion unwinds.
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        /// Cleanup is best effort during an assertion's panic.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    use std::os::unix::{fs::PermissionsExt as _, net::UnixListener};

    /// Host-root proof of group and named-user ACL access for an ordinary uid.
    #[test]
    #[ignore = "requires real root, Unix sockets and POSIX ACL support"]
    fn group_and_acl_write_authority_are_observed() {
        assert!(nix::unistd::Uid::effective().is_root());
        let user = User::from_name("nobody").unwrap().unwrap();
        let root = nix::unistd::mkdtemp("/tmp/rvwrite-XXXXXX").unwrap();
        let _cleanup = RemoveOnDrop(root.clone());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.join("socket");
        let _socket = UnixListener::bind(&path).unwrap();
        nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(0)), Some(user.gid)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let query = || {
            let user = user.clone();
            let paths = vec![path.clone()];
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    tokio::task::spawn_blocking(move || writable(&user, &paths))
                        .await
                        .unwrap()
                })
        };
        assert_eq!(query().unwrap(), BTreeSet::from([0]));
        nix::unistd::chown(
            &path,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(query().unwrap().is_empty());
        // The host fixture uses Python's safe xattr API to install a POSIX ACL;
        // the product probe itself relies only on kernel permission checks.
        let status = std::process::Command::new("/usr/bin/python3").args(["-c",
            "import os,struct,sys; uid=int(sys.argv[2]); acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in [(1,6,0xffffffff),(2,6,uid),(4,0,0xffffffff),(16,6,0xffffffff),(32,0,0xffffffff)]); os.setxattr(sys.argv[1],'system.posix_acl_access',acl)"
        ]).arg(&path).arg(user.uid.to_string()).status().unwrap();
        assert!(status.success());
        assert_eq!(query().unwrap(), BTreeSet::from([0]));
        std::fs::remove_dir_all(root).unwrap();
    }
}
