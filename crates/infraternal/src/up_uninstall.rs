//! Use the Linux join journal to remove the installation it actually published.

use super::{
    existing,
    journal::{self, Journal, Snapshot},
    refused,
};
use crate::up::{
    HOST_FIREWALL_SERVICE, SERVICE_BINARY, SERVICE_DATA, SERVICE_NAME, SYSTEMCTL_CANDIDATES,
    run_systemctl,
};
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Fixed installation paths relative to the trusted system root.
const BASE: &str = "var/lib/infraternal";
/// The unit's public location, also inspected by the service status command.
const UNIT: &str = "etc/systemd/system/infraternal-agent.service";
/// The private policy published before the optional boot unit is started.
const FIREWALL_POLICY: &str = "var/lib/infraternal/host-firewall-agent.json";
/// Shared loader, checked against the join journal before either stop or unlink.
const FIREWALL_UNIT: &str = "etc/systemd/system/infraternal-firewall.service";
/// Loader enablement may predate this installation and must then survive.
const FIREWALL_WANTS: &str =
    "etc/systemd/system/network-pre.target.wants/infraternal-firewall.service";

/// A read-only preview whose journal also binds the administrator handoff.
pub(crate) struct Review {
    /// The host ID is private until the administrator repeats the review.
    pub host: Option<Uuid>,
    /// The committed journal, kept until the last cleanup step.
    pub anchor: PathBuf,
    /// Paths of the reviewed installation.
    pub paths: Vec<PathBuf>,
    /// Existing paths whose exact inode the privileged step needs to check.
    pub conditional: Vec<PathBuf>,
}

/// Select a committed Linux join or an unfinished removal of that join.
pub(crate) fn review(caller: u32) -> io::Result<Review> {
    review_at(Path::new("/"), 0, caller)
}

/// Keep fixture discovery on the same path as the production review.
fn review_at(root: &Path, owner: u32, caller: u32) -> io::Result<Review> {
    let state = journal::inspect(root, owner)?;
    let anchor = root.join(journal::NAME);
    let mut paths = vec![anchor.clone()];
    if state.needs_root && caller != owner {
        let unit = root.join(UNIT);
        if existing(&unit)?.is_some() {
            let text = infraternal_plugin_remote::uninstall::read_service_unit(&unit, owner)?;
            if !text.lines().any(|line| {
                line == format!("ExecStart={SERVICE_BINARY} agent run --data {SERVICE_DATA}")
            }) {
                return Err(io::ErrorKind::NotFound.into());
            }
        }
        let mut conditional = Vec::new();
        for name in [
            UNIT,
            FIREWALL_UNIT,
            FIREWALL_WANTS,
            FIREWALL_POLICY,
            BASE,
            "etc/systemd/system/multi-user.target.wants/infraternal-agent.service",
            "usr/local/bin/infraternal",
            "usr/local/bin/infra",
        ] {
            let path = root.join(name);
            match existing(&path) {
                Ok(Some(_)) => conditional.push(path),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    conditional.push(path);
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        return Ok(Review {
            host: None,
            anchor,
            paths,
            conditional,
        });
    }
    let host = host(root, owner, &state)?;
    for entry in &state.created {
        if state.recorded_inode(&entry.path)
            && entry.path != root.join(SERVICE_DATA.trim_start_matches('/'))
        {
            paths.push(entry.path.clone());
        }
    }
    if journaled_policy(root, &state, owner)?.is_some() {
        paths.push(root.join(FIREWALL_POLICY));
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(Review {
        host: Some(host),
        anchor,
        paths,
        conditional: Vec::new(),
    })
}

/// Read the still-owned enrollment or the host journaled before removal started.
fn host(root: &Path, owner: u32, state: &Snapshot) -> io::Result<Uuid> {
    if !state.committed {
        return Err(io::ErrorKind::NotFound.into());
    }
    let data = root.join(SERVICE_DATA.trim_start_matches('/'));
    let unit = root.join(UNIT);
    check_ancestors(root, &data, owner)?;
    check_ancestors(root, &unit, owner)?;
    if existing(&unit)?.is_some() && !state.recorded_inode(&unit)
        || existing(&data)?.is_some() && !state.recorded_inode(&data)
    {
        return Err(refused(
            "The Linux installation changed after it was recorded.",
        ));
    }
    match state.uninstalling {
        Some(host) => Ok(host),
        None if state.recorded_inode(&unit) && state.recorded_inode(&data) => {
            crate::remote::local_enrolled_host(&data, owner)
        }
        None => Err(refused("The Linux installation receipt is incomplete.")),
    }
}

/// Require real, protected directories before accessing a path below a journaled ancestor.
fn check_ancestors(root: &Path, path: &Path, owner: u32) -> io::Result<()> {
    let relative = path.strip_prefix(root).map_err(io::Error::other)?;
    let mut ancestor = root.to_path_buf();
    super::super::check_directory(&fs::symlink_metadata(root)?, owner)?;
    for component in relative
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?
        .components()
    {
        ancestor.push(component);
        let Some(metadata) = existing(&ancestor)? else {
            break;
        };
        super::super::check_directory(&metadata, owner)?;
    }
    Ok(())
}

/// Run the systemd and kernel steps with the journal held through deletion.
pub(crate) fn remove(expected: Uuid, keep: bool, anchor: &str) -> io::Result<Vec<String>> {
    let root = Path::new("/");
    let manager = crate::trusted_program::trusted_program(&SYSTEMCTL_CANDIDATES, 0)
        .map_err(|_| refused("Could not resolve the system service manager."))?;
    remove_at(
        root,
        0,
        expected,
        keep,
        anchor,
        |args| run_systemctl(&manager, args, None),
        |filesystem, snapshot| {
            let runtime = infraternal_agent::sessions::state_path(None)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(infraternal_plugin_remote::uninstall::retire_sessions(
                    &runtime, 0,
                ))?;
            let reports = (infraternal_agent::plugins::KERNEL.retire)(&runtime)?;
            infraternal_plugin_api::mesh_ssh_files::remove_client_files(filesystem)?;
            let shared = clear_firewall(filesystem, snapshot)?;
            Ok((
                reports
                    .into_iter()
                    .map(infraternal_plugin_remote::uninstall::left_line)
                    .collect(),
                shared,
            ))
        },
    )
}

/// Remove the reviewed join in restartable order. Callbacks keep fixtures off the real systemd and kernel.
fn remove_at(
    root: &Path,
    owner: u32,
    expected: Uuid,
    keep: bool,
    anchor: &str,
    manager: impl Fn(&[&str]) -> io::Result<()>,
    retire: impl FnOnce(&Path, &Snapshot) -> io::Result<(Vec<String>, bool)>,
) -> io::Result<Vec<String>> {
    let (mut journal, state) = Journal::open_removal(root, owner)?;
    let current = fs::symlink_metadata(root.join(journal::NAME))?;
    if format!("{}:{}", current.dev(), current.ino()) != anchor
        || host(root, owner, &state)? != expected
    {
        return Err(refused(
            "The Linux installation changed after the uninstall review.",
        ));
    }
    let base = root.join(BASE);
    let data = root.join(SERVICE_DATA.trim_start_matches('/'));
    let backup =
        infraternal_plugin_api::uninstall_state::destination(&base, &expected.simple().to_string());
    if keep {
        infraternal_plugin_api::uninstall_state::check_destination(&data, &backup, owner)?;
    }
    if state.uninstalling.is_none() {
        journal.start_removal(expected)?;
    }
    if state.recorded_inode(&root.join(UNIT)) {
        manager(&["stop", SERVICE_NAME])?;
    }
    let (mut left, shared_loader) = retire(root, &state)?;
    if !shared_loader && state.recorded_inode(&root.join(FIREWALL_UNIT)) {
        manager(&["stop", HOST_FIREWALL_SERVICE])?;
    }
    if keep {
        infraternal_plugin_api::uninstall_state::preserve(&data, &backup, owner)?;
    }
    // Delete manager paths and reload before removing the running image. A
    // retry still has an executable even if activation cleanup fails.
    let unit_dir = root.join("etc/systemd/system");
    let firewall_unit = root.join(FIREWALL_UNIT);
    let firewall_wants = root.join(FIREWALL_WANTS);
    for entry in state
        .created
        .iter()
        .rev()
        .filter(|entry| entry.path.starts_with(&unit_dir))
    {
        if shared_loader && (entry.path == firewall_unit || entry.path == firewall_wants) {
            continue;
        }
        remove_entry(root, owner, entry, &mut left)?;
    }
    manager(&["daemon-reload"])?;
    // Do not take the PATH link away until all other substantive cleanup is done.
    let command = root.join("usr/local/bin/infraternal");
    let image = root.join(SERVICE_BINARY.trim_start_matches('/'));
    for entry in state.created.iter().rev().filter(|entry| {
        !entry.path.starts_with(&unit_dir)
            && entry.path != command
            && entry.path != image
            && !image.starts_with(&entry.path)
            && !command.starts_with(&entry.path)
    }) {
        remove_entry(root, owner, entry, &mut left)?;
    }
    for entry in state.created.iter().rev().filter(|entry| {
        entry.path == command
            || entry.path == image
            || image.starts_with(&entry.path)
            || command.starts_with(&entry.path)
    }) {
        remove_entry(root, owner, entry, &mut left)?;
    }
    journal.finish_removal(owner)?;
    Ok(left)
}

/// A foreign replacement remains untouched, and only the private enrollment owns descendants.
fn remove_entry(
    root: &Path,
    owner: u32,
    entry: &super::Created,
    left: &mut Vec<String>,
) -> io::Result<()> {
    check_ancestors(root, &entry.path, owner)?;
    let Some(metadata) = existing(&entry.path)? else {
        return Ok(());
    };
    if entry.identity != (metadata.dev(), metadata.ino()) || metadata.uid() != owner {
        left.push(format!(
            "Left {} because it belongs to another installation.",
            entry.path.display()
        ));
        return Ok(());
    }
    if entry.enrollment {
        fs::remove_dir_all(&entry.path)?;
    } else if metadata.is_dir() {
        if let Err(error) = fs::remove_dir(&entry.path) {
            if error.kind() != io::ErrorKind::DirectoryNotEmpty {
                return Err(error);
            }
            left.push(format!(
                "Left {} because it contains other files.",
                entry.path.display()
            ));
            return Ok(());
        }
    } else {
        fs::remove_file(&entry.path)?;
    }
    // The journal is the last durable deletion, even when /var and /etc have separate filesystems.
    fs::File::open(entry.path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
}

/// Retire the owned agent rules and leave the loader if another role needs it.
fn clear_firewall(root: &Path, state: &Snapshot) -> io::Result<bool> {
    #[cfg(any(feature = "plugin-mesh", feature = "plugin-server"))]
    {
        use infraternal_plugin_mesh::host_firewall::{self, HostFirewallPaths};
        let paths = HostFirewallPaths::under(root);
        if journaled_policy(root, state, 0)?.is_some() {
            host_firewall::clear_installed_agent_rules_at(&paths, None)
                .map_err(io::Error::other)?;
            fs::File::open(root.join(BASE))?.sync_all()?;
        }
        Ok(existing(paths.server_policy_path())?.is_some()
            || existing(paths.agent_policy_path())?.is_some())
    }
    #[cfg(not(any(feature = "plugin-mesh", feature = "plugin-server")))]
    if journaled_policy(root, state, 0)?.is_some() {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Use a build with Mesh support to remove the installed host firewall.",
        ))
    } else {
        Ok(false)
    }
}

/// The live agent atomically rewrites its reserved policy when the Mesh UDP
/// listener changes. Verify that marked file against the original publication,
/// even if the current inode differs.
fn journaled_policy(root: &Path, state: &Snapshot, owner: u32) -> io::Result<Option<PathBuf>> {
    let path = root.join(FIREWALL_POLICY);
    if !state.created.iter().any(|entry| entry.path == path) || existing(&path)?.is_none() {
        return Ok(None);
    }
    #[cfg(any(feature = "plugin-mesh", feature = "plugin-server"))]
    infraternal_plugin_mesh::host_firewall::read_policy_file_for_owner(&path, owner)
        .map_err(io::Error::other)?;
    #[cfg(not(any(feature = "plugin-mesh", feature = "plugin-server")))]
    let _ = owner;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    //! Exercise actual journal and filesystem transitions with an isolated service manager.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::{
        cell::Cell,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };

    /// Seed the same committed journal and public layout that a Linux join leaves.
    fn installed(root: &Path, owner: u32, host: Uuid) {
        let (mut journal, _) = Journal::open(root, owner).unwrap();
        journal.begin().unwrap();
        for (name, dir, enrollment) in [
            (BASE, true, false),
            ("var/lib/infraternal/agent", true, true),
            ("var/lib/infraternal/bin", true, false),
            ("var/lib/infraternal/bin/infraternal", false, false),
            (UNIT, false, false),
            (FIREWALL_UNIT, false, false),
            (FIREWALL_WANTS, false, false),
            (FIREWALL_POLICY, false, false),
            ("usr/local/bin/infraternal", false, false),
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if dir {
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            } else if name == "usr/local/bin/infraternal" {
                std::os::unix::fs::symlink(SERVICE_BINARY, &path).unwrap();
            } else {
                fs::write(&path, b"fixture").unwrap();
            }
            #[cfg(any(feature = "plugin-mesh", feature = "plugin-server"))]
            if name == FIREWALL_POLICY {
                use infraternal_plugin_mesh::host_firewall;
                fs::write(
                    &path,
                    host_firewall::serialize_policy_file(&host_firewall::Policy::default())
                        .unwrap(),
                )
                .unwrap();
            }
            journal
                .record(&path, &fs::symlink_metadata(&path).unwrap(), enrollment)
                .unwrap();
        }
        let identity = root.join("var/lib/infraternal/agent/identity.json");
        fs::write(
            &identity,
            serde_json::to_vec(&serde_json::json!({
                "host_id": host, "execution_uid": owner, "server_name": "local",
                "ca_der": "", "certificate_der": "", "key_der": ""
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(identity, fs::Permissions::from_mode(0o600)).unwrap();
        journal.commit().unwrap();
    }

    /// The same Linux join resumes after stops, kernel cleanup, a backup, and unit unlink.
    #[test]
    fn linux_up_uninstall_resumes_through_published_boundaries() {
        let root = std::env::temp_dir().join(format!("lu-{}", Uuid::new_v4().simple()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        for failing_step in ["agent-stop", "kernel", "firewall-stop", "manager-reload"] {
            let trial = root.join(failing_step);
            fs::create_dir(&trial).unwrap();
            let host = Uuid::new_v4();
            installed(&trial, owner, host);
            let foreign = trial.join("usr/local/bin/infra");
            fs::write(&foreign, b"foreign command").unwrap();
            let before = review_at(&trial, owner, owner).unwrap();
            assert_eq!(before.host, Some(host));
            assert!(before.paths.contains(&trial.join(FIREWALL_WANTS)));
            let metadata = fs::symlink_metadata(before.anchor).unwrap();
            let anchor = format!("{}:{}", metadata.dev(), metadata.ino());
            let fired = Cell::new(false);
            let cut = |step| {
                if step == failing_step && !fired.replace(true) {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            };
            let interrupted = remove_at(
                &trial,
                owner,
                host,
                true,
                &anchor,
                |args| match args {
                    ["stop", SERVICE_NAME] => cut("agent-stop"),
                    ["stop", HOST_FIREWALL_SERVICE] => cut("firewall-stop"),
                    ["daemon-reload"] => cut("manager-reload"),
                    _ => panic!("unexpected service action {args:?}"),
                },
                |_, _| cut("kernel").map(|()| (Vec::new(), false)),
            )
            .unwrap_err();
            assert_eq!(interrupted.kind(), io::ErrorKind::Interrupted);
            assert_eq!(review_at(&trial, owner, owner).unwrap().host, Some(host));
            let base = trial.join(BASE);
            let backup = infraternal_plugin_api::uninstall_state::destination(
                &base,
                &host.simple().to_string(),
            );
            if failing_step == "manager-reload" {
                assert!(!trial.join(UNIT).exists());
                assert!(backup.join("enrollment/identity.json").is_file());
            }
            remove_at(
                &trial,
                owner,
                host,
                true,
                &anchor,
                |_| Ok(()),
                |_, _| Ok((Vec::new(), false)),
            )
            .unwrap();
            assert!(!base.exists());
            assert!(backup.join("enrollment/identity.json").is_file());
            assert!(!trial.join(journal::NAME).exists());
            assert!(!trial.join(UNIT).exists());
            assert!(!trial.join(FIREWALL_UNIT).exists());
            assert!(!trial.join(FIREWALL_POLICY).exists());
            assert!(!trial.join("usr/local/bin/infraternal").is_symlink());
            assert_eq!(fs::read(foreign).unwrap(), b"foreign command");
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// An atomic listener update keeps the agent's policy owned without trusting an arbitrary file.
    #[cfg(any(feature = "plugin-mesh", feature = "plugin-server"))]
    #[test]
    fn linux_up_review_includes_a_rewritten_agent_firewall_policy() {
        let root = std::env::temp_dir().join(format!("lu-{}", Uuid::new_v4().simple()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        installed(&root, owner, Uuid::new_v4());
        let path = root.join(FIREWALL_POLICY);
        let previous = path.with_extension("old");
        fs::rename(&path, &previous).unwrap();
        fs::copy(&previous, &path).unwrap();
        let state = journal::inspect(&root, owner).unwrap();
        assert!(!state.recorded_inode(&path));
        assert_eq!(
            journaled_policy(&root, &state, owner).unwrap(),
            Some(path.clone())
        );
        assert!(
            review_at(&root, owner, owner)
                .unwrap()
                .paths
                .contains(&path)
        );
        fs::write(&path, b"foreign policy").unwrap();
        assert!(journaled_policy(&root, &state, owner).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
