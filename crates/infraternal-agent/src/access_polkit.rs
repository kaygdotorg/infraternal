//! Conservative polkit inspection for the revoke access report (#355).
//! JavaScript rules can call arbitrary policy helpers, so this does not try to
//! interpret them. Only exact known default content or ASCII whitespace-only files
//! can prove no additional authority. Unknown policy is privileged.
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use nix::unistd::User;
use sha2::{Digest as _, Sha256};

/// Current and legacy policy locations. Legacy admin-identity configuration is
/// included because it can give an ordinary account administrative authority.
const POLICY_ROOTS: &[(&str, &str)] = &[
    ("/etc/polkit-1/rules.d", "rules"),
    ("/run/polkit-1/rules.d", "rules"),
    ("/usr/local/share/polkit-1/rules.d", "rules"),
    ("/usr/share/polkit-1/rules.d", "rules"),
    ("/etc/polkit-1/localauthority", "pkla"),
    ("/var/lib/polkit-1/localauthority", "pkla"),
    ("/etc/polkit-1/localauthority.conf.d", "conf"),
    ("/etc/polkit-1/actions", "policy"),
    ("/run/polkit-1/actions", "policy"),
    ("/usr/share/polkit-1/actions", "policy"),
    ("/usr/local/share/polkit-1/actions", "policy"),
];

/// One scan's limits, shared across all policy trees. Exhaustion is unknown,
/// never an empty result; policy content is not recorded or returned.
struct Budget {
    /// Directory entries still available, including irrelevant extensions.
    entries: usize,
    /// Aggregate policy bytes still available.
    bytes: usize,
    /// Deadline checked between filesystem operations.
    deadline: Instant,
}

/// Exact packaged defaults observed on the supported proof hosts. These hashes
/// identify content, never filenames: editing or appending a rule invalidates
/// the exception. The admin rule only selects the sudo group, which the outer
/// privilege check independently checks. The network rule names one account.
fn rule_allows_or_unknown(text: &[u8], user: &str) -> bool {
    // sha2 0.11 digests are byte arrays without `LowerHex`; format them the
    // way the startup trust check does.
    let digest = format!("{:x}", base16ct::HexDisplay(&Sha256::digest(text)));
    match digest.as_str() {
        "29f073ed9a8a6996b62f718e2bec962d5c84d311d23bb874830b4f9887eeabbf" => false,
        "f199e386a9297858331b00df07ed0b0ee5fcf4bea67f6c0bccc8a92b7e310bbd" => {
            user == "systemd-network"
        }
        // Do not parse JavaScript comments: its line terminators differ from
        // Rust's. Every non-whitespace unknown file is executable policy for
        // this decision, even when it appears to contain only a comment.
        _ => text.iter().any(|byte| !byte.is_ascii_whitespace()),
    }
}

/// Read a protected regular policy file with no symlink following or blocking
/// special files. Oversized, unreadable or writable policy fails closed.
fn policy_allows_or_unknown(path: &Path, user: &str, budget: &mut Budget) -> bool {
    let Ok(file) = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    else {
        return true;
    };
    let Ok(metadata) = file.metadata() else {
        return true;
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return true;
    }
    let mut bytes = Vec::new();
    if file.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
        return true;
    }
    let Some(remaining) = budget.bytes.checked_sub(bytes.len()) else {
        return true;
    };
    budget.bytes = remaining;
    if path.extension().is_some_and(|value| value == "policy") {
        // Reading still establishes ownership, size and completeness. Effective
        // XML defaults are inspected through pkaction after all files are read.
        false
    } else {
        rule_allows_or_unknown(&bytes, user)
    }
}

/// Inspect bounded policy subtrees, including legacy category directories.
/// Every directory must be root-owned, protected and not a symbolic link.
fn directory_allows_or_unknown(
    path: &Path,
    extension: &str,
    user: &str,
    depth: usize,
    budget: &mut Budget,
) -> bool {
    if depth > 8 || Instant::now() >= budget.deadline {
        return true;
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        Ok(metadata)
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 =>
        {
            return true;
        }
        Ok(_) => {}
    }
    let Ok(entries) = fs::read_dir(path) else {
        return true;
    };
    for entry in entries {
        let Some(remaining) = budget.entries.checked_sub(1) else {
            return true;
        };
        budget.entries = remaining;
        if Instant::now() >= budget.deadline {
            return true;
        }
        let Ok(entry) = entry else {
            return true;
        };
        let Ok(kind) = entry.file_type() else {
            return true;
        };
        if kind.is_symlink() {
            return true;
        }
        let path = entry.path();
        if kind.is_dir() {
            if directory_allows_or_unknown(&path, extension, user, depth + 1, budget) {
                return true;
            }
        } else if path.extension().is_some_and(|value| value == extension)
            && policy_allows_or_unknown(&path, user, budget)
        {
            return true;
        }
    }
    false
}

/// Extract additional absolute load directories named in this installed daemon.
/// Compilers can split common path prefixes into separate constants, so the
/// upstream locations remain a minimum, not a guess at an exhaustive list.
fn binary_policy_roots(bytes: &[u8]) -> Vec<(PathBuf, &'static str)> {
    let mut roots = Vec::new();
    for part in bytes.split(|byte| !byte.is_ascii_graphic()) {
        let Ok(text) = std::str::from_utf8(part) else {
            continue;
        };
        for suffix in ["/polkit-1/rules.d", "/polkit-1/actions"] {
            if text.starts_with('/') && text.ends_with(suffix) && !text.contains("..") {
                let extension = if suffix.ends_with("rules.d") {
                    "rules"
                } else {
                    "policy"
                };
                roots.push((PathBuf::from(text), extension));
            }
        }
    }
    roots
}

/// Obtain the executable from the system manager, never PATH or a guessed
/// package location. Unreadable or unusually large executables fail closed.
fn installed_policy_roots() -> Option<Vec<(PathBuf, &'static str)>> {
    let output = crate::access_privilege::host_output(
        "systemctl",
        &["show", "polkit.service", "-p", "ExecStart", "--value"],
    )?;
    let executable = output.split("path=").nth(1)?.split(" ;").next()?;
    let path = fs::canonicalize(executable).ok()?;
    for parent in path.ancestors() {
        let meta = fs::symlink_metadata(parent).ok()?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return None;
        }
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= 16 * 1024 * 1024).then(|| binary_policy_roots(&bytes))
}

/// Every other way polkit's authority daemon can run, besides its systemd
/// unit: the system bus activation file and the daemon's installed paths on
/// Debian-, Fedora- and Arch-style hosts.
const DAEMON_PATHS: &[&str] = &[
    "/usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service",
    "/usr/lib/polkit-1/polkitd",
    "/usr/libexec/polkitd",
    "/usr/libexec/polkit-1/polkitd",
];

/// Decide from observations whether polkit is absent. `load_state` is the
/// manager's `LoadState` of `polkit.service` (`None` when the manager did
/// not answer) and `exists` reports whether a path exists or may exist.
/// Only a definite "not-found" with none of [`DAEMON_PATHS`] present proves
/// that no polkit authority can answer; anything uncertain is "present".
fn absent_from(load_state: Option<&str>, exists: impl Fn(&str) -> bool) -> bool {
    load_state.is_some_and(|state| state.trim() == "not-found")
        && !DAEMON_PATHS.iter().any(|path| exists(path))
}

/// True when polkit is not installed, so no rule or action default can grant
/// this account anything (#355). Without this, a host without polkit failed
/// closed (it has no polkit.service to read), and no host could be clean.
/// Installing polkit or claiming its bus name both need root.
fn absent() -> bool {
    let state = crate::access_privilege::host_output(
        "systemctl",
        &["show", "polkit.service", "-p", "LoadState", "--value"],
    );
    absent_from(state.as_deref(), |path| {
        !fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

/// Exact login1 actions approved as harmless for this root-route check (#355).
/// Inhibition and self-linger affect session lifetime, and chvt selects a virtual
/// terminal; none permits executing arbitrary code as root. Session teardown
/// separately handles linger (D353). No prefix match or other yes grant is safe.
const HARMLESS_ACTIONS: &[&str] = &[
    "org.freedesktop.login1.chvt",
    "org.freedesktop.login1.inhibit-block-idle",
    "org.freedesktop.login1.inhibit-block-shutdown",
    "org.freedesktop.login1.inhibit-block-sleep",
    "org.freedesktop.login1.inhibit-delay-shutdown",
    "org.freedesktop.login1.inhibit-delay-sleep",
    "org.freedesktop.login1.inhibit-handle-hibernate-key",
    "org.freedesktop.login1.inhibit-handle-lid-switch",
    "org.freedesktop.login1.inhibit-handle-power-key",
    "org.freedesktop.login1.inhibit-handle-reboot-key",
    "org.freedesktop.login1.inhibit-handle-suspend-key",
    "org.freedesktop.login1.set-self-linger",
];

/// Whether one `annotation:` line of an approved action keeps its grant
/// inside the approved set. polkit authorizes every action an
/// `org.freedesktop.policykit.imply` annotation names along with the action
/// itself, so an approved id that implies anything else hands out that other
/// action too. `org.freedesktop.policykit.exec.path` makes `pkexec` run the
/// named program as root under the action's defaults. Only an implication of
/// further approved ids is accepted; every other annotation, including one
/// this reader does not know, extends the grant (#355).
fn annotation_stays_approved(annotation: &str) -> bool {
    annotation
        .strip_prefix("org.freedesktop.policykit.imply ->")
        .is_some_and(|ids| {
            let mut ids = ids.split_ascii_whitespace().peekable();
            ids.peek().is_some() && ids.all(|id| HARMLESS_ACTIONS.contains(&id))
        })
}

/// Read effective .policy defaults through polkit's own XML parser. Every
/// action must have exactly one of each scope; unknown formats fail closed.
/// Only the exact approved action ids may retain a stock yes default, and an
/// approved action that keeps one must not reach any other action or program
/// through its annotations (see [`annotation_stays_approved`]).
fn action_defaults_allow_or_unknown(text: &str) -> bool {
    let mut action = None;
    let mut scopes = 0u8;
    // Whether the current action's yes rests on the approved list, and
    // whether one of its annotations reaches past that list.
    let mut approved_yes = false;
    let mut extends = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if !line.starts_with(char::is_whitespace) {
            if action.is_some() && (scopes != 7 || (approved_yes && extends)) {
                return true;
            }
            let Some(id) = line.strip_suffix(':') else {
                return true;
            };
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            {
                return true;
            }
            action = Some(id);
            scopes = 0;
            approved_yes = false;
            extends = false;
        } else if let Some(rest) = line.trim_start().strip_prefix("implicit ") {
            let Some((scope, value)) = rest.split_once(':') else {
                return true;
            };
            let bit = match scope {
                "any" => 1,
                "inactive" => 2,
                "active" => 4,
                _ => return true,
            };
            if action.is_none() || scopes & bit != 0 {
                return true;
            }
            match value.trim() {
                "no" | "auth_self" | "auth_self_keep" | "auth_admin" | "auth_admin_keep" => {}
                "yes" if action.is_some_and(|id| HARMLESS_ACTIONS.contains(&id)) => {
                    approved_yes = true;
                }
                _ => return true,
            }
            scopes |= bit;
        } else if let Some(rest) = line.trim_start().strip_prefix("annotation:") {
            if action.is_none() {
                return true;
            }
            extends |= !annotation_stays_approved(rest.trim());
        }
    }
    action.is_none() || scopes != 7 || (approved_yes && extends)
}

/// Check all current and legacy polkit roots. Unfamiliar executable policy is
/// privileged even if it appears to name somebody else: textual matching cannot
/// establish the meaning of a JavaScript rule or an imported helper.
pub(crate) fn privileged(account: &User) -> bool {
    if absent() {
        return false;
    }
    let mut budget = Budget {
        entries: 1024,
        bytes: 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    let Some(extra) = installed_policy_roots() else {
        return true;
    };
    let roots = POLICY_ROOTS
        .iter()
        .map(|(path, extension)| (PathBuf::from(path), *extension))
        .chain(extra);
    for (path, extension) in roots {
        let path = path.as_path();
        for ancestor in path.ancestors().skip(1) {
            match fs::symlink_metadata(ancestor) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(metadata)
                    if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => {
                }
                _ => return true,
            }
        }
        if directory_allows_or_unknown(path, extension, &account.name, 0, &mut budget) {
            return true;
        }
    }
    if Instant::now() >= budget.deadline {
        return true;
    }
    crate::access_privilege::host_output("pkaction", &["--verbose"])
        .is_none_or(|output| action_defaults_allow_or_unknown(&output))
}

#[cfg(test)]
mod tests {
    //! Open-ended policy must never be mistaken for explicit denial.
    use super::*;

    /// Every upstream runtime/local override location must be inspected.
    #[test]
    fn runtime_local_and_action_policy_are_covered() {
        for required in [
            "/run/polkit-1/rules.d",
            "/usr/local/share/polkit-1/rules.d",
            "/usr/share/polkit-1/actions",
            "/etc/polkit-1/actions",
            "/run/polkit-1/actions",
            "/usr/local/share/polkit-1/actions",
        ] {
            assert!(
                POLICY_ROOTS.iter().any(|(path, _)| *path == required),
                "missing {required}"
            );
        }
    }

    /// Compiled extra locations and permissive effective action defaults count.
    #[test]
    fn compiled_locations_and_action_defaults_fail_closed() {
        let roots = binary_policy_roots(
            b"header\0/opt/site/polkit-1/rules.d\0/opt/site/polkit-1/actions\0",
        );
        assert!(roots.contains(&(PathBuf::from("/opt/site/polkit-1/rules.d"), "rules")));
        assert!(roots.contains(&(PathBuf::from("/opt/site/polkit-1/actions"), "policy")));
        let denied = "local.admin:\n  implicit any: no\n  implicit inactive: auth_admin\n  implicit active: auth_admin_keep\n";
        assert!(!action_defaults_allow_or_unknown(denied));
        assert!(action_defaults_allow_or_unknown(
            &denied.replace("auth_admin_keep", "yes")
        ));
        assert!(action_defaults_allow_or_unknown("unknown"));
    }

    /// Polkit counts as absent only when its unit is definitely not found and
    /// neither its bus activation file nor its daemon exists.
    #[test]
    fn only_a_proven_missing_polkit_is_absent() {
        assert!(absent_from(Some("not-found\n"), |_| false));
        assert!(!absent_from(Some("loaded\n"), |_| false));
        assert!(!absent_from(None, |_| false));
        assert!(!absent_from(Some("not-found"), |path| path.ends_with(".service")));
        assert!(!absent_from(Some("not-found"), |path| path.ends_with("polkitd")));
    }

    /// Only the owner's exact harmless login1 ids may have a stock yes grant.
    #[test]
    fn harmless_stock_actions_do_not_hide_other_yes_grants() {
        for id in [
            "chvt",
            "inhibit-block-idle",
            "inhibit-block-shutdown",
            "inhibit-block-sleep",
            "inhibit-delay-shutdown",
            "inhibit-delay-sleep",
            "inhibit-handle-hibernate-key",
            "inhibit-handle-lid-switch",
            "inhibit-handle-power-key",
            "inhibit-handle-reboot-key",
            "inhibit-handle-suspend-key",
            "set-self-linger",
        ] {
            let text = format!(
                "org.freedesktop.login1.{id}:\n  implicit any: yes\n  implicit inactive: yes\n  implicit active: yes\n"
            );
            assert!(!action_defaults_allow_or_unknown(&text), "{id}");
        }
        for id in [
            "org.freedesktop.login1.reboot",
            "org.freedesktop.login1.set-self-linger-extra",
            "local.admin",
        ] {
            let text = format!(
                "{id}:\n  implicit any: yes\n  implicit inactive: no\n  implicit active: no\n"
            );
            assert!(action_defaults_allow_or_unknown(&text), "{id}");
        }
    }

    /// An approved yes action may imply only other approved ids: polkit
    /// grants what it implies, and `pkexec` runs an action's `exec.path`
    /// program as root. Any other annotation on it fails closed, while the
    /// same annotation on an action without a yes grants nothing.
    #[test]
    fn approved_actions_cannot_reach_other_actions_or_programs() {
        let approved = |annotation: &str| {
            format!(
                "org.freedesktop.login1.chvt:\n  description:       Change Session\n  implicit any:      auth_admin_keep\n  implicit inactive: yes\n  implicit active:   yes\n{annotation}"
            )
        };
        assert!(!action_defaults_allow_or_unknown(&approved("")));
        assert!(!action_defaults_allow_or_unknown(&approved(
            "  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.inhibit-delay-sleep org.freedesktop.login1.inhibit-block-idle\n"
        )));
        for annotation in [
            "  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.systemd1.manage-units\n",
            "  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.inhibit-block-idle org.freedesktop.systemd1.manage-units\n",
            "  annotation:        org.freedesktop.policykit.imply ->\n",
            "  annotation:        org.freedesktop.policykit.exec.path -> /bin/sh\n",
            "  annotation:        org.freedesktop.policykit.exec.allow_gui -> true\n",
            "  annotation:        unknown\n",
        ] {
            assert!(
                action_defaults_allow_or_unknown(&approved(annotation)),
                "{annotation}"
            );
            // The next action's header closes this one, which must still fail.
            assert!(
                action_defaults_allow_or_unknown(&format!(
                    "{}local.denied:\n  implicit any: no\n  implicit inactive: no\n  implicit active: no\n",
                    approved(annotation)
                )),
                "{annotation}"
            );
        }
        let denied = "local.admin:\n  implicit any: auth_admin\n  implicit inactive: auth_admin\n  implicit active: auth_admin_keep\n  annotation:        org.freedesktop.policykit.exec.path -> /usr/bin/update-alternatives\n";
        assert!(!action_defaults_allow_or_unknown(denied));
        assert!(action_defaults_allow_or_unknown(
            "  annotation:        org.freedesktop.policykit.imply -> local.admin\n"
        ));
    }

    /// Real host policy goes through the same parser as planted action defaults.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires real host root and the installed polkit policy"]
    async fn real_stock_login1_action_is_harmless() {
        assert!(nix::unistd::Uid::effective().is_root());
        tokio::task::spawn_blocking(|| {
            let text = crate::access_privilege::host_output(
                "pkaction",
                &[
                    "--verbose",
                    "--action-id",
                    "org.freedesktop.login1.set-self-linger",
                ],
            )
            .unwrap();
            assert!(!action_defaults_allow_or_unknown(&text));
        })
        .await
        .unwrap();
    }

    /// User rules, group rules, legacy grants and arbitrary JavaScript all warn.
    #[test]
    fn polkit_user_group_and_unknown_policy_are_privileged() {
        for policy in [
            &b"polkit.addRule(function(action, subject) { if (subject.user == 'alice') return polkit.Result.YES; });"[..],
            &b"polkit.addRule(function(action, subject) { if (subject.isInGroup('operators')) return polkit.Result.YES; });"[..],
            &b"load('/some/other/policy');"[..],
            &b"[Root]\nIdentity=unix-group:operators\nAction=*\nResultAny=yes\n"[..],
            &b"\xff"[..],
            &b"// no local rules\n"[..],
            &b"// comment\rpolkit.addRule(function() { return polkit.Result.YES; });"[..],
            "// comment\u{2028}polkit.addRule(function() { return polkit.Result.YES; });".as_bytes(),
        ] {
            assert!(rule_allows_or_unknown(policy, "alice"));
        }
        assert!(!rule_allows_or_unknown(b" \n\r\t", "alice"));
    }

    /// Exercise the actual filesystem reader as both ordinary and host root.
    /// Ordinary ownership is unknown; root-owned empty trees can prove absence.
    #[test]
    fn policy_trees_and_scan_limits_fail_closed() {
        let root = nix::unistd::mkdtemp("/tmp/rvpk-XXXXXX").unwrap();
        let inspect = |extension, entries, bytes| {
            directory_allows_or_unknown(
                &root,
                extension,
                "alice",
                0,
                &mut Budget {
                    entries,
                    bytes,
                    deadline: Instant::now() + Duration::from_secs(1),
                },
            )
        };
        assert_eq!(
            inspect("rules", 20, 65536),
            !nix::unistd::Uid::effective().is_root()
        );
        let policy = root.join("50-local.rules");
        fs::write(&policy, "// no rules\n").unwrap();
        assert!(inspect("rules", 0, 65536));
        assert!(inspect("rules", 20, 0));
        fs::write(
            &policy,
            "polkit.addRule(function() { return polkit.Result.YES; });",
        )
        .unwrap();
        assert!(inspect("rules", 20, 65536));
        fs::remove_file(&policy).unwrap();
        std::os::unix::fs::symlink("/missing-policy-directory", root.join("linked")).unwrap();
        assert!(inspect("rules", 20, 65536));
        fs::remove_file(root.join("linked")).unwrap();
        let legacy = root.join("50-local.d");
        fs::create_dir(&legacy).unwrap();
        fs::write(
            legacy.join("root.pkla"),
            "[Root]\nIdentity=unix-group:operators\nResultAny=yes\n",
        )
        .unwrap();
        assert!(inspect("pkla", 20, 65536));
        fs::remove_dir_all(root).unwrap();
    }
}
