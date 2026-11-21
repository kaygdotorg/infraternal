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

/// Exact login1 actions approved as harmless for this root-route check (#355),
/// in every session scope. The D382 console power actions are approved
/// separately, for an active session only ([`CONSOLE_POWER_ACTIONS`]).
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

/// D382 (owner, 2026-11-10): the console power actions stock Linux grants
/// an active local console session. They reboot, power off, suspend or
/// hibernate the machine, or choose what the next boot starts; none writes
/// a file the account chooses or runs a command, so they do not count as
/// admin powers. Exactly these 12 ids, and only their `implicit active`
/// default: a `yes` for any other session, or for any other id (halt, the
/// `-ignore-inhibit` variants, and every other grant), still counts.
const CONSOLE_POWER_ACTIONS: &[&str] = &[
    "org.freedesktop.login1.reboot",
    "org.freedesktop.login1.reboot-multiple-sessions",
    "org.freedesktop.login1.power-off",
    "org.freedesktop.login1.power-off-multiple-sessions",
    "org.freedesktop.login1.suspend",
    "org.freedesktop.login1.suspend-multiple-sessions",
    "org.freedesktop.login1.hibernate",
    "org.freedesktop.login1.hibernate-multiple-sessions",
    "org.freedesktop.login1.set-reboot-parameter",
    "org.freedesktop.login1.set-reboot-to-boot-loader-entry",
    "org.freedesktop.login1.set-reboot-to-boot-loader-menu",
    "org.freedesktop.login1.set-reboot-to-firmware-setup",
];

/// Actions an approved action may imply without being approved itself.
/// Stock `reboot` and `power-off` imply setting the message logind sends to
/// logged-in terminals before it shuts down: text shown to people, never a
/// file or a command. Its own defaults are still read like any action's.
/// The owner (2026-11-21) chose to ignore it only "when it comes with the
/// stock reboot defaults": only the [`WALL_MESSAGE_FROM`] actions may imply
/// it, and a grant of its own still counts.
const IMPLIED_ONLY: &[&str] = &["org.freedesktop.login1.set-wall-message"];

/// The stock actions whose defaults imply [`IMPLIED_ONLY`]'s wall message.
/// An implication of it from any other action counts as a grant.
const WALL_MESSAGE_FROM: &[&str] = &[
    "org.freedesktop.login1.reboot",
    "org.freedesktop.login1.power-off",
];

/// Whether a `yes` (or `auth_self`) default for `scope` of action `id` is
/// approved: the harmless login1 ids in every scope, the D382 console power
/// ids for an active session only.
fn approved(id: &str, scope: &str) -> bool {
    HARMLESS_ACTIONS.contains(&id) || (scope == "active" && CONSOLE_POWER_ACTIONS.contains(&id))
}

/// What one `annotation:` line of an approved action reaches. polkit
/// authorizes every action an `org.freedesktop.policykit.imply` annotation
/// names along with the action itself, under the implying action's own
/// defaults, so an approved id that implies anything else hands out that
/// other action too. `org.freedesktop.policykit.exec.path` makes `pkexec`
/// run the named program as root under the action's defaults.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Only ids approved in every session scope ([`HARMLESS_ACTIONS`]).
    Harmless,
    /// Also a D382 console power id or an [`IMPLIED_ONLY`] id. That is
    /// approved only when the implying action's own `yes` is for an active
    /// session alone; otherwise the implied action reaches inactive and
    /// remote sessions too (J1051).
    Console,
    /// Anything else, including an annotation this reader does not know.
    Beyond,
}

/// Classify one `annotation:` line of approved action `action` (see
/// [`Reach`]). Only an implication of known ids stays inside the approved
/// set (#355), and the wall message only from [`WALL_MESSAGE_FROM`].
fn annotation_reach(action: &str, annotation: &str) -> Reach {
    let Some(ids) = annotation.strip_prefix("org.freedesktop.policykit.imply ->") else {
        return Reach::Beyond;
    };
    // An empty list is not a known implication.
    let mut reach = Reach::Beyond;
    for id in ids.split_ascii_whitespace() {
        if IMPLIED_ONLY.contains(&id) && !WALL_MESSAGE_FROM.contains(&action) {
            return Reach::Beyond;
        } else if CONSOLE_POWER_ACTIONS.contains(&id) || IMPLIED_ONLY.contains(&id) {
            reach = Reach::Console;
        } else if !HARMLESS_ACTIONS.contains(&id) {
            return Reach::Beyond;
        } else if reach == Reach::Beyond {
            reach = Reach::Harmless;
        }
    }
    reach
}

/// Read effective .policy defaults through polkit's own XML parser. Every
/// action must have exactly one of each scope; unknown formats fail closed.
/// Only the exact approved action ids may retain a stock yes default (see
/// [`approved`]), and an
/// approved action that keeps one must not reach any other action or program
/// through its annotations (see [`Reach`]): a console power id only from an
/// action whose `yes` is for an active session alone.
fn action_defaults_allow_or_unknown(text: &str) -> bool {
    let mut action = None;
    let mut scopes = 0u8;
    // Whether the current action's yes rests on the approved list, and
    // whether one of its annotations reaches past that list.
    let mut approved_yes = false;
    let mut extends = false;
    // Whether that yes also covers inactive or remote sessions, and whether
    // an annotation implies a console power id (D382: active session only).
    let mut wide_yes = false;
    let mut console = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if !line.starts_with(char::is_whitespace) {
            if action.is_some()
                && (scopes != 7 || (approved_yes && (extends || (wide_yes && console))))
            {
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
            wide_yes = false;
            console = false;
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
            // `auth_self` asks only for the account's own credentials, so
            // whoever can sign in as the account holds that action: a grant,
            // like `yes`, allowed only where `yes` is. Only refusal or an
            // administrator's approval grants nothing.
            match value.trim() {
                "no" | "auth_admin" | "auth_admin_keep" => {}
                "yes" | "auth_self" | "auth_self_keep"
                    if action.is_some_and(|id| approved(id, scope)) =>
                {
                    approved_yes = true;
                    wide_yes |= scope != "active";
                }
                _ => return true,
            }
            scopes |= bit;
        } else if let Some(rest) = line.trim_start().strip_prefix("annotation:") {
            let Some(id) = action else {
                return true;
            };
            match annotation_reach(id, rest.trim()) {
                Reach::Harmless => {}
                Reach::Console => console = true,
                Reach::Beyond => extends = true,
            }
        }
    }
    action.is_none() || scopes != 7 || (approved_yes && (extends || (wide_yes && console)))
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
        for own in ["auth_self", "auth_self_keep"] {
            assert!(
                action_defaults_allow_or_unknown(&denied.replace("auth_admin_keep", own)),
                "{own}"
            );
        }
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

    /// D382: a stock polkitd host comes out clean. This is `pkaction
    /// --verbose` from a stock Debian 13 host (polkitd 126, systemd 257),
    /// whose login1 policy grants an active session the 12 console power
    /// actions and the harmless inhibit, chvt and self-linger ids.
    const STOCK_DEBIAN13: &str = include_str!("testdata/pkaction-debian13.txt");

    /// D382: the stock action set is clean, each console power id is ignored
    /// for an active session only, and every other yes still counts.
    #[test]
    fn console_power_actions_are_ignored_and_every_other_grant_counts() {
        assert!(!action_defaults_allow_or_unknown(STOCK_DEBIAN13));
        assert_eq!(CONSOLE_POWER_ACTIONS.len(), 12);
        let defaults = |id: &str, any: &str, inactive: &str, active: &str| {
            format!(
                "{id}:\n  implicit any:      {any}\n  implicit inactive: {inactive}\n  implicit active:   {active}\n"
            )
        };
        for id in CONSOLE_POWER_ACTIONS {
            assert!(
                !action_defaults_allow_or_unknown(&defaults(
                    id,
                    "auth_admin_keep",
                    "auth_admin_keep",
                    "yes"
                )),
                "{id}"
            );
            // Away from the console, the same id is a grant.
            for (any, inactive) in [("yes", "auth_admin_keep"), ("auth_admin_keep", "yes")] {
                assert!(
                    action_defaults_allow_or_unknown(&defaults(id, any, inactive, "yes")),
                    "{id} any {any} inactive {inactive}"
                );
            }
        }
        for id in [
            "org.freedesktop.login1.halt",
            "org.freedesktop.login1.reboot-ignore-inhibit",
            "org.freedesktop.login1.power-off-ignore-inhibit",
            "org.freedesktop.login1.set-wall-message",
            "org.freedesktop.login1.set-user-linger",
            "org.freedesktop.login1.reboot-extra",
            "org.freedesktop.systemd1.manage-units",
            "org.freedesktop.NetworkManager.settings.modify.system",
        ] {
            assert!(
                action_defaults_allow_or_unknown(&defaults(
                    id,
                    "auth_admin_keep",
                    "auth_admin_keep",
                    "yes"
                )),
                "{id}"
            );
        }
        // Any other yes in the stock set itself still flags it, and so does
        // an approved console action that reaches a non-approved one.
        let units = "org.freedesktop.systemd1.manage-units:";
        let at = STOCK_DEBIAN13.find(units).unwrap();
        let end = at + STOCK_DEBIAN13[at..].find("implicit active:").unwrap();
        let line_end = end + STOCK_DEBIAN13[end..].find('\n').unwrap();
        let granted = format!(
            "{}implicit active:   yes{}",
            &STOCK_DEBIAN13[..end],
            &STOCK_DEBIAN13[line_end..]
        );
        assert!(action_defaults_allow_or_unknown(&granted));
        // Stock halt (auth_admin only) implies the same wall message: an
        // annotation on an action without a yes grants nothing, so only the
        // approved reboot reaching manage-units may flag.
        let wall = "imply -> org.freedesktop.login1.set-wall-message";
        let units = "imply -> org.freedesktop.systemd1.manage-units";
        let reboot = STOCK_DEBIAN13
            .find("\norg.freedesktop.login1.reboot:\n")
            .unwrap();
        let halt = STOCK_DEBIAN13
            .find("\norg.freedesktop.login1.halt:\n")
            .unwrap();
        let reaching = |from: usize| {
            let at = from + STOCK_DEBIAN13[from..].find(wall).unwrap();
            format!(
                "{}{units}{}",
                &STOCK_DEBIAN13[..at],
                &STOCK_DEBIAN13[at + wall.len()..]
            )
        };
        assert!(action_defaults_allow_or_unknown(&reaching(reboot)));
        assert!(!action_defaults_allow_or_unknown(&reaching(halt)));
    }

    /// Owner, 2026-11-21: `login1.set-wall-message` is ignored only when it
    /// comes with the stock reboot and power-off defaults, which imply it. A
    /// grant of its own, or an implication from any other action, counts.
    #[test]
    fn the_wall_message_counts_unless_stock_reboot_or_power_off_implies_it() {
        const WALL: &str = "org.freedesktop.login1.set-wall-message";
        assert!(!action_defaults_allow_or_unknown(STOCK_DEBIAN13));
        let defaults = |any: &str, inactive: &str, active: &str| {
            format!(
                "{WALL}:\n  implicit any:      {any}\n  implicit inactive: {inactive}\n  implicit active:   {active}\n"
            )
        };
        for (any, inactive, active) in [
            ("auth_admin_keep", "auth_admin_keep", "yes"),
            ("auth_admin_keep", "yes", "auth_admin_keep"),
            ("yes", "auth_admin_keep", "auth_admin_keep"),
            ("auth_admin_keep", "auth_admin_keep", "auth_self"),
        ] {
            assert!(
                action_defaults_allow_or_unknown(&defaults(any, inactive, active)),
                "{any} {inactive} {active}"
            );
        }
        let imply = |from: &str| {
            let header = format!("\n{from}:\n");
            let at = STOCK_DEBIAN13.find(&header).unwrap() + header.len();
            format!(
                "{}  annotation:        org.freedesktop.policykit.imply -> {WALL}\n{}",
                &STOCK_DEBIAN13[..at],
                &STOCK_DEBIAN13[at..]
            )
        };
        for stock in [
            "org.freedesktop.login1.reboot",
            "org.freedesktop.login1.power-off",
        ] {
            assert!(!action_defaults_allow_or_unknown(&imply(stock)), "{stock}");
        }
        for other in [
            "org.freedesktop.login1.suspend",
            "org.freedesktop.login1.reboot-multiple-sessions",
            "org.freedesktop.login1.set-reboot-to-firmware-setup",
            "org.freedesktop.login1.inhibit-delay-shutdown",
        ] {
            assert!(action_defaults_allow_or_unknown(&imply(other)), "{other}");
        }
    }

    /// D382 ignores the console power ids for an active session only. polkit
    /// grants an implied action with the implying action's own defaults, so
    /// an approved action whose `yes` also covers other sessions (stock
    /// `inhibit-delay-shutdown` has `implicit any: yes`, `chvt` has
    /// `implicit inactive: yes`) must not imply one of them: that hands
    /// reboot or power-off to every session, SSH included (J1051).
    #[test]
    fn console_power_is_never_implied_beyond_an_active_session() {
        let imply = |from: &str, to: &str| {
            let header = format!("\n{from}:\n");
            let at = STOCK_DEBIAN13.find(&header).unwrap() + header.len();
            format!(
                "{}  annotation:        org.freedesktop.policykit.imply -> {to}\n{}",
                &STOCK_DEBIAN13[..at],
                &STOCK_DEBIAN13[at..]
            )
        };
        for from in [
            "org.freedesktop.login1.inhibit-delay-shutdown",
            "org.freedesktop.login1.chvt",
            "org.freedesktop.login1.set-self-linger",
        ] {
            for to in [
                "org.freedesktop.login1.reboot",
                "org.freedesktop.login1.power-off-multiple-sessions",
                "org.freedesktop.login1.set-reboot-to-firmware-setup",
                "org.freedesktop.login1.set-wall-message",
            ] {
                assert!(
                    action_defaults_allow_or_unknown(&imply(from, to)),
                    "{from} -> {to}"
                );
            }
            // An all-session action may still imply another all-session one.
            assert!(
                !action_defaults_allow_or_unknown(&imply(
                    from,
                    "org.freedesktop.login1.inhibit-block-idle"
                )),
                "{from}"
            );
        }
        // An active-only console action may imply another console action.
        assert!(!action_defaults_allow_or_unknown(&imply(
            "org.freedesktop.login1.suspend",
            "org.freedesktop.login1.reboot"
        )));
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

    /// D382 on a real host: the whole installed action set of a stock
    /// polkitd host (no extra policy packages) reads as no grant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires real host root and a stock polkit action set"]
    async fn real_stock_action_set_is_clean() {
        assert!(nix::unistd::Uid::effective().is_root());
        tokio::task::spawn_blocking(|| {
            let text = crate::access_privilege::host_output("pkaction", &["--verbose"]).unwrap();
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
