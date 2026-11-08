//! Conservative polkit inspection for the revoke access report (#355).
//! JavaScript rules can call arbitrary policy helpers, so this does not try to
//! interpret them. Only exact known default content or ASCII whitespace-only files
//! can prove no additional authority. Unknown policy is privileged.
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
    time::{Duration, Instant},
};

use nix::unistd::User;
use sha2::{Digest as _, Sha256};

/// Current and legacy policy locations. Legacy admin-identity configuration is
/// included because it can give an ordinary account administrative authority.
const POLICY_ROOTS: &[(&str, &str)] = &[
    ("/etc/polkit-1/rules.d", "rules"),
    ("/usr/share/polkit-1/rules.d", "rules"),
    ("/etc/polkit-1/localauthority", "pkla"),
    ("/var/lib/polkit-1/localauthority", "pkla"),
    ("/etc/polkit-1/localauthority.conf.d", "conf"),
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
    let digest = format!("{:x}", Sha256::digest(text));
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
    rule_allows_or_unknown(&bytes, user)
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

/// Check all current and legacy polkit roots. Unfamiliar executable policy is
/// privileged even if it appears to name somebody else: textual matching cannot
/// establish the meaning of a JavaScript rule or an imported helper.
pub(crate) fn privileged(account: &User) -> bool {
    let mut budget = Budget {
        entries: 1024,
        bytes: 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    for (root, extension) in POLICY_ROOTS {
        let path = Path::new(root);
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
    Instant::now() >= budget.deadline
}

#[cfg(test)]
mod tests {
    //! Open-ended policy must never be mistaken for explicit denial.
    use super::*;

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
