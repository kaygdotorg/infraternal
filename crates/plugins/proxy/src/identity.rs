//! Defines the fixed unprivileged identity used by the rootful Traefik child [#281].

/// Dedicated user ID for the managed Traefik child in rootful mode.
pub(crate) const TRAEFIK_UID: u32 = 65_532;
/// Dedicated group ID for the managed Traefik child in rootful mode.
pub(crate) const TRAEFIK_GID: u32 = 65_532;

/// Whether the caller can use the approved rootful Traefik child identity.
#[must_use]
pub(crate) fn rootful() -> bool {
    if !nix::unistd::Uid::effective().is_root() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        // Root in a one-ID user namespace cannot switch to or chown files for Traefik.
        namespace_id_is_mapped("/proc/self/uid_map", TRAEFIK_UID)
            && namespace_id_is_mapped("/proc/self/gid_map", TRAEFIK_GID)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Child identity, preserving the caller's identity for rootless operation.
#[must_use]
pub(crate) fn child_ids() -> (u32, u32) {
    if rootful() {
        (TRAEFIK_UID, TRAEFIK_GID)
    } else {
        (
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
        )
    }
}

#[cfg(target_os = "linux")]
fn namespace_id_is_mapped(path: &str, child_id: u32) -> bool {
    std::fs::read_to_string(path).is_ok_and(|mapping| {
        mapping.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let Some(container_start) = fields.next().and_then(|value| value.parse::<u64>().ok())
            else {
                return false;
            };
            if fields
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .is_none()
            {
                return false;
            }
            let Some(length) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                return false;
            };
            let Some(container_end) = container_start.checked_add(length) else {
                return false;
            };
            (container_start..container_end).contains(&u64::from(child_id))
        })
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "The user namespace subprocess is required to exercise this identity boundary."
    )]

    use std::process::Command;

    #[test]
    fn user_namespace_root_without_traefik_id_mappings_is_rootless() {
        const PROBE: &str = "INFRATERNAL_PROXY_IDENTITY_USERNS_PROBE";
        if std::env::var_os(PROBE).is_some() {
            assert!(nix::unistd::Uid::effective().is_root());
            assert!(!super::rootful());
            return;
        }

        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--fork"])
            .arg(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "identity::tests::user_namespace_root_without_traefik_id_mappings_is_rootless",
                "--nocapture",
            ])
            .env(PROBE, "1")
            .status()
            .expect("start user namespace identity probe");
        assert!(
            status.success(),
            "user namespace identity probe failed: {status}"
        );
    }
}
