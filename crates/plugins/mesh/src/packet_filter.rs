//! Applies the packet filter and diagnoses Linux host settings.

/// Shared filter used at the Linux and macOS packet boundaries.
pub(crate) use infraternal_mesh_node::packet_filter::*;

/// Read [`REQUIRED_SYSCTLS`] from `/proc/sys` and log a warning for each setting that would
/// let the kernel act on a part of a packet the filter does not judge.
///
/// Called once when the `GotaTun` engine starts. It warns rather than refuses: the settings are
/// host-wide, owned by the host's own configuration, and the defaults are already correct.
#[cfg(target_os = "linux")]
pub(crate) fn warn_about_sysctl_gaps() {
    for gap in sysctl_gaps(|name| std::fs::read_to_string(format!("/proc/sys/{name}")).ok()) {
        tracing::warn!(setting = %gap, "mesh packet filter relies on a host setting that is not at its required value");
    }
}
