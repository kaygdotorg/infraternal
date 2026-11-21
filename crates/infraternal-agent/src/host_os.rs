//! Names the host's operating system in the infraternal agent's link Hello, and reads it back on the server [D349], #146.
//!
//! A host that joins by invitation never runs the SSH probe, so the server
//! had no idea it was a Mac and the canvas never offered its app windows. The
//! agent now says which OS it runs in the Hello `client_info` text, which every
//! server already receives and, until now, ignored:
//!
//! ```text
//! infraternal agent os=macos
//! infraternal agent os=linux
//! ```
//!
//! Old servers ignore the suffix and old agents send plain `infraternal agent`,
//! so both directions stay compatible. The server accepts only the exact
//! strings above ([`reported_os`]); anything else counts as "not said", so a
//! host cannot store arbitrary text this way.

/// Every OS token this module can report, with the name the server stores and the canvas shows.
///
/// The token is `std::env::consts::OS`, which the compiler fixes for each build, so an agent always
/// names its own OS and needs no runtime probe (#337). The table is closed on purpose: the server accepts
/// only these tokens, so a host can never store free text this way.
const KNOWN_OS: &[(&str, &str)] = &[
    ("linux", "Linux"),
    ("macos", "macOS"),
    ("windows", "Windows"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("netbsd", "NetBSD"),
    ("dragonfly", "DragonFly BSD"),
    ("illumos", "illumos"),
    ("solaris", "Solaris"),
    ("android", "Android"),
    ("ios", "iOS"),
    ("haiku", "Haiku"),
    ("redox", "Redox"),
    ("fuchsia", "Fuchsia"),
    ("aix", "AIX"),
];

/// The `client_info` this build of the infraternal agent sends in its Hello: `infraternal agent os=<target>`.
///
/// Every build sends its own OS, in user mode and root mode alike, since both send this text. Only the
/// `LazyLock` makes it a `&'static str` (the Hello borrows its strings); the text never changes at run time.
pub fn client_info() -> &'static str {
    static TEXT: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("infraternal agent os={}", std::env::consts::OS));
    TEXT.as_str()
}

/// Reads the OS from an agent Hello's `client_info`, as the name the server
/// stores and the canvas shows (`"macOS"`, `"Linux"`, `"FreeBSD"`, ...).
///
/// Returns `None` for an older agent that sends plain `infraternal agent`, a server, a target this table does
/// not list, or any text that is not `infraternal agent os=<listed token>` exactly. The server then keeps the
/// machine's `host-<id>` fallback name (D339).
#[must_use]
pub fn reported_os(client_info: &str) -> Option<&'static str> {
    let token = client_info.strip_prefix("infraternal agent os=")?;
    KNOWN_OS
        .iter()
        .find(|(known, _)| *known == token)
        .map(|(_, name)| *name)
}

#[cfg(test)]
/// Checks that only the exact Hello forms map to an OS name.
mod tests {
    use super::*;

    /// Each listed token maps to its stored name; everything else (old agents, servers, near-misses) is unknown.
    #[test]
    fn only_exact_hello_forms_name_an_os() {
        assert_eq!(reported_os("infraternal agent os=macos"), Some("macOS"));
        assert_eq!(reported_os("infraternal agent os=linux"), Some("Linux"));
        assert_eq!(reported_os("infraternal agent"), None);
        assert_eq!(reported_os("infraternal agent os="), None);
        assert_eq!(reported_os("infraternal agent os=macos "), None);
        assert_eq!(reported_os("infraternal agent os=MacOS"), None);
        assert_eq!(reported_os("infraternal agent os=linux;x"), None);
        assert_eq!(reported_os("infraternal-server/0.1"), None);
    }

    /// #337: a build for any listed system names itself, not only macOS and Linux. Before this, a FreeBSD agent
    /// sent plain `infraternal agent` and its machine fell back to `host-<id>`.
    #[test]
    fn every_listed_system_is_named() {
        assert_eq!(reported_os("infraternal agent os=freebsd"), Some("FreeBSD"));
        assert_eq!(reported_os("infraternal agent os=windows"), Some("Windows"));
        assert_eq!(reported_os("infraternal agent os=illumos"), Some("illumos"));
    }

    /// The Hello this build sends is one the server reads back, for every target this table lists.
    #[test]
    fn this_build_reports_itself() {
        let expected = KNOWN_OS
            .iter()
            .find(|(token, _)| *token == std::env::consts::OS)
            .map(|(_, name)| *name);
        assert_eq!(reported_os(client_info()), expected);
        assert!(client_info().starts_with("infraternal agent os="));
    }
}
