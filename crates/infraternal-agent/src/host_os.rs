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
//! An agent whose enrollment carried no direct server address (enrolled before
//! every invitation named the server's QUIC listener) adds ` direct=none`:
//!
//! ```text
//! infraternal agent os=macos direct=none
//! ```
//!
//! Such a host can only ever link over the public HTTPS origin, and App
//! Windows lanes exist only on QUIC, so the canvas tells the person to add the
//! Mac again rather than suggesting it is asleep (#146, D349). The suffix
//! describes the enrollment, not the current link: a host that has the address
//! but whose QUIC dial failed this time says nothing, because its next dial may
//! succeed.
//!
//! Old servers ignore the text and old agents send plain `infraternal agent`,
//! so both directions stay compatible. The server accepts only
//! `infraternal agent os=<token>` with a token from the closed OS table, optionally
//! followed by ` direct=none` ([`reported`]); anything else counts as "not
//! said", so a host cannot store arbitrary text this way.

use std::sync::atomic::{AtomicBool, Ordering};

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

/// The marker an agent whose enrollment has no direct server address adds after its OS token.
const WITHOUT_DIRECT: &str = " direct=none";

/// Set once at start by the remote client when the stored identity has no
/// direct server address. One agent process serves exactly one enrolled
/// identity, so a process-wide flag is that identity's fact; it saves
/// threading the enrollment through every Hello writer.
static ENROLLED_WITHOUT_DIRECT: AtomicBool = AtomicBool::new(false);

/// Record that this process's enrollment named no direct server address.
///
/// Call it before the first link, from the code that loaded the identity. The
/// fact comes from the stored enrollment, never from a failed name lookup or
/// dial, which are temporary.
pub fn enrolled_without_direct_endpoint() {
    ENROLLED_WITHOUT_DIRECT.store(true, Ordering::Release);
}

/// The `client_info` this build of the infraternal agent sends in its Hello:
/// `infraternal agent os=<target>`, plus ` direct=none` after
/// [`enrolled_without_direct_endpoint`].
///
/// Every build sends its own OS, in user mode and root mode alike, since both send this text. Only the
/// `LazyLock`s make it a `&'static str` (the Hello borrows its strings); each text never changes at run time.
#[must_use]
pub fn client_info() -> &'static str {
    static TEXT: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("infraternal agent os={}", std::env::consts::OS));
    static WITHOUT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "infraternal agent os={}{WITHOUT_DIRECT}",
            std::env::consts::OS
        )
    });
    if ENROLLED_WITHOUT_DIRECT.load(Ordering::Acquire) {
        WITHOUT.as_str()
    } else {
        TEXT.as_str()
    }
}

/// What a Hello's `client_info` says about the host, as the server keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    /// The OS name the server stores and the canvas shows (`"macOS"`, `"Linux"`, `"FreeBSD"`, ...).
    pub os: &'static str,
    /// False when the host's enrollment has no direct server address, so it
    /// can never open App Windows lanes until it is added again.
    pub direct_endpoint: bool,
}

/// Reads the OS and the enrollment's direct-address fact from an agent
/// Hello's `client_info`.
///
/// Returns `None` for an older agent that sends plain `infraternal agent`, a server, a target this table does
/// not list, or any text that is not `infraternal agent os=<listed token>` exactly. The server then keeps the
/// machine's `host-<id>` fallback name (D339).
#[must_use]
pub fn reported(client_info: &str) -> Option<Reported> {
    let rest = client_info.strip_prefix("infraternal agent os=")?;
    let (token, direct_endpoint) = match rest.strip_suffix(WITHOUT_DIRECT) {
        Some(token) => (token, false),
        None => (rest, true),
    };
    let os = KNOWN_OS
        .iter()
        .find(|(known, _)| *known == token)
        .map(|(_, name)| *name)?;
    Some(Reported {
        os,
        direct_endpoint,
    })
}

/// Reads only the OS name from an agent Hello's `client_info`; see [`reported`].
#[must_use]
pub fn reported_os(client_info: &str) -> Option<&'static str> {
    reported(client_info).map(|reported| reported.os)
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

    /// Only the exact ` direct=none` forms say the enrollment lacks the direct address.
    #[test]
    fn only_exact_forms_report_a_missing_direct_endpoint() {
        let without = |os| {
            Some(Reported {
                os,
                direct_endpoint: false,
            })
        };
        assert_eq!(
            reported("infraternal agent os=macos direct=none"),
            without("macOS")
        );
        assert_eq!(
            reported("infraternal agent os=linux direct=none"),
            without("Linux")
        );
        assert_eq!(
            reported("infraternal agent os=macos"),
            Some(Reported {
                os: "macOS",
                direct_endpoint: true,
            })
        );
        assert_eq!(reported("infraternal agent os=macos direct=none "), None);
        assert_eq!(reported("infraternal agent os=macos direct=yes"), None);
        assert_eq!(reported("infraternal agent direct=none"), None);
        assert_eq!(
            reported("infraternal agent os=freebsd direct=none"),
            without("FreeBSD")
        );
        assert_eq!(reported("infraternal agent os=direct=none"), None);
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
        let without = format!("{}{WITHOUT_DIRECT}", client_info());
        assert_eq!(
            reported(&without).map(|r| (r.os, r.direct_endpoint)),
            expected.map(|os| (os, false))
        );
    }
}
