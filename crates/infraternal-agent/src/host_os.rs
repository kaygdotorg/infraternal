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
//! so both directions stay compatible. The server accepts only the exact
//! strings above ([`reported`]); anything else counts as "not said", so a
//! host cannot store arbitrary text this way.

use std::sync::atomic::{AtomicBool, Ordering};

/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(target_os = "macos")]
pub const CLIENT_INFO: &str = "infraternal agent os=macos";
/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(target_os = "linux")]
pub const CLIENT_INFO: &str = "infraternal agent os=linux";
/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const CLIENT_INFO: &str = "infraternal agent";

/// [`CLIENT_INFO`] for an agent whose enrollment has no direct server address.
#[cfg(target_os = "macos")]
const CLIENT_INFO_WITHOUT_DIRECT: &str = "infraternal agent os=macos direct=none";
/// [`CLIENT_INFO`] for an agent whose enrollment has no direct server address.
#[cfg(target_os = "linux")]
const CLIENT_INFO_WITHOUT_DIRECT: &str = "infraternal agent os=linux direct=none";
/// Other systems name no OS, so they have nothing to qualify either.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const CLIENT_INFO_WITHOUT_DIRECT: &str = CLIENT_INFO;

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

/// The `client_info` to send in a Hello now: [`CLIENT_INFO`], plus
/// ` direct=none` after [`enrolled_without_direct_endpoint`].
#[must_use]
pub fn client_info() -> &'static str {
    if ENROLLED_WITHOUT_DIRECT.load(Ordering::Acquire) {
        CLIENT_INFO_WITHOUT_DIRECT
    } else {
        CLIENT_INFO
    }
}

/// What a Hello's `client_info` says about the host, as the server keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    /// The OS name the server stores and the canvas shows (`"macOS"` or `"Linux"`).
    pub os: &'static str,
    /// False when the host's enrollment has no direct server address, so it
    /// can never open App Windows lanes until it is added again.
    pub direct_endpoint: bool,
}

/// Reads the OS and the enrollment's direct-address fact from an agent
/// Hello's `client_info`.
///
/// Returns `None` for an older agent, a server, or any text that is not one of
/// the exact forms this module sends.
#[must_use]
pub fn reported(client_info: &str) -> Option<Reported> {
    let (os, direct_endpoint) = match client_info {
        "infraternal agent os=macos" => ("macOS", true),
        "infraternal agent os=linux" => ("Linux", true),
        "infraternal agent os=macos direct=none" => ("macOS", false),
        "infraternal agent os=linux direct=none" => ("Linux", false),
        _ => return None,
    };
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

    /// Each form this module sends maps to its stored name; everything else is unknown.
    #[test]
    fn only_exact_hello_forms_name_an_os() {
        assert_eq!(reported_os("infraternal agent os=macos"), Some("macOS"));
        assert_eq!(reported_os("infraternal agent os=linux"), Some("Linux"));
        assert_eq!(reported_os("infraternal agent"), None);
        assert_eq!(reported_os("infraternal agent os=macos "), None);
        assert_eq!(reported_os("infraternal agent os=MacOS"), None);
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
    }

    /// The text this build sends is one the server reads back (on the two supported systems).
    #[test]
    fn this_build_reports_itself() {
        let expected = if cfg!(target_os = "macos") {
            Some("macOS")
        } else if cfg!(target_os = "linux") {
            Some("Linux")
        } else {
            None
        };
        assert_eq!(reported_os(CLIENT_INFO), expected);
        assert_eq!(reported_os(CLIENT_INFO_WITHOUT_DIRECT), expected);
        if expected.is_some() {
            assert_eq!(
                reported(CLIENT_INFO_WITHOUT_DIRECT).map(|r| r.direct_endpoint),
                Some(false)
            );
        }
    }
}
