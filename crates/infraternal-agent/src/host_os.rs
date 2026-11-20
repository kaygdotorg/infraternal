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

/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(target_os = "macos")]
pub const CLIENT_INFO: &str = "infraternal agent os=macos";
/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(target_os = "linux")]
pub const CLIENT_INFO: &str = "infraternal agent os=linux";
/// The `client_info` this build of the infraternal agent sends in its Hello.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const CLIENT_INFO: &str = "infraternal agent";

/// Reads the OS from an agent Hello's `client_info`, as the name the server
/// stores and the canvas shows (`"macOS"` or `"Linux"`).
///
/// Returns `None` for an older agent, a server, or any text that is not one of
/// the exact forms this module sends.
#[must_use]
pub fn reported_os(client_info: &str) -> Option<&'static str> {
    match client_info {
        "infraternal agent os=macos" => Some("macOS"),
        "infraternal agent os=linux" => Some("Linux"),
        _ => None,
    }
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
    }
}
