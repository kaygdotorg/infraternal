//! Chooses a stable UDP port for a mesh node and distinguishes the default from an exact override.

use std::io;

/// The standard mesh UDP listener, chosen to match the default mesh subnet.
pub const DEFAULT_PORT: u16 = 10_254;

/// A requested listener and whether the node may select another port if it is occupied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The preferred listener port; zero asks the operating system for a free port.
    pub port: u16,
    /// Only the implicit default or its saved fallback can move to another port automatically.
    pub allow_fallback: bool,
}

/// Resolve an explicit override, saved default-selected port, or the standard mesh port.
///
/// A saved port is used only when the operator has not supplied an override. The saved value is
/// the actual bound port from a prior start, which preserves a fallback across restarts.
/// # Errors
/// Refuses malformed, zero, or reserved ports before the node starts.
pub fn requested(configured: Option<&str>, saved: Option<u16>) -> io::Result<Request> {
    let (port, allow_fallback) = match configured {
        Some(value) => (
            value.parse().map_err(|_| io::ErrorKind::InvalidInput)?,
            false,
        ),
        None => (saved.unwrap_or(DEFAULT_PORT), true),
    };
    if port == 0 || port == 51_820 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(Request {
        port,
        allow_fallback,
    })
}

/// Covers the default port, saved choices, overrides, and invalid values.
#[cfg(test)]
mod tests {
    use super::{DEFAULT_PORT, Request, requested};

    /// An unconfigured node selects the stable owner-chosen UDP listener.
    #[test]
    fn default_port_is_stable_and_may_fall_back() {
        assert!(matches!(
            requested(None, None),
            Ok(Request {
                port: DEFAULT_PORT,
                allow_fallback: true,
            })
        ));
        assert_eq!(DEFAULT_PORT, 10_254);
    }

    /// A configured port wins over the saved port and stays an exact operator choice.
    #[test]
    fn explicit_override_wins_over_saved_port() {
        assert!(matches!(
            requested(Some("32000"), Some(32001)),
            Ok(Request {
                port: 32_000,
                allow_fallback: false,
            })
        ));
    }

    /// A saved port keeps a default listener stable after a collision selected a fallback.
    #[test]
    fn saved_port_is_reused_when_no_override_is_present() {
        assert!(matches!(
            requested(None, Some(32_001)),
            Ok(Request {
                port: 32_001,
                allow_fallback: true,
            })
        ));
    }

    /// Zero, malformed values, and the reserved `WireGuard` port are refused before startup.
    #[test]
    fn invalid_ports_are_rejected() {
        for port in ["0", "51820", "not-a-port"] {
            assert!(requested(Some(port), None).is_err(), "accepted {port:?}");
        }
    }
}
