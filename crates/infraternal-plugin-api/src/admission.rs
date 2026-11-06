//! Typed terminal refusals and on-request node context for compiled resource policies [D198,D214], #151.

use serde::{Deserialize, Serialize};

/// What a host knows about its own sessions right now, for resource policies that decide
/// whether to open another one. The host fills it in itself; it is never read from a caller's
/// JSON, so a caller cannot understate its load.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeContext {
    /// All terminal sessions the host currently has open.
    pub session_count: usize,
    /// How many of those sessions no window is attached to, so they run in the background.
    pub background_session_count: usize,
}

/// Why a host refused to open a terminal. The reason is a fixed code that is safe to show to
/// anyone; only the memory refusal carries numbers (the resource counters).
///
/// Parsing is strict where it matters: unknown extra JSON fields are ignored so new fields can
/// be added, but an unknown `reason` or an invalid counter is an error (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum OpenRefusal {
    /// The host is short of memory. `available_mib` is its free memory in MiB and
    /// `session_count` the sessions it already runs.
    HostMemoryLow {
        available_mib: u64,
        session_count: usize,
    },
    /// The request was malformed or not acceptable.
    Invalid,
    /// The host's account policy refused the login (a rootless host asked for an account that is not its own).
    Permission,
    /// A rootless host has no account matching the person's name and, unlike a root host, cannot fall back to root.
    NoLogin,
    /// A root host without systemd opens no person logins: it could not prove a revoked login's
    /// processes gone (D354). A rootless agent on that host, or a host with systemd, still can.
    NoSystemd,
    /// The terminal could not be opened for a reason the host does not detail.
    Unavailable,
    /// The host could not check or reserve the resources a terminal needs.
    ResourceUnavailable,
    /// The host could not read its own memory figures, so it could not decide.
    HostMemoryUnavailable,
}

impl OpenRefusal {
    /// The JSON reply for a refused terminal: `{"error":"terminal unavailable", "reason": ...}`
    /// plus the counters of the refusal, if it has any. The legacy `error` field stays next to
    /// the typed, additive `reason`.
    ///
    /// # Errors
    /// Returns a JSON serialization failure.
    pub fn json(self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Reply {
            error: &'static str,
            #[serde(flatten)]
            refusal: OpenRefusal,
        }
        serde_json::to_vec(&Reply {
            error: "terminal unavailable",
            refusal: self,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Exercise additive compatibility and strict numeric refusal decoding.
    use super::*;

    /// D354's refusal is its own reason on the wire, so the browser can say why and what works instead.
    #[test]
    fn no_systemd_refusal_has_its_own_reason() {
        let json = OpenRefusal::NoSystemd.json().unwrap();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"error":"terminal unavailable","reason":"no_systemd"}"#
        );
        assert_eq!(
            serde_json::from_slice::<OpenRefusal>(&json).unwrap(),
            OpenRefusal::NoSystemd
        );
    }

    #[test]
    fn memory_refusal_round_trips_without_losing_legacy_error() {
        let refusal = OpenRefusal::HostMemoryLow {
            available_mib: 180,
            session_count: 212,
        };
        let json = refusal.json().unwrap();
        assert_eq!(
            serde_json::from_slice::<OpenRefusal>(&json).unwrap(),
            refusal
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&json).unwrap()["error"],
            "terminal unavailable"
        );
        assert!(serde_json::from_slice::<OpenRefusal>(br#"{"reason":"future"}"#).is_err());
        for body in [
            br#"{"reason":"host_memory_low","available_mib":-1,"session_count":1}"#.as_slice(),
            br#"{"reason":"host_memory_low","available_mib":1,"session_count":1.5}"#,
            br#"{"reason":"host_memory_low","available_mib":1}"#,
        ] {
            assert!(serde_json::from_slice::<OpenRefusal>(body).is_err());
        }
        assert_eq!(
            serde_json::from_slice::<OpenRefusal>(br#"{"reason":"invalid","future":true}"#)
                .unwrap(),
            OpenRefusal::Invalid
        );
    }
}
