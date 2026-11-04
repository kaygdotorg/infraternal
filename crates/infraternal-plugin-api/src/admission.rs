//! Typed terminal refusals and on-request node context for compiled resource policies [D198,D214], #151.

use serde::{Deserialize, Serialize};

/// Live host-owned counts, never taken from a caller's JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeContext {
    pub session_count: usize,
    pub background_session_count: usize,
}

/// Fixed public reason codes; only memory refusal carries resource counters.
/// Unknown JSON fields are additive, but unknown reasons and invalid counters fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum OpenRefusal {
    HostMemoryLow {
        available_mib: u64,
        session_count: usize,
    },
    Invalid,
    /// The host's account policy refused the login (a rootless host asked for an account that is not its own).
    Permission,
    /// A rootless host has no account matching the person's name and, unlike a root host, cannot fall back to root.
    NoLogin,
    Unavailable,
    ResourceUnavailable,
    HostMemoryUnavailable,
}

impl OpenRefusal {
    /// Preserve the legacy error field alongside the typed additive refusal.
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
