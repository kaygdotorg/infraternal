//! Configurable memory headroom for new terminal sessions; retained scrollback is included in `MemAvailable` [D214], #151.

use infraternal_plugin_api::admission::OpenRefusal;
use serde::{Deserialize, Serialize};

/// Bytes in one mebibyte.
const MIB: u64 = 1024 * 1024;

/// The headroom a host must keep free before it accepts a new terminal session.
///
/// The floor is the larger of a fixed amount (MiB) and a share of total memory
/// (percent). Settings are validated before replacing the active policy, so a
/// bad update never leaves a half-applied policy. The fields are private; build
/// one with [`MemoryPolicy::default`] (256 MiB or 5 percent) or
/// [`MemoryPolicy::decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryPolicy {
    /// Fixed part of the floor, in MiB. Serialized as `terminalMemoryFloorMiB`.
    #[serde(rename = "terminalMemoryFloorMiB")]
    floor_mib: u64,
    /// Share of total memory kept free, 0 to 100. Serialized as `terminalMemoryFloorPercent`.
    #[serde(rename = "terminalMemoryFloorPercent")]
    percent: u8,
}

/// The built-in floor: 256 MiB or 5 percent of total memory, whichever is larger.
impl Default for MemoryPolicy {
    fn default() -> Self {
        Self {
            floor_mib: 256,
            percent: 5,
        }
    }
}

impl MemoryPolicy {
    /// Decode a complete bounded settings update without changing a valid policy on failure.
    ///
    /// `input` is a JSON object with exactly the two fields
    /// `terminalMemoryFloorMiB` and `terminalMemoryFloorPercent`; both are
    /// required, so a partial update is refused rather than merged.
    /// # Errors
    /// Rejects unknown fields, overflow, invalid percentages and oversized requests.
    pub fn decode(input: &[u8]) -> Result<Self, super::FactsError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Settings {
            #[serde(rename = "terminalMemoryFloorMiB")]
            floor_mib: u64,
            #[serde(rename = "terminalMemoryFloorPercent")]
            percent: u8,
        }
        if input.len() > super::MAX_FACTS_REQUEST_BYTES {
            return Err(super::FactsError::InvalidRequest);
        }
        let settings: Settings =
            serde_json::from_slice(input).map_err(|_| super::FactsError::InvalidRequest)?;
        if settings.percent > 100 || settings.floor_mib.checked_mul(MIB).is_none() {
            return Err(super::FactsError::InvalidRequest);
        }
        Ok(Self {
            floor_mib: settings.floor_mib,
            percent: settings.percent,
        })
    }

    /// The minimum free memory, in bytes, for a host with `total` bytes of memory.
    ///
    /// This is the larger of the fixed MiB floor and the percentage floor. A
    /// percentage floor rounds up to a byte, avoiding an overflow-prone total × percent.
    #[must_use]
    pub fn floor_bytes(self, total: u64) -> u64 {
        let percent = u64::from(self.percent);
        (self.floor_mib * MIB).max(total / 100 * percent + (total % 100 * percent).div_ceil(100))
    }

    /// Check the current OS sample rather than estimating from empty-shell memory.
    /// Existing output rings, VT history and all other host work reduce available memory.
    ///
    /// `memory` is the latest total and used byte counts, or `None` when the
    /// host could not be sampled. `session_count` is only reported back in the
    /// refusal; it does not affect the decision.
    /// # Errors
    /// Returns the public reason and current counters when admission cannot proceed.
    pub fn admit(
        self,
        memory: Option<super::Capacity>,
        session_count: usize,
    ) -> Result<(), OpenRefusal> {
        let memory = memory
            .filter(|memory| memory.total_bytes > 0 && memory.used_bytes <= memory.total_bytes)
            .ok_or(OpenRefusal::HostMemoryUnavailable)?;
        let available = memory.total_bytes - memory.used_bytes;
        if available < self.floor_bytes(memory.total_bytes) {
            return Err(OpenRefusal::HostMemoryLow {
                available_mib: available / MIB,
                session_count,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Exercise admission at both floor boundaries and reject malformed settings atomically.
    use super::*;
    use crate::Capacity;
    fn memory(total_mib: u64, available: u64) -> Capacity {
        Capacity {
            total_bytes: total_mib * MIB,
            used_bytes: total_mib * MIB - available,
        }
    }

    #[test]
    fn default_floor_refuses_only_below_headroom_even_above_128_sessions() {
        let policy = MemoryPolicy::default();
        assert_eq!(policy.admit(Some(memory(2048, 256 * MIB)), 200), Ok(()));
        assert_eq!(
            policy.admit(Some(memory(2048, 256 * MIB - 1)), 200),
            Err(OpenRefusal::HostMemoryLow {
                available_mib: 255,
                session_count: 200
            })
        );
        let floor = policy.floor_bytes(8192 * MIB);
        assert_eq!(policy.admit(Some(memory(8192, floor)), 200), Ok(()));
        assert_eq!(
            policy.admit(Some(memory(8192, floor - 1)), 200),
            Err(OpenRefusal::HostMemoryLow {
                available_mib: 409,
                session_count: 200
            })
        );
        assert_eq!(
            policy.admit(None, 200),
            Err(OpenRefusal::HostMemoryUnavailable)
        );
    }

    #[test]
    fn custom_policy_rounds_up_and_validates_all_settings_before_use() {
        let policy = MemoryPolicy::decode(
            br#"{"terminalMemoryFloorMiB":0,"terminalMemoryFloorPercent":100}"#,
        )
        .unwrap();
        assert_eq!(policy.floor_bytes(u64::MAX), u64::MAX);
        let percent =
            MemoryPolicy::decode(br#"{"terminalMemoryFloorMiB":0,"terminalMemoryFloorPercent":5}"#)
                .unwrap();
        assert_eq!(percent.floor_bytes(101), 6);
        for input in [
            br#"{"terminalMemoryFloorMiB":0,"terminalMemoryFloorPercent":101}"#.as_slice(),
            br#"{"terminalMemoryFloorMiB":18446744073709551615,"terminalMemoryFloorPercent":5}"#,
            br#"{"terminalMemoryFloorMiB":256,"terminalMemoryFloorPercent":5,"extra":true}"#,
            br#"{"terminalMemoryFloorMiB":256}"#,
        ] {
            assert!(MemoryPolicy::decode(input).is_err());
        }
    }
}
