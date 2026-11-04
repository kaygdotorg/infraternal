//! Makes common relay/direct decisions from measured confidence bounds without idle work [D185,D214,D232].

/// Which route a session's data takes between viewer and host. Session ownership stays with
/// the server through either path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Data goes through the server's relay. Always works.
    Relay,
    /// Data goes straight between viewer and host.
    Direct,
}
/// A latency measurement as a range: the true one-way delay lies between `lower_ns` and
/// `upper_ns` nanoseconds.
///
/// Bounds refer to one current probe generation in the caller's clock domain.
/// Transport adapters supply measurements, including their uncertainty; a
/// configured preference or an uncalibrated cross-host timestamp is no sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estimate {
    /// The probe round this measurement belongs to. Only measurements of the current round count.
    pub generation: u64,
    /// Lowest delay the measurement allows, in nanoseconds.
    pub lower_ns: u64,
    /// Highest delay the measurement allows, in nanoseconds. Must not be below `lower_ns`.
    pub upper_ns: u64,
}
impl Estimate {
    /// True when this estimate is from probe round `generation` and its bounds are ordered.
    fn valid(self, generation: u64) -> bool {
        self.generation == generation && self.lower_ns <= self.upper_ns
    }
}
/// Which paths the transport adapter can actually use for a session. It is established by the
/// compiled, admitted adapter, never by a viewer's latency report. Relay-only adapters cannot
/// advertise a working direct path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Only the relay can be used.
    RelayOnly,
    /// Both the relay and a direct path are available.
    RelayAndDirect,
}
/// Picks the path for probe round `generation`.
///
/// Direct is chosen only when both paths are available, both estimates are valid for this
/// round, and direct is measurably faster: its upper bound is strictly below relay's lower
/// bound. Anything else, including a missing or stale estimate, gives `Relay`. Because the
/// choice is recomputed from the latest estimates, a session moves between paths in both
/// directions without a setting.
///
/// Pure selection is reusable by terminal and desktop adapters. It starts no probe, listener
/// or timer and never changes a delivery-mode default.
#[must_use]
pub fn select(
    generation: u64,
    availability: Availability,
    relay: Option<Estimate>,
    direct: Option<Estimate>,
) -> Path {
    if availability == Availability::RelayAndDirect
        && let (Some(relay), Some(direct)) = (relay, direct)
        && relay.valid(generation)
        && direct.valid(generation)
        && direct.upper_ns < relay.lower_ns
    {
        Path::Direct
    } else {
        Path::Relay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn estimate(lower_ns: u64, upper_ns: u64) -> Estimate {
        Estimate {
            generation: 1,
            lower_ns,
            upper_ns,
        }
    }
    #[test]
    fn only_measurably_faster_current_supported_direct_is_selected() {
        assert_eq!(
            select(
                1,
                Availability::RelayOnly,
                Some(estimate(100, 200)),
                Some(estimate(1, 2))
            ),
            Path::Relay
        );
        assert_eq!(
            select(
                1,
                Availability::RelayAndDirect,
                Some(estimate(100, 200)),
                Some(estimate(1, 99))
            ),
            Path::Direct
        );
        assert_eq!(
            select(
                1,
                Availability::RelayAndDirect,
                Some(estimate(100, 200)),
                Some(estimate(1, 100))
            ),
            Path::Relay
        );
        assert_eq!(
            select(
                2,
                Availability::RelayAndDirect,
                Some(estimate(100, 200)),
                Some(estimate(1, 2))
            ),
            Path::Relay
        );
        assert_eq!(
            select(
                1,
                Availability::RelayAndDirect,
                Some(estimate(100, 99)),
                Some(estimate(1, 2))
            ),
            Path::Relay
        );
    }
    #[test]
    fn worsening_and_recovery_switch_both_ways_without_a_setting() {
        let availability = Availability::RelayAndDirect;
        assert_eq!(
            select(
                1,
                availability,
                Some(estimate(100, 200)),
                Some(estimate(1, 99))
            ),
            Path::Direct
        );
        assert_eq!(
            select(
                1,
                availability,
                Some(estimate(100, 200)),
                Some(estimate(210, 300))
            ),
            Path::Relay
        );
        assert_eq!(
            select(
                1,
                availability,
                Some(estimate(100, 200)),
                Some(estimate(1, 99))
            ),
            Path::Direct
        );
        assert_eq!(
            select(1, availability, Some(estimate(100, 200)), None),
            Path::Relay
        );
    }
}
