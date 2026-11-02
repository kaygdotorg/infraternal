//! Defines the proxy listener pairs admitted by the Mesh ingress firewalls.

/// One HTTP and HTTPS listener pair for a proxy audience.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerPortPair {
    /// Plain HTTP listener port.
    pub http: u16,
    /// TLS listener port.
    pub https: u16,
}

/// One inclusive interval in the proxy listener port set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    /// First accepted port.
    pub start: u16,
    /// Last accepted port.
    pub end: u16,
}

impl PortRange {
    /// Check whether one port is admitted by this inclusive interval.
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Conventional ports selected when the node can bind them.
pub const CONVENTIONAL_LISTENER_PAIR: ListenerPortPair = ListenerPortPair {
    http: 80,
    https: 443,
};

/// Unprivileged pair used when conventional ports are unavailable or the process is rootless.
pub const UNPRIVILEGED_LISTENER_PAIR: ListenerPortPair = ListenerPortPair {
    http: 10_080,
    https: 10_443,
};

/// Number of high-port alternatives scanned for a separate mesh listener pair.
pub const MIXED_LISTENER_PAIR_COUNT: u16 = 256;

/// Every distinct high-port pair the config selector may choose for mesh-only listeners.
pub static MIXED_LISTENER_PAIRS: [ListenerPortPair; MIXED_LISTENER_PAIR_COUNT as usize] =
    mixed_listener_pairs();

/// Compact TCP ranges accepted by the mesh proxy-ingress exception.
pub static PROXY_INGRESS_PORT_RANGES: [PortRange; 4] = [
    PortRange {
        start: CONVENTIONAL_LISTENER_PAIR.http,
        end: CONVENTIONAL_LISTENER_PAIR.http,
    },
    PortRange {
        start: CONVENTIONAL_LISTENER_PAIR.https,
        end: CONVENTIONAL_LISTENER_PAIR.https,
    },
    PortRange {
        start: UNPRIVILEGED_LISTENER_PAIR.http,
        end: UNPRIVILEGED_LISTENER_PAIR.http + MIXED_LISTENER_PAIR_COUNT - 1,
    },
    PortRange {
        start: UNPRIVILEGED_LISTENER_PAIR.https,
        end: UNPRIVILEGED_LISTENER_PAIR.https + MIXED_LISTENER_PAIR_COUNT - 1,
    },
];

const fn mixed_listener_pairs() -> [ListenerPortPair; MIXED_LISTENER_PAIR_COUNT as usize] {
    let mut pairs = [UNPRIVILEGED_LISTENER_PAIR; MIXED_LISTENER_PAIR_COUNT as usize];
    let mut offset = 0_u16;
    while offset < MIXED_LISTENER_PAIR_COUNT {
        let index = offset as usize;
        pairs[index] = ListenerPortPair {
            http: UNPRIVILEGED_LISTENER_PAIR.http + offset,
            https: UNPRIVILEGED_LISTENER_PAIR.https + offset,
        };
        offset += 1;
    }
    pairs
}
