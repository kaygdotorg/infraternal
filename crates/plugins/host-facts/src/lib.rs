//! Collects bounded, low-cost machine facts for an infraternal agent [D120][D156].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

// Everything is behind the `agent` feature: builds without it expose no API.
#[cfg(feature = "agent")]
mod facts;
#[cfg(feature = "agent")]
mod memory;
#[cfg(feature = "agent")]
pub use facts::{
    AgentMode, Capacity, DESCRIPTOR, Engine, FactsError, HostFacts, HostFactsPlugin,
    MAX_FACTS_REQUEST_BYTES, OsRelease, collect_static_facts, decode_configure_request,
    decode_read_request, parse_load_average_text, parse_macos_load_average, parse_os_release,
    refresh_live_facts,
};
#[cfg(feature = "agent")]
pub use memory::MemoryPolicy;

#[cfg(all(test, feature = "agent"))]
mod tests;

#[cfg(all(test, feature = "agent"))]
mod session_counts_tests;
