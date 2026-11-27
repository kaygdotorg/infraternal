//! The relay component: CLI declarations, and behind `runtime` the ciphertext-only mesh relay [131,163,198,313].

pub mod cli;

/// The QUIC engine the relay API speaks (D176), for callers of its types.
#[cfg(feature = "runtime")]
pub use quinn;

#[cfg(feature = "runtime")]
pub mod client;
#[cfg(feature = "runtime")]
pub mod probe;
#[cfg(feature = "runtime")]
pub mod relay;
#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "runtime")]
pub mod tls;
/// The opaque pair tokens that name a relayed pair's link (D402 Q8).
#[cfg(feature = "runtime")]
pub mod token;
#[cfg(feature = "runtime")]
pub mod wire;
