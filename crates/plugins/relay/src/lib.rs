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
#[cfg(feature = "runtime")]
pub mod wire;
