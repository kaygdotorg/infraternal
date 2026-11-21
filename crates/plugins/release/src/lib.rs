//! Owns stable-by-default release settings, explicit edge opt-in and verified metadata as a removable server feature [16,198,201,226].
pub mod descriptor;
#[cfg(feature = "server")]
pub mod latest;
pub mod pointer;
#[cfg(feature = "server")]
pub mod service;
#[cfg(feature = "server")]
mod socket;
/// The server's own update check, download and staging (#211 S3).
#[cfg(feature = "server")]
pub mod update;
#[cfg(feature = "server")]
pub use socket::ReleasePlugin;
/// The applier S4 plugs in for apply and rollback; until then a stub that says so (#211 S5).
#[cfg(feature = "server")]
pub mod apply;
/// The bounded update history shown in the Updates row (#211 S5).
#[cfg(feature = "server")]
pub mod history;
