//! Owns stable-by-default release settings, explicit edge opt-in and verified metadata as a removable server feature [16,198,201,226].
/// Switching to a staged release and the D295 undo (#211 S4).
#[cfg(feature = "server")]
pub mod apply;
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
/// The applier trait the owner controls call for apply and rollback; the server implements it with S4 (#211 S5).
#[cfg(feature = "server")]
pub mod applier;
/// The bounded update history shown in the Updates row (#211 S5).
#[cfg(feature = "server")]
pub mod history;
