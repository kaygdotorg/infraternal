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
/// Installing a signed release folder by hand, to move an existing server onto the boot pointer (#211 S6).
#[cfg(feature = "server")]
pub mod adopt;
/// The applier trait the owner controls call for apply and rollback; the server implements it with S4 (#211 S5).
#[cfg(feature = "server")]
pub mod applier;
/// World-executable CLI copy and `/usr/local/bin/infraternal` link that follow server updates (#211).
#[cfg(feature = "server")]
pub mod cli_link;
/// The bounded update history shown in the Updates row (#211 S5).
#[cfg(feature = "server")]
pub mod history;
/// The web app build a release carries, and the rule that a release image serves it (#211 S6).
#[cfg(feature = "server")]
pub mod web;
