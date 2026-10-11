//! Owns stable-by-default release settings, explicit edge opt-in and verified metadata as a removable server feature [16,198,201,226].
pub mod descriptor;
pub mod pointer;
#[cfg(feature = "server")]
pub mod service;
