//! One kernel exit-readiness source for every authenticated shim; no per-shim task or idle timer [D13,D81].
//!
//! Registrations belong to the live registry and disappear with it. Kernel readiness
//! identifies the registered lifetime, not a later process that reuses its PID.

#[cfg(target_os = "linux")]
#[path = "process_exits_linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "process_exits_macos.rs"]
mod platform;

pub(crate) use platform::ProcessExits;
