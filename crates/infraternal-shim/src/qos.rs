//! Thread quality-of-service classes on macOS (#554).
//!
//! The kernel schedules a thread by its quality-of-service class, and a thread with no class runs wherever
//! the process default puts it. Latency-critical threads (the runtime that relays terminal
//! bytes, the shim that owns a PTY) ask for [`Qos::UserInteractive`] so they are woken on a
//! performance core. Housekeeping threads ask for [`Qos::Utility`] so they never compete.
//!
//! This is **not** what fixes late timers. Measured on a real M1 (#554), only the launchd job's
//! `ProcessType=Interactive` stops timer coalescing; a thread class leaves a 8.33 ms timer at
//! 34 ms. This module only decides which core a woken thread runs on, so keep both.
//!
//! On every other platform each function does nothing and reports success, so callers need no `cfg`.
//! The one FFI call is the single unsafe item in this file: it takes no pointer and no borrowed
//! state, so it has no invariant beyond "called on the thread you mean to change".
#![allow(unsafe_code)]

/// How urgent a thread's work is. Maps to the matching `QOS_CLASS_*` constant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Qos {
    /// Work a person is waiting on right now: relaying keys and paint.
    UserInteractive,
    /// Work that matters but nobody is waiting on: cleanup, uninstall, plugin hosting.
    Utility,
}

impl Qos {
    /// The raw `qos_class_t` value from `<sys/qos.h>`.
    #[cfg(target_os = "macos")]
    const fn raw(self) -> u32 {
        match self {
            Self::UserInteractive => 0x21,
            Self::Utility => 0x11,
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `<pthread/qos.h>`: set the calling thread's class; returns 0 or an errno value.
    fn pthread_set_qos_class_self_np(class: u32, relative_priority: i32) -> i32;
}

/// Give the calling thread `qos`. Call it first thing on the thread you mean to change.
///
/// Returns `true` when the class took effect, and `true` on platforms without quality-of-service classes. A refusal is
/// harmless (the thread keeps its default class), so callers may ignore it.
#[must_use]
pub fn set_current_thread(qos: Qos) -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: plain integers in, an errno out; it only changes the calling thread's class.
        unsafe { pthread_set_qos_class_self_np(qos.raw(), 0) == 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = qos;
        true
    }
}

/// Exercise both classes and the kernel constants.
#[cfg(test)]
mod tests {
    use super::{Qos, set_current_thread};

    /// Both classes apply on the calling thread without error (and are a no-op off macOS).
    #[test]
    fn both_classes_apply() {
        std::thread::spawn(|| {
            assert!(set_current_thread(Qos::Utility));
            assert!(set_current_thread(Qos::UserInteractive));
        })
        .join()
        .unwrap();
    }

    /// The raw values are the kernel's, so a wrong constant would silently pick another class.
    #[cfg(target_os = "macos")]
    #[test]
    fn classes_match_the_kernel_constants() {
        assert_eq!(Qos::UserInteractive.raw(), 0x21);
        assert_eq!(Qos::Utility.raw(), 0x11);
    }
}
